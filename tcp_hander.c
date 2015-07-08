#include "cap_structs.h"
#include "payload_cache.h"
#include <memory.h>


void link_buff(u_char *dest, struct cap_headers *cur_headers, id_payload_map_item_t *cached){
    if(cur_headers->tcp.header.seq > cached->tcp_seq){
        memcpy(dest, cached->payload, cached->payload_len);
        memcpy(dest+cached->payload_len, cur_headers->payload, cur_headers->payload_len);
    }
    else{
        memcpy(dest, cur_headers->payload, cur_headers->payload_len);
        memcpy(dest+cur_headers->payload_len, cached->payload, cached->payload_len);
    }
}

typedef void tcp_callback_t(void* args, u_char *tcp_payload, u_char length, void* extra);

void tcp_handler(struct cap_headers *headers, payload_cache_t *payload_cache, tcp_callback_t callback, void* args){
    if(headers == NULL){return;}
    if(headers->tcp.header.psh != 0){return;}
    if(headers->tcp.header.ack == 0){return;}
    u_int32_t src_ip = headers->ip.header.saddr;
    u_int16_t src_port = headers->tcp.header.source;
    u_int16_t dst_ip = headers->ip.header.saddr;
    
    id_payload_map_item_t *cached_payload_item = payload_cache_find(payload_cache, src_ip, src_port, dst_ip);
    if(cached_payload_item == NULL){
        // no cache return
        callback(args, headers->payload, headers->payload_len, NULL);
    }
    else{
        int cached_payload_len = cached_payload_item->payload_len;
        int linked_payload_len = cached_payload_len+headers->payload_len;
        if(linked_payload_len < 4096){
            u_char buff[4096];
            link_buff(buff, headers, cached_payload_item);
            callback(args, buff, linked_payload_len, NULL);
        }
        else{
            u_char *buff = malloc(cached_payload_len+headers->payload_len);
            link_buff(buff, headers, cached_payload_item);
            callback(args, buff, linked_payload_len, NULL);
            free(buff);
        }
    }
    id_payload_map_item_t *current_item = id_payload_map_item_new(payload_cache);
    id_payload_map_item_init(current_item, src_ip, src_port, dst_ip, headers->tcp.header.seq, headers->payload, headers->payload_len);
    payload_cache_update(payload_cache, current_item);
}

