#include "cap_structs.h"
#include "payload_cache.h"
#include "counter.h"
#include <string.h>
#include <stdlib.h>


void link_buff(u_char *dest, struct cap_headers *cur_headers, id_payload_map_item_t *cached){
    if(cur_headers->tcp.header.seq > cached->tcp_seq){
        COUNTER_INC(tcp_link_package_backward);
        memcpy(dest, cached->payload, cached->payload_len);
        memcpy(dest+cached->payload_len, cur_headers->payload, cur_headers->payload_len);
    }
    else{
        COUNTER_INC(tcp_link_package_foward);
        memcpy(dest, cur_headers->payload, cur_headers->payload_len);
        memcpy(dest+cur_headers->payload_len, cached->payload, cached->payload_len);
    }
    dest[cur_headers->payload_len+cached->payload_len]='\0';
}

typedef void tcp_callback_t(void* args, u_char *tcp_payload, int length, void* extra);

typedef enum{
    HEADER_PART_BAD = 0,
    HEADER_PART_BEG = 1,
    HEADER_PART_END = 2,
    HEADER_PART_FULL = 1|2,
} header_part;
header_part avlible_header_check(u_char *payload, int length){
    if(length<4){return HEADER_PART_BAD;}
    header_part ret=0;
    if((strncmp((const char *)payload, "GET", 3)==0) || (strncmp((const char *)payload, "POST", 4)==0)){
        ret |= HEADER_PART_BEG;
    }
    if(strstr((const char *)payload, "\r\n\r\n")!=NULL){
        ret |= HEADER_PART_END;
    }
    return ret;
}

void tcp_handler(struct cap_headers *headers, payload_cache_t *payload_cache, tcp_callback_t callback, void* args){
    if(headers == NULL){return;}
//     if(headers->tcp.header.psh != 0){return;}
    if(headers->tcp.header.ack == 0){return;}
    u_int32_t src_ip = headers->ip.header.saddr;
    u_int16_t src_port = headers->tcp.header.source;
    u_int16_t dst_ip = headers->ip.header.saddr;
    
    switch(avlible_header_check(headers->payload, headers->payload_len)){
        case HEADER_PART_BAD:
            COUNTER_INC(http_bad_header);
            // ignore
            break;
        case HEADER_PART_BEG:
        case HEADER_PART_END:{
            id_payload_map_item_t *cached_payload_item = payload_cache_find(payload_cache, src_ip, src_port, dst_ip);
            if(cached_payload_item == NULL){
                // not found, store to cache for next try
                id_payload_map_item_t *current_item = id_payload_map_item_new(payload_cache);
                id_payload_map_item_init(current_item, src_ip, src_port, dst_ip,
                                         headers->tcp.header.seq, headers->payload, headers->payload_len);
                payload_cache_update(payload_cache, current_item);
            }
            else if(cached_payload_item->payload_len == 0){
                // not found, store to cache for next try
                // DO NOT CHANGE KEY
                id_payload_map_item_init(cached_payload_item, src_ip, src_port, dst_ip,
                                         headers->tcp.header.seq, headers->payload, headers->payload_len);
            }
            else{
                // found and link_buff
                int if_remove_cache = 0;
                int cached_payload_len = cached_payload_item->payload_len;
                int linked_payload_len = cached_payload_len+headers->payload_len+1;
                if(linked_payload_len < 4096){
                    u_char buff[4096];
                    link_buff(buff, headers, cached_payload_item);
                    if(avlible_header_check(buff, linked_payload_len) == HEADER_PART_FULL){
                        COUNTER_INC(http_linked_header);
                        callback(args, buff, linked_payload_len, NULL);
                        if_remove_cache = 1;
                    }
                }
                else{
                    u_char *buff = malloc(linked_payload_len);
                    link_buff(buff, headers, cached_payload_item);
                    if(avlible_header_check(buff, linked_payload_len) == HEADER_PART_FULL){
                        COUNTER_INC(http_linked_header);
                        callback(args, buff, linked_payload_len, NULL);
                        if_remove_cache = 1;
                    }
                    free(buff);
                }
                
                if(if_remove_cache){
                    // remove old cache but keep item
                    free(cached_payload_item->payload);
                    cached_payload_item->payload_len = 0;
                    cached_payload_item->payload_index = 0;
                }
            }
            }break;
            
        case HEADER_PART_FULL:
            COUNTER_INC(http_full_header);
            callback(args, headers->payload, headers->payload_len, NULL);
            break;
    }
}

