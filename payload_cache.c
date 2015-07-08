#include "payload_cache.h"

#include "global_defines.h"

        


void id_payload_map_item_init(id_payload_map_item_t *obj,
                              u_int32_t source_ip, u_int16_t source_port, u_int32_t dest_ip,
                              u_int32_t tcp_seq, u_char *payload, int payload_len){
    obj->source_ip = source_ip;
    obj->source_port = source_port;
    obj->dest_ip = dest_ip;
    obj->tcp_seq = tcp_seq;
    obj->payload = payload;
    obj->payload_len = payload_len;
}

id_payload_map_item_t *id_payload_map_item_new(payload_cache_t *payload_cache){
    id_payload_map_item_t *item = malloc(sizeof(id_payload_map_item_t));
    item->payload_index = payload_cache->next_index++;
    return item;
}

void id_payload_map_item_fini(id_payload_map_item_t *obj){
    free(obj->payload);
}

int id_payload_map_item_key_cmp(u_int32_t a_source_ip, u_int32_t b_source_ip,
                                u_int16_t a_source_port, u_int16_t b_source_port,
                                u_int32_t a_dest_ip, u_int32_t b_dest_ip){
    if(a_source_ip != b_source_ip){
        return a_source_ip - b_source_ip;
    }
    if(a_source_port != b_source_port){
        return a_source_port - b_source_port;
    }
    if(a_dest_ip != b_dest_ip){
        return a_dest_ip - b_dest_ip;
    }
    return 0;
}


void payload_cache_init(payload_cache_t *payload_cache){
    payload_cache->id_payload_map.rb_node = NULL;
    payload_cache->map_size = 0;
    payload_cache->next_index = CACHE_ITEM_SIZE;
}

void payload_cache_map_fini(struct rb_node *root){
    if(root == NULL){return;}
    id_payload_map_item_t *pc_node = container_of(root, id_payload_map_item_t, node);
    payload_cache_map_fini(root->rb_left);
    payload_cache_map_fini(root->rb_right);
    id_payload_map_item_fini(pc_node);
    free(pc_node);
}


void payload_cache_fini(payload_cache_t *payload_cache){
    payload_cache_map_fini(payload_cache->id_payload_map.rb_node);
}

void payload_cache_map_gc(payload_cache_t *payload_cache){
    if(payload_cache->map_size < CACHE_ITEM_SIZE*2){
        return;
    }
    
    struct rb_node *cur_node;
    id_payload_map_item_t *cur_item;
    for(cur_node=rb_first(&payload_cache->id_payload_map); cur_node!=NULL; cur_node=rb_next(cur_node)){
        cur_item = container_of(payload_cache->id_payload_map.rb_node, id_payload_map_item_t, node);
        if(cur_item->payload_index < (payload_cache->next_index-CACHE_ITEM_SIZE)){
            rb_erase(cur_node, &payload_cache->id_payload_map);
            id_payload_map_item_fini(cur_item);
            free(cur_item);
        }
    }
}

id_payload_map_item_t *payload_cache_find(payload_cache_t *payload_cache, u_int32_t source_ip, u_int16_t source_port, u_int32_t dest_ip){
    struct rb_node *node = payload_cache->id_payload_map.rb_node;

    while (node) {
        id_payload_map_item_t *data = container_of(node, id_payload_map_item_t, node);
        int result;

        result = id_payload_map_item_key_cmp(source_ip, data->source_ip,
                                                source_port, data->source_port,
                                                dest_ip, data->dest_ip);

        if (result < 0){
            node = node->rb_left;
        }
        else if (result > 0){
            node = node->rb_right;
        }
        else{
            return data;
        }
    }
    return NULL;
}

void payload_cache_update(payload_cache_t *payload_cache, id_payload_map_item_t *data){
    payload_cache_map_gc(payload_cache);
    struct rb_root *root = &payload_cache->id_payload_map;
    struct rb_node **new_node = &(root->rb_node);
    struct rb_node *parent = NULL;

    /* Figure out where to put new node */
    while (*new_node) {
        id_payload_map_item_t *thiz = container_of(*new_node, id_payload_map_item_t, node);
        int result = id_payload_map_item_key_cmp(data->source_ip, thiz->source_ip,
                                                data->source_port, thiz->source_port,
                                                data->dest_ip, thiz->dest_ip);

        parent = *new_node;
        if (result < 0){
            new_node = &((*new_node)->rb_left);
        }
        else if (result > 0){
            new_node = &((*new_node)->rb_right);
        }
        else{
            rb_replace_node(*new_node, &data->node, root);
            id_payload_map_item_fini(thiz);
            free(thiz);
            return;
        }
    }

    /* Add new node and rebalance tree. */
    rb_link_node(&data->node, parent, new_node);
    rb_insert_color(&data->node, root);

    return;
}








