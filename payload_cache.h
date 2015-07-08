#ifndef __PAYLOAD_CACHE_H__
#define __PAYLOAD_CACHE_H__

#include <stdlib.h>
#include <sys/types.h>
#include "external/include/linux/rbtree.h"


#undef offsetof
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)

/**
 * container_of - cast a member of a structure out to the containing structure
 * @ptr:        the pointer to the member.
 * @type:       the type of the container struct this is embedded in.
 * @member:     the name of the member within the struct.
 *
 */
#define container_of(ptr, type, member) ({                      \
        const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
        (type *)( (char *)__mptr - offsetof(type,member) );})

        
typedef struct id_payload_map_item_decl{
        struct rb_node node;
        // index
        u_int64_t payload_index;
        
        // keys
        u_int32_t source_ip;
        u_int32_t source_port;
        u_int16_t dest_ip;
//         u_int32_t dest_port; // static 80
        
        //values
        u_int32_t tcp_seq;
        u_char *payload;
        int payload_len;
} id_payload_map_item_t;


typedef struct {
    struct rb_root id_payload_map;
    u_int32_t map_size;
    u_int64_t next_index;
} payload_cache_t;




void id_payload_map_item_init(id_payload_map_item_t *obj,
                              u_int32_t source_ip, u_int16_t source_port, u_int32_t dest_ip,
                              u_int32_t tcp_seq, u_char *payload, int payload_len);

id_payload_map_item_t *id_payload_map_item_new(payload_cache_t *payload_cache);

void id_payload_map_item_fini(id_payload_map_item_t *obj);

int id_payload_map_item_key_cmp(u_int32_t a_source_ip, u_int32_t b_source_ip,
                                u_int16_t a_source_port, u_int16_t b_source_port,
                                u_int32_t a_dest_ip, u_int32_t b_dest_ip);

void payload_cache_init(payload_cache_t *payload_cache);

void payload_cache_fini(payload_cache_t *payload_cache);

void payload_cache_map_gc(payload_cache_t *payload_cache);

id_payload_map_item_t *payload_cache_find(payload_cache_t *payload_cache, u_int32_t source_ip, u_int16_t source_port, u_int32_t dest_ip);

void payload_cache_update(payload_cache_t *payload_cache, id_payload_map_item_t *data);


#endif
    
