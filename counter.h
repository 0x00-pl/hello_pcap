#ifndef __COUNTER_H__
#define __COUNTER_H__

#include <sys/types.h>

typedef struct counter_decl{
    u_int64_t package;
    u_int64_t ip_package;
    u_int64_t tcp_package;
    u_int64_t tcp_port_80_package;
    u_int64_t tcp_link_package_foward;
    u_int64_t tcp_link_package_backward;
    u_int64_t http_request;
    u_int64_t cache_find;
    u_int64_t cache_update;
    u_int64_t cache_gc;
} counter_t;

extern counter_t g_counter;

#if 1
# define COUNTER_INC(member) (g_counter.member++)
#else
# define COUNTER_INC(x)
#endif

void print_counter(counter_t *counter);

#endif
