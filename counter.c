#include "counter.h"
#include <stdio.h>

counter_t g_counter = {0};


void print_counter(counter_t *counter){
#define PRINT_COUNTER_MEMBER(member) \
    printf(#member ": %lu\n", counter->member)
    
    PRINT_COUNTER_MEMBER(package);
    PRINT_COUNTER_MEMBER(ip_package);
    PRINT_COUNTER_MEMBER(tcp_package);
    PRINT_COUNTER_MEMBER(tcp_port_80_package);
    PRINT_COUNTER_MEMBER(tcp_link_package_foward);
    PRINT_COUNTER_MEMBER(tcp_link_package_backward);
    PRINT_COUNTER_MEMBER(http_request);
    PRINT_COUNTER_MEMBER(cache_find);
    PRINT_COUNTER_MEMBER(cache_update);
    PRINT_COUNTER_MEMBER(cache_gc);
    
#undef PRINT_COUNTER_MEMBER
}


