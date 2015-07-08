#include "encode.c"



int tcp_response_payload(struct cap_headers* source, struct cap_headers *dest, u_char *payload, u_int payload_len){
    *dest = *source;
    
    //payload
    dest->payload = payload;
    dest->payload_len = payload_len;
    
    //tcp
    dest->tcp.header.source = source->tcp.header.dest;
    dest->tcp.header.dest = source->tcp.header.source;
    dest->tcp.header.seq = source->tcp.header.ack_seq;
    dest->tcp.header.ack_seq = source->tcp.header.seq + payload_len;
    dest->tcp.header.cwr = 0;
    dest->tcp.header.ece = 0;
    dest->tcp.header.urg = 0;
    dest->tcp.header.ack = 1;
    dest->tcp.header.psh = 1;
    dest->tcp.header.rst = 1;
    dest->tcp.header.syn = 0;
    dest->tcp.header.fin = 1;

    //ip
    dest->ip.header.id = source->ip.header.id + 100;
    dest->ip.header.saddr = source->ip.header.daddr;
    dest->ip.header.daddr = source->ip.header.saddr;
    dest->ip.header.tot_len = IP_LEN(dest->ip.header) + TCP_LEN(dest->tcp.header) + payload_len;
    
    return 0;
}

