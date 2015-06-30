#include "cap_structs.h"
#include <string.h>
#include <stdio.h>

char last_error[256];
const char *get_last_error(){
    return last_error;
}

#define NTOHL(x) x = ntohl(x)
#define NTOHS(x) x = ntohs(x)

int decode_ethernet(u_char *packet, u_int paclen, struct ethhdr *header){
    memcpy(header, packet, ETH_HLEN);
    NTOHS(header->h_proto);
    return 0;
}
int decode_vlan(u_char *packet, u_int paclen, struct vlan_tag *header){
    memcpy(header, packet, VLAN_TAG_LEN);
    NTOHS(header->vlan_tpid);
    NTOHS(header->vlan_tci);
    return 0;
}
int decode_pppoe_8864(u_char *packet, u_int paclen, struct pppoe_8863_8864 *header){
    memcpy(header, packet, PPPOE_SES_HLEN);
    NTOHS(header->header.sid);
    NTOHS(header->header.length);
    NTOHS(header->ppp_prorocol);
    return 0;
}
int decode_ip(u_char *packet, u_int paclen, struct ip_with_options *header){
    struct iphdr *ip = (struct iphdr*) packet;
    size_t size_ip = ip->ihl * 4;
    bzero(header->options, 64);
    memcpy(header, packet, size_ip);
    NTOHS(header->ip.tot_len);
    NTOHS(header->ip.id);
    NTOHS(header->ip.frag_off);
    NTOHS(header->ip.check);
    return 0;
}
int decode_tcp(u_char *packet, u_int paclen, struct tcp_with_options_header *header){
    struct tcphdr *tcp = (struct tcphdr*) packet;
    size_t size_tcp = tcp->doff * 4;
    bzero(header->options, 64);
    memcpy(&header->header, packet, size_tcp);
    NTOHS(header->header.source);
    NTOHS(header->header.dest);
    NTOHL(header->header.seq);
    NTOHL(header->header.ack_seq);
    NTOHS(header->header.window);
    NTOHS(header->header.check);
    NTOHS(header->header.urg_ptr);
    return 0;
}

int decode(u_char *packet, u_int paclen, struct cap_headers *headers){
#define POP_HEADER(size) packet+=size; paclen-=size;
    u_int16_t proto;
    decode_ethernet(packet, paclen, &headers->eth);
    POP_HEADER(ETH_HLEN);
    proto = headers->eth.h_proto;
    
    if(proto == ETH_P_8021Q){
        decode_vlan(packet, paclen, &headers->vlan);
        POP_HEADER(VLAN_TAG_LEN);
        proto = headers->vlan.vlan_tci;
    }
    
    if(proto == ETH_P_8021Q){
        decode_vlan(packet, paclen, &headers->vlan1);
        POP_HEADER(VLAN_TAG_LEN);
        proto = headers->vlan1.vlan_tci;
    }
    
    if(proto == ETH_P_PPP_SES){
        decode_pppoe_8864(packet, paclen, &headers->pppoe);
        POP_HEADER(PPPOE_SES_HLEN);
        proto = ETH_P_IP;
    }
    
    // assert(proto == ETH_P_IP)
    if(proto != ETH_P_IP){
        sprintf(last_error, "[error][decode]: unknow proto.\n");
        return -1;
    }
    
    decode_ip(packet, paclen, &headers->ip);
    size_t size_ip = headers->ip.ip.ihl * 4;
    POP_HEADER(size_ip);
    
    size_t size_tcp;
    switch(headers->ip.ip.protocol){
        case IPPROTO_TCP:
            decode_tcp(packet, paclen, &headers->tcp);
            size_tcp = headers->tcp.header.doff * 4;
            POP_HEADER(size_tcp);
            headers->payload = packet;
            headers->payload_len = headers->ip.ip.tot_len - (size_ip+size_tcp);
            break;
        default:
            sprintf(last_error, "[error][decode][ip]: unknow proto.\n");
            return -1;
    }
    return 0;
#undef POP_HEADER
}

#undef NTOHL
#undef NTOHS

