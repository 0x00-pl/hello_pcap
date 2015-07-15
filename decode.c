#include "decode.h"
#include "debug.h"
#include "counter.h"

#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>

static void print_mac(u_char mac[ETH_ALEN]){
    printf("%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static void print_ethernet(struct ethhdr *header){
    printf("(struct ethhdr){\n");
    printf("    .h_dest = "); print_mac(header->h_dest); printf(",\n");
    printf("    .h_source = "); print_mac(header->h_source); printf(",\n");
    printf("    .h_proto = 0x%04x,\n", header->h_proto);
    printf("};\n");
}

static void print_vlan(struct vlan_tag *header){
    printf("(struct vlan_tag){\n");
    printf("    .vlan_tpid = 0x%04x,\n", header->vlan_tpid);
    printf("    .vlan_tci = 0x%04x,\n", header->vlan_tci);
    printf("};\n");
}

static void print_pppoe_hdr(struct pppoe_hdr *header){
    printf("(struct pppoe_hdr){\n");
    printf("    .ver = %x,\n", header->ver);
    printf("    .type = %x,\n", header->type);
    printf("    .code = %x,\n", header->code);
    printf("    .sid = 0x%04x,\n", header->sid);
    printf("    .length = %d,\n", header->length);
    printf("};\n");
}

static void print_pppoe_8864(struct pppoe_8863_8864 *header){
    print_pppoe_hdr(&header->header);
    printf("ppp_prorocol = 0x%04x;\n", header->ppp_prorocol);
}

static void print_iphdr(struct iphdr *header){
    printf("(struct iphdr){\n");
    printf("    .version = %x,\n", header->version);
    printf("    .ihl = %x,\n", header->ihl);
    printf("    .tos = %02x,\n", header->tos);
    printf("    .tot_len = %d,\n", header->tot_len);
    printf("    .id = 0x%04x,\n", header->id);
    printf("    .frag_off = %04x,\n", header->frag_off);
    printf("    .ttl = %d,\n", header->ttl);
    printf("    .protocol = 0x%02x,\n", header->protocol);
    printf("    .check = 0x%04x,\n", header->check);
    printf("    .saddr = %s,\n", inet_ntoa(*(struct in_addr*)&header->saddr));
    printf("    .daddr = %s,\n", inet_ntoa(*(struct in_addr*)&header->daddr));
    printf("};\n");
}

static void print_ip_with_options(struct ip_with_options *header){
  print_iphdr(&header->header);
  printf("options=...;\n");
}

static void print_tcphdr(struct tcphdr *header){
    printf("(struct tcphdr){\n");
    printf("    .source = %d,\n", header->source);
    printf("    .dest = %d,\n", header->dest);
    printf("    .seq = 0x%08x,\n", header->seq);
    printf("    .ack_seq = 0x%08x,\n", header->ack_seq);
    printf("    .doff = %x,\n", header->doff);
    printf("    .res1 = %x,\n", header->res1);
    printf("    .cwr = %x,\n", header->cwr);
    printf("    .ece = %x,\n", header->ece);
    printf("    .urg = %x,\n", header->urg);
    printf("    .ack = %x,\n", header->ack);
    printf("    .psh = %x,\n", header->psh);
    printf("    .rst = %x,\n", header->rst);
    printf("    .syn = %x,\n", header->syn);
    printf("    .fin = %x,\n", header->fin);
    printf("    .window = 0x%04x,\n", header->window);
    printf("    .check = 0x%04x,\n", header->check);
    printf("    .urg_ptr = 0x%04x,\n", header->urg_ptr);
    printf("};\n");
}

static void print_tcp_with_options(struct tcp_with_options_header *header){
  print_tcphdr(&header->header);
  printf("options=...;\n");
}


#define NTOHL(x) x = ntohl(x)
#define NTOHS(x) x = ntohs(x)

void ip_net_order(struct ip_with_options *header){
    NTOHS(header->header.tot_len);
    NTOHS(header->header.id);
    NTOHS(header->header.frag_off);
    NTOHS(header->header.check);
}

void tcp_net_order(struct tcp_with_options_header *header){
    NTOHS(header->header.source);
    NTOHS(header->header.dest);
    NTOHL(header->header.seq);
    NTOHL(header->header.ack_seq);
    NTOHS(header->header.window);
    NTOHS(header->header.check);
    NTOHS(header->header.urg_ptr);
}

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
    ip_net_order(header);
    return 0;
}
int decode_tcp(u_char *packet, u_int paclen, struct tcp_with_options_header *header){
    struct tcphdr *tcp = (struct tcphdr*) packet;
    size_t size_tcp = tcp->doff * 4;
    bzero(header->options, 64);
    memcpy(&header->header, packet, size_tcp);
    tcp_net_order(header);
    return 0;
}

int decode(u_char *packet, u_int paclen, struct cap_headers *headers){
#define POP_HEADER(size) packet+=size; paclen-=size;
    u_int16_t proto;
    decode_ethernet(packet, paclen, &headers->eth);
    POP_HEADER(ETH_HLEN);
    IF_DEBUG(print_ethernet(&headers->eth));
    proto = headers->eth.h_proto;
    
    if(proto == ETH_P_8021Q){
        decode_vlan(packet, paclen, &headers->vlan);
        POP_HEADER(VLAN_TAG_LEN);
        IF_DEBUG(print_vlan(&headers->vlan));
        proto = headers->vlan.vlan_tci;
    }
    
    if(proto == ETH_P_8021Q){
        decode_vlan(packet, paclen, &headers->vlan1);
        POP_HEADER(VLAN_TAG_LEN);
        IF_DEBUG(print_vlan(&headers->vlan1));
        proto = headers->vlan1.vlan_tci;
    }
    
    if(proto == ETH_P_PPP_SES){
        decode_pppoe_8864(packet, paclen, &headers->pppoe);
        POP_HEADER(PPPOE_SES_HLEN);
        IF_DEBUG(print_pppoe_8864(&headers->pppoe));
        proto = ETH_P_IP;
    }
    
    // assert(proto == ETH_P_IP)
    if(proto != ETH_P_IP){
        sprintf(last_error, "[error][decode]: unknow proto.\n");
        return -1;
    }
    COUNTER_INC(ip_package);
    
    decode_ip(packet, paclen, &headers->ip);
    size_t size_ip = headers->ip.header.ihl * 4;
    POP_HEADER(size_ip);
    IF_DEBUG(print_ip_with_options(&headers->ip));
    
    size_t size_tcp;
    switch(headers->ip.header.protocol){
    case IPPROTO_TCP:
        COUNTER_INC(tcp_package);
        decode_tcp(packet, paclen, &headers->tcp);
        size_tcp = headers->tcp.header.doff * 4;
        POP_HEADER(size_tcp);
        IF_DEBUG(print_tcp_with_options(&headers->tcp));
        headers->payload = packet;
        headers->payload_len = headers->ip.header.tot_len - (size_ip+size_tcp);
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

