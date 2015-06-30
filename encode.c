#include "decode.c"


#define NTOHL(x) x = ntohl(x)
#define NTOHS(x) x = ntohs(x)


int encode_ethernet(struct ethhdr *header, u_char *packet){
    NTOHS(header->h_proto);
    memcpy(packet, header, ETH_HLEN);
    NTOHS(header->h_proto);
    return 0;
}
int encode_vlan(struct vlan_tag *header, u_char *packet){
    NTOHS(header->vlan_tpid);
    NTOHS(header->vlan_tci);
    memcpy(packet, header, VLAN_TAG_LEN);
    NTOHS(header->vlan_tpid);
    NTOHS(header->vlan_tci);
    return 0;
}
int encode_pppoe_8864(struct pppoe_8863_8864 *header, u_char *packet){
    NTOHS(header->header.sid);
    NTOHS(header->header.length);
    NTOHS(header->ppp_prorocol);
    memcpy(packet, header, PPPOE_SES_HLEN);
    NTOHS(header->header.sid);
    NTOHS(header->header.length);
    NTOHS(header->ppp_prorocol);
    return 0;
}

u_int16_t ip_checksum(u_char *data, size_t size){
    int i;
    u_int32_t check = 0;
    for(i=0; i<size; i+=2){
        u_int16_t tmp = *(u_int16_t*)&data[i];
        check += ntohs(tmp);
    }
    check = (check>>16) + (check&0xffff);
    check ^= 0xffff;
    return ntohs(check);
}

int encode_ip(struct ip_with_options *header, u_char *packet){
    size_t size_ip = header->ip.ihl * 4;
    header->ip.check = 0;
    NTOHS(header->ip.tot_len);
    NTOHS(header->ip.id);
    NTOHS(header->ip.frag_off);
    NTOHS(header->ip.check);
    memcpy(packet, header, size_ip);
    NTOHS(header->ip.tot_len);
    NTOHS(header->ip.id);
    NTOHS(header->ip.frag_off);
    NTOHS(header->ip.check);
    (*(struct ip_with_options*)packet).ip.check
        = ip_checksum(packet, size_ip);
    return 0;
}

u_int16_t tcp_checksum(u_char *data, size_t size, u_char *data2, size_t size2){
    int i;
    u_int32_t check = 0;
    for(i=0; i<size; i+=2){
        u_int16_t tmp = *(u_int16_t*)&data[i];
        check += tmp;
    }
    
    if(size % 2 != 0){
        data2[size2] = 0;
    }
    for(i=0; i<size2; i+=2){
        u_int16_t tmp = *(u_int16_t*)&data2[i];
        check += tmp;
    }
    check = (check>>16) + (check&0xffff);
    check ^= 0xffff;
    return check;
}

int encode_tcp(struct tcp_with_pseudo_header *header, u_char *packet){
    size_t size_tcp = header->header.doff * 4;
    header->pseudo.tcp_length = size_tcp + header->payload_len;
    header->header.check = 0;
    NTOHS(header->header.source);
    NTOHS(header->header.dest);
    NTOHL(header->header.seq);
    NTOHL(header->header.ack_seq);
    NTOHS(header->header.window);
    NTOHS(header->header.check);
    NTOHS(header->header.urg_ptr);
    memcpy(packet, &header->header, size_tcp);
    NTOHS(header->header.source);
    NTOHS(header->header.dest);
    NTOHL(header->header.seq);
    NTOHL(header->header.ack_seq);
    NTOHS(header->header.window);
    NTOHS(header->header.check);
    NTOHS(header->header.urg_ptr);
    memcpy(packet + size_tcp, header->payload, header->payload_len);
    (*(struct tcphdr*)packet).check =
        tcp_checksum((u_char*)header, PSEUDO_HEADER_LEN+size_tcp, packet, size_tcp + header->payload_len);
    return 0;
}

int encode(struct cap_headers *headers, u_char *packet, u_int *paclen_ptr){
#define PUSH_HEADER(size) packet+=size; paclen+=size;
    u_int paclen = 0;
    u_int16_t proto;
    encode_ethernet(&headers->eth, packet);
    PUSH_HEADER(ETH_HLEN);
    proto = headers->eth.h_proto;
    
    if(proto == ETH_P_8021Q){
        encode_vlan(&headers->vlan, packet);
        PUSH_HEADER(VLAN_TAG_LEN);
        proto = headers->vlan.vlan_tci;
    }
    
    if(proto == ETH_P_8021Q){
        encode_vlan(&headers->vlan1, packet);
        PUSH_HEADER(VLAN_TAG_LEN);
        proto = headers->vlan1.vlan_tci;
    }
    
    if(proto == ETH_P_PPP_SES){
        encode_pppoe_8864(&headers->pppoe, packet);
        PUSH_HEADER(PPPOE_SES_HLEN);
        proto = ETH_P_IP;
    }
    
    // assert(proto == ETH_P_IP)
    if(proto != ETH_P_IP){
        sprintf(last_error, "[error][encode]: unknow proto.\n");
        return -1;
    }
    
    size_t size_ip = headers->ip.ip.ihl * 4;
    size_t size_tcp = headers->tcp.header.doff * 4;
    headers->ip.ip.tot_len = size_ip + size_tcp + headers->tcp.payload_len;
    encode_ip(&headers->ip, packet);
    PUSH_HEADER(size_ip);
    
    switch(headers->ip.ip.protocol){
        case IPPROTO_TCP:
            headers->tcp.pseudo.sourceIP = headers->ip.ip.saddr;
            headers->tcp.pseudo.destIP = headers->ip.ip.daddr;
            headers->tcp.pseudo.reserve = 0;
            headers->tcp.pseudo.protocol = headers->ip.ip.protocol;
            headers->tcp.pseudo.tcp_length = size_tcp + headers->tcp.payload_len;
            
            encode_tcp(&headers->tcp, packet);
            PUSH_HEADER(size_tcp);
            PUSH_HEADER(headers->tcp.payload_len);
            break;
        default:
            sprintf(last_error, "[error][encode][ip]: unknow proto.\n");
            return -1;
    }
    *paclen_ptr = paclen;
    return 0;
#undef PUSH_HEADER
}

#undef NTOHL
#undef NTOHS