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

void ip_checksum(struct ip_with_options *header){
    int i;
    u_char *buff;
    u_int32_t check = 0;
    size_t size_ip = IP_LEN(header->header);
    
    IF_DEBUG(printf("++++ip checksum++++\n"));
    IF_DEBUG(print_ip_with_options(header));
    
    header->header.check = 0;
    
    ip_net_order(header);
    buff = (u_char*)header;
    for(i=0; i<size_ip; i+=2){
        u_int16_t tmp = *(u_int16_t*)&buff[i];
        check += ntohs(tmp);
    }
    ip_net_order(header);
    
    check = (check>>16) + (check&0xffff);
    check ^= 0xffff;
    header->header.check = check;
    
    IF_DEBUG(print_ip_with_options(header));
    IF_DEBUG(printf("----ip checksum----\n"));
}

int encode_ip(struct ip_with_options *header, u_char *packet){
    size_t size_ip = IP_LEN(header->header);
    ip_net_order(header);
    memcpy(packet, header, size_ip);
    ip_net_order(header);
    return 0;
}

void tcp_checksum(struct tcp_with_options_header *header, u_int source_ip, u_int dest_ip, u_char *payload, u_int payload_len){
    int i;
    u_char *buff;
    u_int32_t check = 0;
    u_int tcphdr_len = TCP_LEN(header->header);
    
    IF_DEBUG(printf("++++tcp checksum++++\n"));
    IF_DEBUG(print_tcp_with_options(header));
    
    header->header.check = 0;
    
    struct _pseudo_header psdh = {
      source_ip, dest_ip,
      0, IPPROTO_TCP,
      tcphdr_len+payload_len
    };
    NTOHS(psdh.tcp_length);
    
    buff = (u_char*)&psdh;
    for(i=0; i<PSEUDO_HEADER_LEN; i+=2){
        u_int16_t tmp = *(u_int16_t*)&buff[i];
        check += tmp;
    }
    
    tcp_net_order(header);
    buff = (u_char*)header;
    for(i=0; i<tcphdr_len; i+=2){
        u_int16_t tmp = *(u_int16_t*)&buff[i];
        check += tmp;
    }
    tcp_net_order(header);
    
    if(payload_len % 2 != 0){
        payload[payload_len] = 0;
	payload_len++;
    }
    buff = payload;
    for(i=0; i<payload_len; i+=2){
        u_int16_t tmp = *(u_int16_t*)&buff[i];
        check += tmp;
    }
    check = (check>>16) + (check&0xffff);
    check ^= 0xffff;
    
    header->header.check = check;
    
    IF_DEBUG(print_tcp_with_options(header));
    IF_DEBUG(printf("----tcp checksum----\n"));
}

int encode_tcp(struct tcp_with_options_header *header, u_char *packet){
    size_t size_tcp = TCP_LEN(header->header);
    tcp_net_order(header);
    memcpy(packet, &header->header, size_tcp);
    tcp_net_order(header);
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
    
    size_t size_ip = IP_LEN(headers->ip.header);
    size_t size_tcp = TCP_LEN(headers->tcp.header);
    headers->ip.header.tot_len = size_ip + size_tcp + headers->payload_len;
    ip_checksum(&headers->ip);
    encode_ip(&headers->ip, packet);
    PUSH_HEADER(size_ip);
    
    switch(headers->ip.header.protocol){
        case IPPROTO_TCP:
            tcp_checksum(&headers->tcp, headers->ip.header.saddr, headers->ip.header.daddr, headers->payload, headers->payload_len);
            encode_tcp(&headers->tcp, packet);
            PUSH_HEADER(size_tcp);
	    memcpy(packet, headers->payload, headers->payload_len);
            PUSH_HEADER(headers->payload_len);
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