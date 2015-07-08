#ifndef __ENCODE_H_
#define __ENCODE_H_

#include "decode.h"



int encode_ethernet(struct ethhdr *header, u_char *packet);

int encode_vlan(struct vlan_tag *header, u_char *packet);

int encode_pppoe_8864(struct pppoe_8863_8864 *header, u_char *packet);

void ip_checksum(struct ip_with_options *header);

int encode_ip(struct ip_with_options *header, u_char *packet);

void tcp_checksum(struct tcp_with_options_header *header, u_int source_ip, u_int dest_ip, u_char *payload, u_int payload_len);

int encode_tcp(struct tcp_with_options_header *header, u_char *packet);

int encode(struct cap_headers *headers, u_char *packet, u_int *paclen_ptr);


#endif
