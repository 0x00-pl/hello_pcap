#ifndef __DECODE_H__
#define __DECODE_H__

#include "cap_structs.h"


void ip_net_order(struct ip_with_options *header);

void tcp_net_order(struct tcp_with_options_header *header);

int decode_ethernet(u_char *packet, u_int paclen, struct ethhdr *header);

int decode_vlan(u_char *packet, u_int paclen, struct vlan_tag *header);

int decode_pppoe_8864(u_char *packet, u_int paclen, struct pppoe_8863_8864 *header);

int decode_ip(u_char *packet, u_int paclen, struct ip_with_options *header);

int decode_tcp(u_char *packet, u_int paclen, struct tcp_with_options_header *header);

int decode(u_char *packet, u_int paclen, struct cap_headers *headers);


#endif

