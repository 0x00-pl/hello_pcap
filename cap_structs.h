#ifndef __CAP_STRUCTS_H__
#define __CAP_STRUCTS_H__

#include <net/if.h>
#include <netinet/in.h>
#include <linux/if_ether.h>
#include <pcap/vlan.h>
#include <linux/if_pppox.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

struct pppoe_8863_8864{
    struct pppoe_hdr header;
    u_int16_t ppp_prorocol; // ETH_P_PPP_SES(8864) only
};

struct ip_with_options{
    struct iphdr header;
    u_char options[64];
};

typedef struct _pseudo_header
{
  unsigned int sourceIP;
  unsigned int destIP;
  unsigned char reserve;
  unsigned char protocol;
  unsigned short tcp_length;
} PSEUDO_HEADER;

#define PSEUDO_HEADER_LEN 12

struct tcp_with_options_header{
    struct tcphdr header;
    u_char options[64];
};

#define IP_LEN(iphdr_) ((iphdr_).ihl * 4)
#define TCP_LEN(tcphdr_) ((tcphdr_).doff * 4)

struct cap_headers{
    struct ethhdr eth;
    struct vlan_tag vlan;
    struct vlan_tag vlan1;
    struct pppoe_8863_8864 pppoe;
    struct ip_with_options ip;
    struct tcp_with_options_header tcp;
    u_char *payload;
    int payload_len;
};


#endif