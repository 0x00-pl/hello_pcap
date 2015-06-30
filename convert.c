#include <ctype.h>
#include <string.h>


/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN  6

/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

int convert_u(u_char *src, u_char *dst, int len, int reverse){
    if(reverse){
        memcpy(dst, src, len);
    }
    else{
        memcpy(src, dst, len);
    }
    return 1;
}


int convert_net_order_16(uint16_t *v){
    *v = ((*v)<<8)&0xff00 | ((*v)>>8)&0x00ff;
    return 1;
}

int convert_net_order_16_lr(uint16_t *l, uint16_t *r, int reverse){
    convert_net_order_16(reverse?l:r);
    return 1;
}

int convert_net_order_32_lr(uint32_t *l, uint32_t *r, int reverse){
    if(reverse){
        *l = ((*l)<<24)&0xff000000 | ((*l)<<8)&0x00ff0000 | ((*l)>>8)&0x0000ff00 | ((*l)>>24)&0x000000ff;
    }
    else{
        *r = ((*r)<<24)&0xff000000 | ((*r)<<8)&0x00ff0000 | ((*r)>>8)&0x0000ff00 | ((*r)>>24)&0x000000ff;
    }
}

int convert_ethernet_header(u_char *buf, struct sniff_ethernet *header, int reverse){
    convert_u(buf, header, sizeof(struct sniff_ethernet), reverse);
}

uint16_t ip_header_check_sum(struct sniff_ip *header){
    uint16 *buf = (uint16*)header;
    uint32 check = 0;
    int i;
    for(i=0; i<10; i++){
        //tmp := binary.BigEndian.Uint16(p.IPheader.Data[i : i+2])
        //check += uint64(tmp)
        uint16 tmp = buf[i];
        convert_net_order_16(&tmp);
        check += tmp;
    }
//     check = (check >> 16) + (check & 0xFFFF)
    check = (check>>16) + (check&0xffff);
//     check = check + (check >> 16)
//     check = check + (check>>16); // never used
//     check = check ^ 0xFFFF
    check = check ^ 0xffff;
//     return uint16(check)
    return check;
}

int convert_ip_header(u_char *buf, struct sniff_ip *header, const u_char *payload,  int payload_len, int reverse){
    if(reverse){
//         IP长度
//         IPLen := uint16(40 + p.TCPHeaders.DataOffset + len(p.SendData))
        header->ip_len = 40 + payload_len;
//         binary.BigEndian.PutUint16(buff[4:6], p.IPheader.Id+100) //Id(改)
        header->ip_id += 100;
//         binary.BigEndian.PutUint16(buff[10:12], 0)               //Checksum(改)
        header->ip_sum = 0;
//         binary.BigEndian.PutUint16(buff[10:12], p.CheckSumIP())
        header->ip_sum = ip_header_check_sum(header);
    }

    convert_u(buf, header, sizeof(struct sniff_ip), reverse);
    return 1;
}


uint16_t tcp_header_check_sum(struct sniff_tcp *header){
    uint16 *buf = (uint16*)header;
    //TODO
}

int convert_tcp_header(u_char *buf, struct sniff_tcp *header, const u_char *payload,  int payload_len, int reverse){
    if(reverse){
//         binary.BigEndian.PutUint16(buff[16:18], 0)                                       //Checksum---不同(改)
        header.th_sum = 0;
        header.th_sum = tcp_header_check_sum(header);
    }
    
    convert_u(buf, header, sizeof(struct sniff_tcp), reverse);
    return 1;
}





