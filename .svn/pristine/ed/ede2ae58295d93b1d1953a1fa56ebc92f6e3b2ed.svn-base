#ifndef ANALYSIS_PACKET_H
#define ANALYSIS_PACKET_H


#include <node.h>
#include <v8.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>
#include <node_buffer.h>
//s#include "binding.h"

#include <sys/types.h>
#include <pcap.h>
#include <pcap/pcap.h>
#include <libnet.h>

using namespace v8;
using namespace node;



#define SPO_RET_STATUS_INT  int                 /* the func return status, is int */
#define SPO_RET_VALUE_INT   int                 /* the func return value, is int */
#define SPO_RET_BOOLEN_INT  int                 /* the func return boolen, is int */

#define SPOOFER_OK (0)                      /* ok, for the return value */
#define SPOOFER_FALSE (0)                   /* false, for the return value */
#define SPOOFER_TRUE (1)                    /* true, for the conditions */
#define SPOOFER_FAILURE (-1)                /* failure, for the return value */

#define SPOOFER_VLAN_LEN (4)                /* vlan level is 4 byte */
#define SPOOFER_ETH_ADDR_LEN    (6)


#define SPOOFER_ETH_TYPE_VLAN   (0x8100)    /* the eth type is vlan */

/* no vlan env */
#define SPOOFER_IP_OFFSET   (LIBNET_ETH_H)                                  /* 14 */
#define SPOOFER_TCP_OFFSET  (LIBNET_ETH_H + LIBNET_IPV4_H)                          /* 34 */
#define SPOOFER_UDP_OFFSET  (LIBNET_ETH_H + LIBNET_IPV4_H)                          /* 34 */
#define SPOOFER_DNS_OFFSET  (LIBNET_ETH_H + LIBNET_IPV4_H + LIBNET_UDP_H)                   /* 42 */

/* vlan env */
#define SPOOFER_VLAN_OFFSET (LIBNET_ETH_H )                                  /* 14 */

#define SPOOFER_IP_OFFSET_VLAN   (LIBNET_ETH_H + SPOOFER_VLAN_LEN)                      /* 18 */
#define SPOOFER_TCP_OFFSET_VLAN  (LIBNET_ETH_H + SPOOFER_VLAN_LEN + LIBNET_IPV4_H)              /* 38 */
#define SPOOFER_UDP_OFFSET_VLAN  (LIBNET_ETH_H + SPOOFER_VLAN_LEN + LIBNET_IPV4_H)              /* 38 */
#define SPOOFER_DNS_OFFSET_VLAN  (LIBNET_ETH_H + SPOOFER_VLAN_LEN + LIBNET_IPV4_H + LIBNET_UDP_H)       /* 46 */


#define SPOOFER_MAX_TCP_OPTION_LEN (40) /* the max tcp option len is 40 at rfc */
#define SPOOFER_HTTP_INFO_AMOUNT   (2)  /* http info is tow field : http  line and http header */

#define SPOOFER_VLAN_PROT_MASK  0xe000  /* prot is 3 bit */
#define SPOOFER_VLAN_CFI_MASK   0x1000  /* vlan cfi is 1 bit */
#define SPOOFER_VLAN_ID_MASK    0x0fff  /* vlan id is 12 bit */

#define SPOOFER_HTTP_PACKET_MSG_TYPE (1)                    /* the msg type of packet */

#define SPOOFER_HTTP_LINE_FIELD_AMOUNT (3)                  /* http line amount */
#define SPOOFER_HTTP_HEADER_FIELD_AMOUNT (3)                /* http header field amount, we just need 'host', 'referer', 'cookie' */

#define SPOOFER_SPACE   (0x20)  /* the char ' ' is 0x20 */
#define LF     (u_char) '\n'    /* 0x0a */
#define CR     (u_char) '\r'    /* 0x0d */
#define CRLF   "\r\n"


/* get the string len */

#define SPOOFER_REFERER_STR_LEN ((strlen("referer")) + 2)   /* the string len */
#define SPOOFER_REFERER_VAR_LEN (9)

#define SPOOFER_COOKIE_STR_LEN  ((strlen("cookie")) + 2)    /*  */
#define SPOOFER_COOKIE_VAR_LEN  (8)

#define SPOOFER_HOST_STR_LEN    ((strlen("host")) + 2)
#define SPOOFER_HOST_VAR_LEN    (6)
#define SPOOFER_RUNNING_IN_VLAN (1)


/**
 *  The following struct is for the tcp/ip net level.
 *
 **/

typedef struct spo_sniff_ether_s {
    u_char ether_dhost[6];                 /* dst mac address */
    u_char ether_shost[6];                 /* src mac address */
    u_short ether_type;                                 /* ether type */
}spo_sniff_ether_t, *spo_sniff_ether_p;


typedef struct spo_sniff_ip_s {
    u_char ip_vhl;
#define IP_V(ip) (((ip)->ip_vhl & 0xf0) >> 4)       /* ip version */
#define IP_HL(ip) ((ip)->ip_vhl & 0x0f)             /* ip header length */

    u_char ip_tos;
    u_short ip_len;                                     /* ip total len */
    u_short ip_id;                                      /* ip's id */
    u_short ip_off;                                     /* ip fragment offset */


#define IP_RF 0x8000
#define IP_DF 0x4000
#define IP_MF 0x2000
#define IP_OFFMASK 0x1fff

    u_char ip_ttl;                                      /* ip's ttl */
    u_char ip_p;                                        /*ip protocol*/
    u_short ip_sum;                                     /*ip check sum*/

    struct in_addr ip_src;                              /* ip src address */
    struct in_addr ip_dst;                              /* ip dst address */
}spo_sniff_ip_t, *spo_sniff_ip_p;


typedef u_int tcp_seq_t;

typedef struct spo_sniff_tcp_s {
    u_short tcp_sport;                                  /* tcp src port */
    u_short tcp_dport;                                  /* tcp dst port */
    tcp_seq_t tcp_seq;                                  /* tcp current seq */
    tcp_seq_t tcp_ack;                                  /* tcp ack */

    u_char tcp_offx2;                                   /* tcp header len, just 6 bit */
    u_char tcp_flags;                                   /* tcp flag */

    u_short tcp_win;                                    /* tcp win size */
    u_short tcp_sum;                                    /* tcp sum check */
    u_short tcp_urp;                                    /* Urgent Pointer */
}spo_sniff_tcp_t, *spo_sniff_tcp_p;


typedef struct spo_sniff_udp_s {
    u_short udp_sport;                                  /* udp src port */
    u_short udp_dport;                                  /* udp dst port */
    u_short udp_len;                                    /* udp total length */
    u_short udp_sum;                                    /* udp check sum */
}spo_sniff_udp_t, *spo_sniff_udp_p;


typedef struct spo_sniff_dns_s {
    u_short dns_id;                                     /* dns id */
    u_short dns_flag;                                   /* dns flg */
    u_short dns_ques;                                   /* question amount */
    u_short dns_ans;                                    /* answer amount */
    u_short dns_auth;                                   /*  */
    u_short dns_add;
}spo_sniff_dns_t, *spo_sniff_dns_p;


/**
 *  when we catch a http get request packet, we record the request's info.
 *
 *  we use these info to build the response packet, and send it to client.
 *
 **/

typedef struct spo_http_hijack_info_s {
    u_char src_mac[SPOOFER_ETH_ADDR_LEN];                  /* 6 bytes mac src address */
    u_char dst_mac[SPOOFER_ETH_ADDR_LEN];                  /* 6 bytes mac dst address */

    u_short vlan_id;

    u_short tcp_src_port;               /* tcp's src port  */
    u_short tcp_dst_port;               /* tcp's dst port  */

    u_long ip_src_addr;                 /* ip's src address */
    u_long ip_dst_addr;                 /* ip's dst address */
    u_short ip_len;                     /* ip's total len */
    u_short ip_off;                     /* ip offset */

    /**
     *  tcp_next_seq = ip->total_len - tcp->head_len - ip->head_len
     *  so we can compute it by follow :
     *  int len = (u_int)ntohs(ip->ip_len) - ((u_int)(tcp->tcp_offx2 >> 2) + LIBNET_IPV4_H)
     **/

    u_int tcp_seq_rela;                 /* tcp packet's seq, it is relative */
    u_int tcp_ack_rela;                 /* tcp packet's ack, it is relative */
    u_char tcp_header_len;            /* tcp packet's header length */
    uint8_t tcp_resp_flg;               /* tcp's flage, we save it, and used in response packet */

    int tcp_op_len;                     /* if this tcp packet has option, we save it len */
    uint8_t tcp_op[40];                 /* tcp option the largest is 40 byte */
     char vlan_targe;                    /* running in vlan ? */
}spo_http_hijack_info_t, spo_http_hjk_info_t;

#define SPOOFER_HTTP_HJK_INFO_SIZE  (sizeof(spo_http_hjk_info_t))



/* record the string */
typedef struct spo_string_s {
    size_t len;                 /* the string len */
    u_char *data;               /* the string data start's pointer */
}spo_str_t;




SPO_RET_STATUS_INT spo_hijacking_http_info(const u_char *packet, spo_http_hjk_info_t *hjk_info);
SPO_RET_STATUS_INT spo_analysis_http_packet(const u_char *packet, spo_str_t *info[]);
#endif // IPC_H
