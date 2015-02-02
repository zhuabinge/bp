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
#include "binding.h"

#include <sys/types.h>
#include <pcap.h>
#include <pcap/pcap.h>
#include <libnet.h>

using namespace v8;
using namespace node;

#define SPO_RET_STATUS_INT  int      /* the func return status, is int */
#define SPO_RET_VALUE_INT   int      /* the func return value, is int */
#define SPO_RET_BOOLEN_INT  int      /* the func return boolen, is int */

#define SPOOFER_OK (0)          /* ok, for the return value */
#define SPOOFER_FALSE (0)       /* false, for the return value */
#define SPOOFER_TRUE (1)        /* true, for the conditions */
#define SPOOFER_FAILURE (-1)    /* failure, for the return value */

#define SPOOFER_VLAN_LEN (4)    /* vlan level is 4 byte */

/* no vlan env */
#define SPOOFER_IP_OFFSET   (LIBNET_ETH_H)  /* 14 */
#define SPOOFER_TCP_OFFSET  (LIBNET_ETH_H + LIBNET_IPV4_H)  /* 34 */
#define SPOOFER_UDP_OFFSET  (LIBNET_ETH_H + LIBNET_IPV4_H)  /* 34 */
#define SPOOFER_DNS_OFFSET  (LIBNET_ETH_H + LIBNET_IPV4_H + LIBNET_UDP_H)   /* 42 */

/* vlan env */
#define SPOOFER_VLAN_OFFSET (LIBNET_ETH_H)  /* 14 */

#define SPOOFER_IP_OFFSET_VLAN   (LIBNET_ETH_H + SPOOFER_VLAN_LEN)  /* 18 */
#define SPOOFER_TCP_OFFSET_VLAN  (LIBNET_ETH_H + SPOOFER_VLAN_LEN + LIBNET_IPV4_H)  /* 38 */
#define SPOOFER_UDP_OFFSET_VLAN  (LIBNET_ETH_H + SPOOFER_VLAN_LEN + LIBNET_IPV4_H)  /* 38 */
#define SPOOFER_DNS_OFFSET_VLAN  (LIBNET_ETH_H + SPOOFER_VLAN_LEN + LIBNET_IPV4_H + LIBNET_UDP_H)   /* 46 */


#define SPOOFER_VLAN_PROT_MASK  0xe000  /* prot is 3 bit */
#define SPOOFER_VLAN_CFI_MASK   0x1000  /* vlan cfi is 1 bit */
#define SPOOFER_VLAN_ID_MASK    0x0fff  /* vlan id is 12 bit */

#define SPOOFER_HTTP_PACKET_MSG_TYPE (1)                    /* the msg type of packet */

#define SPOOFER_HTTP_LINE_FIELD_AMOUNT (3)                  /* http line amount */
#define SPOOFER_HTTP_HEADER_FIELD_AMOUNT (3)                /* http header field amount, we just need 'host', 'referer', 'cookie' */


#define LF     (u_char) '\n'    /* 0x0a */
#define CR     (u_char) '\r'    /* 0x0d */
#define CRLF   "\r\n"


/**
 *  The following struct is for the tcp/ip net level.
 *
 **/

typedef struct spo_sniff_ether_s {
    u_char ether_dhost[ETHER_ADDR_LEN];                 /* dst mac address */
    u_char ether_shost[ETHER_ADDR_LEN];                 /* src mac address */
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
    u_char src_mac[6];                  /* 6 bytes mac src address */
    u_char dst_mac[6];                  /* 6 bytes mac dst address */

    u_short vlan_id;

    u_short tcp_src_port;               /* tcp's src port  */
    u_short tcp_dst_port;               /* tcp's dst port  */

    u_long ip_src_addr;                 /* ip's src address */
    u_long ip_dst_addr;                 /* ip's dst address */

    /**
     *  tcp_next_seq = ip->total_len - tcp->head_len - ip->head_len
     *  so we can compute it by follow :
     *  int len = (u_int)ntohs(ip->ip_len) - ((u_int)(tcp->tcp_offx2 >> 2) + LIBNET_IPV4_H)
     **/
    u_int tcp_next_seq;                 /* is the tcp ack seq for response, we have to compute it */
    u_int tcp_seq_rela;                 /* tcp packet's seq, it is relative */

    u_int tcp_resp_seq;                 /* tcp response's seq, we compute and save it here */
    u_int tcp_resp_Ack;                 /* tcp response's Ack, we compute and save it here  */

    int tcp_op_len;                     /* if this tcp packet has option, we save it len */
    uint8_t tcp_op[40];                 /* tcp option the largest is 40 byte */

    uint8_t tcp_resp_flg;               /* tcp's flage, we save it, and used in response packet */

    u_short ip_off;                     /* ip offset */

    u_int tcp_rst_resp_seq;             /* when we send rst response packet, we have to compute the rst resp seq */

    /**
     *  at rst packet we can find the formula for rst_resp_Ack.
     *  hjk_info->tcp_resp_Ack = hjk_info->tcp_next_seq + hjk_info->tcp_seq_rela;
     **/
    u_int tcp_rst_resp_Ack;             /* when we send rst response packet, we have to compute the rst resp Ack */
}spo_http_hijack_info_t, spo_http_hjk_info_t;

#define SPOOFER_HTTP_HJK_INFO_SIZE  (sizeof(spo_http_hjk_info_t))



/* record the string */
typedef struct spo_string_s {
    size_t len;                 /* the string len */
    u_char *data;               /* the string data start's pointer */
}spo_str_t;





/************************** analysis http packet **********************************************/



inline SPO_RET_STATUS_INT spo_init_string(spo_str_t *str, int n) {

    int i = 0;

    if (str == NULL || n <= 0) {
        return SPOOFER_FAILURE;
    }

    for (i = 0; i < n; i++) {
        str[i].data = NULL;
        str[i].len = 0;
    }

    return SPOOFER_OK;
}






/**
 *
 *  the packet is in 802.3 -1q vlan ?
 *
 *  @param packet, the packet we catch.
 *
 *  @return the judgment result.
 *
 *  status finished, tested.
 *
 *  ok
 *
 **/

inline SPO_RET_BOOLEN_INT spo_is_802_1q_vlan(const u_char *packet) {

    spo_sniff_ether_t *eth = (spo_sniff_ether_t *) packet;

    if (ntohs(eth->ether_type) == 0x8100) {
        printf("is --- vlan *******\nSPOOFER_B");
        return SPOOFER_TRUE;
    }

    return SPOOFER_FALSE;
}


/**
 *
 *  when we catch the http packet, we get the http packets's size in here.
 *
 *  @param packet, is the http packet we catched.
 *
 *  @return size, is the packet total size.
 *
 **/

inline size_t spo_http_packet_size(const u_char *packet) {

    size_t packet_size = 0;

    if (packet == NULL) {
        return SPOOFER_FAILURE;
    }

    if (spo_is_802_1q_vlan(packet) == SPOOFER_TRUE) {   /* is running vlan env */

        spo_sniff_ip_t *ip =  (spo_sniff_ip_t *) (packet + SPOOFER_IP_OFFSET_VLAN);

        /* packet size eq ip len + vlan header len + eth header len */
        packet_size = ntohs(ip->ip_len) + SPOOFER_IP_OFFSET_VLAN;

        return packet_size;

    }else {

        spo_sniff_ip_t *ip =  (spo_sniff_ip_t *) (packet + LIBNET_ETH_H);

        packet_size = ntohs(ip->ip_len) + LIBNET_ETH_H;

        return packet_size;

    }
}


/**
 *
 *  get the http packet's tcp level options's length.
 *
 *  the option length < 40 byte.
 *
 *  @param packet, is the http request packet we catched.
 *
 *  @return op_len, is the options's length.
 *
 *  ok
 *
 **/

short spo_get_tcp_options_len(const u_char *packet) {

    short op_len = -1;
    spo_sniff_tcp_t *tcp = NULL;

    if (packet == NULL) {
        return SPOOFER_FAILURE;
    }

    if (spo_is_802_1q_vlan(packet) == SPOOFER_TRUE) {
        tcp = (spo_sniff_tcp_t *) (packet + SPOOFER_TCP_OFFSET_VLAN);
    }else {
        tcp = (spo_sniff_tcp_t *) (packet + SPOOFER_TCP_OFFSET);
    }

    op_len = (short) ((short)(tcp->tcp_offx2 >> 2) - LIBNET_TCP_H);

    return op_len;
}


/**
 *
 *  get the http request packet start pointer.
 *
 *  @param packet, is the http request packet we catched.
 *
 *  @return http_start, is the http start pointer.
 *
 *  ok
 *
 **/

const u_char *spo_http_start(const u_char *packet) {

    u_char *http_start = NULL;

    if (packet == NULL) {
        return NULL;
    }

    if (spo_is_802_1q_vlan(packet) == SPOOFER_TRUE) {
        http_start = (u_char *) (packet + SPOOFER_TCP_OFFSET_VLAN
                                 + LIBNET_TCP_H + spo_get_tcp_options_len(packet));
    }else {
        http_start = (u_char *) (packet + SPOOFER_TCP_OFFSET
                                 + LIBNET_TCP_H + spo_get_tcp_options_len(packet));
    }

    if ((long)spo_http_packet_size(packet) == (long)(http_start - packet)) {
        return NULL;
    }

    return http_start;
}


/******************************!!!!!!!!!!!!!!!!!***************/


/**
 *
 *  get the http request packet method.
 *
 *  @param packet, is the packet we catched.
 *
 *  @param method, used to save the method name and name's len.
 *
 *  @return int, is the exec status.
 *
 **/

SPO_RET_STATUS_INT spo_http_request_method(const u_char *http_start, spo_str_t *mtd, int mtd_off) {


    u_char *ch = NULL;

    if (mtd == NULL) {
        mtd->data = NULL;
        mtd->len = 0;
        return SPOOFER_FAILURE;
    }

    if (http_start == NULL) {
        mtd->data = NULL;
        mtd->len = 0;
        return SPOOFER_OK;
    }

    ch = (u_char *) (((u_char *)http_start) + mtd_off);

    if (*ch == CR || *ch == LF) {
        mtd->data = NULL;
        mtd->len = 0;
        return SPOOFER_OK;
    }

    while (*ch == 0x20) {    //skip the ' ', hex is 0x20
        ch++;
    }

    mtd->data = ch;

    while (*ch != 0x20) {
        ch++;
    }

    mtd->len = (size_t)(ch - mtd->data);
    if (mtd->len == 0) {
        mtd->data = NULL;
        mtd->len = 0;
        return SPOOFER_FAILURE;
    }

    return SPOOFER_OK;
}


/**
 *
 *  get the http request url.
 *
 *  and save the url at param url
 *
 *
 **/

SPO_RET_STATUS_INT spo_http_request_url(const u_char *http_start, spo_str_t *url, int url_off, size_t pkt_s) {

    u_char *ch = NULL;
    size_t i = 0;

    if (url == NULL) {
        return SPOOFER_FAILURE;
    }

    if (http_start == NULL) {
        url->data = NULL;
        url->len = 0;
        return SPOOFER_OK;
    }

    ch = (u_char *) (((u_char *) http_start) + url_off);

    url->data = ch;

    for (i = 0; i < pkt_s; i++) {
        if (*ch == 0x20) {
            break;
        }
        ch++;
    }

    if (i >= pkt_s) {
        url->data = NULL;
        url->len = 0;
        return SPOOFER_FAILURE;
    }

    url->len = (size_t) (ch - url->data);
    if (url->len == 0) {
        url->data = NULL;
        url->len = 0;
        return SPOOFER_FAILURE;
    }

    return SPOOFER_OK;

}


SPO_RET_STATUS_INT spo_http_version(const u_char *http_start, spo_str_t *version, int url_off, size_t pkt_s) {

    u_char *ch = NULL;
    size_t i = 0;

    if (version == NULL) {
        return SPOOFER_FAILURE;
    }

    if (http_start == NULL) {
        version->data = NULL;
        version->len = 0;
        return SPOOFER_OK;
    }

    ch = (u_char *) (((u_char *) http_start) + url_off);

    version->data = ch;

    for (i = 0; i < pkt_s; i++) {
        if (*ch == CR && *(ch + 1) == LF) {
            break;
        }
        ch++;
    }

    version->len = (size_t) (ch - version->data);
    if (version->len == 0) {
        version->data = NULL;
        version->len = 0;
        return SPOOFER_FAILURE;
    }

    return SPOOFER_OK;

}


/**
 *
 *  analysis the http request header.
 *
 **/

SPO_RET_STATUS_INT spo_http_request_header(const u_char *http_start, spo_str_t *head_info, int head_off, size_t pkt_s) {

    int j = 0;
    size_t i = 0;
    u_char *field = NULL;

    if (http_start == NULL || head_info == NULL) {
        return SPOOFER_FAILURE;
    }

    u_char *ch = (u_char *) ((u_char *) http_start + head_off);

    field = ch;

    for (i = 0; i < pkt_s; i++) {
        if (*ch == CR && *(ch + 1) == LF) {

            if (memcmp(field, "Referer", strlen("Referer")) == 0) {
                //printf("found the referer\n");
                head_info[0].data = field;
                head_info[0].len =  (size_t) (ch - head_info[0].data);
                ch = ch + 2;
                if (*ch == CR && *(ch + 1) == LF) {
                    break;
                }
                field = ch;
                continue;
            }

            if (memcmp(field, "Cookie", strlen("Cookie")) == 0) {
                //printf("found the Cookie\n");
                head_info[1].data = field;
                head_info[1].len =  (size_t) (ch - head_info[1].data);
                ch = ch + 2;
                if (*ch == CR && *(ch + 1) == LF) {
                    break;
                }
                field = ch;
                continue;
            }

            if (memcmp(field, "Host", strlen("Host")) == 0) {   /* found the Host */
                //printf("found the Host\n");
                head_info[2].data = field;      /* record the key and value */
                head_info[2].len =  (size_t) (ch - head_info[2].data);
                ch = ch + 2;
                if (*ch == CR && *(ch + 1) == LF) {
                    break;
                }
                field = ch;
                continue;
            }

            ch = ch + 2;
            field = ch;
            continue;
        }
        ch++;
    }

    return SPOOFER_OK;

}



/**
 *
 *  analysis the packets we catched.
 *
 * */

SPO_RET_STATUS_INT spo_analysis_http_line(const u_char *http_start, spo_str_t *line, size_t pkt_s) {

    int offset = -1;
    int ret = -1;

    if (line == NULL) {
        return SPOOFER_FAILURE;
    }

    /* get the request method */

    if (http_start == NULL) {
        goto bad_analysis;
    }else {
        ret = spo_http_request_method(http_start, &line[0], 0);
        if (ret == SPOOFER_FAILURE) goto bad_analysis;

        if (!(line[0].len == 3 && memcmp(line[0].data, "GET", 3) == 0)) {
            goto bad_analysis;
        }
    }

    /* get the request url */

    if (line[0].len == 0 || line[0].data == NULL) {
        goto bad_analysis;
    }else {
        offset = line[0].len + 1;   /* add 1 is skip the ' '(0x20) */

        ret = spo_http_request_url(http_start, &line[1], offset, pkt_s);
        if (ret == SPOOFER_FAILURE) goto bad_analysis;
    }

    /* get the http version */
    if (line[1].len == 0 || line[1].data == NULL) {
        goto bad_analysis;
    }else {
        offset = offset + line[1].len + 1;

        ret = spo_http_version(http_start, &line[2], offset, pkt_s);
        if (ret == SPOOFER_FAILURE) goto bad_analysis;
    }

    if (line[2].len == 0 || line[2].data == NULL) {
        goto bad_analysis;
    }

    return SPOOFER_OK;

bad_analysis:

    return SPOOFER_FAILURE;

}


/**
 *
 *  when we catched a packet packet, we analysis it.
 *
 *  if this packet is we need, we get it's info that we need and save the info at hjk_info.
 *
 *  after save the info, we send the hjk_info to msg queue.
 *
 *  @param packet, is the packet we catched.
 *
 *  @return exec status.
 *
 **/

SPO_RET_STATUS_INT spo_do_analysis_http_packet(const u_char *packet, spo_str_t *info[]) {

    int ret = -1;
    int i = 0;
    int header_offset = 0;
    size_t pkt_s = 0;

    spo_str_t *line = NULL;
    spo_str_t *header_info = NULL;
    const u_char *http_start = NULL;

    if (packet == NULL) {
        return SPOOFER_FAILURE;
    }

    /* if the packet is tcp hand shark packet, we just return */
    http_start = spo_http_start(packet);

    if (http_start == NULL) {
        return SPOOFER_FAILURE;
    }

    line = (spo_str_t *) malloc(sizeof(spo_str_t) * SPOOFER_HTTP_LINE_FIELD_AMOUNT);

    if (line == NULL) {
        /* wirte err log */
        return SPOOFER_FAILURE;
    }
    spo_init_string(line, SPOOFER_HTTP_LINE_FIELD_AMOUNT);

    header_info = (spo_str_t *) malloc(sizeof(spo_str_t) * SPOOFER_HTTP_HEADER_FIELD_AMOUNT);
    if (header_info == NULL) {
        free(line);
        return SPOOFER_FAILURE;
    }
    spo_init_string(header_info, SPOOFER_HTTP_HEADER_FIELD_AMOUNT);	/* must init the str, set the data to null and the len to 0 */

    pkt_s = spo_http_packet_size(packet);

    ret = spo_analysis_http_line(http_start, line, pkt_s);
    if (ret == SPOOFER_FAILURE) {
        free(line);
        return SPOOFER_FAILURE;
    }

    for (i = 0; i < SPOOFER_HTTP_LINE_FIELD_AMOUNT; i++) {
        header_offset = header_offset + line[i].len;
    }

    header_offset = header_offset + 4;      /* skip tow 0x20 (space) and the '\r\n' in the end */

    ret = spo_http_request_header(http_start, header_info, header_offset, pkt_s);
    if (ret == SPOOFER_FAILURE) {
        free(header_info);
        return SPOOFER_FAILURE;
    }

    info[0] = line;
    info[1] = header_info;

    return SPOOFER_OK;
}




/* packaging the info in here !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! !!!!!!!!!!!!*/

void spo_packaging_info() {

}



void spo_anslysis_http_packet(const u_char *packet) {
	if (packet == NULL) {
		printf("packet is null\n");
		return;
	}
}


void msgrcv_async(uv_work_t *req) {
  struct rcv_req *orig = (struct rcv_req *) req->data;

  #ifdef _DEBUG
  std::cout << "-- MSGRCV --\n" << "ID: " << orig->id << "\nBUFFER LENGTH: " << orig->buffer_length << "\nMSGTYP: " << orig->msgtyp << "\nFLAGS: " << orig->flags << std::endl;
  #endif


  orig->ret = msgrcv(orig->id, orig->buffer, orig->buffer_length, orig->msgtyp, orig->flags);

  if (orig->ret < 1) {
    orig->error = strerror(errno);
    #ifdef _DEBUG
    std::cout << "ERRNO: " << errno << std::endl;
    #endif
  }
}



void after_msgrcv_async(uv_work_t *req) {
  struct rcv_req *orig = (struct rcv_req *) req->data;
  Handle<Value> err =
    (orig->ret < 0) ? String::New(strerror(errno)) : Null();

  Local<Object> global = Context::GetCurrent()->Global();
  Local<Function> bufferConstructor = Local<Function>::Cast(global->Get(String::New("Buffer")));

  Buffer *slowMsg = Buffer::New(orig->buffer_length);
  char *p = (char *) orig->buffer + (int) sizeof(long);
  memcpy(Buffer::Data(slowMsg), p, orig->buffer_length);

  const u_char *packet = (const u_char *) p;
  spo_str_t *info[2];
  spo_do_analysis_http_packet(packet, info);

     int i = 0;
    for (i = 0; i <2; i++) {

        if (info[i] != NULL) {

            spo_str_t *str = info[i];
            int t = 0;

            for (t = 0; t < 3; t++) {
                if (str[t].data != NULL) {
                    int j = 0;
                    for (j = 0; j < (int) str[t].len; j++) {
                        printf("%c", *(str[t].data + j));
                    }
                    printf("\n");
                }
            }
            printf("------------\n\n");

        }

    }
  free(info[0]);
  free(info[1]);
  Handle<Value> bufArgv[] = { slowMsg->handle_, Integer::New(orig->buffer_length), Integer::New(0) };
  Handle<Value> msg;
  if (orig->ret < 0)
    msg = Null();
  else
    msg = bufferConstructor->NewInstance(3, bufArgv);
  Handle<Value> argv[] = { err, msg };
  orig->cbl->Call(Context::GetCurrent()->Global(), 2, argv);
}



Handle<Value> node_msgrcv(const Arguments& args) {
  HandleScope scope;
  struct rcv_req *req = new rcv_req;

  if(
      args.Length() < 5 ||
      !args[0]->IsNumber() || !args[1]->IsNumber() || !args[2]->IsNumber() || !args[3]->IsNumber() || !args[4]->IsFunction()
    ) {
    ThrowException(Exception::TypeError(String::New("msgrcv requires 3 arguments")));

    return scope.Close(Undefined());
  }

  req->id  = args[0]->ToNumber()->Value();
  req->buffer_length = args[1]->ToNumber()->Value();
  req->flags = args[2]->ToNumber()->Value();
  req->msgtyp = args[3]->ToNumber()->Value();
  req->buffer = new char[req->buffer_length];
  req->cbl  = Persistent<Function>::New(Local<Function>::Cast(args[4]));
  req->req.data = req;

  uv_queue_work(uv_default_loop(), &req->req, msgrcv_async, (uv_after_work_cb)after_msgrcv_async);

  return scope.Close(Undefined());
}

