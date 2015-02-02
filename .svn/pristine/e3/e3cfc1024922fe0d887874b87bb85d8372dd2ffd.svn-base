#include "analysis_packet.h"




/*
 *  init the string data and len. set the data to null and set the len to 0, this is must to do.
 *
 *  @param str, is the string array that have to init.
 *
 *  @param n, is the len of the string array.
 *
 *  @return int, is the exec status.
 *
 **/

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

    if (ntohs(eth->ether_type) == SPOOFER_ETH_TYPE_VLAN) {
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
 **/

inline const u_char *spo_http_start(const u_char *packet) {

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



/**
 *
 *  get the http request packet method.
 *
 *  @param packet, is the packet we catched.
 *
 *  @param method, used to save the method name and name's len.
 *
 *  @return int, is the exec status.*
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

    while (*ch == SPOOFER_SPACE) {    /* skip the ' ', hex is 0x20 */
        ch++;
    }

    mtd->data = ch;

    while (*ch != SPOOFER_SPACE) {
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
 *  @param url_off, is the offset between http start to url.
 *
 *  @param pkt_s, is the packet size.
 *
 *  @return int, is the exec status.
 *
 **/

SPO_RET_STATUS_INT spo_http_request_url(const u_char *http_start, spo_str_t *url, int url_off, size_t pkt_s) {

    u_char *ch = NULL;
    size_t i = 0;

    if (url == NULL) {
        //printf("url == NULL\n");
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
        if ((*ch) == 0x20) {
            break;
        }
        //printf("%c", *ch);
        ch++;
    }


    if (i >= pkt_s) {
//        printf("\npack size %ld\n\n", (long)pkt_s);
//        printf("ch ---- \n");
//        printf("%d\n\n", (int)i);
//        i = 0;
//        ch = url->data;
//        while (*ch != ' ') {
//            //printf("%c", *(ch));
//            i++;
//            //printf("%ld\n", (long)i);
//            ch++;
//        }
//        printf("%ld\n", (long)i);

        url->data = NULL;
        url->len = 0;
        //printf("i >= pkt_s\n");
        return SPOOFER_FAILURE;
    }

    url->len = (size_t) (ch - url->data);
    if (url->len == 0) {
        url->data = NULL;
        url->len = 0;
        //printf("url len too len\n");
        return SPOOFER_FAILURE;
    }

    return SPOOFER_OK;
}

/**
 *
 *  get the http version. but the http version we not need.
 *
 *  @param http_start, is the pointer that http start.
 *
 *  @param version, save that the http version.
 *
 *  @param version_off, is the offset between http start and version.
 *
 *  @param pkt_s, is the packet size.
 *
 *  @return int, is the exec status.
 *
 **/

SPO_RET_STATUS_INT spo_http_version(const u_char *http_start, spo_str_t *version, int version_off, size_t pkt_s) {

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

    ch = (u_char *) (((u_char *) http_start) + version_off);

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
 *  analysis the http request header. we need referer, cookie and host in packet.
 *
 *  @param http_start, is the pointer that http start.
 *
 *  @param head_info, the array of string. save the info we need.
 *
 *  @param head_off, the offset between http start and header.
 *
 *  @param pkt_s, is the packet size.
 *
 *  @return int, the exec status.
 *
 **/

SPO_RET_STATUS_INT spo_http_request_header(const u_char *http_start, spo_str_t *head_info, int head_off, size_t pkt_s) {

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
                head_info[0].data = field + SPOOFER_REFERER_VAR_LEN;    /* skip the targe 'Referer: ' */
                head_info[0].len =  (size_t) (ch - head_info[0].data);
                ch = ch + 2;
                if (*ch == CR && *(ch + 1) == LF) {
                    break;
                }
                field = ch;
                continue;
            }

            if (memcmp(field, "Cookie", strlen("Cookie")) == 0) {
                head_info[1].data = field + SPOOFER_COOKIE_VAR_LEN;
                head_info[1].len =  (size_t) (ch - head_info[1].data);
                ch = ch + 2;
                if (*ch == CR && *(ch + 1) == LF) {
                    break;
                }
                field = ch;
                continue;
            }

            if (memcmp(field, "Host", strlen("Host")) == 0) {   /* found the Host */
                head_info[2].data = field + SPOOFER_HOST_VAR_LEN;      /* record the key and value */
                head_info[2].len =  (size_t) (ch - head_info[2].data);

                ch = ch + 2;
                if (*ch == CR && *(ch + 1) == LF) {
                    break;
                }
                field = ch;
                continue;
            }

            ch = ch + 2;    /* skip the '\r\n' */
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
 *  @param http_start, the point to the http start.
 *
 *  @param line, is the string save http request line.
 *
 *  @param pkt_s, is the packet size.
 *
 * */

SPO_RET_STATUS_INT spo_analysis_http_line(const u_char *http_start, spo_str_t *line, size_t pkt_s) {

    int offset = -1;
    int ret = -1;

    if (line == NULL) {
        //printf("line is null\n");
        return SPOOFER_FAILURE;
    }

    /* get the request method */

    if (http_start == NULL) {
        goto bad_analysis;
    }else {
        ret = spo_http_request_method(http_start, &line[0], 0);
        if (ret == SPOOFER_FAILURE) {
            //printf("get request method err\n");
            goto bad_analysis;
        }

        if (!(line[0].len == 3 && memcmp(line[0].data, "GET", 3) == 0)) {
            //printf("the way is not GET\n");
            goto bad_analysis;
        }
    }

    /* get the request url */

    if (line[0].len == 0 || line[0].data == NULL) {
        goto bad_analysis;
    }else {
        offset = line[0].len + 1;   /* add 1 is skip the ' '(0x20) */

        ret = spo_http_request_url(http_start, &line[1], offset, pkt_s);
        if (ret == SPOOFER_FAILURE) {
            //printf("get request\n");
            goto bad_analysis;
        }
    }

    /* get the http version */
    if (line[1].len == 0 || line[1].data == NULL) {
        goto bad_analysis;
    }else {
        offset = offset + line[1].len + 1;

        ret = spo_http_version(http_start, &line[2], offset, pkt_s);
        if (ret == SPOOFER_FAILURE) {
            //printf("get version err\n");
            goto bad_analysis;
        }
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

SPO_RET_STATUS_INT spo_analysis_http_packet(const u_char *packet, spo_str_t *info[]) {

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
        //printf("not http\n");
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
        if (line != NULL) {
            free(line);
        }
        return SPOOFER_FAILURE;
    }

    spo_init_string(header_info, SPOOFER_HTTP_HEADER_FIELD_AMOUNT); /* must init the str, set the data to null and the len to 0 */

    info[0] = line;
    info[1] = header_info;

    pkt_s = spo_http_packet_size(packet);

    ret = spo_analysis_http_line(http_start, line, pkt_s);
    if (ret == SPOOFER_FAILURE) {
        //printf("line err\n");

//        printf("\n\n\n");
//        int d = 0;
//        for (d = 0; d < 50; d++) {
//            printf("%c", *(http_start + d));
//        }
//        printf("\n");
        return SPOOFER_FAILURE;
    }

    for (i = 0; i < SPOOFER_HTTP_LINE_FIELD_AMOUNT; i++) {
        header_offset = header_offset + line[i].len;
    }

    header_offset = header_offset + 4;      /* skip tow 0x20 (space) and the '\r\n' in the end */

    ret = spo_http_request_header(http_start, header_info, header_offset, pkt_s);
    if (ret == SPOOFER_FAILURE) {
        //printf("header err\n");
        return SPOOFER_FAILURE;
    }

    return SPOOFER_OK;
}



/**
 *
 *  when we get http request packet and the packet is we want,
 *
 *  we record the packet info that we need.
 *
 *  @param packet, is the packet we catched.
 *
 *  @param hjk_info, the packet info will save in this struct.
 *
 *  @return the exec status.
 *
 * */

SPO_RET_STATUS_INT spo_hijacking_http_info(const u_char *packet, spo_http_hjk_info_t *hjk_info) {

    if (packet == NULL || hjk_info == NULL) {
        return SPOOFER_FAILURE;
    }

    spo_sniff_ether_t *eth;
    spo_sniff_ip_t *ip;
    spo_sniff_tcp_t *tcp;

    eth = (spo_sniff_ether_t *) packet;
    hjk_info->vlan_id = 0;

    if (spo_is_802_1q_vlan(packet) == SPOOFER_TRUE) {
        ip = (spo_sniff_ip_t *) (packet + SPOOFER_IP_OFFSET_VLAN);
        tcp = (spo_sniff_tcp_t *) (packet + SPOOFER_TCP_OFFSET_VLAN);
        hjk_info->vlan_id = *((u_short *)(packet + SPOOFER_VLAN_OFFSET ));
        //printf("vlan id === > %x\n", hjk_info->vlan_id );
        hjk_info->vlan_targe = SPOOFER_RUNNING_IN_VLAN;
    }else {
        ip = (spo_sniff_ip_t *) (packet + SPOOFER_IP_OFFSET);
        tcp = (spo_sniff_tcp_t *) (packet + SPOOFER_TCP_OFFSET);
        hjk_info->vlan_targe = 0;
    }

    /* copy the src and dst mac, we can improve by pointer */
    memcpy(hjk_info->src_mac, eth->ether_shost, SPOOFER_ETH_ADDR_LEN);
    memcpy(hjk_info->dst_mac, eth->ether_dhost, SPOOFER_ETH_ADDR_LEN);

    /* copy the src and dst ip address */
    hjk_info->ip_src_addr = ip->ip_src.s_addr;
    hjk_info->ip_dst_addr = ip->ip_dst.s_addr;
    hjk_info->ip_len = ip->ip_len;

    /* copy the ip flg */
    hjk_info->ip_off = ip->ip_off;

    /* copy the src and dst tcp port */
    hjk_info->tcp_src_port = tcp->tcp_sport;
    hjk_info->tcp_dst_port = tcp->tcp_dport;

    /* get the tcp seq and ack */
    hjk_info->tcp_seq_rela = tcp->tcp_seq;
    hjk_info->tcp_ack_rela = tcp->tcp_ack;
    hjk_info->tcp_header_len = tcp->tcp_offx2;
    hjk_info->tcp_resp_flg = tcp->tcp_flags;

    hjk_info->tcp_op_len = ((int)((tcp->tcp_offx2 >> 2)) - LIBNET_TCP_H);

    if (hjk_info->tcp_op_len > 0) {
        u_char *tcp_op_start = (u_char *)tcp + LIBNET_TCP_H;
        memcpy(hjk_info->tcp_op, tcp_op_start, hjk_info->tcp_op_len);
    }

    return SPOOFER_OK;
}
