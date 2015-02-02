#ifndef SPO_ANALYSTS_H
#define SPO_ANALYSTS_H

#include <sys/types.h>


struct spo_analy_sm_s {
    struct in_addr ip_src;          /* ip src address */
    u_int tcp_ack;                  /* tcp ack */
    u_short tcp_sport;              /* tcp src port */
};


struct spo_analy_s {
    size_t buf_size;                /* buf's size, is calloc size */
    size_t pkt_len;                 /* the lengthe of this http request */
    u_char *buf;                    /* the data's buf */
    struct spo_analy_sm_s sm;       /* the pkt info to comp */
    u_char alarm;                   /* the alaem times */
};


void spo_analysts(void *proc_infos);

#endif // SPO_ANALYSTS_H
