#ifndef SPOOFER_H
#define SPOOFER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <assert.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/sendfile.h>
#include <errno.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <libnet.h>

#define SPO_RET_STATUS  int      /* the func return status, is int */
#define SPO_RET_VALUE   int      /* the func return value, is int */
#define SPO_RET_BOOLEN  int      /* the func return boolen, is int */

#define SPO_OK (0)          /* ok, for the return value */
#define SPO_FALSE (0)       /* false, for the return value */
#define SPO_TRUE (1)        /* true, for the conditions */
#define SPO_FAILURE (-1)    /* failure, for the return value */
#define SPO_ERR (-2)        /* something err */
#define SPO_NOT_HTTP (-2)   /* when analysis packet, if the packet not a http packet, we return this*/

#define SPO_MAIN        (0)
#define SPO_SNIFFER     (1)
#define SPO_ANALYSTS    (2)
#define SPO_HP_SPOOFER  (3)
#define SPO_DNS_SPOOFER (4)
#define SPO_SENDER      (5)
#define SPO_LOGER       (6)


/* switch */

#define SPO_DEBUG               (1)     /* printf debug info */
#define SPO_SEE_TIME            (0)     /* printf debug info */
#define SPO_DAEMON              (0)     /* running as a daemon */
#define SPO_SHUTDOWN_DNS_SPOF   (0)     /* shut down dns spoofers */
#define SPO_SHUTDOWN_HP_SPOF    (0)     /* shut down http spoofers */
#define SPO_SHUTDOWN_SND        (0)     /* shut down senders */
#define SPO_TEST_PF             (0)     /* used to test pf */
#define SPO_SND_RST             (0)     /* send the rst packet to servers */
#define SPO_VERIFY              (0)     /* used to ues verification */


# define spo_likely(x)	__builtin_expect(!!(x), 1)
# define spo_unlikely(x)	__builtin_expect(!!(x), 0)


typedef unsigned char uint8_t;

/* pool */
typedef struct spo_big_pool_s spo_big_pool_t;   /* big mem pool */
typedef struct spo_pool_s spo_pool_t;           /* mem pool */

/* msg */
typedef struct spo_msg_s spo_msg_t;
typedef struct spo_packet_s spo_packet_t;
typedef struct spo_dns_packet_s spo_dns_pkt_t;
typedef struct spo_build_packet_s spo_bld_pkt_t;

/* cfg */
typedef struct spo_info_header_s spo_info_header_t;
typedef struct spo_analy_info_s spo_analy_info_t;
typedef struct spo_analy_info_header_s spo_analy_info_header_t;
typedef struct spo_info_s spo_info_t;
typedef struct spo_cfg_g_s spo_cfg_g_t;
typedef struct spo_cfg_s spo_cfg_t;
typedef struct spo_hp_data_info_s spo_hp_data_info_t;
typedef struct spo_http_data_s spo_hp_data_t;
typedef struct spo_http_cfg_line_s spo_hp_line_t;
typedef struct spo_http_dmn_s spo_hp_dmn_t;
typedef struct spo_dns_data_s spo_dns_data_t;
typedef struct spo_dmn_data_header_s spo_dmn_data_header_t;
typedef struct spo_dmn_s spo_dmn_t;

/* avl tree */
typedef struct spo_tree_header_s spo_tree_header_t;
typedef struct spo_tree_node_s spo_tree_node_t;

/* rbt tree */
typedef struct spo_rbtree_s spo_rbtree_t;
typedef struct spo_rbt_node_s spo_rbt_node_t;

/* queue */
typedef struct spo_queue_node_s spo_que_node_t;
typedef struct spo_queue_s spo_queue_t;

/* hjk info */
typedef struct spo_http_hijack_info_s spo_hp_hjk_t;
typedef struct spo_dns_hijack_info_s spo_dns_hjk_t;

/* analysts, MTU */
typedef struct spo_analy_s spo_analy_t;
typedef struct spo_analy_sm_s spo_analy_sm_t;

/* log */
typedef struct spo_statis_s spo_statis_t;
typedef struct spo_statis_header_s spo_statis_head_t;
typedef struct spo_log_s spo_log_t;


typedef struct spo_proc_node_s {
   spo_cfg_t *cfg;          /* prog cfg */
   spo_pool_t *pool;        /* process's mem pool */
   spo_msg_t *hp_pkt;       /* sniffers send it to msg, spoofers, http sender use it to get msg in queueu */
   spo_msg_t *snd_pkt;      /* http spoofers send it to msg queue, ponit to http data's copy */
   spo_msg_t *dns_pkt;      /* use to send the dns pkt */
   spo_msg_t *log;          /* use to send the log msg */
   spo_dmn_data_header_t *dmn_data_header;      /* data tree's header */
   spo_dmn_t *http_dmn_header;                  /* http dmn cfg tree's header */
   spo_info_t *info;                            /* process's cfg info */
   void (*work_func) (void *);
   int *hp_msgid;
   int *dns_msgid;
   pid_t pid;
   int proc_idx;
   char proc_type;          /* this proc's type */

   volatile uint8_t security : 1;
   volatile uint8_t hp_cfg_security : 1;
   volatile uint8_t dns_cfg_security : 1;
   volatile uint8_t hp_data_security : 1;

   volatile uint8_t hp_cfg_tmp_security : 1;
   volatile uint8_t hp_data_tmp_security : 1;
   volatile uint8_t dns_cfg_tmp_security : 1;
   volatile uint8_t alarm_security : 1;
}spo_proc_node_t;


typedef struct spo_proc_header_s{
    spo_proc_node_t *sniffers;
    spo_proc_node_t *analysts;
    spo_proc_node_t *d_spofs;
    spo_proc_node_t *h_spofs;
    spo_proc_node_t *senders;
    spo_proc_node_t *log;
    uint sniff_n:8;
    uint analy_n:8;
    uint d_spoof_n:8;
    uint h_spoof_n:8;
    uint snd_n:8;
}spo_proc_header_t;


/*  */

extern int proc_idx;

extern spo_proc_node_t *current;                /* current process's struct */

extern spo_proc_header_t *proc_queue;
extern spo_tree_header_t *dns_data;
extern spo_tree_header_t *hp_data;
extern spo_tree_header_t *hp_mtd;               /* http's method */
extern spo_dmn_t *hp_dmn;
extern spo_cfg_t *prog_cfg;

extern spo_msg_t *sys_log;                      /* use to log the system log when init */

extern SPO_RET_STATUS (*inst_func[13]) (void);  /* the manage's instruction's working funcs */

extern int log_msgid;
extern int statis_msgid;
extern int sys_shmid;                           /* when we have to see the total time */
extern char **sys_argv;

#endif // SPOOFER_H
