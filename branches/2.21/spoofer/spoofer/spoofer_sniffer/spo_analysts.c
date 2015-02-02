#include "../spoofer_system/spoofer.h"
#include "../spoofer_pool/spo_pool.h"
#include "../spoofer_kernel/spo_kernel.h"
#include "../spoofer_config/spo_config.h"
#include "../spoofer_linux/spo_linux.h"
#include "../spoofer_sniffer/spo_sniffer.h"
#include "../spoofer_test/spo_test.h"
#include "../spoofer_log/spo_log.h"
#include "../spoofer_sniffer/spo_analysts.h"


#define SPO_DFT_CACHE_UNIT_SIZE     (8192)      /* the cache's Unit size */
#define SPO_ANALYSTS_POOL_S         (8192 * 8)  /* analysts's pool size */


#define SPO_HP_HEAD_COMPLETE        (0)         /* the http packet is completed */
#define SPO_HP_HEAD_INTERRUP        (1)
#define SPO_HP_HEAD_HALF            (2)
#define SPO_HP_HEAD_PART            (3)



static SPO_RET_STATUS spo_analy_comp_pkt(void *old_pkt, void *come_pkt);
static SPO_RET_STATUS spo_analy_free_cache_unit(void *unit);
static SPO_RET_STATUS spo_analy_free_queue_data(void *data_);

static SPO_RET_STATUS spo_do_analy_clean();
struct spo_analy_s *spo_create_analy();
static size_t spo_cache2buf_amt(size_t cache_size);


/* -- -- -- - -- -- -- --- -  Interruption  --- - - -- -- --  - -- - -- - - --- - */

static void spo_analy_clean(int sig, siginfo_t *info, void *p);
static void spo_rld_hp_cfg(int sig, siginfo_t *info, void *p);
static void spo_rld_hp_cfg_tmp(int sig, siginfo_t *info, void *p);
static void spo_to_update(spo_proc_node_t *node);


/* -- -- -- - -- -- ---- -  analysis http pkts  --- - -- --  - -- - -- - - --- - */

static inline const u_char *spo_http_start(const u_char *packet);
static SPO_RET_STATUS spo_http_host(const u_char *packet, spo_packet_t *pkt);
static SPO_RET_STATUS spo_http_request_method(const u_char *http_start, spo_str_t *mtd, int mtd_off);
static SPO_RET_STATUS spo_http_method_filter(spo_tree_header_t *mtd_header, spo_str_t *mtd);
static SPO_RET_STATUS spo_analy_http_request(spo_packet_t *pkt, const u_char *packet);
static SPO_RET_STATUS spo_analysts_send(const u_char *packet, size_t caplen, int msgid);
static SPO_RET_STATUS spo_analysts_comp_info(spo_analy_sm_t *analy, const u_char *packet);


/* -- -- -- - -- -- - - - - --- - -  Solve MTU  --- - -- --  - -- - -- - - --- - */

static SPO_RET_STATUS spo_analy_decide_pkt(const u_char *packet, size_t pkt_s, const u_char *hp_start);
static SPO_RET_STATUS
spo_span_traversal_clean(spo_rbt_node_t *t_node, spo_rbtree_t *rbt, spo_queue_t *alm_que, spo_queue_t *tmp_que);
static SPO_RET_STATUS
spo_do_analy_clean__(spo_queue_t *alm_que, spo_queue_t *mtu_que, spo_rbtree_t *alm_rbt, spo_rbtree_t *mtu_rbt);
static SPO_RET_STATUS
spo_analy_decide_in(spo_queue_t *queue, spo_rbtree_t *rbt, const u_char *packet, size_t pkt_s);
static SPO_RET_STATUS
spo_analy_decide_part_in(spo_queue_t *queue, spo_rbtree_t *rbt,
                         const u_char *packet, const u_char *hp_start, size_t pkt_s);
static SPO_RET_STATUS spo_analy_decide_out(spo_queue_t *queue, spo_rbtree_t *rbt,
                            const u_char *packet, const u_char *hp_start, size_t pkt_s, int snd_msgid);


/* -- -- -- - -- -- -- - --- - -  init analysts  --- - -- --  -- - -- - - --- - */

static SPO_RET_STATUS spo_analy_init_sig();
static SPO_RET_STATUS spo_do_analy_build_cache(spo_queue_t *queue, size_t amt);
static SPO_RET_STATUS spo_analy_build_alarm_cache(spo_queue_t *queue, size_t amt);
static SPO_RET_STATUS spo_analy_build_cache(size_t cache_size);
static SPO_RET_STATUS spo_init_analysts(spo_proc_node_t *node);
static SPO_RET_STATUS spo_analysts_init_pool(spo_proc_node_t *node);
static inline SPO_RET_STATUS spo_init_analy(struct spo_analy_s *analy);
static SPO_RET_STATUS spo_do_analysts(const u_char *packet, size_t pkt_s, int snd_msgid);


static int pkt_len_ = sizeof(spo_msg_t) + sizeof(spo_packet_t);


spo_rbtree_t *mtu_rbt = NULL;
spo_queue_t *mtu_que = NULL;
spo_rbtree_t *alarm_rbt = NULL;
spo_queue_t *alarm_que = NULL;

static int alarm_time = 799999;



static inline SPO_RET_STATUS spo_init_analy(struct spo_analy_s *analy)
{
    if (analy == NULL) return SPO_FAILURE;

    analy->alarm         = 0;
    analy->buf           = NULL;
    analy->buf_size      = 0;
    analy->pkt_len       = 0;
    analy->sm.tcp_ack       = 0;
    analy->sm.tcp_sport     = 0;

    memset(&(analy->sm.ip_src), '\0', sizeof(struct in_addr));

    return SPO_OK;
}


struct spo_analy_s *spo_create_analy()
{
    struct spo_analy_s *analy = NULL;

    if ((analy = spo_calloc(sizeof(struct spo_analy_s))) == NULL) return NULL;

    spo_init_analy(analy);

    return analy;
}


static inline size_t spo_cache2buf_amt(size_t cache_size)
{
    size_t amt = 0;

    if (cache_size <= 16 * 1024 * 1024) cache_size = 16 * 1024 * 1024;

    amt = (cache_size / SPO_DFT_CACHE_UNIT_SIZE) + 1;

    return amt;
}


static void spo_analy_clean(int sig, siginfo_t *info, void *p)
{
    info = info;
    p = p;

    if (sig == SIGALRM) {
        current->security = 1;
        current->alarm_security = 1;
    }
}


static SPO_RET_STATUS spo_analy_comp_pkt(void *old_pkt, void *come_pkt)
{
    spo_analy_t *old = (spo_analy_t *) old_pkt;
    spo_analy_t *come = (spo_analy_t *) come_pkt;

    if (old->sm.tcp_sport > come->sm.tcp_sport) return 1;
    else {
        if (old->sm.tcp_sport < come->sm.tcp_sport) {
            return -1;
        }else {     /* proc eq */
            if (old->sm.ip_src.s_addr > come->sm.ip_src.s_addr) {
                return 1;
            }else {
                if (old->sm.ip_src.s_addr < come->sm.ip_src.s_addr) {
                    return -1;
                }else {
                    if (old->sm.tcp_ack > come->sm.tcp_ack) {
                        return 1;
                    }else {
                        if (old->sm.tcp_ack < come->sm.tcp_ack) return -1;
                        else return 0;
                    }
                }
            }
        }
    }

    return SPO_OK;
}


static SPO_RET_STATUS spo_analy_free_cache_unit(void *unit)
{
    if (unit != NULL) spo_free(unit);

    return SPO_OK;
}


static SPO_RET_STATUS spo_analy_free_queue_data(void *data_)
{
    spo_rbt_node_t *node = (spo_rbt_node_t *) data_;

    if (data_ == NULL) return SPO_OK;

    if (node->key != NULL) spo_free(node->key);

    spo_free(node);

    return SPO_OK;
}


static void spo_rld_hp_cfg(int sig, siginfo_t *info, void *p)
{
    info = info;
    p = p;

    if (sig == SIGUSR1) {
#if SPO_DEBUG
        printf("hp spoofer rld hp cfg\n");
#endif
        current->security = 1;
        current->hp_cfg_security = 1;

    }
}


static void spo_rld_hp_cfg_tmp(int sig, siginfo_t *info, void *p)
{
    info = info;
    p = p;

    if (sig == SIGUSR2) {
#if SPO_DEBUG
        printf("hp spoofer rld hp cfg tmp\n");
#endif
        current->security = 1;
        current->hp_cfg_tmp_security = 1;

    }
}


static SPO_RET_STATUS
spo_span_traversal_clean(spo_rbt_node_t *t_node, spo_rbtree_t *rbt, spo_queue_t *alm_que, spo_queue_t *tmp_que)
{
    spo_que_node_t *q_node = NULL;

    if (spo_unlikely(!t_node || !rbt || !alm_que || !tmp_que)) return SPO_FAILURE;

    if (t_node->left != &rbt->nil) {
        if (spo_unlikely((q_node = spo_queue_rm_node(alm_que)) == NULL)) {
            if ((q_node = spo_create_queue_node(NULL, NULL)) == NULL) exit(EXIT_FAILURE);
        }

        q_node->data = t_node->left;
        spo_enter_queue(tmp_que, q_node);
    }

    if (t_node->right != &rbt->nil) {
        if (spo_unlikely((q_node = spo_queue_rm_node(alm_que)) == NULL)) {;
            if ((q_node = spo_create_queue_node(NULL, NULL)) == NULL) exit(EXIT_FAILURE);
        }

        q_node->data = t_node->right;
        spo_enter_queue(tmp_que, q_node);
    }

    t_node->parent = t_node->left = t_node->right = NULL;

    return SPO_OK;
}


static SPO_RET_STATUS
spo_do_analy_clean__(spo_queue_t *alm_que, spo_queue_t *mtu_que, spo_rbtree_t *alm_rbt, spo_rbtree_t *mtu_rbt)
{
    spo_queue_t *tmp_que = NULL;        /* used to Traversal mtu_rbt */
    spo_que_node_t *q_node = NULL;
    spo_rbt_node_t *t_node = NULL;
    spo_analy_t *analy = NULL;

    if (spo_unlikely(alm_que == NULL || mtu_que == NULL || alm_rbt == NULL || mtu_rbt == NULL))
        return SPO_FAILURE;

    if (spo_unlikely(mtu_rbt->size <= 0 || mtu_rbt->root == &mtu_rbt->nil)) return SPO_OK;

    if ((tmp_que = spo_create_queue(NULL, NULL)) == NULL) return SPO_FAILURE;

    if ((q_node = spo_queue_rm_node(alm_que)) == NULL) return SPO_FAILURE;

    q_node->data = mtu_rbt->root;
    spo_enter_queue(tmp_que, q_node);

    while (!spo_queue_empty(tmp_que)) {
        q_node = spo_queue_rm_node(tmp_que);
        t_node = q_node->data;
        analy = t_node->key;

        q_node->data = NULL;
        spo_enter_queue(alm_que, q_node);

        spo_span_traversal_clean(t_node, mtu_rbt, alm_que, tmp_que);

        if (++analy->alarm >= 2)
            spo_enter_queue(mtu_que, (spo_que_node_t *) t_node->carrier);       /* this rbt node Expired */
        else
            spo_insert_rbt_node(alm_rbt, t_node);           /* Reorganize Not expired rbt node */
    }

    spo_destory_queue(tmp_que);

    mtu_rbt->size = 0;
    mtu_rbt->root = &mtu_rbt->nil;

    return SPO_OK;
}


static SPO_RET_STATUS spo_do_analy_clean()
{
    spo_rbtree_t *tmp_rbt = NULL;

    if (mtu_rbt->size <= 0 || mtu_rbt->root == &mtu_rbt->nil) return SPO_OK;

    if (spo_do_analy_clean__(alarm_que, mtu_que, alarm_rbt, mtu_rbt) == SPO_FAILURE)
        return SPO_FAILURE;

    printf("------\n");
    tmp_rbt = mtu_rbt;
    mtu_rbt = alarm_rbt;
    alarm_rbt = tmp_rbt;

    return SPO_OK;
}


static void spo_to_update(spo_proc_node_t *node)
{
    if (node->security == 1) {
        int ret = 0;
        int type = 0;

        if (node->alarm_security == 1) {
            spo_do_analy_clean();           /* clean all expired rbt nodes */
            node->security = 0;
            node->alarm_security = 0;
        }

        if (node->hp_cfg_security == 1) {
            ret = spo_reload_http_config(node->cfg, node);
            node->security = 0;
            node->hp_cfg_security = 0;
            type = SPO_UP_HP_CFG;
            goto spo_snif_update_fial;
        }

spo_snif_update_fial:

        if (ret == SPO_FAILURE) {
            char log_info[256] = {'\0'};
            spo_updata_log(type, log_info);
            spo_do_snd_log_msg(current->log, log_info, SPO_LOG_LEVEL_ERR);
        }
    }
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

static inline const u_char *spo_http_start(const u_char *packet)
{
    u_char *http_start = NULL;

    if (spo_is_802_1q_vlan(packet) == SPO_TRUE) {
        http_start = (u_char *) (packet + SPO_TCP_OFFSET_VLAN
                                 + LIBNET_TCP_H + spo_get_tcp_options_len(packet));
    }else {
        http_start = (u_char *) (packet + SPO_TCP_OFFSET
                                 + LIBNET_TCP_H + spo_get_tcp_options_len(packet));
    }

    if ((long)spo_packet_size(packet) == (long)(http_start - packet)) return NULL;

    return http_start;
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

static SPO_RET_STATUS spo_http_host(const u_char *packet, spo_packet_t *pkt)
{
    u_char *field = NULL;
    u_char *http_start = NULL;
    size_t i = 0;
    size_t len = ((size_t) pkt->pkt_s - (size_t) pkt->http_s + 3);
    spo_str_t *host = &((spo_str_t *) pkt->pkt_info)[1];

    http_start = (u_char *) (packet + pkt->http_s);
    field = http_start;

    for (i = 0; i <= len; i += 2) {
        if (*(http_start) == SPO_CR) {      /* '\r' */
            if (*(http_start + 1) == SPO_LF) {
                if (memcmp(field, "Host", 4) == 0) {
                    host->data = field + SPO_HOST_VAR_LEN;
                    host->len = (size_t) (http_start - host->data);
                    return SPO_OK;
                }
            }
            http_start += 2;
            field = http_start;
            continue;
        }

        if (*(http_start) == SPO_LF) {      /* '\n */
            if (*(http_start - 1) == SPO_CR) {
                if (memcmp(field, "Host", 4) == 0) {
                    host->data = field + SPO_HOST_VAR_LEN;
                    host->len = (size_t) (http_start - host->data -1);
                    return SPO_OK;
                }
            }
            http_start += 1;
            field = http_start;
            continue;
        }

        http_start += 2;
    }

    if (i > len) return SPO_FAILURE;

    return SPO_OK;
}


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

static SPO_RET_STATUS spo_http_request_method(const u_char *http_start, spo_str_t *mtd, int mtd_off)
{
    u_char *ch = NULL;
    int i = SPO_MAX_QUE_METHOD;

    ch = (u_char *) (((u_char *)http_start) + mtd_off);

    if (spo_unlikely(*ch == SPO_CR || *ch == SPO_LF)) return SPO_FAILURE;

    while (*ch == 0x20 && i >= 0) {    /* skip the ' ', hex is 0x20 */
        ch++;
        i--;
    }

    mtd->data = ch;
    i = SPO_MAX_QUE_METHOD;

    while (*ch != 0x20 && i >= 0) {
        ch++;
        i--;
    }

    if (i < 0) return SPO_FAILURE;

    if ((mtd->len = (size_t)(ch - mtd->data)) == 0) return SPO_FAILURE;

    return SPO_OK;
}


/**
 *
 *  filter the http request method. we need the 'GET'.
 *
 * */

static SPO_RET_STATUS spo_http_method_filter(spo_tree_header_t *mtd_header, spo_str_t *mtd)
{
    if (spo_unlikely(mtd == NULL || mtd->data == NULL)) return SPO_FAILURE;

    if (spo_tree_match(mtd_header, mtd, spo_comp_hp_mtd) == NULL) return SPO_FAILURE;

    return SPO_OK;
}


/**
 *
 *  analysis the http packet, get the http request host and method.
 *
 * */

static SPO_RET_STATUS spo_analy_http_request(spo_packet_t *pkt, const u_char *packet)
{
    const u_char *http_start = NULL;
    spo_str_t *info = NULL;

    pkt->op_len = spo_get_tcp_options_len(packet);

    info = (spo_str_t *) pkt->pkt_info;

    if ((http_start = spo_http_start(packet)) == NULL) return SPO_FAILURE;  /* get http start */

    pkt->http_s = http_start - packet;  /* record the offset */

    /* get the request method */
    if (spo_http_request_method(http_start, &info[0], 0) == SPO_FAILURE) return SPO_FAILURE;

    /* filter the http query method */
    if (spo_http_method_filter(hp_mtd, &info[0]) == SPO_FAILURE) return SPO_FAILURE;

    if (spo_http_host(packet, pkt) == SPO_FAILURE) return SPO_FAILURE;  /* geth the host */

    return SPO_OK;
}


/**
 *
 *  analysis http packet.
 *
 *  is domain is we need, send this packet to http spoofer.
 *
 * */

static SPO_RET_STATUS spo_analysts_send(const u_char *packet, size_t caplen, int msgid)
{
    register spo_proc_node_t *node = current;
    spo_msg_t *msg = node->snd_pkt;
    register spo_packet_t *pkt = (spo_packet_t *) (msg->data);
    spo_tree_header_t *header = node->http_dmn_header->dmn;
    spo_str_t *infos = (spo_str_t *) pkt->pkt_info;

#if SPO_SEE_TIME
    spo_use_time(SPO_TIME_START, "sniffer");
#endif

    /* judge the msg queue status */
    if (spo_msg_queue_stat(msgid, 4) == SPO_FAILURE) return SPO_FAILURE;

    spo_rst_packet(pkt);    /* reset the pkt, and reset the info */

    if (spo_unlikely((pkt->pkt_s = caplen) >= pkt->max_pkts - pkt_len_))
        return SPO_FAILURE;

    if (spo_analy_http_request(pkt, packet) == SPO_FAILURE) return SPO_FAILURE;

#if SPO_SEE_TIME
    spo_snif_used_time();
#endif
    if (spo_tree_match(header, &(infos[1]), spo_comp_http_dmn) == NULL) return SPO_FAILURE;

    memcpy(pkt->packet, packet, pkt->pkt_s);

    if (spo_msgsnd(msgid, msg, pkt->pkt_s + pkt_len_, IPC_NOWAIT) == SPO_FAILURE) {
#if SPO_DEBUG
            printf("fail to send\n");
#endif
        return SPO_FAILURE;
    }

#if SPO_SEE_TIME
    spo_use_time(SPO_TIME_END, "sniffer");
#endif

    return SPO_OK;
}


static SPO_RET_STATUS spo_analysts_comp_info(spo_analy_sm_t *analy, const u_char *packet)
{
    spo_sniff_ip_t *ip;
    spo_sniff_tcp_t *tcp;

    if (spo_is_802_1q_vlan(packet) == SPO_TRUE) {
        ip = (spo_sniff_ip_t *) (packet + SPO_IP_OFFSET_VLAN);
        tcp = (spo_sniff_tcp_t *) (packet + SPO_TCP_OFFSET_VLAN);
    }else {
        ip = (spo_sniff_ip_t *) (packet + SPO_IP_OFFSET);
        tcp = (spo_sniff_tcp_t *) (packet + SPO_TCP_OFFSET);
    }

    analy->ip_src.s_addr = ip->ip_src.s_addr;
    analy->tcp_sport = tcp->tcp_sport;
    analy->tcp_ack = tcp->tcp_ack;

    return SPO_OK;
}


static SPO_RET_STATUS
spo_analy_decide_in(spo_queue_t *queue, spo_rbtree_t *rbt, const u_char *packet, size_t pkt_s)
{
    register spo_packet_t *pkt = (spo_packet_t *) (current->snd_pkt->data);
    spo_tree_header_t *header = current->http_dmn_header->dmn;
    spo_str_t *infos = (spo_str_t *) pkt->pkt_info;
    spo_que_node_t *q_node = NULL;
    spo_analy_t *analy = NULL;

    spo_rst_packet(pkt);    /* reset the pkt, and reset the info */

    if (spo_unlikely((pkt->pkt_s = pkt_s) >= pkt->max_pkts - pkt_len_))
        return SPO_FAILURE;

    if (spo_analy_http_request(pkt, packet) == SPO_FAILURE) return SPO_FAILURE;

    if (spo_tree_match(header, &(infos[1]), spo_comp_http_dmn) == NULL) return SPO_FAILURE;

    if ((q_node = spo_queue_rm_node(queue)) == NULL) return SPO_FAILURE;

    analy = (spo_analy_t *) ((spo_rbt_node_t *) q_node->data)->key;
    spo_analysts_comp_info(&analy->sm, packet);

    analy->alarm = 0;
    memcpy(analy->buf, packet, pkt_s);
    analy->pkt_len += pkt_s;

    spo_insert_rbt_node(rbt, (spo_rbt_node_t *) q_node->data);

    return SPO_OK;
}


/**
 *
 *  whem a http request more tow pkt, we call this func to deal with it.
 *
 *  this func is look like spo_analy_decide_out, but we didn't Merger them.
 *
 *  if merage, we have to more one param and more one 'if'.
 *
 * */

static SPO_RET_STATUS
spo_analy_decide_part_in(spo_queue_t *queue, spo_rbtree_t *rbt,
                         const u_char *packet, const u_char *hp_start, size_t pkt_s)
{
    spo_analy_t analy;
    spo_rbt_node_t *t_node = NULL;
    spo_analy_t *t_analy = NULL;
    spo_que_node_t *q_node = NULL;
    size_t size = 0;
    u_char *buf = NULL;

    spo_analysts_comp_info(&analy.sm, packet);

    if ((t_node = spo_find_rbt_node(rbt, &analy)) == NULL) return SPO_FAILURE;

    t_analy = (spo_analy_t *) t_node->key;
    if (spo_unlikely(t_analy == NULL)) return SPO_FAILURE;

    size = pkt_s - (hp_start - packet);
    buf = t_analy->buf + t_analy->pkt_len;

    if ((t_analy->pkt_len += size) > t_analy->buf_size) goto spo_bad_decide_part;

    memcpy(buf, hp_start, size);       /* the pkt completed */

    return SPO_OK;

spo_bad_decide_part:

    t_node = spo_remove_rbt_node(rbt, t_node);
    q_node = (spo_que_node_t * ) t_node->carrier;
    spo_enter_queue(queue, q_node);

    return SPO_OK;
}


static SPO_RET_STATUS spo_analy_decide_out(spo_queue_t *queue, spo_rbtree_t *rbt,
                            const u_char *packet, const u_char *hp_start, size_t pkt_s, int snd_msgid)
{
    spo_analy_t analy;
    spo_rbt_node_t *t_node = NULL;
    spo_que_node_t *q_node = NULL;
    spo_analy_t *t_analy = NULL;
    size_t size = 0;
    u_char *buf = NULL;

    spo_analysts_comp_info(&analy.sm, packet);

    if ((t_node = spo_find_remove_rbt_node(rbt, &analy)) == NULL) return SPO_FAILURE;

    /**
     *
     *  here the hp pkt is we need.
     *  it's domain we need, the hp's method we need.
     *  we send it to msg queue.
     *
     **/

    t_analy = (spo_analy_t *) t_node->key;
    if (spo_unlikely(t_analy == NULL)) return SPO_FAILURE;

    size = pkt_s - (hp_start - packet);
    buf = t_analy->buf + t_analy->pkt_len;

    if ((t_analy->pkt_len += size) > t_analy->buf_size) goto spo_bad_decide;

    memcpy(buf, hp_start, size);       /* the pkt completed */

    spo_analysts_send(t_analy->buf, t_analy->pkt_len, snd_msgid);   /* snd the pkt to hp spoofers */

spo_bad_decide:

    q_node = (spo_que_node_t * ) t_node->carrier;
    spo_enter_queue(queue, q_node);

    return SPO_OK;
}


static SPO_RET_STATUS spo_analy_decide_pkt(const u_char *packet, size_t pkt_s, const u_char *hp_start)
{
    const u_char *ch = packet;

    if (spo_unlikely(packet == NULL || pkt_s == 0)) return SPO_FAILURE;

    ch = ch + pkt_s - 4;

    if (spo_unlikely(hp_start == NULL)) return SPO_FAILURE;

    while (*(hp_start) == 0x20) hp_start++;     /* skip ' ' (0x20) */

    /* is http request start */
    if (memcmp(hp_start, "GET", 3) == 0 || memcmp(hp_start, "POST", 4) == 0 || memcmp(hp_start, "HEAD", 4) == 0) {
        if (*(ch) == 0x0d && *(ch + 1) == 0x0a && *(ch + 2) == 0x0d && *(ch + 3) == 0x0a) {  /* is a completed http head */
            return SPO_HP_HEAD_COMPLETE;
        }else {
            /* the http pkt's head not completed */
            return SPO_HP_HEAD_INTERRUP;
        }
    }else {
        /* here the pkt could the header's Lower half */
        if (*(ch) == 0x0d && *(ch + 1) == 0x0a && *(ch + 2) == 0x0d && *(ch + 3) == 0x0a)
            return SPO_HP_HEAD_HALF;

        return SPO_HP_HEAD_PART;
    }
}


static SPO_RET_STATUS spo_do_analysts(const u_char *packet, size_t pkt_s, int snd_msgid)
{
    const u_char *hp_start = NULL;
    int ret = 0;

    if (spo_unlikely(packet == NULL || pkt_s == 0)) return SPO_FAILURE;

    hp_start = spo_http_start(packet);

    ret = spo_analy_decide_pkt(packet, pkt_s, hp_start);
    if (ret == SPO_HP_HEAD_COMPLETE)
        return spo_analysts_send(packet, pkt_s, snd_msgid);

    if (ret == SPO_HP_HEAD_INTERRUP)
        return spo_analy_decide_in(mtu_que, mtu_rbt, packet, pkt_s);

    if (ret == SPO_HP_HEAD_HALF) /* go to search the rbt */
        return spo_analy_decide_out(mtu_que, mtu_rbt, packet, hp_start, pkt_s, snd_msgid);

    if (ret == SPO_HP_HEAD_PART)
        return spo_analy_decide_part_in(mtu_que, mtu_rbt, packet, hp_start, pkt_s);

    return SPO_FAILURE;
}


static SPO_RET_STATUS spo_analy_build_alarm_cache(spo_queue_t *queue, size_t amt)
{
    size_t i = 0;
    spo_que_node_t *q_node = NULL;

    if (amt <= 0 || queue == NULL) return SPO_FAILURE;

    for (i = 0; i <= amt; i++) {
        if ((q_node = spo_create_queue_node(NULL, NULL)) == NULL) continue;

        spo_enter_queue(queue, q_node);
    }

    return SPO_OK;
}


static SPO_RET_STATUS spo_do_analy_build_cache(spo_queue_t *queue, size_t amt)
{
    size_t i = 0;
    spo_que_node_t *q_node  = NULL;
    spo_rbt_node_t *t_node  = NULL;
    spo_analy_t *analy       = NULL;
    u_char *cache_unit        = NULL;

    if (queue == NULL || amt == 0) return SPO_FAILURE;

    for (i = 0; i < amt; i++) {
        cache_unit = spo_calloc(sizeof(u_char) * SPO_DFT_CACHE_UNIT_SIZE);
        if (cache_unit == NULL) continue;

        if ((analy = spo_create_analy()) == NULL) {
            if (cache_unit != NULL) spo_free(cache_unit);
            continue;
        }

        analy->buf = cache_unit;
        analy->buf_size = sizeof(u_char) * SPO_DFT_CACHE_UNIT_SIZE;

        if ((t_node = spo_create_rbt_node()) == NULL) {
            if (cache_unit != NULL) spo_free(cache_unit);
            if (analy != NULL) spo_free(analy);
            continue;
        }

        t_node->key = analy;

        if ((q_node = spo_create_queue_node(NULL, t_node)) == NULL) {
            if (cache_unit != NULL) spo_free(cache_unit);
            if (analy != NULL) spo_free(analy);
            if (t_node != NULL) spo_free(t_node);
            continue;
        }

        t_node->carrier = q_node;       /* point to rbt node's carrier */
        q_node->data = t_node;

        spo_enter_queue(queue, q_node);
    }

    return SPO_OK;
}


static SPO_RET_STATUS spo_analy_build_cache(size_t cache_size)
{
    spo_rbtree_t *rbt       = NULL;
    spo_queue_t *queue      = NULL;
    size_t amt = 0;

    rbt = spo_create_rbtree(spo_analy_comp_pkt, spo_analy_free_cache_unit, spo_remove_rbt_node);
    if (rbt == NULL) return SPO_FAILURE;

    queue = spo_create_queue(NULL, spo_analy_free_queue_data);
    if (queue == NULL) return SPO_FAILURE;

    alarm_rbt = spo_create_rbtree(spo_analy_comp_pkt, spo_analy_free_cache_unit, spo_remove_rbt_node);
    if (alarm_rbt == NULL) return SPO_FAILURE;

    alarm_que = spo_create_queue(NULL, spo_analy_free_queue_data);
    if (alarm_que == NULL) return SPO_FAILURE;

    amt = spo_cache2buf_amt(cache_size);
    spo_do_analy_build_cache(queue, amt);

    spo_analy_build_alarm_cache(alarm_que, amt / 2 + 1);

    mtu_rbt = rbt;
    mtu_que = queue;

    return SPO_OK;
}


static SPO_RET_STATUS spo_analysts_init_pool(spo_proc_node_t *node)
{
    spo_pool_t *pool = NULL;
    spo_packet_t *pkt = NULL;
    spo_str_t *infos = NULL;
    size_t size = 0;
    spo_log_t *log = NULL;
    int i = 0;

    if (node == NULL) return SPO_FAILURE;

    /* create analysts pool */
    if ((pool = spo_create_pool(SPO_ANALYSTS_POOL_S)) == NULL) return SPO_FAILURE;
    node->pool = pool;

    if ((node->hp_pkt = spo_palloc(pool, node->cfg->global->max_http_pkt_s)) == NULL) return SPO_FAILURE;
    node->hp_pkt->type = SPO_PKT_MSG_TYPE;

    /* init analysts's snd pkt */
    if ((node->snd_pkt = spo_palloc(pool, node->cfg->global->max_http_pkt_s)) == NULL) return SPO_FAILURE;
    node->snd_pkt->type = SPO_PKT_MSG_TYPE;  /* init the hp msg type */

    pkt = (spo_packet_t *) ((char *) (node->snd_pkt->data));
    pkt->len = node->cfg->global->max_http_pkt_s;
    pkt->max_pkts = pkt->len - (sizeof(spo_packet_t) + sizeof(spo_msg_t));

    if ((pkt->pkt_info = spo_palloc(pool, 2 * sizeof(spo_str_t))) == NULL) return SPO_FAILURE;
    pkt->info_amt = 2;

    /* init infos */
    infos = (spo_str_t *) pkt->pkt_info;
    for (i = 0; i < pkt->info_amt; i++) spo_init_str(&infos[i]);

    /* init log and statis */
    size = sizeof(spo_msg_t) + sizeof(spo_log_t) + node->cfg->global->max_log_len;
    if ((node->log = spo_palloc(pool, size)) == NULL) return SPO_FAILURE;

    log = (spo_log_t *) node->log->data;
    log->pid = node->pid;
    log->proc_type = SPO_SNIFFER;
    log->size = size;

    return SPO_OK;
}


static SPO_RET_STATUS spo_analy_init_sig()
{
    sigset_t set;
    memset(&set, '\0', sizeof(sigset_t));

    spo_fill_sigmask(&set);

    spo_del_sig_in_set(SIGUSR1, &set);  //http cfg reload
    spo_del_sig_in_set(SIGUSR2, &set);  //dns cfg reload
    spo_del_sig_in_set(SIGALRM, &set);  //statis

    spo_signal_a_sigset(&set);

    spo_signal_a_sig(SIGUSR1, spo_rld_hp_cfg);
    spo_signal_a_sig(SIGUSR2, spo_rld_hp_cfg_tmp);
    spo_signal_a_sig(SIGALRM, spo_analy_clean);

    return SPO_OK;
}


static SPO_RET_STATUS spo_init_analysts(spo_proc_node_t *node)
{
    if (node == NULL) return SPO_FAILURE;

    spo_analy_init_sig();

    if (spo_analysts_init_pool(node) == SPO_FAILURE) return SPO_FAILURE;

    spo_analy_build_cache(node->cfg->global->analysts_cache);

    return SPO_OK;
}


void spo_analysts(void *proc_infos)
{
    spo_msg_t *msg = NULL;
    spo_proc_node_t *node;
    register u_char *packet = NULL;
    register size_t size = 0;
    int rcv_msgid = current->hp_msgid[1];
    int *snd_msgs = &current->dns_msgid[1];
    uint msg_amt = current->dns_msgid[0] - 1;
    uint counter = 0;
    int ret = 0;

    if (proc_infos != NULL) proc_infos = proc_infos;

    spo_set_proc_titel("analy");

    node = current;
    size = node->cfg->global->max_http_pkt_s;

    if (spo_init_analysts(node) == SPO_FAILURE) return;

    ualarm(alarm_time, alarm_time);

    msg = node->hp_pkt;

    while (1) {
        spo_to_update(node);

        ret = spo_msgrcv(rcv_msgid, msg, size, SPO_PKT_MSG_TYPE, 0);
        if (ret == SPO_FAILURE) continue;

        packet = (u_char *) msg->data;
        spo_do_analysts(packet, ret, snd_msgs[counter]);

        if (++counter > msg_amt) counter = 0;
    }
}
