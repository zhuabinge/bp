#include "../spoofer_system/spoofer.h"
#include "../spoofer_config/spo_config.h"
#include "../spoofer_pool/spo_pool.h"
#include "../spoofer_linux/spo_linux.h"
#include "../spoofer_test/spo_test.h"
#include "../spoofer_sniffer/spo_sniffer.h"
#include "../spoofer_sender/spo_sender.h"
#include "../spoofer_system/spo_system.h"



void spo_str_printf(spo_str_t *str, int type)
{
    size_t i = 0;

    if (str == NULL || str->data == NULL) return;

    if (type == 0) {
        for (i = 0; i < str->len; i++) {
            printf("%02x ", *(str->data + i));
        }
    }else {
        for (i = 0; i < str->len; i++) {
            printf("%c", *(str->data + i));
        }
    }

    printf("\n");
}


void spo_test_cfg_g(spo_cfg_t *cfg)
{
    int i = 0;
    printf("max dns pkt %ld\n", cfg->global->max_dns_pkt_s);
    printf("max http pkt %ld\n", cfg->global->max_http_pkt_s);
    printf("max send size %ld\n", cfg->global->max_send_size);
    printf("max log len %ld\n", cfg->global->max_log_len);
    printf("dns data path --%s--\n", cfg->global->d_data_path);
    printf("http dmn cfg file --%s--\n", cfg->global->h_dmn_cfg_file);
    printf("http data path --%s--\n", cfg->global->h_data_path);

    spo_info_t *info = NULL;
    info = cfg->inf_header.infos;
    while (info != NULL) {
        printf("dev --%s--\n", info->dev);
        printf("filter --%s--\n", info->filter);
        printf("useing lib --%s--\n", info->lib);
        printf("proc type --%s--\n", info->type);
        printf("cpu id %d\n", info->cpuid);

        if (info->h_msgid != NULL) {
            printf("hp msgid amount %d\n", info->h_msgid[0]);

            for (i = 1; i <= info->h_msgid[0]; i++) {
                printf("msgid    %d\n", info->h_msgid[i]);
            }
        }

        if (info->d_msgid != NULL) {
            printf("\ndns msgid amount %d\n", info->d_msgid[0]);
            for (i = 1; i <= info->d_msgid[0]; i++) {
                printf("msgid    %d\n", info->d_msgid[i]);
            }
        }

        printf("\n\n next ----\n");
        info = info->next;
    }


    spo_analy_info_t *analy_info = cfg->global->analy_hd->infos;
    spo_analy_info_t *p = analy_info;

    printf("the analysts amount is %d\n", cfg->global->analy_hd->amt);

    while (p != NULL) {

        printf("analy dev --%s--\n", p->dev);
        for (i = 1; i <= p->hp_msgid[0]; i++) {
            printf("%d\n", p->hp_msgid[i]);
        }

        p = p->next;
        printf("+++++++++++++++\n");
    }
}


SPO_RET_STATUS spo_test_insert_tree_queue(spo_tree_header_t *header, spo_tree_node_t *node)
{
    if (header->root == NULL) header->root = node;
    else {
        node->link.next = &header->root->link;
        header->root = node;
    }

    return SPO_OK;
}


static SPO_RET_BOOLEN spo_test_comp_dmn(spo_str_t *dmn, spo_str_t *host)
{
    if (dmn == NULL || dmn->data == NULL || host == NULL || host->data == NULL)
        return SPO_FALSE;

    if (dmn->len == host->len)
        if (memcmp(dmn->data, host->data, dmn->len) == 0)  return SPO_TRUE;

    return SPO_FALSE;
}



SPO_RET_BOOLEN spo_test_comp_http_dmn(spo_tree_node_t *node, spo_str_t *host)
{
    spo_hp_dmn_t *http_dmn = (spo_hp_dmn_t *) node->key;
    return spo_test_comp_dmn((spo_str_t *)&http_dmn->dmn, host);
}

SPO_RET_BOOLEN spo_test_comp_http_data_dmn(spo_tree_node_t *node, spo_str_t *host)
{
    spo_hp_data_t *data = (spo_hp_data_t *) node->key;
    return spo_test_comp_dmn((spo_str_t *) &data->dmn, host);
}


SPO_RET_BOOLEN spo_test_comp_dns_data_dmn(spo_tree_node_t *node, spo_str_t *host)
{
    spo_dns_data_t *data = (spo_dns_data_t *) node->key;
    return spo_test_comp_dmn((spo_str_t *) &data->dmn, host);
}


spo_tree_node_t *spo_search_node_by_host(spo_tree_header_t *header, spo_str_t *host,
                                         int (*comp_func) (spo_tree_node_t *, spo_str_t *))
{
    spo_tree_node_t *node = NULL;
    spo_cnt_t *p = &header->root->link;

    while (p != NULL) {
        node = spo_container_data(p, spo_tree_node_t, link);
        if (comp_func(node, host) ==  SPO_TRUE) return node;

        p = p->next;
    }

    return NULL;
}


static SPO_RET_STATUS spo_test_http_cfg_line(spo_hp_line_t *cfg_line)
{
    cfg_line = cfg_line;

    return SPO_OK;
}


void spo_test_http_dmn_cfg(spo_hp_dmn_t *dmn)
{
    printf("domain name --%s--\n", dmn->dmn.data);
    printf("domain name len %d\n", (int)dmn->dmn.len);

    spo_hp_line_t *line = dmn->cfg_line;

    while (line != NULL) {
        spo_test_http_cfg_line(line);
        line = line->next;
    }

    printf("\n\n");
}


void spo_test_dmn_cfg(spo_dmn_t *dmn)
{
    spo_cnt_t *p = NULL;
    spo_tree_node_t *node = NULL;

    p = &dmn->dmn->root->link;

    while (p != NULL) {
        node = spo_container_data(p, spo_tree_node_t, link);
        spo_hp_dmn_t *h_dmn = (spo_hp_dmn_t *) node->key;
        spo_test_http_dmn_cfg(h_dmn);
        p = p->next;
    }
}


SPO_RET_STATUS spo_test_dns_data(void *data_)
{
    if (data_ == NULL) {
        printf("dns data is null\n");
        return SPO_FAILURE;
    }

    spo_dns_data_t *data = (spo_dns_data_t *) data_;
    printf("dmn len -- %d\n", (int)data->dmn.len);
    printf("dmn name --%s--\n", data->dmn.data);
        size_t i = 0;
    for (i = 0; i < data->dmn.len; i++) {
        printf("%02x ", *(data->dmn.data + i));
    }
    printf("\n");

    printf("data len %d\n", (int)data->data.len);
    printf("data dataq --%s--\n", data->data.data);

    return SPO_OK;
}


SPO_RET_STATUS spo_test_http_data(void *data_)
{
    if (data_ == NULL) {
        printf("http data is null\n");
        return SPO_FAILURE;
    }

    spo_hp_data_t *data = (spo_hp_data_t *) data_;

    printf("dmn len -- %d\n", (int)data->dmn.len);
    printf("dmn name --%s--\n", data->dmn.data);

    printf("data len %d\n", (int)data->data.len);
    printf("data dataq --%s--\n", data->data.data);

    printf("num -- %d\n", data->num);

    return SPO_OK;
}


/* ---------  test for search module ---------- */

void spo_test_http_data_search()
{
/* test http domain data */
    spo_tree_header_t *header = spo_load_http_data_cfg("http_domain_data");
    PreOrderTraverse(header->root, spo_visist_http_data);
    printf("deep %d\n", spo_find_tree_deep(&header->root->link));
    int num = 0;
    while (1) {
        printf("input a num to find the data\n");
        scanf("%d", &num);
        printf("input num is %d\n", num);
        if (num == -1) break;
        spo_tree_node_t *node = spo_tree_match(header, &num, spo_comp_http_data_dmn);
        if (node == NULL) printf("no match\n");
        else {
            printf("------- the node data is ------\n");
            spo_visist_http_data(node->key);
            printf("------\n\n");
        }
    }
}


void spo_test_http_dmn_search()
{
    /* test http cfg dmn */
    spo_dmn_t *dmn_cfg = (spo_dmn_t *)spo_load_http_dmn_cfg("http_dmn_config");
    spo_tree_header_t *header = dmn_cfg->dmn;
    spo_str_t str;
    char domain[64] = {'\0'};

    printf("\n\n");
    PreOrderTraverse(header->root, spo_visist_http_dmn_cfg);
    printf("------\n\n");
    InOrderTraverse(header->root, spo_visist_http_dmn_cfg);
    printf("deep %d\n", spo_find_tree_deep(&header->root->link));

    while (1) {
        printf("input a http domain to find the data\n");
        scanf("%s", domain);
        printf("the input domain is --%s--\n", domain);
        if (memcmp(domain, "exit", 4) == 0) break;

        str.data = (u_char *)domain;
        str.len = strlen(domain);

        spo_tree_node_t *node = spo_tree_match(header, &str, spo_comp_http_dmn);
        if (node == NULL) printf("no match\n");
        else {
            printf("------- the node data is ------\n");
            spo_visist_http_dmn_cfg(node->key);
            printf("------\n\n");
        }

        memset(domain, '\0', 64);
    }
}


void spo_test_dns_data_search()
{
    spo_str_t str;
    char domain[64] = {'\0'};

    /* tets dns data cfg */
    spo_tree_header_t *header = spo_load_dns_data_cfg("dns_domain_data");
    PreOrderTraverse(header->root, spo_visist_dns_data);
    printf("deep %d\n", spo_find_tree_deep(&header->root->link));

    spo_destory_tree(header, spo_destory_dns_data);
    printf("destory success\n");

    return;

    while (1) {
        printf("input a dns domain to find the data\n");
        scanf("%s", domain);
        printf("the input domain is --%s--\n", domain);

        if (memcmp(domain, "exit", 4) == 0) break;

        str.data = (u_char *)domain;
        str.len = strlen(domain);

        spo_tree_node_t *node = spo_tree_match(header, &str, spo_comp_dns_data_dmn);
        if (node == NULL) printf("no match\n");
        else {
            printf("------- the node data is ------\n");
            spo_visist_dns_data(node->key);
            printf("------\n\n");
        }

        memset(domain, '\0', 64);
    }
}


void spo_printf_mtd(void *mtd_)
{
    spo_str_t *mtd = (spo_str_t *) mtd_;

    printf("--%s-- %d\n", mtd->data, (int) mtd->len);
}


void spo_test_prog_cfg()
{
    /* test program cfg */
    spo_cfg_t *cfg = (spo_cfg_t *)spo_load_prog_cfg("config");
    spo_test_cfg_g(cfg);

    InOrderTraverse(cfg->global->hp_mtd->root, spo_printf_mtd);
}


void spo_test_sys()
{

//    char *set_cok = "Cookies: BDSVRTM=130; path=/BD_HOME=1;"
//    " path=/H_PS_PSSID=6255_10162_1432_10624_10572_10490_10213_10501_10496_10510_"
//    "10647_10052_10459_10065_10218_10687_9392_10356_10666_10096_10658_10442_10403_9950_10688_10627;"
//    " path=/; domain=.baidu.com\r\n"
//    "Host: www.baidu.com\r\n\r\n";

//    int i = 0;

//    for (i = 0; i < strlen(set_cok); i++) {
//        printf("%2x ", *(set_cok + i));
//    }
//    printf("\n");


    int fd;
    int ret = 0;
    int i = 0;

//    fd = spo_open("/home/lele/fork", O_CREAT | O_RDWR, 0666);

//    if (fd == SPO_FAILURE) {
//        perror("2\n");
//    }

//    int ret = spo_write(fd, set_cok, strlen(set_cok));
//    if (ret == SPO_FAILURE) {
//        printf("fail\n");
//        perror(":");
//    }

//    spo_close(fd);
    fd = spo_open("/home/lele/9@yhd.com_301", O_CREAT | O_RDWR, 0666);

    char buf[600];
    memset(buf, '\0', 600);

    ret = spo_read(fd, buf, 600);
    printf("ret %d\n", ret);

    for (i = 0; i < ret; i++) {
        printf("%02x ", buf[i]);
    }
    printf("---\n\n");


    /* test load all config */
    //spo_test_http_data_search();

    //spo_test_http_dmn_search();

    //spo_test_dns_data_search();

    //spo_test_prog_cfg();
}




void spo_test_snif_proc(void *v)
{
    v = v;

    printf("i am sniffer , my pid is %d\n", getpid());

    while (1) {
        sleep(1);
    }

    return;
}



void spo_test_hp_spof_proc(void *v)
{
    v = v;

    printf("i am http spoofer , my pid is %d\n", getpid());

    while (1) {
        sleep(1);
    }

    return;
}


void spo_test_dns_spof_proc(void *v)
{
    v = v;

    //printf("i am dns spoofer , my pid is %d\n", getpid());

    while (1) {
        sleep(1);
    }

    return;
}


void spo_test_snd_proc(void *v)
{
    v = v;

    //printf("i am  sender , my pid is %d\n", getpid());

    while (1) {
        sleep(1);
    }

    return;
}

//void spo_test_log_proc(void *v)
//{
//    if (v == NULL) printf("log v is NULL\n");

//    //printf("i am  loger , my pid is %d\n", getpid());

//    while (1) {
//        sleep(1);
//    }

//    return;
//}


/* - - -- - -- - - -- - - -- --  test rbt  - -- - - -- - -- - -- - - -- - - - -- -  */


static int spo_test_comp_rbt(void *old_, void *i_node_)
{
    int old = *((int *) old_);
    int node = *((int *) i_node_);

    if (old == node) return 0;
    else {
        if (old > node) return 1;
        return -1;
    }
}


int spo_test_free_queue_data(void *data_)
{
    printf("the delete data is --%s--\n", (char *) data_);

    spo_free(data_);

    return SPO_OK;
}


void clean_rbt_2(spo_rbtree_t *rbt)
{
    spo_queue_t *queue = NULL;
    spo_rbt_node_t *t_node = NULL;
    spo_que_node_t *q_node = NULL;
    int i = 0;

    queue = spo_create_queue(NULL, spo_test_free_queue_data);

    q_node = spo_create_queue_node(NULL, (void *) rbt->root);

    spo_enter_queue(queue, q_node);

    while (!spo_queue_empty(queue)) {
        q_node = spo_queue_rm_node(queue);
        t_node = q_node->data;

        spo_free(q_node);
        q_node = NULL;

        int data = *((int *) t_node->key);
        printf("%-3d ", data);

        i++;
        if (i % 16 == 0) {
            printf("\n");
        }

        if (t_node->left != &rbt->nil) {
            q_node = spo_create_queue_node(NULL, (void *) t_node->left);
            spo_enter_queue(queue, q_node);
        }

        if (t_node->right != &rbt->nil) {
            q_node = spo_create_queue_node(NULL, (void *) t_node->right);
            spo_enter_queue(queue, q_node);
        }
    }

    printf("\n\n");
}


void clean_rbt(spo_rbtree_t *rbt)
{
    spo_queue_t *queue = NULL;
    spo_rbt_node_t *t_node = NULL;
    spo_que_node_t *q_node = NULL;
    spo_rbtree_t *active_rbt = NULL;
    int i = 0;

    active_rbt = spo_create_rbtree(spo_test_comp_rbt, NULL, NULL);

    queue = spo_create_queue(NULL, spo_test_free_queue_data);

    q_node = spo_create_queue_node(NULL, (void *) rbt->root);

    spo_enter_queue(queue, q_node);

    while (!spo_queue_empty(queue)) {
        q_node = spo_queue_rm_node(queue);
        t_node = q_node->data;

        spo_free(q_node);
        q_node = NULL;

        int data = *((int *) t_node->key);
        printf("%-3d ", data);

        i++;
        if (i % 16 == 0) {
            printf("\n");
        }

        if (t_node->left != &rbt->nil) {
            q_node = spo_create_queue_node(NULL, (void *) t_node->left);
            spo_enter_queue(queue, q_node);
        }

        if (t_node->right != &rbt->nil) {
            q_node = spo_create_queue_node(NULL, (void *) t_node->right);
            spo_enter_queue(queue, q_node);
        }

        if (data % 2 == 0 || data == 33 || data == 21 || data == 41 || data == 47) {
            t_node->parent = t_node->left = t_node->right = NULL;
            spo_insert_rbt_node(active_rbt, t_node);
        }
    }

    printf("\n\n");
    printf("-------------------------------\n");

    clean_rbt_2(active_rbt);
}


void spo_test_rbt()
{
    int i = 0;
    int *key = NULL;
    struct spo_rbt_node_s *node = NULL;

    struct spo_rbtree_s * header = spo_create_rbtree(spo_test_comp_rbt, NULL, NULL);
    if (header == NULL) return;

    for (i = 0; i < 0; i++) {
        node = malloc(sizeof(struct spo_rbt_node_s));
        if (node == NULL) continue;

        key = malloc(sizeof(int));
        if (key == NULL) continue;

        *((int *) key) = i;

        node->key = key;
        node->color = -1;
        node->left = NULL;
        node->parent = NULL;
        node->right = NULL;

        spo_insert_rbt_node(header, node);
    }

//    for (i = 0; i < 8; i++) {
//        node = spo_find_rbt_node(header, &i);
//        if (node == NULL) {
//            printf("not find i is %d\n", i);
//        }
//    }

    clean_rbt(header);

    printf("finished\n");
}


/* -- --- -- -- -- -- - - --- --  test queue  --- -- -- -- -- -- -- - -- - --- - */



void spo_printf_queue_elem(struct spo_queue_s *queue, void (*queue_visit) (void *data))
{
    struct spo_queue_node_s *node = NULL;

    if (queue == NULL || queue->elements == NULL) return;

    node = queue->elements;

    while (node != NULL) {
        queue_visit(node->data);
        node = spo_cnt_queue_node(node->link.next);
    }

    printf("\n");
    node = queue->tail;

    while (node != NULL) {
        queue_visit(node->data);
        node = spo_cnt_queue_node(node->link.prev);
    }
    printf("\n\n");
}


void spo_test_printf_queue_data(void *data_)
{
    char *data = data_;

    printf("--%s--  ", data);
}





void spo_test_queue()
{
    struct spo_queue_node_s *node = NULL;
    struct spo_queue_s *queue = NULL;
    char *data = NULL;
    int i = 0;

    queue = spo_create_queue(NULL, spo_test_free_queue_data);

    if (queue == NULL) return;

    for (i = 0; i < 6; i++) {
        if ((data = spo_calloc(sizeof(char) * 4)) == NULL) return;

        memset(data, 'A', 3);
        data[0] = 'a' + i;

        node = spo_create_queue_node(NULL, data);

        if (node == NULL) return;

        spo_enter_queue(queue, node);

        spo_printf_queue_elem(queue, spo_test_printf_queue_data);

        printf("\n");
    }

    printf("queue size %d\n", (int) queue->size);
    printf("----------------- ----------------- \n\n");

    for (i = 0; i < 5; i++) {
        node = spo_queue_rm_node(queue);
        spo_test_printf_queue_data(node->data);
        printf("\n");
        spo_printf_queue_elem(queue, spo_test_printf_queue_data);
        spo_enter_queue(queue, node);
        spo_printf_queue_elem(queue, spo_test_printf_queue_data);
    }

    spo_destory_queue(queue);

    printf("\n");
}
