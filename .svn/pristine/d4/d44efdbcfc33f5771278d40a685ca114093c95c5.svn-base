#ifndef SPO_KERNEL_H
#define SPO_KERNEL_H

#include <sys/types.h>
#include <pthread.h>

/* tree's type */
#define SPO_HTTP_DMN_TREE   (1)
#define SPO_HTTP_DATA_TREE  (2)
#define SPO_DNS_TREE        (4)


/* get container's data */
#define spo_container_data(q, type, link) (type *) \
    ((u_char *) q - offsetof(type, link))


/* comp func */
typedef int (spo_comp_tree_func) (void *, void *);

/* destory tree node key func */
typedef int (spo_free_key_func) (void *);

/* tree's status */
typedef enum spo_bool_e {
    FALSE   = 0,
    TRUE    = 1
}spo_bool_t;


/* string */
typedef struct spo_string_s {
    size_t len;
    u_char *data;
}spo_str_t;

/* a container for spoofer system */
typedef struct spo_container_s {
    struct spo_container_s *prev;
    struct spo_container_s *next;
}spo_cnt_t;


/* record a rbt node */
struct spo_tree_node_s {
    spo_cnt_t link;
    void *key;			//数据
    struct spo_tree_node_s *parent;   /* Reserve */
    int bf;                         /* Balance factor */
};


/* is the rbt header */
struct spo_tree_header_s {
    spo_tree_node_t *root;          /* this tree root */
    spo_tree_node_t *current;       /* the current node, use it to targe */
    spo_comp_tree_func *c;          /* record the comp func, when used to insert a node */
    spo_free_key_func *free_key;    /* uesd to free the tree node's key */
    int rbt_type;                   /* tree type */
    int amonut;                     /* this tree size, node amount */
};

/* init the string */
inline SPO_RET_STATUS spo_init_str(spo_str_t *str);


/*  get the tree node by container. */
inline spo_tree_node_t *spo_cnt_tree_node(spo_cnt_t *cnt);


/* comp strings */
inline SPO_RET_VALUE spo_comp_str(spo_str_t *str, spo_str_t *comp);
inline SPO_RET_STATUS spo_comp_string(spo_str_t *str, const char *string);

/* create and init tree struct */
spo_tree_node_t *spo_create_tree_node();
spo_tree_header_t *spo_create_tree_header();

/* destory tree struct */
SPO_RET_STATUS spo_destory_tree_node(spo_tree_node_t *node, int (*free_node_data) (void *));
void spo_do_destory_tree(spo_cnt_t *node_link, int (*free_node_key_func) (void *));
SPO_RET_STATUS spo_destory_tree(spo_tree_header_t *header, int (*free_node_key) (void *));


/* deep */
SPO_RET_VALUE spo_find_tree_deep(spo_cnt_t *BT);

/* visist */
void spo_visist_http_data(void *data_);
void spo_visist_dns_data(void *data_);
void spo_visist_http_dmn_cfg(void *data_);

void InOrderTraverse(spo_tree_node_t *root, void (*visist_func) (void *));
void PreOrderTraverse(spo_tree_node_t *root, void (*visist_func) (void *));


/* node's key comp func, for match domain */
inline SPO_RET_VALUE spo_comp_http_dmn(void *http_dmn_, void *host);
inline SPO_RET_VALUE spo_comp_http_data_dmn(void *h_data_, void *num_);
inline SPO_RET_VALUE spo_comp_dns_data_dmn(void *d_data_, void *host);
inline SPO_RET_VALUE spo_comp_hp_mtd(void *mtd_, void *mtd_new_);

/* tree node comp func, for insert node */
inline SPO_RET_VALUE spo_comp_http_dmn_node(void *t_node, void *i_node);
inline SPO_RET_VALUE spo_comp_http_data_dmn_node(void *t_node, void *i_node);
inline SPO_RET_VALUE spo_comp_dns_data_dmn_node(void *t_node, void *i_node);

/* build tree */
spo_bool_t spo_insert_AVL(spo_tree_node_t **t,
                          spo_tree_node_t *node, spo_bool_t *taller, int (*comp_func) (void *, void *));

/* serch a tree node in avl tree */
spo_tree_node_t *spo_tree_match(spo_tree_header_t *header, void *data,
                                  int (*comp_func) (void *, void *));



/* - - -- - - - - - -- - - -   rbt module   - - - - -- -- -- - - ---  */


typedef int (spo_comprbt) (void *, void *);
typedef int (spo_rbt_free_key) (void *);

/**
 *
 *  remove the rbt's node
 *  not free the tree's node, just remove the node form the tree.
 *
 * */

typedef int (spo_rm_rbt_node) (void *, void *);


struct spo_rbt_node_s {
    struct spo_rbt_node_s *parent;
    struct spo_rbt_node_s *left;
    struct spo_rbt_node_s *right;
    void *key;
    void *carrier;                      /* load this rbt node' struct, ues to Combine other struct like queue */
    int color;
};

struct spo_rbtree_s {
    struct spo_rbt_node_s *root;
    spo_comprbt *cmp_func;
    spo_rbt_free_key *free_key;
    spo_rm_rbt_node *rm_node;
    struct spo_rbt_node_s nil;
    uint size;
};


SPO_RET_STATUS spo_rbt_size(struct spo_rbtree_s * rbt);
SPO_RET_STATUS spo_insert_rbt_node(struct spo_rbtree_s *rbt, struct spo_rbt_node_s *nd);
struct spo_rbt_node_s *spo_find_rbt_node(struct spo_rbtree_s *rbt, void *key);
struct spo_rbt_node_s *spo_min_rbt_node(struct spo_rbtree_s *rbt);
struct spo_rbt_node_s *spo_create_rbt_node();
struct spo_rbtree_s *spo_create_rbtree(spo_comprbt *cmp_func, void *free_key, void *rm_node);
struct spo_rbt_node_s *spo_remove_rbt_node(struct spo_rbtree_s *rbt, struct spo_rbt_node_s *nd);
struct spo_rbt_node_s *spo_find_remove_rbt_node(struct spo_rbtree_s *rbt, void *key);
SPO_RET_STATUS spo_delete_rbt_node(struct spo_rbtree_s *rbt, struct spo_rbt_node_s *nd);
SPO_RET_STATUS spo_destory_rbt(struct spo_rbtree_s *rbt, spo_rbt_free_key *free_key);



/* - - -- - - - - - -- - - -   queue module   - - - - -- -- -- - - ---  */


typedef int (spo_queue_free_data) (void *);

struct spo_queue_node_s {
    spo_cnt_t link;
    void *data;
    u_char status:2;              /* 1 is busy, 0 is idle */
    u_char flg:6;
};


struct spo_queue_s {
    struct spo_queue_node_s *elements;
    struct spo_queue_node_s *tail;
    spo_queue_free_data *free_nd_data;      /* used to free the node's data */
    void *pool;                             /* this queue's elem alloc in a pool or cache */
    pthread_cond_t cond;                    /* process or thread block in here */
    pthread_mutex_t mutex;                  /* uesd in Multi-process or Multithreading env */
    size_t size;                            /* the size of this queue */
    uint quote_n;                           /* the amount of process or thread to quote this queue */
};


inline struct spo_queue_node_s *spo_cnt_queue_node(spo_cnt_t *cnt);
struct spo_queue_node_s *spo_create_queue_node(spo_pool_t *pool, void *node_data);
struct spo_queue_s *spo_create_queue(spo_pool_t *pool, spo_queue_free_data *free_data);
inline SPO_RET_VALUE spo_queue_size(struct spo_queue_s *queue);
struct spo_queue_node_s *spo_queue_front(struct spo_queue_s *queue);
struct spo_queue_node_s *spo_queue_rear(struct spo_queue_s *queue);
SPO_RET_BOOLEN spo_queue_empty(struct spo_queue_s *queue);
SPO_RET_STATUS spo_enter_queue(struct spo_queue_s *queue, struct spo_queue_node_s *node);
struct spo_queue_node_s *spo_queue_rm_node(struct spo_queue_s *queue);
SPO_RET_STATUS spo_queue_delete_node(struct spo_queue_s *queue);
SPO_RET_STATUS spo_clean_queue(struct spo_queue_s *queue);
SPO_RET_STATUS spo_destory_queue(struct spo_queue_s *queue);

#endif // SPO_KERNEL_H
