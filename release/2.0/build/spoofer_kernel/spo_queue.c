#include "../spoofer_system/spoofer.h"
#include "../spoofer_pool/spo_pool.h"
#include "spo_kernel.h"



static SPO_RET_STATUS spo_init_queue_node(struct spo_queue_node_s *node, void *node_data, u_char flg);
static SPO_RET_STATUS spo_init_queue(struct spo_queue_s *queue, spo_pool_t *pool, spo_queue_free_data *free_data);
static SPO_RET_STATUS spo_queue_destory_node(struct spo_queue_node_s *node, spo_queue_free_data *free_data);


/**
 *
 *  get the queue node by container.
 *
 * */

inline struct spo_queue_node_s *spo_cnt_queue_node(spo_cnt_t *cnt)
{
    struct spo_queue_node_s *node = NULL;

    if (cnt == NULL) return NULL;

    node = (struct spo_queue_node_s *) spo_container_data(cnt, spo_que_node_t, link);

    return node;
}


static SPO_RET_STATUS spo_init_queue_node(struct spo_queue_node_s *node, void *node_data, u_char flg)
{
    if (node == NULL) return SPO_FAILURE;

    node->data      = node_data;
    node->link.next = NULL;
    node->link.prev = NULL;
    node->status    = 0;        /* 0 is idle, 1 is busy */
    node->flg       = flg;      /* 1 , this node alloc in pool */

    return SPO_OK;
}


struct spo_queue_node_s *spo_create_queue_node(spo_pool_t *pool, void *node_data)
{
    struct spo_queue_node_s *node = NULL;
    u_char flg = 0;

    if (pool == NULL) {
        if ((node = spo_calloc(sizeof(struct spo_queue_node_s))) == NULL) return NULL;
    }else {
        if ((node = spo_palloc(pool, sizeof(struct spo_queue_node_s))) == NULL) return NULL;
        flg = SPO_ALLOC_IN_POOL;
    }

    spo_init_queue_node(node, node_data, flg);

    return node;
}


static SPO_RET_STATUS spo_init_queue(struct spo_queue_s *queue, spo_pool_t *pool, spo_queue_free_data *free_data)
{
    if (queue == NULL) return SPO_FAILURE;

    queue->free_nd_data = free_data;
    queue->elements     = NULL;
    queue->pool         = pool;
    queue->quote_n      = 1;
    queue->size         = 0;
    queue->tail         = NULL;

    pthread_mutex_init(&queue->mutex, NULL);
    pthread_cond_init(&queue->cond, NULL);

    return SPO_OK;
}


struct spo_queue_s *spo_create_queue(spo_pool_t *pool, spo_queue_free_data *free_data)
{
    struct spo_queue_s *queue = NULL;

    if (pool == NULL) {
        if ((queue = spo_calloc(sizeof(struct spo_queue_s))) == NULL) return NULL;
    }else {
        if ((queue = spo_palloc(pool, sizeof(struct spo_queue_s))) == NULL) return NULL;
    }

    spo_init_queue(queue, pool, free_data);

    return queue;
}


inline SPO_RET_VALUE spo_queue_size(struct spo_queue_s *queue)
{
    if (queue == NULL) return SPO_FAILURE;

    return queue->size;
}


struct spo_queue_node_s *spo_queue_front(struct spo_queue_s *queue)
{
    if (queue == NULL) return NULL;

    return queue->elements;
}


struct spo_queue_node_s *spo_queue_rear(struct spo_queue_s *queue)
{
    if (queue == NULL) return NULL;

    return queue->tail;
}


SPO_RET_BOOLEN spo_queue_empty(struct spo_queue_s *queue)
{
    if (queue->size <= 0 || queue->elements == NULL) return SPO_TRUE;

    return SPO_FALSE;
}


SPO_RET_STATUS spo_enter_queue(struct spo_queue_s *queue, struct spo_queue_node_s *node)
{
    if (queue == NULL || node == NULL) return SPO_FAILURE;

    if (queue->size == 0 && queue->elements == NULL) {
        queue->elements = node;
        queue->tail = node;
        node->link.next = node->link.prev = NULL;
    }else {
        queue->tail->link.next = &node->link;
        node->link.prev = &queue->tail->link;
        node->link.next = NULL;
        queue->tail = node;
    }

    queue->size++;

    return SPO_OK;
}


struct spo_queue_node_s *spo_queue_rm_node(struct spo_queue_s *queue)
{
    struct spo_queue_node_s *node = NULL;

    if (queue == NULL || queue->elements == NULL || queue->size == 0) return NULL;

    node = queue->elements;

    if (queue->tail == queue->elements) {       /* the queue just one element */
        queue->tail = queue->elements = NULL;
    }else {
        /* here the queue more than one, so queue->elements never be NULL */
        queue->elements = spo_cnt_queue_node(node->link.next);
        queue->elements->link.prev = NULL;
    }

    node->link.prev = node->link.next = NULL;
    queue->size--;

    return node;
}


static SPO_RET_STATUS spo_queue_destory_node(struct spo_queue_node_s *node, spo_queue_free_data *free_data)
{
    if (node == NULL) return SPO_OK;

    if (free_data != NULL || node->data != NULL) free_data(node->data);

    if (node->flg == SPO_ALLOC_IN_POOL) return SPO_OK;

    spo_free(node);

    return SPO_OK;
}


SPO_RET_STATUS spo_queue_delete_node(struct spo_queue_s *queue)
{
    struct spo_queue_node_s *node = NULL;

    if (queue == NULL || queue->elements == NULL) return SPO_FAILURE;

    if ((node = spo_queue_rm_node(queue)) == NULL) return SPO_FAILURE;

    spo_queue_destory_node(node, queue->free_nd_data);

    return SPO_OK;
}


SPO_RET_STATUS spo_clean_queue(struct spo_queue_s *queue)
{
    struct spo_queue_node_s *node = NULL;

    if (queue == NULL || queue->elements == NULL) return SPO_OK;

    node = spo_queue_rm_node(queue);

    while (node != NULL) {
        spo_queue_destory_node(node, queue->free_nd_data);
        node = spo_queue_rm_node(queue);
    }

    queue->elements = queue->tail = NULL;
    queue->size = 0;

    return SPO_OK;
}


SPO_RET_STATUS spo_destory_queue(struct spo_queue_s *queue)
{
    if (queue == NULL) return SPO_OK;

    if (--queue->quote_n == 0) {
        spo_clean_queue(queue);
        if (queue->pool == NULL) spo_free(queue);
    }

    return SPO_OK;
}
