#include "../spoofer_system/spoofer.h"
#include "../spoofer_pool/spo_pool.h"
#include "spo_kernel.h"

#define SPO_RBT_RED     (1)
#define SPO_RBT_BLACK   (0)



static void spo_left_rotate(struct spo_rbtree_s *rbt, struct spo_rbt_node_s *node);
static void spo_right_rotate(struct spo_rbtree_s *rbt, struct spo_rbt_node_s *node);
static void spo_insert_fixup(struct spo_rbtree_s *rbt, struct spo_rbt_node_s *nd);
static void spo_delete_fixup(struct spo_rbtree_s *rbt, struct spo_rbt_node_s *nd);
static struct spo_rbt_node_s *spo_rbt_successor(struct spo_rbtree_s *rbt, struct spo_rbt_node_s *nd);
static SPO_RET_STATUS spo_destory_rbt_node(spo_rbt_node_t *node, spo_rbt_free_key *free_key);
static SPO_RET_STATUS spo_free_rbtree(struct spo_rbtree_s *rbt);


/* - -- - - - - -- - - - - - red black tree - - - -- - - - - -- -  */


SPO_RET_STATUS spo_rbt_size(struct spo_rbtree_s * rbt)
{
    if (rbt == NULL) return SPO_OK;

    return rbt->size;
}


static void spo_left_rotate(struct spo_rbtree_s *rbt, struct spo_rbt_node_s *node)
{
    struct spo_rbt_node_s *tmp = node->right;

    node->right = tmp->left;

    if (tmp->left != &rbt->nil)
        tmp->left->parent = node;

    tmp->parent = node->parent;

    if (node->parent == &rbt->nil)
        rbt->root = tmp;
    else if (node == node->parent->left)
        node->parent->left = tmp;
    else
        node->parent->right = tmp;

    tmp->left = node;
    node->parent = tmp;
}


static void spo_right_rotate(struct spo_rbtree_s *rbt, struct spo_rbt_node_s *node)
{
    struct spo_rbt_node_s *tmp = node->left;

    node->left = tmp->right;

    if (tmp->right != &rbt->nil)
        tmp->right->parent = node;

    tmp->parent = node->parent;

    if (node->parent == &rbt->nil)
        rbt->root = tmp;
    else if (node == node->parent->left)
        node->parent->left = tmp;
    else
        node->parent->right = tmp;

    tmp->right = node;
    node->parent = tmp;
}


static void spo_insert_fixup(struct spo_rbtree_s *rbt, struct spo_rbt_node_s *nd)
{
    struct spo_rbt_node_s *tmp;

    while (nd->parent->color == SPO_RBT_RED) {
        if (nd->parent == nd->parent->parent->left) {
            tmp = nd->parent->parent->right;

            if (tmp->color == SPO_RBT_RED) {
                nd->parent->color = tmp->color = SPO_RBT_BLACK;
                nd->parent->parent->color = SPO_RBT_RED;
                nd = nd->parent->parent;
            } else {

                if (nd == nd->parent->right) {
                    nd = nd->parent;
                    spo_left_rotate(rbt, nd);
                }

                nd->parent->color = SPO_RBT_BLACK;
                nd->parent->parent->color = SPO_RBT_RED;
                spo_right_rotate(rbt, nd->parent->parent);
            }
        } else {
            tmp = nd->parent->parent->left;

            if (tmp->color == SPO_RBT_RED) {
                nd->parent->color = tmp->color = SPO_RBT_BLACK;
                nd->parent->parent->color = SPO_RBT_RED;
                nd = nd->parent->parent;
            } else {

                if (nd == nd->parent->left) {
                    nd = nd->parent;
                    spo_right_rotate(rbt, nd);
                }

                nd->parent->color = SPO_RBT_BLACK;
                nd->parent->parent->color = SPO_RBT_RED;
                spo_left_rotate(rbt, nd->parent->parent);
            }
        }
    }

    rbt->root->color = SPO_RBT_BLACK;
}


static void spo_delete_fixup(struct spo_rbtree_s *rbt, struct spo_rbt_node_s *nd)
{
    struct spo_rbt_node_s *tmp = &rbt->nil;

    while (nd != rbt->root && nd->color == SPO_RBT_BLACK)
        if (nd == nd->parent->left) {
            tmp = nd->parent->right;

            if (tmp->color == SPO_RBT_RED) {
                tmp->color = SPO_RBT_BLACK;
                nd->parent->color = SPO_RBT_RED;
                spo_left_rotate(rbt, nd->parent);
                tmp = nd->parent->right;
            }

            if (tmp->left->color == SPO_RBT_BLACK && tmp->right->color == SPO_RBT_BLACK) {
                tmp->color = SPO_RBT_RED;
                nd = nd->parent;
            } else {

                if (tmp->right->color == SPO_RBT_BLACK) {
                    tmp->left->color = SPO_RBT_BLACK;
                    tmp->color = SPO_RBT_RED;
                    spo_right_rotate(rbt, tmp);
                    tmp = nd->parent->right;
                }

                tmp->color = nd->parent->color;
                nd->parent->color = SPO_RBT_BLACK;
                tmp->right->color = SPO_RBT_BLACK;
                spo_left_rotate(rbt, nd->parent);
                nd = rbt->root; /* end while */
            }
        } else {
            tmp = nd->parent->left;

            if (tmp->color == SPO_RBT_RED) {
                tmp->color = SPO_RBT_BLACK;
                nd->parent->color = SPO_RBT_RED;
                spo_right_rotate(rbt, nd->parent);
                tmp = nd->parent->left;
            }

            if (tmp->right->color == SPO_RBT_BLACK && tmp->left->color == SPO_RBT_BLACK) {
                tmp->color = SPO_RBT_RED;
                nd = nd->parent;
            } else {

                if (tmp->left->color == SPO_RBT_BLACK) {
                    tmp->right->color = SPO_RBT_BLACK;
                    tmp->color = SPO_RBT_RED;
                    spo_left_rotate(rbt, tmp);
                    tmp = nd->parent->left;
                }

                tmp->color = nd->parent->color;
                nd->parent->color = SPO_RBT_BLACK;
                tmp->left->color = SPO_RBT_BLACK;
                spo_right_rotate(rbt, nd->parent);
                nd = rbt->root; /* end while */
            }
        }

    nd->color = SPO_RBT_BLACK;
}



/* - - - -- - -- - -- - -  insert and find and create rbt node  -- - - - - - -- - -- */


SPO_RET_STATUS spo_insert_rbt_node(struct spo_rbtree_s *rbt, struct spo_rbt_node_s *nd)
{
    struct spo_rbt_node_s *tmp = &rbt->nil, *itor = rbt->root;

    if (nd == NULL) return SPO_FAILURE;

    while (itor != &rbt->nil) {
        tmp = itor;
        if ((rbt->cmp_func) (itor->key, nd->key) > 0)
            itor = itor->left;
        else
            itor = itor->right;
    }

    nd->parent = tmp;

    if (tmp == &rbt->nil)
        rbt->root = nd;
    else {
        if ((rbt->cmp_func) (tmp->key, nd->key) > 0)
            tmp->left = nd;
        else
            tmp->right = nd;
    }

    nd->left = nd->right = &rbt->nil;
    nd->color = SPO_RBT_RED;
    spo_insert_fixup(rbt, nd);
    rbt->size++;

    return SPO_OK;
}


/**
 *
 *  find_node and delete_node are not safe
 *
 *  delete node may return NULL.
 *
 * */

struct spo_rbt_node_s *spo_find_rbt_node(struct spo_rbtree_s *rbt, void *key)
{
    struct spo_rbt_node_s *nd = &rbt->nil;
    int ret = 0;
    nd = rbt->root;

    while (nd != &rbt->nil) {
        ret = (rbt->cmp_func) (nd->key, key);
        if (ret > 0) {
            nd = nd->left;
            continue;
        }

        if (ret < 0) {
            nd = nd->right;
            continue;
        }

        if (ret == 0) return nd;
    }

    return NULL;
}


struct spo_rbt_node_s *spo_min_rbt_node(struct spo_rbtree_s *rbt)
{
    struct spo_rbt_node_s *tmp, *ret;

    tmp = rbt->root;
    ret = &rbt->nil;

    if (tmp == &rbt->nil) return NULL;

    while (tmp != &rbt->nil) {
        ret = tmp;
        tmp = tmp->left;
    }

    if (ret == &rbt->nil) return NULL;

    return ret;
}


struct spo_rbt_node_s *spo_create_rbt_node()
{
    struct spo_rbt_node_s *node = NULL;

    if ((node = spo_calloc(sizeof(struct spo_rbt_node_s))) == NULL) return NULL;

    node->carrier   = NULL;
    node->color     = SPO_RBT_BLACK;
    node->key       = NULL;
    node->left      = NULL;
    node->right     = NULL;
    node->parent    = NULL;

    return node;
}


struct spo_rbtree_s *spo_create_rbtree(spo_comprbt *cmp_func, void *free_key, void *rm_node)
{
    struct spo_rbtree_s *rbt = spo_calloc(sizeof(struct spo_rbtree_s));
    if (rbt == NULL) return NULL;

    rbt->cmp_func   = cmp_func;
    rbt->size       = 0;
    rbt->free_key   = free_key;
    rbt->rm_node    = rm_node;
    rbt->nil.parent = &(rbt->nil);
    rbt->nil.left   = &(rbt->nil);
    rbt->nil.right  = &(rbt->nil);
    rbt->nil.color  = SPO_RBT_BLACK;
    rbt->nil.key    = NULL;
    rbt->root       = &rbt->nil;

    return rbt;
}


/* - - - -- - -- - - - -- - -  remove and destory rbt node -- - - - - - - -- - -- */


static struct spo_rbt_node_s *spo_rbt_successor(struct spo_rbtree_s *rbt, struct spo_rbt_node_s *nd)
{
    struct spo_rbt_node_s *min = &rbt->nil;

    if (nd->right != &rbt->nil) {
        min = nd->right;

        while (min->left != &rbt->nil)
            min = min->left;

        return min;
    }

    min = nd->parent;

    while ((min != &rbt->nil) && (nd == min->right)) {
        nd = min;
        min = min->parent;
    }

    return min;
}


/**
 *
 *  free node, return val
 *
 * */

struct spo_rbt_node_s *spo_remove_rbt_node(struct spo_rbtree_s *rbt, struct spo_rbt_node_s *nd)
{
    void *key = NULL;
    struct spo_rbt_node_s *tmp, *itor;

    if (nd == NULL || rbt == NULL) return NULL;

    key = nd->key;

    if (nd->left == &rbt->nil || nd->right == &rbt->nil)
        tmp = nd;
    else
        tmp = spo_rbt_successor(rbt, nd);

    if (tmp->left != &rbt->nil)
        itor = tmp->left;
    else
        itor = tmp->right;

    itor->parent = tmp->parent;

    if (tmp->parent == &rbt->nil)
        rbt->root = itor;
    else {
        if (tmp == tmp->parent->left)
            tmp->parent->left = itor;
        else
            tmp->parent->right = itor;
    }

    if (tmp != itor) nd->key = tmp->key;
    if (tmp->color == SPO_RBT_BLACK) spo_delete_fixup(rbt, itor);

    rbt->size--;
    tmp->key = key;

    tmp->left = tmp->right = tmp->parent = NULL;

    return tmp;
}


struct spo_rbt_node_s *spo_find_remove_rbt_node(struct spo_rbtree_s *rbt, void *key)
{
    struct spo_rbt_node_s *node = NULL;

    if (rbt == NULL || key == NULL) return NULL;

    if ((node = spo_find_rbt_node(rbt, key)) == NULL) return NULL;

    return spo_remove_rbt_node(rbt, node);
}


static SPO_RET_STATUS spo_destory_rbt_node(spo_rbt_node_t *node, spo_rbt_free_key *free_key)
{
    if (node == NULL) return SPO_OK;

    if (node->key != NULL) free_key(node->key);

    spo_free(node);

    return SPO_OK;
}


SPO_RET_STATUS spo_delete_rbt_node(struct spo_rbtree_s *rbt, struct spo_rbt_node_s *nd)
{
    if ((nd = spo_remove_rbt_node(rbt, nd)) == NULL) return SPO_OK;

    spo_destory_rbt_node(nd, rbt->free_key);

    return SPO_OK;
}


/* - - - -- - -- -- - - - -- - -  destory rbt  -- - - - -- - - - -- - - - -- - -- */


static SPO_RET_STATUS spo_free_rbtree(struct spo_rbtree_s *rbt)
{
    if (spo_rbt_size(rbt) > 0) return SPO_FAILURE;

    spo_free(rbt);

    return SPO_OK;
}


SPO_RET_STATUS spo_destory_rbt(struct spo_rbtree_s *rbt, spo_rbt_free_key *free_key)
{
    if (rbt == NULL) return SPO_OK;

    free_key = free_key;

    /* find all node and free_key it */

    spo_free_rbtree(rbt);

    return SPO_OK;
}
