#include "hash_mem.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "opmem.h"

#define MIN_NODES       16
#define UP_LOAD         (2*LH_LOAD_MULT) /* load times 256 (default 2) */
#define DOWN_LOAD       (LH_LOAD_MULT) /* load times 256 (default 1) */

#define LH_LOAD_MULT    256

struct op_hash_node_st {
	void *data;
	struct op_hash_node_st *next;
};

struct op_hash_st {
	struct op_hash_node_st **b;
	int (*comp) (const void *, const void *);

	unsigned long (*hash) (const void *);
	unsigned int num_nodes;
	unsigned int num_alloc_nodes;
	unsigned int p;
	unsigned int pmax;
	unsigned long up_load;      /* load times 256 */
	unsigned long down_load;    /* load times 256 */
	unsigned long num_items;
	unsigned long num_expands;
	unsigned long num_expand_reallocs;
	unsigned long num_contracts;
	unsigned long num_contract_reallocs;
	unsigned long num_hash_calls;
	unsigned long num_comp_calls;
	unsigned long num_insert;
	unsigned long num_replace;
	unsigned long num_delete;
	unsigned long num_no_delete;
	unsigned long num_retrieve;
	unsigned long num_retrieve_miss;
	unsigned long num_hash_comps;
	int error;
};

static int expand(struct op_hash_st *lh);
static void contract(struct op_hash_st *lh);
static struct op_hash_node_st **getrn(struct op_hash_st *lh, const void *data, unsigned long *rhash);

void *op_hash_mem_new(unsigned long (*hash) (const void *), int (*compare) (const void *, const void *))
{
    struct op_hash_st *ret;
    int i;

	if (hash == NULL || compare == NULL) {
		return NULL;
	}

    if ((ret = op_calloc(1, sizeof(struct op_hash_st))) == NULL)
        goto err0;
    if ((ret->b = op_calloc(1, sizeof(struct op_hash_node_st *) * MIN_NODES)) == NULL)
        goto err1;
    for (i = 0; i < MIN_NODES; i++)
        ret->b[i] = NULL;
    ret->comp = compare;
    ret->hash = hash;
    ret->num_nodes = MIN_NODES / 2;
    ret->num_alloc_nodes = MIN_NODES;
    ret->p = 0;
    ret->pmax = MIN_NODES / 2;
    ret->up_load = UP_LOAD;
    ret->down_load = DOWN_LOAD;
    ret->num_items = 0;

    ret->num_expands = 0;
    ret->num_expand_reallocs = 0;
    ret->num_contracts = 0;
    ret->num_contract_reallocs = 0;
    ret->num_hash_calls = 0;
    ret->num_comp_calls = 0;
    ret->num_insert = 0;
    ret->num_replace = 0;
    ret->num_delete = 0;
    ret->num_no_delete = 0;
    ret->num_retrieve = 0;
    ret->num_retrieve_miss = 0;
    ret->num_hash_comps = 0;

    ret->error = 0;
    return (ret);
 err1:
    op_free(ret);
 err0:
    return (NULL);
}

void op_hash_mem_free(void *h)
{
    unsigned int i;
    struct op_hash_node_st *n, *nn;
	struct op_hash_st *lh = (struct op_hash_st *)h;

    if (lh == NULL)
        return;

    for (i = 0; i < lh->num_nodes; i++) {
        n = lh->b[i];
        while (n != NULL) {
            nn = n->next;
            op_free(n);
            n = nn;
        }
    }
    op_free(lh->b);
    op_free(lh);
}

void *op_hash_mem_insert(void *h, void *data)
{
    unsigned long hash;
    struct op_hash_node_st *nn, **rn;
    void *ret;
	struct op_hash_st *lh = (struct op_hash_st *)h;

    lh->error = 0;
    if (lh->up_load <= (lh->num_items * LH_LOAD_MULT / lh->num_nodes)
            && !expand(lh))
        return NULL;

    rn = getrn(lh, data, &hash);

    if (*rn == NULL) {
        if ((nn = (struct op_hash_node_st *)op_calloc(1,sizeof(struct op_hash_node_st))) == NULL) {
            lh->error++;
            return (NULL);
        }
        nn->data = data;
        nn->next = NULL;
        *rn = nn;
        ret = NULL;
        lh->num_insert++;
        lh->num_items++;
    } else {                    /* replace same key */

        ret = (*rn)->data;
        (*rn)->data = data;
        lh->num_replace++;
    }
    return (ret);
}

void *op_hash_mem_delete(void *h, const void *data)
{
    unsigned long hash;
    struct op_hash_node_st *nn, **rn;
    void *ret;
	struct op_hash_st *lh = (struct op_hash_st *)h;
    lh->error = 0;
    rn = getrn(lh, data, &hash);

    if (*rn == NULL) {
        lh->num_no_delete++;
        return (NULL);
    } else {
        nn = *rn;
        *rn = nn->next;
        ret = nn->data;
        op_free(nn);
        lh->num_delete++;
    }

    lh->num_items--;
    if ((lh->num_nodes > MIN_NODES) &&
        (lh->down_load >= (lh->num_items * LH_LOAD_MULT / lh->num_nodes)))
        contract(lh);

    return (ret);
}

void *op_hash_mem_retrieve(void *h, const void *data)
{
    unsigned long hash;
    struct op_hash_node_st **rn;
    void *ret;
	struct op_hash_st *lh = (struct op_hash_st *)h;
    lh->error = 0;
    rn = getrn(lh, data, &hash);

    if (*rn == NULL) {
        lh->num_retrieve_miss++;
        return (NULL);
    } else {
        ret = (*rn)->data;
        lh->num_retrieve++;
    }
    return (ret);
}

static void doall_util_fn(struct op_hash_st *lh, int use_arg, void (*search) (void *),
                          void (*search_arg) (void *, void *), void *arg)
{
    int i;
    struct op_hash_node_st *a, *n;

    if (lh == NULL)
        return;

    /*
     * reverse the order so we search from 'top to bottom' We were having
     * memory leaks otherwise
     */
    for (i = lh->num_nodes - 1; i >= 0; i--) {
        a = lh->b[i];
        while (a != NULL) {
            /*
             * 28/05/91 - eay - n added so items can be deleted via lh_doall
             */
            /*
             * 22/05/08 - ben - eh? since a is not passed, this should not be
             * needed
             */
            n = a->next;
            if (use_arg)
                search_arg(a->data, arg);
            else
                search(a->data);
            a = n;
        }
    }
}

void op_hash_mem_doall(void *h, void (*search) (void *))
{
	struct op_hash_st *lh = (struct op_hash_st *)h;

    doall_util_fn(lh, 0, search, NULL, NULL);
}

void op_hash_mem_doall_arg(void *h, void (*search) (void *, void*), void *arg)
{
	struct op_hash_st *lh = (struct op_hash_st *)h;

    doall_util_fn(lh, 1, NULL, search, arg);

}

static int expand(struct op_hash_st *lh)
{
    struct op_hash_node_st **n, **n1, **n2, *np;
    unsigned int p, pmax, nni, j;
    unsigned long hash;

    nni = lh->num_alloc_nodes;
    p = lh->p;
    pmax = lh->pmax;
    if (p + 1 >= pmax) {
        j = nni * 2;
        n = op_realloc(lh->b, (int)(sizeof(struct op_hash_node_st *) * j));
        if (n == NULL) {
            lh->error++;
            return 0;
        }
        lh->b = n;
        memset(n + nni, 0, sizeof(*n) * (j - nni));
        lh->pmax = nni;
        lh->num_alloc_nodes = j;
        lh->num_expand_reallocs++;
        lh->p = 0;
    } else {
        lh->p++;
    }

    lh->num_nodes++;
    lh->num_expands++;
    n1 = &(lh->b[p]);
    n2 = &(lh->b[p + pmax]);
    *n2 = NULL;

    for (np = *n1; np != NULL;) {

        hash = lh->hash(np->data);
        lh->num_hash_calls++;
        if ((hash % nni) != p) { /* move it */
            *n1 = (*n1)->next;
            np->next = *n2;
            *n2 = np;
        } else
            n1 = &((*n1)->next);
        np = *n1;
    }

    return 1;
}

static void contract(struct op_hash_st *lh)
{
    struct op_hash_node_st **n, *n1, *np;

    np = lh->b[lh->p + lh->pmax - 1];
    lh->b[lh->p + lh->pmax - 1] = NULL; /* 24/07-92 - eay - weird but :-( */
    if (lh->p == 0) {
		
        n = (struct op_hash_node_st **)op_realloc(lh->b,
                                           (unsigned int)(sizeof(struct op_hash_node_st *)
                                                          * lh->pmax));
        if (n == NULL) {
/*                      fputs("realloc error in lhash",stderr); */
            lh->error++;
            return;
        }
        lh->num_contract_reallocs++;
        lh->num_alloc_nodes /= 2;
        lh->pmax /= 2;
        lh->p = lh->pmax - 1;
        lh->b = n;
    } else
        lh->p--;

    lh->num_nodes--;
    lh->num_contracts++;

    n1 = lh->b[(int)lh->p];
    if (n1 == NULL)
        lh->b[(int)lh->p] = np;
    else {
        while (n1->next != NULL)
            n1 = n1->next;
        n1->next = np;
    }
}

static struct op_hash_node_st **getrn(struct op_hash_st *lh, const void *data, unsigned long *rhash)
{
    struct op_hash_node_st **ret, *n1;
    unsigned long hash, nn;
	int (*cf) (const void *, const void *);

    hash = (*(lh->hash)) (data);
    lh->num_hash_calls++;
    *rhash = hash;

    nn = hash % lh->pmax;
    if (nn < lh->p)
        nn = hash % lh->num_alloc_nodes;

    cf = lh->comp;
    ret = &(lh->b[(int)nn]);
    for (n1 = *ret; n1 != NULL; n1 = n1->next) {
        lh->num_comp_calls++;
        if (cf(n1->data, data) == 0)
            break;
        ret = &(n1->next);
    }
    return (ret);
}

/*
 * The following hash seems to work very well on normal text strings no
 * collisions on /usr/dict/words and it distributes on %2^n quite well, not
 * as good as MD5, but still good.
 */

unsigned long op_hash_num_items(void *h)
{
	struct op_hash_st *lh = (struct op_hash_st *)h;

    return lh ? lh->num_items : 0;
}

