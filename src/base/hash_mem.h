#ifndef __HASH_MEM_H__
#define __HASH_MEM_H__

void *op_hash_mem_new(unsigned long (*hash) (const void *), int (*compare) (const void *, const void *));
void op_hash_mem_free(void *h);
void *op_hash_mem_insert(void *h, void *data);
void *op_hash_mem_delete(void *h, const void *data);
void *op_hash_mem_retrieve(void *h, const void *data);
void op_hash_mem_doall(void *h, void (*search) (void *));
void op_hash_mem_doall_arg(void *h, void (*search) (void *, void*), void *arg);

unsigned long op_hash_mem_num_items(void *h);

#endif


