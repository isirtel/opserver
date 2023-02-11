#ifndef __HASH_H__
#define __HASH_H__

void *op_hash_new(unsigned long (*hash) (const void *), int (*compare) (const void *, const void *));
void op_hash_free(void *h);
void *op_hash_insert(void *h, void *data);
void *op_hash_delete(void *h, const void *data);
void *op_hash_retrieve(void *h, const void *data);
void op_hash_doall(void *h, void (*search) (void *));
void op_hash_doall_arg(void *h, void (*search) (void *, void*), void *arg);

unsigned long op_hash_num_items(void *h);
unsigned long long op_hash_string(const char * c);

#endif
