#ifndef __OP_MEM_H__
#define __OP_MEM_H__
#include <stdlib.h>

void *opmem_init(void);
void opmem_exit(void *mem);

void *op_malloc(size_t size);
void *op_calloc(size_t nmemb, size_t size);
void *op_realloc(void *ptr, size_t size);
void op_free(void *ptr);

int op_mem_information (char *buf, int size);
int op_mem_father_node_information (char *buf, int size);

void op_mem_release_check(void *mem);


#endif
