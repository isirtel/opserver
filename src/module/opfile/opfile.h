#ifndef _OPFILE_H__
#define _OPFILE_H__
#include "opfile_pub.h"

void *opfile_init(void);
void opfile_exit(void *file);

struct file_ext_info * opfile_check_mem(char *file_buf, unsigned int size);
struct file_ext_info * opfile_check_path(char *file_path);

struct file_to_text *opfile_to_text(char *file_buf, unsigned int size, unsigned int file_type);
struct file_to_text *opfile_to_text_path(char *file_path, unsigned int file_type);

#endif
