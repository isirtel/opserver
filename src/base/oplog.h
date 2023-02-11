#ifndef __OP_LOG_H__
#define __OP_LOG_H__
#include <string.h>

enum OPLOGLEVEL{
	oplog_level_error,
	oplog_level_warn,
	oplog_level_info,
	oplog_level_debug,
	oplog_level_max,
};

enum OPLOGTYPE {
	oplog_none,
	oplog_prog,
	oplog_max,
	
};

void *oplog_init(void);
void oplog_exit(void *oplog);
void oplog_print(int log_type, char *file, const char *function, int line, int level, const char *fmt, ...);
void oplog_print_ex(int log_type, char *file, const char *function, int line, int level, const char *fmt, ...);

#define log_error(fmt...) oplog_print(oplog_prog,__FILE__,__FUNCTION__,__LINE__,oplog_level_error,fmt)
#define log_warn(fmt...) oplog_print(oplog_prog,__FILE__,__FUNCTION__,__LINE__,oplog_level_warn,fmt)
#define log_info(fmt...) oplog_print(oplog_prog,__FILE__,__FUNCTION__,__LINE__,oplog_level_info,fmt)
#define log_debug(fmt...) oplog_print(oplog_prog,__FILE__,__FUNCTION__,__LINE__,oplog_level_debug,fmt)

#define log_error_ex(fmt...) oplog_print_ex(oplog_prog,__FILE__,__FUNCTION__,__LINE__,oplog_level_error,fmt)
#define log_warn_ex(fmt...) oplog_print_ex(oplog_prog,__FILE__,__FUNCTION__,__LINE__,oplog_level_warn,fmt)
#define log_info_ex(fmt...) oplog_print_ex(oplog_prog,__FILE__,__FUNCTION__,__LINE__,oplog_level_info,fmt)
#define log_debug_ex(fmt...) oplog_print_ex(oplog_prog,__FILE__,__FUNCTION__,__LINE__,oplog_level_debug,fmt)

#endif
