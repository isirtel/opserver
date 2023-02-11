#ifndef __OPSQL_H__
#define __OPSQL_H__

//#define OPSQL_UNKNOWN_TYPE    0
#define OPSQL_CHAR            1
#define OPSQL_NUMERIC         2
#define OPSQL_DECIMAL         3
#define OPSQL_INTEGER         4
#define OPSQL_SMALLINT        5
#define OPSQL_FLOAT           6
#define OPSQL_REAL            7
#define OPSQL_DOUBLE          8
#define OPSQL_DATETIME        9
#define OPSQL_VARCHAR        12
#define OPSQL_TYPE_DATE      91
#define OPSQL_TYPE_TIME      92
#define OPSQL_TYPE_TIMESTAMP 93

#define OPSQL_LEN 1024

void *opsql_init(char *conf_path);

void opsql_exit(void *_sql);

void *opsql_alloc(void);
void opsql_free(void *handle);

int opsql_bind_col(void *handle, int col, int type, void* param, int param_size);

int opsql_query(void *handle,char *sql);

int opsql_fetch(void *handle);

int opsql_fetch_scroll(void *handle, int row);
int opsql_exe(void *handle,char *sql);

int opsql_exe_single(char *sql);

#endif
