#include<stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>

#include "opsql.h"
#include "odbc/sql.h"
#include "odbc/sqlext.h"
#include "odbc/sqltypes.h"
#include "iniparser.h"
#include "opbox/utils.h"

#define OPSQL_SERVER "opsql:path"
#define SQL_ODBCSYSINI "ODBCSYSINI"
#define SQL_ODBCINI "ODBCINI"

struct _opsql_struct {
	HENV henv;
	SQLHDBC hdbc;
	SQLHSTMT stmt;
	pthread_mutex_t lock;
	pthread_mutexattr_t attr;
	char path[128];
};

static struct _opsql_struct *self;

void *opsql_init(char *conf_path)
{

	struct _opsql_struct *_sql = NULL;
	SQLRETURN rcode = 0;
	dictionary *dict = NULL;
	const char * str = NULL;
	char buf_tmp[240] = {};

	_sql = calloc(1, sizeof(struct _opsql_struct));
	if (!_sql) {
		printf ("%s %d calloc failed[%d]\n",__FILE__,__LINE__, errno);
		goto exit;
	}
	
	self = _sql;

	dict = iniparser_load(conf_path);
	if (!dict) {
		printf ("%s %d iniparser_load faild[%s]\n",__FILE__,__LINE__, conf_path);
		goto exit;
	}

	if(!(str = iniparser_getstring(dict,OPSQL_SERVER,NULL))) {
		printf ("%s %d iniparser_getstring faild[%s]\n",__FILE__,__LINE__, OPSQL_SERVER);
		iniparser_freedict(dict);
		goto exit;
	}

	op_strlcpy(_sql->path, str, sizeof(_sql->path));

	iniparser_freedict(dict);

	snprintf(buf_tmp, sizeof(buf_tmp),"%s/odbc.ini", _sql->path);
	setenv(SQL_ODBCSYSINI, _sql->path, 1);
	setenv(SQL_ODBCINI, buf_tmp, 1);



	rcode = SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &_sql->henv);
	if (rcode != SQL_SUCCESS && rcode != SQL_SUCCESS_WITH_INFO) {
		printf ("%s %d SQLAllocHandle failed\n",__FILE__,__LINE__);
		goto exit;
	}

	rcode = SQLSetEnvAttr(_sql->henv, SQL_ATTR_ODBC_VERSION, (void *)SQL_OV_ODBC3, 0);
	if (rcode != SQL_SUCCESS && rcode != SQL_SUCCESS_WITH_INFO) {
		printf ("%s %d SQLSetEnvAttr failed\n",__FILE__,__LINE__);
		goto exit;
	}

	rcode = SQLAllocHandle(SQL_HANDLE_DBC, _sql->henv, &_sql->hdbc);
	if (rcode != SQL_SUCCESS && rcode != SQL_SUCCESS_WITH_INFO) {
		printf ("%s %d SQLAllocHandle failed\n",__FILE__,__LINE__);
		goto exit;
	}


	rcode = SQLConnect(_sql->hdbc, (SQLCHAR *)"isir", SQL_NTS,
		(SQLCHAR *)"isir", SQL_NTS, (SQLCHAR *)"isir", SQL_NTS);

	if (rcode != SQL_SUCCESS && rcode != SQL_SUCCESS_WITH_INFO) {
		printf ("%s %d SQLConnect failed\n",__FILE__,__LINE__);
		goto exit;
	}

	if(pthread_mutexattr_init(&_sql->attr)) {
		printf ("%s %d pthread_mutexattr_init faild\n",__FILE__,__LINE__);
		goto exit;
	}

	if(pthread_mutex_init(&_sql->lock, &_sql->attr)) {
		printf ("%s %d pthread_mutex_init faild\n",__FILE__,__LINE__);
		goto exit;
	}
	
	return _sql;
exit:
	opsql_exit(_sql);

	return NULL;
 
} 


void *opsql_alloc(void)
{
	SQLHSTMT stmt = NULL;
	struct _opsql_struct *_sql = self;
	SQLRETURN rcode = 0;
	SQLINTEGER status = SQL_CD_TRUE;
	stmt = calloc(1, sizeof(SQLHSTMT));
	if (!stmt) {
		printf ("%s %d calloc failed\n",__FUNCTION__,__LINE__);
		goto failed;
	}

	pthread_mutex_lock(&_sql->lock);
	rcode = SQLGetConnectAttr(_sql->hdbc, SQL_ATTR_CONNECTION_DEAD, &status, 0, 0);

	if (rcode != SQL_SUCCESS && rcode != SQL_SUCCESS_WITH_INFO) {
		printf ("%s %d SQLGetConnectAttr failed\n",__FILE__,__LINE__);
		
		pthread_mutex_unlock(&_sql->lock);
		goto failed;
	}

	if (status == SQL_CD_TRUE) {
		printf ("%s %d sql disconnect failed, try reconnect\n",__FUNCTION__,__LINE__);
		SQLDisconnect(_sql->hdbc);
		rcode = SQLConnect(_sql->hdbc, (SQLCHAR *)"isir", SQL_NTS,
			(SQLCHAR *)"isir", SQL_NTS, (SQLCHAR *)"isir", SQL_NTS);

		if (rcode != SQL_SUCCESS && rcode != SQL_SUCCESS_WITH_INFO) {
			printf ("%s %d SQLConnect failed\n",__FILE__,__LINE__);
			pthread_mutex_unlock(&_sql->lock);
			goto failed;
		}

	}
	
	rcode = SQLAllocHandle(SQL_HANDLE_STMT, _sql->hdbc,&stmt);
	if (rcode != SQL_SUCCESS && rcode != SQL_SUCCESS_WITH_INFO) {
		printf ("%s %d SQLAllocHandle failed\n",__FUNCTION__,__LINE__);
		pthread_mutex_unlock(&_sql->lock);
		goto failed;
	}

	SQLSetStmtAttr(stmt,SQL_ATTR_CURSOR_SCROLLABLE,(SQLPOINTER)SQL_SCROLLABLE,SQL_NTS);

	pthread_mutex_unlock(&_sql->lock);
	return stmt;
failed:
	if (stmt)
		free(stmt);
	return NULL;
}

void opsql_free(void *handle)
{
	SQLFreeHandle(SQL_HANDLE_STMT, handle);
	return;
}

int opsql_bind_col(void *handle, int col, int type, void* param, int param_size)
{
	SQLRETURN rcode = 0;
	static SQLLEN res = SQL_NTS;
	rcode = SQLBindCol(handle, col, type, param, param_size, &res);
	if(rcode != SQL_SUCCESS && rcode != SQL_SUCCESS_WITH_INFO) {
		printf("%s %d opsql_bind_col [%d][%d] failed!\n", __FUNCTION__, __LINE__, col, rcode);
		goto failed;
	}

	return 0;
failed:
	return -1;
}

int opsql_query(void *handle,char *sql)
{
	SQLRETURN rcode = 0;
	SQLLEN row_count = 0;

	rcode = SQLExecDirect(handle, (SQLCHAR*)sql, SQL_NTS);
	if(rcode != SQL_SUCCESS && rcode != SQL_SUCCESS_WITH_INFO) {
		printf("%s %d SQLExecDirect [%s] failed!\n", __FUNCTION__, __LINE__, sql);
		goto failed;
	}

	rcode = SQLRowCount(handle, &row_count);
	if(rcode != SQL_SUCCESS && rcode != SQL_SUCCESS_WITH_INFO) {
		printf("%s %d SQLRowCount [%s] failed!\n", __FUNCTION__, __LINE__, sql);
		goto failed;
	}


	return row_count;
failed:
	return -1;
}

int opsql_exe(void *handle,char *sql)
{
	SQLRETURN rcode = 0;

	rcode = SQLExecDirect(handle, (SQLCHAR*)sql, SQL_NTS);
	if(rcode != SQL_SUCCESS && rcode != SQL_SUCCESS_WITH_INFO) {
		printf("%s %d SQLExecDirect [%s] failed!\n", __FUNCTION__, __LINE__, sql);
		goto failed;
	}

	return 0;
failed:
	return -1;
}

int opsql_exe_single(char *sql)
{
	SQLRETURN rcode = 0;

	void *handle = opsql_alloc();
	if (!handle)
		return -1;
	rcode  = opsql_exe(handle, sql);
	if(rcode != SQL_SUCCESS && rcode != SQL_SUCCESS_WITH_INFO) {
		printf("%s %d SQLExecDirect [%s] failed!\n", __FUNCTION__, __LINE__, sql);
		goto failed;
	}
	opsql_free(handle);
	return 0;
failed:
	return -1;
}

int opsql_fetch(void *handle)
{
	SQLRETURN rcode = 0;
	rcode = SQLFetch(handle);
	if(rcode != SQL_SUCCESS && rcode != SQL_SUCCESS_WITH_INFO) {
		printf("%s %d opsql_fetch failed!\n", __FUNCTION__, __LINE__);
		goto failed;
	}

	return 0;
failed:
	return -1;
}

int opsql_fetch_scroll(void *handle, int row)
{
	SQLRETURN rcode = 0;
	rcode = SQLFetchScroll(handle, SQL_FETCH_ABSOLUTE, row);
	if(rcode != SQL_SUCCESS && rcode != SQL_SUCCESS_WITH_INFO) {
		printf("%s %d SQLFetchScroll failed!\n", __FUNCTION__, __LINE__);
		goto failed;
	}

	return 0;
failed:
	return -1;

}

void opsql_exit(void *_sql)
{
	//清理工作, 释放具体的资源句柄
	//SQLFreeHandle(SQL_HANDLE_STMT, stmt);
	//SQLDisconnect(hdbc);
	//SQLFreeHandle(SQL_HANDLE_DBC, hdbc);
	//SQLFreeHandle(SQL_HANDLE_ENV, henv);
	
	//rcode = SQLNumResultCols(stmt,&col_num);
	//if(rcode != SQL_SUCCESS && rcode != SQL_SUCCESS_WITH_INFO) {
		//printf("%s %d SQLNumResultCols [%s] failed!\n", __FUNCTION__, __LINE__, sql);
		//goto failed;
	//}

#if 0
		void *handle = NULL;
	handle = opsql_alloc();
	
	char sno[30];
	char sname[30];
	char ssex[30];
	char sbirthday[30];
	char sclass[30];

	//printf("student2 has %d row num\n", opsql_query_table_row(handle, "student2"));
	int count = opsql_query(handle, "select * from student2");

	printf("----------------count=%d\n", count);
	opsql_bind_col(handle, 1, OPSQL_CHAR, sno, sizeof(sno));
	opsql_bind_col(handle, 2, OPSQL_CHAR, sname, sizeof(sname));
	opsql_bind_col(handle, 3, OPSQL_CHAR, ssex, sizeof(ssex));
	opsql_bind_col(handle, 4, OPSQL_DATETIME, sbirthday, sizeof(sbirthday));
	opsql_bind_col(handle, 5, OPSQL_CHAR, sclass, sizeof(sclass));

	while(count >= 1) {
		opsql_fetch(handle);
		printf("sno=%s,sname=%s, ssex=%s, sclass=%s\n", sno, sname, ssex, sclass );
		count--;
	}
	printf("******************\n");
	opsql_fetch_scroll(handle, 5);
	printf("sno=%s,sname=%s, ssex=%s, sclass=%s\n", sno, sname, ssex, sclass );
	opsql_fetch_scroll(handle, 7);
	printf("sno=%s,sname=%s, ssex=%s, sclass=%s\n", sno, sname, ssex, sclass );
#endif
	return;
}


