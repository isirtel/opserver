#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <stdarg.h>

#include "opmail.h"
#include "base/oplog.h"
#include "base/opsql.h"
#include "opbox/utils.h"

#include "base/sql_name.h"

struct opmail_info
{
	pthread_mutex_t lock;
	pthread_mutexattr_t attr;
	char smtp_auth_code[256];
	char message[65536];
	char content[60000];
};

static struct opmail_info *self = NULL;

void *opmail_init(void)
{
	void *handle = NULL;
	char sql[OPSQL_LEN];
	struct opmail_info *mail = NULL;
	int count = 0;
	char value[256] ;
		
	mail = calloc(1, sizeof(struct opmail_info));
	if (!mail) {
		log_error("calloc failed\n");
		goto out;
	}

	handle = opsql_alloc();
	if (!handle) {
		log_warn("opsql_alloc failed\n");
		goto out;
	}

	snprintf(sql, sizeof(sql),"select %s from %s where map_key='%s';", TAB_KEY_VALUE_ELE_VALUE, TABLE_KEY_VALUE,TAB_VALUE_STMP_KEY);
	log_debug("sql:%s\n",sql);
	count = opsql_query(handle, sql);
	if (count <= 0) {
		log_warn("opsql_query failed\n");
		goto out;
	}

	opsql_bind_col(handle, 1, OPSQL_CHAR, value, sizeof(value));
	memset(value, 0, sizeof(value));
	if(opsql_fetch_scroll(handle, count) < 0) {
		log_warn("opsql_fetch_scroll failed[%d]\n", count);
		goto out;
	}

	if(pthread_mutexattr_init(&mail->attr)) {
		log_error ("pthread_mutexattr_init faild\n");
		goto out;
	}

	if(pthread_mutex_init(&mail->lock, &mail->attr)) {
		log_error ("pthread_mutex_init faild\n");
		goto out;
	}

	log_debug("%s=%s\n", TAB_VALUE_STMP_KEY,value);
	op_strlcpy(mail->smtp_auth_code, value, sizeof(mail->smtp_auth_code));
	opsql_free(handle);
	self = mail;
	return mail;
out:
	opmail_exit(mail);
	return NULL;
}

void opmail_exit(void *mail)
{
	if (!mail)
		return;

	return;
}

void opmail_send_message(char *to, char *theme, char *content)
{
	if (!to || !self)
		return;

	pthread_mutex_lock(&self->lock);
	/*sendEmail -xu isirtel@163.com -t isirtel@sina.com -u "sendmain test" -m "test body" -s smtp.163.com -f isirtel@163.com -xp xxxxxxxxx  -o message-charset=utf-8*/
	snprintf(self->message, sizeof(self->message), 
			"sendEmail -o message-charset=utf-8 -xu isirtel@163.com -t %s -u \"%s\" -m \"%s\" -s smtp.163.com -f isirtel@163.com -xp %s",
			to,theme, content, self->smtp_auth_code);
	log_debug("sendemail:%s\n", self->message);
	system(self->message);
	pthread_mutex_unlock(&self->lock);
	return;
}
void opmail_send_message_ex(char *to, char *theme, const char *fmt, ...)
{
	va_list args;

	if (!to || !self)
		return;
	va_start(args, fmt);
	pthread_mutex_lock(&self->lock);

	vsnprintf((char*)self->content, sizeof(self->content), fmt, args);
	va_end(args);
	snprintf(self->message, sizeof(self->message), 
			"sendEmail -o message-charset=utf-8 -xu isirtel@163.com -t %s -u \"%s\" -m \"%s\" -s smtp.163.com -f isirtel@163.com -xp %s",
			to,theme, self->content, self->smtp_auth_code);
	log_debug("sendemail:%s\n", self->message);
	system(self->message);
	pthread_mutex_unlock(&self->lock);
	return;
}


