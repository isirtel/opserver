#include <stdio.h>
#include <pthread.h>
#include <errno.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <signal.h>
#include <fcntl.h>

#include "config.h"
#include "oplog.h"
#include "iniparser.h"
#include "opbox/usock.h"
#include "opbox/utils.h"
#include "event.h"
#include "opbox/list.h"
#include "opmem.h"

#define LOG_COLOR_NONE "\033[m"
#define LOG_COLOR_BLACK "\033[0;30m"
#define LOG_COLOR_RED "\033[0;31m"
#define LOG_COLOR_GREEN "\033[0;32m"
#define LOG_COLOR_YELLOW "\033[0;33m"
#define LOG_COLOR_BULE "\033[0;34m"
#define LOG_COLOR_PURPLE "\033[0;35m"
#define LOG_COLOR_WHITE "\033[0;37m"

#define LOG_SERVER "oplog:log_ip"
#define LOG_PORT "oplog:log_port"
#define LOG_PROG_ROOT "oplog:prog_log_path"

#define LOG_BUF_SIZE 8192
#define LOG_RECV_LIST_SIZE 4096
#define LOG_DISK_THREAD_NUM 2

struct log_level_name_map {
	char *name;
	char *color;
};

enum LOG_FORMAT_TYPE {
	LOG_FORMAT_DETAIL,

};

struct log_level_name_map log_level_map[] = {
	[oplog_level_error] = {.name = "error", .color = LOG_COLOR_RED},
	[oplog_level_warn] = {.name = "warn ", .color = LOG_COLOR_PURPLE},
	[oplog_level_info] = {.name = "info ", .color = LOG_COLOR_GREEN},
	[oplog_level_debug] = {.name = "debug", .color = LOG_COLOR_WHITE},
};

struct _log_thread_ 
{
	pthread_t thread_id;
	pthread_attr_t thread_attr;
	pthread_t disk_thread_id[LOG_DISK_THREAD_NUM];
	pthread_attr_t disk_thread_attr[LOG_DISK_THREAD_NUM];
	int disk_run;
};

struct _log_socket {
	int sock_fd;
	unsigned int ip;
	unsigned short port;
};

struct _log_send_header {
	char file[64];
	char function[64];
	int line;
	int level;
	int type;
};

struct _log_send_ {
	int send_fd;
	struct sockaddr_in send_addr;
	pthread_mutex_t lock;
	pthread_mutexattr_t attr;
	unsigned char buf_send[LOG_BUF_SIZE];
};

struct _log_item_buf_ {
	unsigned char *buf;
	int size;
};

struct _log_item_
{
	struct list_head list;
	struct _log_item_buf_ log;
};

struct _log_recv_ {
	struct list_head vector; 
	int vector_num;
	pthread_cond_t cont;
	pthread_condattr_t cont_attr;
	pthread_mutex_t lock;
	pthread_mutexattr_t attr;
	unsigned char buf_secv[LOG_BUF_SIZE];
	int disk_run;
};

struct _log_prog_ {
	int fd;
	char root_path[256];
	struct tm tm;
	unsigned char log_format[LOG_BUF_SIZE];
};

struct _oplog_struct_
{
	struct _log_thread_ thread;
	struct _log_socket sock;
	struct event_base *base;
	struct event *ev;
	struct _log_send_ send;
	struct _log_recv_ recv;
	struct _log_prog_ prog;
};

typedef void (*log_cb)(struct _log_send_header *head, unsigned char *content, int content_size);

struct _op_log_cb {
	int type;
	log_cb cb;
};

static struct _oplog_struct_ *self;
static struct _log_send_ log_send_ex;

static void op_log_prog(struct _log_send_header *head, unsigned char *content, int content_size);

static struct _op_log_cb _g_log_cb[oplog_max] = {
	[oplog_prog] = {.type=oplog_prog, .cb= op_log_prog},
};

static void oplog_job(evutil_socket_t fd,short what,void* arg)
{
	int ret = 0;
	struct sockaddr_in addr;
	socklen_t addr_len;
	unsigned char * str = NULL;
	struct _log_item_ *item = NULL;
	struct _oplog_struct_ *_op = NULL;

	_op = (struct _oplog_struct_ *)arg;
	if (!_op) {
		printf ("%s %d oplog_job handle failed\n",__FILE__,__LINE__);
		goto out;
	}

	ret = recvfrom(fd,_op->recv.buf_secv, sizeof(_op->recv.buf_secv), 0, (struct sockaddr*)&addr, &addr_len);
	if(ret < 0) {
		printf ("%s %d oplog_job read failed[%d]\n",__FILE__,__LINE__,errno);
		goto out;
	}

	if (ret > LOG_BUF_SIZE || ret < (int)sizeof(struct _log_send_header)) {
		printf ("%s %d oplog_job recv message length [%d] is not support\n",__FILE__,__LINE__, ret);
		goto out;
	}
	
	str = op_calloc(1,ret+1);
	if (!str) {
		printf ("%s %d oplog_job calloc failed[%d]\n",__FILE__,__LINE__,errno);
		goto out;
	}

	item = op_calloc(1, sizeof(*item));
	if (!item) {
		printf ("%s %d oplog_job calloc failed[%d]\n",__FILE__,__LINE__,errno);
		goto out;
	}

	memcpy(str, _op->recv.buf_secv, ret);

	item->log.buf = str;
	item->log.size = ret;
	INIT_LIST_HEAD(&item->list);

	pthread_mutex_lock(&_op->recv.lock);
	if (_op->recv.vector_num > LOG_RECV_LIST_SIZE) {
		printf ("%s %d oplog_job vctor is full\n",__FILE__,__LINE__);
		op_free(str);
		op_free(item);
		pthread_mutex_unlock(&_op->recv.lock);
		goto out;
	}

	list_add_tail(&item->list, &_op->recv.vector);
	_op->recv.vector_num++;
	pthread_cond_broadcast(&_op->recv.cont);
	pthread_mutex_unlock(&_op->recv.lock);
	return;
out:
	return;
}

static void *oplog_routine (void *arg)
{
	if(event_base_dispatch(arg) < 0) {
		printf ("%s %d oplog_routine failed\n",__FILE__,__LINE__);
		pthread_detach(pthread_self());
		pthread_exit(NULL);
		goto exit;
	}

	printf ("%s %d oplog_routine exit\n",__FILE__,__LINE__);
exit:
	return NULL;
}

static int _oplog_check_disk(void)
{
	time_t t;
	struct tm *tm;
	char buf_format[512];

	t=time(NULL);
	tm = localtime(&t);

	if (tm->tm_year != self->prog.tm.tm_year || tm->tm_mon != self->prog.tm.tm_mon ||
			tm->tm_mday != self->prog.tm.tm_mday)
		memcpy(&self->prog.tm, tm, sizeof(struct tm));

	snprintf(buf_format, sizeof(buf_format), "%s/%d-%02d-%02d", self->prog.root_path,
			self->prog.tm.tm_year+1900, self->prog.tm.tm_mon+1, self->prog.tm.tm_mday);

	if (access(buf_format, F_OK) < 0 || self->prog.fd <= 0) {

		if (self->prog.fd)
			close(self->prog.fd);

		self->prog.fd = open(buf_format, O_WRONLY|O_APPEND|O_CREAT, 0666);
		if (self->prog.fd < 0) {
			printf ("%s %d _oplog_check_disk open failed[%s][%d]\n",__FILE__,__LINE__, 
					buf_format, errno);
			return -1;
		}

		return self->prog.fd;
	}

	return self->prog.fd;
}

static void log_header_ntohl(struct _log_send_header * head)
{
	if (!head)
		return;

	head->level = ntohl(head->level);
	head->line = ntohl(head->line);
	head->type = ntohl(head->type);
	return;
}

static int _oplog_format(int format_type, unsigned char * fromat_buf, int buf_size, struct _log_send_header *head, unsigned char *message)
{
	time_t ti;
	struct tm *t;
	struct timeval t2;
	int ret = 0;

	ti = time(NULL);
	
	t = localtime(&ti);

	gettimeofday(&t2, NULL);

	switch(format_type) {

		case LOG_FORMAT_DETAIL:
			ret = snprintf((char*)fromat_buf, buf_size,
					"%s%d-%02d-%02d %02d:%02d:%02d:%03lu %s %d %s 	%s%s",
					log_level_map[head->level].color,t->tm_year+1900, t->tm_mon+1, t->tm_mday,
					t->tm_hour, t->tm_min, t->tm_sec, t2.tv_usec/1000,head->function, head->line,
					log_level_map[head->level].name, message,LOG_COLOR_NONE);
			break;
		default:
			ret = snprintf((char*)fromat_buf, buf_size,
					"%s%d-%02d-%02d %02d:%02d:%02d:%03lu %s 	%s%s",
					log_level_map[head->level].color,t->tm_year+1900, t->tm_mon+1, t->tm_mday,
					t->tm_hour, t->tm_min, t->tm_sec, t2.tv_usec/1000,
					log_level_map[head->level].name, message,LOG_COLOR_NONE);
			break;
	}

	return ret;

}

static void _oplog_sync_to_disk(int fd, struct _log_send_header *head, unsigned char *content)
{
	int ret = 0;

	if (!content || fd < 0) {
		printf ("%s %d _oplog_sync_to_disk parameter failed\n",__FILE__,__LINE__);
		goto out;
	}

	if (head->type != oplog_prog){
		printf ("%s %d _oplog_sync_to_disk head type is not support, type= %d\n",__FILE__,__LINE__, head->type);
		goto out;
	}
	
	if (head->level > oplog_level_max) {
		printf ("%s %d _oplog_sync_to_disk level parameter failed\n",__FILE__,__LINE__);
		goto out;
	}

	ret = _oplog_format(LOG_FORMAT_DETAIL, self->prog.log_format, LOG_BUF_SIZE, head, content);

	if (write(fd, self->prog.log_format, ret) < 0) {
		printf ("%s %d _oplog_sync_to_disk write failed[%d]\n",__FILE__,__LINE__, errno);
		goto out;
	}

out:
	return;
}

static void op_log_prog(struct _log_send_header *head, unsigned char *content, int content_size)
{
	int log_fd = 0;

	if ((log_fd = _oplog_check_disk()) < 0) {
		printf ("%s %d _oplog_check_disk failed[%x]\n",__FILE__,__LINE__, (unsigned int)pthread_self());
		goto out;
	}

	_oplog_sync_to_disk(log_fd, head, content);

out:
	return;
}

static void *oplog_dispatch (void *arg)
{
	struct _log_recv_ *_recv = NULL;
	struct _log_item_ *item;
	struct _log_send_header * head;
	unsigned char *content = NULL;
	
	_recv = (struct _log_recv_ *)arg;

	if (!_recv) {
		printf ("%s %d oplog_disk handle failed\n",__FILE__,__LINE__);
		goto exit;
	}

	_recv->disk_run = 1;

	while(_recv->disk_run) {
		pthread_mutex_lock(&_recv->lock);
		if (list_empty(&_recv->vector))
			pthread_cond_wait(&_recv->cont, &_recv->lock);

		if(list_empty(&_recv->vector))
			goto next;

		item = list_first_entry(&_recv->vector, struct _log_item_ , list);
		if (!item) {
			printf ("%s %d oplog_disk item failed[%x]\n",__FILE__,__LINE__, (unsigned int)pthread_self());
			goto next;
		}

		head = (struct _log_send_header *)item->log.buf;
		log_header_ntohl(head);
		if (head->type <= oplog_none || head->type >= oplog_max) {
			printf ("%s %d oplog type is not support, type=%d\n",__FILE__,__LINE__, head->type);
			goto _delete;
		}

		if (!_g_log_cb[head->type].cb) {
			printf ("%s %d oplog type cb is not support, type=%d\n",__FILE__,__LINE__, head->type);
			goto _delete;
		}

		content = item->log.buf+sizeof(struct _log_send_header);

		_g_log_cb[head->type].cb(head, content,item->log.size);

_delete:
		list_del_init(&item->list);
		if (item->log.buf) {
			op_free(item->log.buf);
			item->log.buf = NULL;
		}

		op_free(item);
		_recv->vector_num--;
next:
		pthread_mutex_unlock(&_recv->lock);
	}
	
exit:
	printf ("%s %d oplog_disk exit[%x]\n",__FILE__,__LINE__, (unsigned int)pthread_self());
	return NULL;
}

static int oplog_init_ex(void)
{
	dictionary *dict = NULL;
	const char *ip = NULL;
	unsigned int u_ip = 0;
	int str_int = 0;
	unsigned short port = 0;
	struct sockaddr_in in;

	dict = iniparser_load(OPSERVER_CONF);
	if (!dict) {
		printf ("%s %d iniparser_load faild[%s]\n",__FILE__,__LINE__, OPSERVER_CONF);
		goto exit;
	}

	if(!(ip = iniparser_getstring(dict,LOG_SERVER,NULL))) {
		printf ("%s %d iniparser_getstring faild[%s]\n",__FILE__,__LINE__, LOG_SERVER);
		iniparser_freedict(dict);
		goto exit;
	}

	if ((str_int =iniparser_getint(dict,LOG_PORT,-1))< 0) {
		printf ("%s %d iniparser_getint faild[%s]\n",__FILE__,__LINE__, LOG_PORT);
		iniparser_freedict(dict);
		goto exit;
	}

	port = str_int;

	u_ip = ntohl(inet_addr(ip));
	iniparser_freedict(dict);

	log_send_ex.send_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if(log_send_ex.send_fd < 0) {
		printf ("%s %d socket faild[%d]\n",__FILE__,__LINE__, errno);
		goto exit;
	}
	log_send_ex.send_addr.sin_family = AF_INET;
	log_send_ex.send_addr.sin_addr.s_addr = htonl(u_ip);
	log_send_ex.send_addr.sin_port = htons(port);

	memset(&in, 0, sizeof(in));
	in.sin_family = AF_INET;
	in.sin_addr.s_addr = htonl(u_ip);
	if(bind(log_send_ex.send_fd, (struct sockaddr *) &in, sizeof(in)) < 0) {
		printf ("%s %d bind faild[%d]\n",__FILE__,__LINE__, errno);
		close(log_send_ex.send_fd);
		goto exit;
	}

	if(pthread_mutexattr_init(&log_send_ex.attr)) {
		close(log_send_ex.send_fd);
		printf ("%s %d oplog pthread_mutexattr_init faild\n",__FILE__,__LINE__);
		goto exit;
	}

	if(pthread_mutex_init(&log_send_ex.lock, &log_send_ex.attr)) {
		close(log_send_ex.send_fd);
		pthread_mutexattr_destroy(&log_send_ex.attr);
		printf ("%s %d oplog pthread_mutex_init faild\n",__FILE__,__LINE__);
		goto exit;
	}

	return 0;
exit:
	return -1;
}

void *oplog_init(void)
{
	struct _oplog_struct_ *_op = NULL;
	dictionary *dict = NULL;
	const char *ip = NULL;
	const char *str = NULL;
	int str_int = 0;
	int i = 0;
	struct sockaddr_in in;

	_op = calloc(1, sizeof(struct _oplog_struct_));
	if (!_op) {
		printf ("%s %d oplog_init failed[errno:%d]\n",__FILE__,__LINE__, errno);
		goto exit;
	}

	dict = iniparser_load(OPSERVER_CONF);
	if (!dict) {
		printf ("%s %d iniparser_load faild[%s]\n",__FILE__,__LINE__, OPSERVER_CONF);
		goto exit;
	}

	if(!(ip = iniparser_getstring(dict,LOG_SERVER,NULL))) {
		printf ("%s %d iniparser_getstring faild[%s]\n",__FILE__,__LINE__, LOG_SERVER);
		iniparser_freedict(dict);
		goto exit;
	}

	_op->sock.ip = ntohl(inet_addr(ip));
	if ((str_int =iniparser_getint(dict,LOG_PORT,-1))< 0) {
		printf ("%s %d iniparser_getint faild[%s]\n",__FILE__,__LINE__, LOG_PORT);
		iniparser_freedict(dict);
		goto exit;
	}

	_op->sock.port = str_int;

	if(!(str = iniparser_getstring(dict,LOG_PROG_ROOT,NULL))) {
		printf ("%s %d iniparser_getstring faild[%s]\n",__FILE__,__LINE__, LOG_PROG_ROOT);
		iniparser_freedict(dict);
		goto exit;
	}

	op_strlcpy(_op->prog.root_path, str, sizeof(_op->prog.root_path));
	
	_op->sock.sock_fd = usock(USOCK_IPV4ONLY|USOCK_UDP|USOCK_SERVER, ip, usock_port(_op->sock.port));
	if (_op->sock.sock_fd < 0) {
		iniparser_freedict(dict);
		printf ("%s %d usock faild[%d]\n",__FILE__,__LINE__,errno);
		goto exit;
	}
	
	iniparser_freedict(dict);
	
	_op->send.send_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if(_op->send.send_fd < 0) {
		printf ("%s %d socket faild[%d]\n",__FILE__,__LINE__, errno);
		goto exit;
	}
	_op->send.send_addr.sin_family = AF_INET;
	_op->send.send_addr.sin_addr.s_addr = htonl(_op->sock.ip);
	_op->send.send_addr.sin_port = htons(_op->sock.port);

	memset(&in, 0, sizeof(in));
	in.sin_family = AF_INET;
	in.sin_addr.s_addr = htonl(_op->sock.ip);
	if(bind(_op->send.send_fd, (struct sockaddr *) &in, sizeof(in)) < 0) {
		printf ("%s %d bind faild[%d]\n",__FILE__,__LINE__, errno);
		goto exit;
	}

	if(pthread_mutexattr_init(&_op->send.attr)) {
		printf ("%s %d oplog pthread_mutexattr_init faild\n",__FILE__,__LINE__);
		goto exit;
	}

	if(pthread_mutex_init(&_op->send.lock, &_op->send.attr)) {
		printf ("%s %d oplog pthread_mutex_init faild\n",__FILE__,__LINE__);
		goto exit;
	}

	if(pthread_mutexattr_init(&_op->recv.attr)) {
		printf ("%s %d oplog pthread_mutexattr_init faild\n",__FILE__,__LINE__);
		goto exit;
	}

	if(pthread_mutex_init(&_op->recv.lock, &_op->recv.attr)) {
		printf ("%s %d oplog pthread_mutex_init faild\n",__FILE__,__LINE__);
		goto exit;
	}

	if(pthread_condattr_init(&_op->recv.cont_attr)) {
		printf ("%s %d oplog pthread_condattr_init faild\n",__FILE__,__LINE__);
		goto exit;
	}

	if(pthread_cond_init(&_op->recv.cont, &_op->recv.cont_attr)) {
		printf ("%s %d oplog pthread_cond_init faild\n",__FILE__,__LINE__);
		goto exit;
	}

	INIT_LIST_HEAD(&_op->recv.vector);

	_op->base = event_base_new();
	if (!_op->base) {
		printf ("%s %d oplog event_base_new faild\n",__FILE__,__LINE__);
		goto exit;
	}

	_op->ev = event_new(_op->base, _op->sock.sock_fd, EV_READ|EV_PERSIST, oplog_job, _op);
	if(!_op->ev) {
		printf ("%s %d oplog event_new faild\n",__FILE__,__LINE__);
		goto exit;
	}

	if(event_add(_op->ev, NULL) < 0) {
		printf ("%s %d oplog event_add faild\n",__FILE__,__LINE__);
		goto exit;
	}

	if(pthread_attr_init(&_op->thread.thread_attr)) {
		printf ("%s %d oplog pthread_attr_init faild\n",__FILE__,__LINE__);
		goto exit;
	}

	self = _op;

	if(pthread_create(&_op->thread.thread_id, &_op->thread.thread_attr, oplog_routine, _op->base)) {
		printf ("%s %d oplog pthread_create faild\n",__FILE__,__LINE__);
		goto exit;
	}
	
	for( i = 0; i < LOG_DISK_THREAD_NUM; i++) {
		if(pthread_attr_init(&_op->thread.disk_thread_attr[i])) {
			printf ("%s %d oplog pthread_attr_init faild\n",__FILE__,__LINE__);
			goto exit;
		}
		
		if(pthread_create(&_op->thread.disk_thread_id[i], &_op->thread.disk_thread_attr[i], oplog_dispatch, &_op->recv)) {
			printf ("%s %d oplog pthread_create faild\n",__FILE__,__LINE__);
			goto exit;
		}
	}

	return _op;
exit:

	oplog_exit(_op);
	return NULL;
}

void oplog_exit(void *oplog)
{
	struct _oplog_struct_ *_op = NULL;
	int i = 0;
	void *retval;
	
	if (!oplog)
		return;

	printf ("%s %d oplog exit\n",__FILE__,__LINE__);

	_op = oplog;

	if (_op->thread.thread_id) {
		printf ("%s %d oplog event_base_loopbreak\n",__FILE__,__LINE__);
		while(event_base_loopbreak(_op->base) < 0)
			usleep(100);
		pthread_kill(_op->thread.thread_id, SIGUSR1);
		pthread_join(_op->thread.thread_id, &retval);
		printf ("%s %d oplog thread[%x] exit,status=%s\n",__FILE__,__LINE__, (unsigned int)_op->thread.thread_id, (char*)retval);
		pthread_attr_destroy(&_op->thread.thread_attr);
	}

	if(_op->base) {
		printf ("%s %d oplog pthread_kill [%d],break=%d\n",__FILE__,__LINE__, SIGUSR1, event_base_got_break(_op->base));
		if (_op->ev)
			event_free(_op->ev);
		event_base_free(_op->base);
	}

	if(_op->recv.disk_run) {
		_op->recv.disk_run = 0;
		pthread_mutex_lock(&_op->recv.lock);
		pthread_cond_broadcast(&_op->recv.cont);
		pthread_mutex_unlock(&_op->recv.lock);
		for (i = 0; i < LOG_DISK_THREAD_NUM;i++) {
			if (_op->thread.disk_thread_id[i]) {
				pthread_join(_op->thread.disk_thread_id[i], &retval);
				printf ("%s %d oplog thread[%x] exit,status=%s\n",__FILE__,__LINE__, (unsigned int)_op->thread.disk_thread_id[i], (char*)retval);
				pthread_attr_destroy(&_op->thread.disk_thread_attr[i]);
			}
		}
	}
	
	if (_op->send.send_fd)
		close(_op->send.send_fd);

	if(_op->sock.sock_fd)
		close(_op->sock.sock_fd);

	pthread_cond_destroy(&_op->recv.cont);

	pthread_mutex_destroy(&_op->send.lock);
	
	pthread_mutex_destroy(&_op->recv.lock);

	pthread_condattr_destroy(&_op->recv.cont_attr);
	
	pthread_mutexattr_destroy(&_op->send.attr);
	
	pthread_mutexattr_destroy(&_op->recv.attr);


	free(_op);
	_op = NULL;
	self = NULL;

	printf ("%s %d oplog exit over\n",__FILE__,__LINE__);

	return;
}

static void log_write(unsigned char *buf, unsigned int size)
{
	sendto(self->send.send_fd, buf, size, 0, (struct sockaddr *)&self->send.send_addr, sizeof(self->send.send_addr));
	return;
}

static void log_write_ex(unsigned char *buf, unsigned int size)
{
	sendto(log_send_ex.send_fd, buf, size, 0, (struct sockaddr *)&log_send_ex.send_addr, sizeof(log_send_ex.send_addr));
	return;
}

void oplog_print(int log_type, char *file, const char *function, int line, int level, const char *fmt, ...)
{
	va_list args;
	size_t size = 0;
	struct _log_send_header *head =NULL;

	if (!self)
		return;

	va_start(args, fmt);
	pthread_mutex_lock(&self->send.lock);
	head = (struct _log_send_header *)self->send.buf_send;
	op_strlcpy(head->file, file, sizeof(head->file));
	op_strlcpy(head->function, function, sizeof(head->function));
	head->line = htonl(line);
	head->level = htonl(level);
	head->type = htonl(log_type);
	size = vsnprintf((char*)(self->send.buf_send+sizeof(*head)), LOG_BUF_SIZE-sizeof(*head), fmt, args);
	log_write(self->send.buf_send,size+sizeof(*head));
	pthread_mutex_unlock(&self->send.lock);
	va_end(args);

	return;
}

void oplog_print_ex(int log_type, char *file, const char *function, int line, int level, const char *fmt, ...)
{
	static int oplog_ex_init = 0;
	
	va_list args;
	size_t size = 0;
	struct _log_send_header *head =NULL;
	
	if (!oplog_ex_init) {
		if (oplog_init_ex() < 0) {
			printf ("%s %d oplog_init_ex init failed\n",__FILE__,__LINE__);
			return;
		}

		oplog_ex_init = 1;
	}

	va_start(args, fmt);
	pthread_mutex_lock(&log_send_ex.lock);
	head = (struct _log_send_header *)log_send_ex.buf_send;
	op_strlcpy(head->file, file, sizeof(head->file));
	op_strlcpy(head->function, function, sizeof(head->function));
	head->line = htonl(line);
	head->level = htonl(level);
	head->type = htonl(log_type);
	size = vsnprintf((char*)(log_send_ex.buf_send+sizeof(*head)), LOG_BUF_SIZE-sizeof(*head), fmt, args);
	log_write_ex(log_send_ex.buf_send,size+sizeof(*head));
	pthread_mutex_unlock(&log_send_ex.lock);
	va_end(args);
	return;
}


