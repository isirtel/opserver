#include <errno.h>
#include <stdlib.h>
#include <pthread.h>

#include "event.h"

#include "op4g.h"
#include "base/oplog.h"

#include "u9300.h"
#include "iniparser.h"
#include "config.h"
#include "op4g_handle.h"

#include "opbox/utils.h"
#include "_4g_pdu.h"
#include "op4g_bus.h"
#include "base/oprpc.h"

#define _4G_DEV "op4G:dev"
#define _4G_CENTER_MESSAGE "op4G:message_centor"

#define _4G_READ_BUF_SIZE 2048

enum {
	MODULE_U9300,
};

typedef int (*module_init) (int fd, char*, struct _4g_module_init *);
typedef void (*module_exit) (void);

typedef int (*module_uart) (int fd, unsigned int event_type, struct _4g_uart_handle *handle);
typedef int (*module_interface)(int fd, unsigned int event_type, struct _4g_iface_handle *iface);

struct _4g_module_support {
	int vendor_id;
	int product_id;
	module_init init;
	module_exit exit;
	module_uart uart_handle;
	module_interface iface;
	
};

struct _4g_module_support module_support[] = {
	[MODULE_U9300] = {.vendor_id = 0x1c9e, .product_id= 0x9b3c, .init = u9300_init, .exit = u9300_exit, .uart_handle = u9300_uart_handle, .iface = u9300_interface},
};

struct _4g_thread_ 
{
	pthread_t thread_id;
	pthread_attr_t thread_attr;
};

struct _4g_uart {
	int fd;
	char dev_name[64];
};

struct _4g_buf {
	unsigned char bf[_4G_READ_BUF_SIZE];
	unsigned int index;
};

struct _op4g_struct {
	struct _4g_module_support *module;
	struct _4g_uart uart;
	struct event_base *base;
	struct event *ev;
	struct _4g_thread_ thread;
	pthread_mutex_t lock;
	pthread_mutexattr_t attr;
	struct _4g_buf buf;
	char center_message[64];
};

static struct _op4g_struct *self = NULL;

static struct _4g_module_support * op4g_get_vid_pid(int *vendor_id, int *produce_id)
{
	int i = 0;
	int len = 0;
	int vid = 0;
	int pid = 0;

	len = sizeof(module_support)/sizeof(module_support[0]);

	vid = 0x1c9e;
	pid = 0x9b3c;

	for (i = 0; i < len; i++) {
		if (module_support[i].vendor_id != vid ||  module_support[i].product_id != pid)
			continue;

		*vendor_id = vid;
		*produce_id = pid;
		return &module_support[i];
	}

	return NULL;
}

static void op4g_job(evutil_socket_t fd,short what,void* arg)
{
	struct _4g_module_support *module = NULL;
	int ret = 0;
	int event = 0;

	struct _4g_uart_handle handle_param;
	memset(&handle_param, 0, sizeof(handle_param));

	if (self->buf.index >= _4G_READ_BUF_SIZE-1)
		self->buf.index = 0;

	ret = read(fd, self->buf.bf+self->buf.index, _4G_READ_BUF_SIZE-self->buf.index-1);
	if (what == EV_READ && !ret) {
		log_warn("op4g free fd[%d], dev may drop\n", fd);
		close(fd);
		event_del(self->ev);
		goto out;
	}
	self->buf.index += ret;
	self->buf.bf[self->buf.index] = 0;
	
	log_debug("4g response: %s\n", self->buf.bf);
	module = (struct _4g_module_support *)arg;
	if (!module) {
		log_warn("module is unvalid\n");
		goto out;
	}

	handle_param.req = NULL;
	handle_param.req_size = 0;
	handle_param.resp = self->buf.bf;
	handle_param.resp_size = self->buf.index;
	event = _4G_EVENT_READ;

	event = module->uart_handle(fd, event, &handle_param);
	switch (event) {
		case _4G_EVENT_MORE:
			break;
		case _4G_EVENT_NONE:
		case _4G_EVENT_NEXT:
		default:
			self->buf.index = 0;
			break;
	}

out:
	return;
}

static void *op4g_routine (void *arg)
{
	if(event_base_loop(arg, EVLOOP_NO_EXIT_ON_EMPTY) < 0) {
		log_error ("op4g_routine failed\n");
		pthread_detach(pthread_self());
		pthread_exit(NULL);
		goto exit;
	}

	log_debug ("op4g_routine exit\n");
exit:
	return NULL;
}

void op4g_rpc_register (void)
{
	op_tipc_register(tipc_opserver_send_quotes,_4g_send_quotes);

	op_local_register(tipc_opserver_send_quotes,_4g_send_quotes);
	return;
}
void *op4g_init(void)
{
	struct _op4g_struct *_4g = NULL;
	const char *str = NULL;
	dictionary *dict = NULL;
	int vendor_id = 0;
	int product_id = 0;
	struct _4g_module_init module_param;
	
	memset(&module_param , 0, sizeof(module_param));
	_4g = calloc(1, sizeof(*_4g));
	if (!_4g) {
		log_error("calloc failed[%d]\n", errno);
		goto exit;
	}

	self = _4g;

	dict = iniparser_load(OPSERVER_CONF);
	if (!dict) {
		log_error ("iniparser_load faild[%s]\n", OPSERVER_CONF);
		goto exit;
	}

	if(!(str = iniparser_getstring(dict,_4G_DEV,NULL))) {
		log_error ("iniparser_getstring faild[%s]\n", _4G_DEV);
		iniparser_freedict(dict);
		goto exit;
	}

	log_info("op4g: dev(%s)\n",str);

	op_strlcpy(_4g->uart.dev_name, str, sizeof(_4g->uart.dev_name));

	if(!(str = iniparser_getstring(dict,_4G_CENTER_MESSAGE,NULL))) {
		log_error ("iniparser_getstring faild[%s]\n", _4G_CENTER_MESSAGE);
		iniparser_freedict(dict);
		goto exit;
	}

	op_strlcpy(_4g->center_message, str, sizeof(_4g->center_message));
	iniparser_freedict(dict);

	_4g->uart.fd = uart_open(_4g->uart.dev_name);
	
	if (_4g->uart.fd < 0) {
		log_error ("uart_open faild[%s]\n", _4g->uart.dev_name);
		goto exit;
	}

	if (!(_4g->module = op4g_get_vid_pid(&vendor_id, &product_id))) {
		log_error("get vendor and product id failed failed\n");
		goto exit;
	}

	log_info("op4g: vendor_id=%x, product_id=%x\n", vendor_id, product_id);

	_4g->base = event_base_new();
	if (!_4g->base) {
		log_error ("event_base_new faild\n");
		goto exit;
	}

	_4g->ev = event_new(_4g->base,_4g->uart.fd, EV_READ|EV_PERSIST, op4g_job, _4g->module);
	if(!_4g->ev) {
		log_error ("event_new faild\n");
		goto exit;
	}

	if(event_add(_4g->ev, NULL) < 0) {
		log_error ("event_add faild\n");
		goto exit;
	}

	if(pthread_mutexattr_init(&_4g->attr)) {
		log_error ("pthread_mutexattr_init faild\n");
		goto exit;
	}

	if(pthread_mutex_init(&_4g->lock, &_4g->attr)) {
		log_error ("pthread_mutex_init faild\n");
		goto exit;
	}

	if(pthread_attr_init(&_4g->thread.thread_attr)) {
		log_error ("pthread_attr_init faild\n");
		goto exit;
	}

	if(pthread_create(&_4g->thread.thread_id, &_4g->thread.thread_attr, op4g_routine, _4g->base)) {
		log_error ("pthread_create faild\n");
		goto exit;
	}

	op4g_rpc_register();

	module_param.base = _4g->base;
	module_param.thread_id = _4g->thread.thread_id;
	if (_4g->module->init(_4g->uart.fd, _4g->center_message, &module_param) < 0) {
		log_error("op4g: module init failed\n");
		goto exit;
	}

	return _4g;

exit:
	op4g_exit(_4g);
	return NULL;
}

void op4g_send_message(char *phone_num, char *message)
{
	log_debug("[%s]send message\n",phone_num);
	struct _op4g_struct *_4g = self;
	struct _4g_iface_handle iface;
	memset(&iface, 0, sizeof(iface));
	iface.req[0] = phone_num;
	iface.req[1] = message;

	if (!self) {
		log_warn("4g module should init first\n");
		return;
	}
	_4g->module->iface(_4g->uart.fd, _4G_EVENT_SEND_MESSAGE, &iface);
	return;
}

void op4g_send_message_ex(char *phone_num, const char *fmt, ...)
{
	va_list args;
	char message[1024] = {};
	
	va_start(args, fmt);
	vsnprintf((char*)message, sizeof(message), fmt, args);
	va_end(args);
	op4g_send_message(phone_num, message);
	return;
}

void op4g_exit(void *_4g)
{
	self= NULL;
	return;
}


