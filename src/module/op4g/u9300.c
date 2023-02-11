#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <unistd.h>
#include <signal.h>

#include "event.h"
#include "u9300.h"
#include "base/oplog.h"
#include "opbox/list.h"
#include "opbox/utils.h"
#include "_4g_pdu.h"

#define _4G_WAIT_MS 3000
struct _4g_timer {
	struct event *at_cmd;
	struct event *at_no_response;
};

struct _u9300_struct {
	int fd;
	pthread_mutex_t lock;
	pthread_mutexattr_t attr;
	pthread_cond_t cont;
	pthread_condattr_t cont_attr;
	struct list_head list;
	struct _4g_cmd *current;
	char short_message[_4G_MESSAGE_SIZE];
	size_t short_message_size;
	char center_message[64];
	struct _4g_timer timer;
	struct _4g_module_init param;
};

static struct _u9300_struct *self = NULL;

static int u9300_cmd_vendor_name(struct _4g_cmd *cmd, unsigned char *resp, int resp_size);

static int u9300_cmd_module_type(struct _4g_cmd *cmd, unsigned char *resp, int resp_size);

static int u9300_cmd_message(struct _4g_cmd *cmd, unsigned char *resp, int resp_size);
static int u9300_cmd_message_content(struct _4g_cmd *cmd, unsigned char *resp, int resp_size);



struct _4g_cmd u9300_cmd [_4G_CMD_MAX] = {
	[_4G_CMD_AT_TEST] = {.at = "AT\r", .at_cmd_cb = NULL},
	[_4G_CMD_AT_CFUN_OFF] = {.at = "AT+CFUN=0\r", .at_cmd_cb = NULL},
	[_4G_CMD_AT_CFUN_ON] = {.at = "AT+CFUN=1\r", .at_cmd_cb = NULL},

	[_4G_CMD_VENDOR_NAME] = {.at = "AT+CGMI\r", .at_cmd_cb = u9300_cmd_vendor_name},
	[_4G_CMD_MODULE_TYPE] = {.at = "AT+CGMM\r", .at_cmd_cb = u9300_cmd_module_type},
	[_4G_CMD_MODULE_IMEI] = {.at = "AT+CGSN\r", .at_cmd_cb = NULL},
	[_4G_MESSAGE_SET_TEXT] = {.at = "AT+CMGF=1\r", .at_cmd_cb = NULL},
	[_4G_MESSAGE_SET_PDU] = {.at = "AT+CMGF=0\r", .at_cmd_cb = NULL},
	[_4G_MESSAGE_SET_ENCODE] = {.at = "AT+CSCS=\"UCS2\"\r", .at_cmd_cb = NULL},
	[_4G_MESSAGE_SET_TEXT_PARAM] = {.at = "AT+CSMP=17,71,0,8\r", .at_cmd_cb = NULL},
	[_4G_MESSAGE_SEND] = {.at = NULL, .at_cmd_cb = u9300_cmd_message, .cmd = _4G_MESSAGE_SEND},
	[_4G_MESSAGE_SEND_CONTENT] = {.at = NULL, .at_cmd_cb = u9300_cmd_message_content, .cmd = _4G_MESSAGE_SEND_CONTENT},
	[_4G_AT_TMP] = {.at = NULL},
};

static void u9300_add_cmd(unsigned int cmd)
{
	if (cmd >= _4G_CMD_MAX || !u9300_cmd[cmd].at) {
		log_warn("cmd not support[cmd=%d]\n", cmd);
		goto exit;
	}

	list_add_tail(&u9300_cmd[cmd].list, &self->list);

exit:
	return;
}

static void u9300_set_at_cmd(unsigned int cmd, char*at_cmd, int size)
{
	if (cmd >= _4G_CMD_MAX) {
		log_warn("cmd not support[cmd=%d]\n", cmd);
		goto exit;
	}

	u9300_cmd[cmd].at_size =size;

	if (cmd == _4G_MESSAGE_SEND) {
		if (u9300_cmd[cmd].at) {
			free(u9300_cmd[cmd].at);
			u9300_cmd[cmd].at = NULL;
		}
	}

	u9300_cmd[cmd].at = at_cmd;

exit:
	return;
}

char* u9300_get_cmd(unsigned int cmd)
{
	if (cmd >= _4G_CMD_MAX || !u9300_cmd[cmd].at) {
		log_warn("cmd not support[cmd=%d]\n", cmd);
		goto exit;
	}

	return u9300_cmd[cmd].at;
exit:
	return NULL;
}

static int u9300_write_cmd()
{
	struct _4g_cmd *item = NULL;
	int ret = 0;
	int size = 0;
	 struct timeval tv;
	pthread_mutex_lock(&self->lock);
	if (list_empty(&self->list))
		goto out;

	item = list_first_entry(&self->list, struct _4g_cmd , list);
	
	size = item->at_size?item->at_size:(int)strlen(item->at);
	self->current = item;
	log_debug("4g write[%d],size=%d cmd=%s\n" ,self->fd, size,item->at);
	ret = write(self->fd, item->at, size);
	if (ret < 0) {
		log_warn("write failed [cmd=%s][errno]\n", item->at, errno);
		goto out;
	}

	tv.tv_sec = _4G_WAIT_NO_RESPONSE_MS/1000;
	tv.tv_usec = 0;
	event_add(self->timer.at_no_response, &tv);
	pthread_kill(self->param.thread_id, SIGUSR1);
out:
	pthread_mutex_unlock(&self->lock);
	return 0;
}

int u9300_cmd_vendor_name(struct _4g_cmd *cmd, unsigned char *resp, int resp_size)
{

	return 0;
}

int u9300_cmd_module_type(struct _4g_cmd *cmd, unsigned char *resp, int resp_size)
{

	return 0;
}

int u9300_cmd_message(struct _4g_cmd *cmd, unsigned char *resp, int resp_size)
{

	log_debug("u9300 send message\n");

	struct _u9300_struct *u = self;

	u9300_set_at_cmd(_4G_MESSAGE_SEND_CONTENT, u->short_message, u->short_message_size);
	u9300_add_cmd(_4G_MESSAGE_SEND_CONTENT);

	return 0;
}

int u9300_cmd_message_content(struct _4g_cmd *cmd, unsigned char *resp, int resp_size)
{
	log_debug("u9300 message content handle:%s\n", resp);
	if (!strstr((char*)resp, "OK"))
		return -1;

	return 0;
}

static  void u9300_atcmd_timeout(evutil_socket_t fd , short what, void *arg)
{
	struct _u9300_struct *u = self;
	struct _4g_cmd *item = NULL;

	if (!u->current || list_empty(&u->list))
		return;
	log_warn("cmd current is timeout, release it :%s\n", u->current->at);
	while(!list_empty(&u->list)) {
		item = list_first_entry(&u->list, struct _4g_cmd , list);
		list_del(&item->list);
	}
	pthread_cond_signal(&u->cont);
	u->current = NULL;
	pthread_mutex_unlock(&u->lock);

	log_warn("cmd current is timeout, release over\n");

	return;
}

static  void u9300_atcmd_no_respobse(evutil_socket_t fd , short what, void *arg)
{
	struct _u9300_struct *u = self;
	int ret = 0;
	int size = 0;

	if (!u->current || list_empty(&u->list))
		return;

	log_debug("atcmd_no_respobse, try send again [cmd=%s]\n", u->current->at);

	size = u->current->at_size?u->current->at_size:(int)strlen(u->current->at);

	ret = write(u->fd, u->current->at, size);
	if (ret < 0) {
		log_warn("write failed [cmd=%s][errno]\n", u->current->at, errno);
		return;
	}
	
	return;

}


int u9300_init(int fd, char*center_message, struct _4g_module_init * param)
{
	struct _u9300_struct *u = NULL;
	int i = 0;
	int len = 0;

	log_debug("u9300 init\n");

	u = calloc(1, sizeof(*u));
	if (!u) {
		log_error("calloc failed[%d]\n", errno);
		goto exit;
	}
	
	u->fd = fd;
	self = u;

	memcpy(&u->param, param, sizeof(u->param));
	op_strlcpy(u->center_message,center_message, sizeof(u->center_message));
	if(pthread_mutexattr_init(&u->attr)) {
		log_error ("pthread_mutexattr_init faild\n");
		goto exit;
	}

	if(pthread_mutex_init(&u->lock, &u->attr)) {
		log_error ("pthread_mutex_init faild\n");
		goto exit;
	}

	if(pthread_condattr_init(&u->cont_attr)) {
		log_error ("pthread_rwlockattr_init faild\n");
		goto exit;
	}

	if(pthread_cond_init(&u->cont, &u->cont_attr)) {
		log_error (" pthread_rwlock_init faild\n");
		goto exit;
	}

	INIT_LIST_HEAD(&u->list);

	u->timer.at_cmd = evtimer_new(u->param.base, u9300_atcmd_timeout, NULL);
	if (!u->timer.at_cmd) {
		log_error (" evtimer_newfaild\n");
		goto exit;
	}

	u->timer.at_no_response = evtimer_new(u->param.base, u9300_atcmd_no_respobse, NULL);
	if (!u->timer.at_cmd) {
		log_error (" evtimer_newfaild\n");
		goto exit;
	}

	len = sizeof(u9300_cmd)/sizeof(u9300_cmd[0]);

	for (i = 0; i < len; i++)
		INIT_LIST_HEAD(&u9300_cmd[i].list);


	pthread_mutex_lock(&u->lock);
	//u9300_add_cmd(_4G_CMD_AT_TEST);
	u9300_add_cmd(_4G_CMD_VENDOR_NAME);
	u9300_add_cmd(_4G_CMD_MODULE_TYPE);
	u9300_add_cmd(_4G_CMD_MODULE_IMEI);
	u9300_add_cmd(_4G_MESSAGE_SET_PDU);
	u9300_add_cmd(_4G_MESSAGE_SET_ENCODE);
	pthread_mutex_unlock(&u->lock);

	u9300_write_cmd();

	return 0;

exit:
	u9300_exit();
	return -1;
}

static int u9300_is_at_cmd_ok(struct _4g_cmd *item, unsigned char *at, int at_size)
{
	int i = 0 ;
	for (i =0 ; i < at_size; i++) {
		if (at[i] == 0x0d && (i+1 < at_size && at[i+1] == 0x0a))
			 return 1;
	}

	return 0;
}

int u9300_uart_handle(int fd, unsigned int event_type, struct _4g_uart_handle *handle)
{
	struct _4g_cmd *item = NULL;
	struct _u9300_struct *u = self;
	int size = 0;
	int ret = 0;
	struct timeval tv;

	pthread_mutex_lock(&u->lock);

	if (list_empty(&u->list) || !u->current)
		goto NONE;

	event_del(u->timer.at_no_response);

	log_debug("u9300 resp: %s\n", handle->resp);

	if (!u9300_is_at_cmd_ok(u->current, handle->resp,handle->resp_size))
		goto MORE;

	log_debug("u9300 try call cb\n");
	if (u->current->at_cmd_cb)
		ret = u->current->at_cmd_cb(u->current, handle->resp, handle->resp_size);

	if (ret < 0) {
		log_debug("add timer wait timeout for cmd:%s\n",u->current->at);
		tv.tv_sec = _4G_WAIT_RESPONSE_ERROR/1000;
		tv.tv_usec = 0;
		event_add(u->timer.at_cmd, &tv);
		pthread_kill(u->param.thread_id, SIGUSR1);
		goto MORE;
	}

	event_del(u->timer.at_cmd);

	log_debug("delete cmd:%s\n",u->current->at);

	list_del(&u->current->list);

	if (list_empty(&u->list))
		goto NONE;

	u->current->at_size = 0;

	item = list_first_entry(&u->list, struct _4g_cmd , list);

	u->current = item;
	
	size = item->at_size?item->at_size:(int)strlen(item->at);
	log_debug("4g write[%d],size=%d, cmd=%s\n" ,u->fd, size, item->at);
	if (write(u->fd, item->at, size) < 0) {
		log_warn("write failed [cmd=%s][errno]\n", item->at, errno);
		goto NONE;
	}

	tv.tv_sec = 7;
	tv.tv_usec = 0;
	event_add(u->timer.at_no_response, &tv);

	pthread_mutex_unlock(&u->lock);
	return _4G_EVENT_NEXT;
NONE:
	
	pthread_cond_signal(&u->cont);
	u->current = NULL;
	pthread_mutex_unlock(&u->lock);
	return _4G_EVENT_NONE;
MORE:
	pthread_mutex_unlock(&u->lock);
	return _4G_EVENT_MORE;
}

static int u9300_send_message(char *phone, char *message)
{
	struct _u9300_struct *u = self;
	#define SET_MESSGASE_SEND_SIZE 64
	int count = 0;
	struct timeval now;
	struct timespec abstime;
	int ret = 0;
	
	gettimeofday(&now, NULL);
	abstime.tv_sec = now.tv_sec + _4G_WAIT_MS/1000;
	abstime.tv_nsec = now.tv_usec * 1000;

	log_debug("u9300 try send message,phone:%s, message=%s\n", phone, message);

	char *at_cmd = calloc(1, SET_MESSGASE_SEND_SIZE); /* phone null */
	if (!at_cmd) {
		log_warn("calloc[errno]\n", errno);
		return -1;
	}

	pthread_mutex_lock(&u->lock);
	if (!list_empty(&u->list)) {
		log_debug("u9300_send_message, list is not empty, wait\n");
		ret = pthread_cond_timedwait(&u->cont, &u->lock, &abstime);
		if (ret == ETIMEDOUT) {
			pthread_mutex_unlock(&u->lock);
			free(at_cmd);
			log_warn("u9300 wait send message failed\n");
			goto out;
		}
	}

	log_debug("u9300_send_message, list is empty, wait over\n");

	u->short_message_size =  message_ucs2_combi_mesage(u->center_message, phone, message, u->short_message, sizeof(u->short_message), &count);
	snprintf(at_cmd, SET_MESSGASE_SEND_SIZE, "AT+CMGS=%02d\r", count);
	u9300_set_at_cmd(_4G_MESSAGE_SEND, at_cmd, 0);
	u9300_add_cmd(_4G_MESSAGE_SEND);
	pthread_mutex_unlock(&u->lock);
	u9300_write_cmd();
out:
	return 0;
}

int u9300_interface(int fd, unsigned int event_type, struct _4g_iface_handle *iface)
{

	switch (event_type){
		case _4G_EVENT_SEND_MESSAGE:
			return u9300_send_message(iface->req[0], iface->req[1]);

		default:
			break;
	}

	return 0;
}

void u9300_exit(void)
{
	return;
}


