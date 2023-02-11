#include <errno.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>

#include "oprpc.h"
#include "opmem.h"
#include "oplog.h"
#include "event.h"
#include "tipcc.h"
#include "opbox/hash.h"
#include "opbox/usock.h"

#define TIPC_HEAD_PREFIX_VALUE 0xeefe3451
#define TIPC_WAIT_TIMEOUT_MS 9000

struct _rpc_tipc_thread_ 
{
	pthread_t thread_id;
	pthread_attr_t thread_attr;
};

struct _tipc_header {
	unsigned int prefix;
	unsigned int module;
	unsigned int type;
	unsigned int data_size;
};

#define TIPC_HEADER_SIZE sizeof(struct _tipc_header)

enum TIPC_EVENT {
	TIPC_EVENT_RECV_HEAD =1 ,
	TIPC_EVENT_RECV_CONTENT,
};

struct _tipc_client {
	int fd;
	struct sockaddr_in in;
	struct bufferevent *buffer;
	struct _tipc_header head;
	unsigned char req_content[RPC_REQ_SIZE];
	unsigned char response_content[RPC_RESPONSE_SIZE];
	unsigned int water_level;
	unsigned int event_type;
};

struct _op_tipc {
	int tipc_fd;
	struct sockaddr_tipc sa;
	struct event_base *base;
	struct event *ev;
	struct _rpc_tipc_thread_ thread;
	rpc_cb cb[RPC_MAX_ELEMENT];
	void *client_hash;
	unsigned int module;
};

struct _op_local_rpc {
	pthread_mutex_t lock;
	pthread_mutexattr_t attr;
	rpc_cb cb[RPC_MAX_ELEMENT];
	unsigned int module;
};


static struct _op_tipc *tipc_self = NULL;
static struct _op_local_rpc *local_self = NULL;

void op_tipc_exit(struct _op_tipc *tipc)
{
	if (!tipc)
		return;

	return;
}

static void *rpc_tipc_routine (void *arg)
{
	if(event_base_loop(arg, EVLOOP_NO_EXIT_ON_EMPTY) < 0) {
		log_warn_ex ("thread routine failed\n");
		pthread_detach(pthread_self());
		pthread_exit(NULL);
		goto exit;
	}

	log_debug_ex ("thread routine exit\n");
exit:
	return NULL;
}

static void rpc_free_client(struct _tipc_client *client)
{
	if (!client)
		return;

	if (client->fd)
		close(client->fd);

	if (client->buffer)
		bufferevent_free(client->buffer);

	op_hash_delete(tipc_self->client_hash, client);

	op_free(client);
	return;
}

static void tipc_buffer_flush(struct evbuffer *evb, struct bufferevent *bev)
{
	char buf[1024] = {};
	size_t size = 0;
	size = evbuffer_get_length(evb);

	while(size > 0) {
		bufferevent_read(bev, buf, sizeof(buf));
		size = evbuffer_get_length(evb);
	}

	return;
}

static void tipc_header_hton(struct _tipc_header *head)
{
	head->prefix = htonl(head->prefix);
	head->type = htonl(head->type);
	head->module = htonl(head->module);
	head->data_size = htonl(head->data_size);
	return;
}

static void tipc_header_ntoh(struct _tipc_header *head)
{
	head->prefix = ntohl(head->prefix);
	head->type = ntohl(head->type);
	head->module = ntohl(head->module);
	head->data_size = ntohl(head->data_size);
	return;
}

static void tipc_read(struct bufferevent *bev, void *ctx)
{
	struct _op_tipc *tipc = NULL;
	tipc = tipc_self;

	struct evbuffer *evb = NULL;
	struct _tipc_client *client = NULL;
	client = (struct _tipc_client *)ctx;
	size_t size = 0;
	size_t length = 0;
	int ret;
	int fd = 0;

	if (!bev || !client) {
		log_warn_ex("tipc read: parameter is null\n");
		sleep(1);
		return;
	}

	evb = bufferevent_get_input(bev);

	length = evbuffer_get_length(evb);
	fd = bufferevent_getfd(bev);

_recv:
	if (client->event_type == TIPC_EVENT_RECV_HEAD) {
		size = bufferevent_read(bev, &client->head, client->water_level);
		if (size != client->water_level) {
			log_warn_ex("bufferevent_read size not support, read size=%u, water_level=%u\n", (unsigned int)size, (unsigned int)client->water_level);
			goto out;
		}

		tipc_header_ntoh(&client->head);
		if (client->head.prefix != TIPC_HEAD_PREFIX_VALUE) {
			log_warn_ex("prefix not support: %x\n", client->head.prefix);
			goto out;
		}

		if (client->head.data_size > RPC_REQ_SIZE) {
			log_warn_ex("data size too larger\n", client->head.data_size);
			goto out;
		}

		client->event_type = TIPC_EVENT_RECV_CONTENT;
		client->water_level = client->head.data_size;
		if (length - size >= client->head.data_size) {
			log_debug_ex("recv complete\n");
			goto _recv;
		}
	} else if (client->event_type == TIPC_EVENT_RECV_CONTENT)  {
			if (!client->water_level)
				size = 0;
			else {
				size = bufferevent_read(bev, client->req_content, client->water_level);
				if (size != client->water_level) {
					log_warn_ex("bufferevent_read size not support, read size=%u, water_level=%u\n", (unsigned int)size, (unsigned int)client->water_level);
					goto out;
				}
			}

			if (client->head.module != tipc->module) {
				log_warn_ex("not support module, register: %u, get module:%u\n", tipc->module, client->head.module);
				goto out;
			}

			if (client->head.type >= RPC_MAX_ELEMENT) {
				log_warn_ex("not support type, get module: %u, get type:%u\n", client->head.module, client->head.type);
				goto out;
			}

			if (!tipc->cb[client->head.type]) {
				log_warn_ex("not support type, get module: %u, get type:%u, type not register\n", client->head.module, client->head.type);
				goto out;
			}

			ret = tipc->cb[client->head.type](client->req_content, client->water_level, client->response_content, RPC_RESPONSE_SIZE);
			if (ret < 0)
				ret = 0;

			if (ret > RPC_RESPONSE_SIZE) {
				log_warn_ex("not support type, get module: %u, get type:%u, response size [%d] too large\n", client->head.module, client->head.type, ret);
				goto out;
			}
			
			log_debug_ex("tipc server response : size = %d\n", ret);

			client->head.data_size = (unsigned int)ret;
			tipc_header_hton(&client->head);
			write(fd, &client->head, sizeof(client->head));
			if (ret)
				write(fd, client->response_content, ret);
			log_debug_ex("tipc server response over: wait next request\n");
			goto out;
	} else {
		log_warn_ex("not support event type:%u", client->event_type);
		goto out;
	}

	return;
out:
	client->event_type = TIPC_EVENT_RECV_HEAD;
	client->water_level = TIPC_HEADER_SIZE;
	tipc_buffer_flush(evb, bev);
	return;
}

static void tipc_event(struct bufferevent *bev, short what, void *ctx)
{
	struct _tipc_client *client = NULL;

	client = (struct _tipc_client *)ctx;

	if (!bev || !client) {
		log_warn_ex("tipc_event failed, parameter is null\n");
		sleep(1);
		return;
	}
	
	if (what & (BEV_EVENT_ERROR|BEV_EVENT_EOF)) {
		log_debug_ex("tipc_event client disconnect, fd= %d\n", client->fd);
		rpc_free_client(client);
		return;
	}

	return;
}

static void rpc_tipc_accept__dispatch(evutil_socket_t fd,short what,void* arg)
{
	struct _op_tipc *tipc = NULL;
	int client_fd;
	struct sockaddr_in in;
	struct _tipc_client *client = NULL;
	int sock_len = 0;
	tipc = (struct _op_tipc *)arg;
	if (!tipc) {
		log_warn_ex ("rpc_tipc_dispatch parameter is null\n");
		goto out;
	}

	memset(&in, 0, sizeof(in));
	client_fd = accept(fd, (struct sockaddr *)&in, (socklen_t*)&sock_len);
	if (client_fd < 0) {
		log_warn_ex ("accept failed, errno%d\n", errno);
		sleep(1);
		goto out;
	}

	client = op_calloc(1, sizeof(struct _tipc_client));
	if (!client) {
		log_warn_ex ("op_calloc failed\n");
		goto out;
	}

	client->fd = client_fd;

	memcpy(&client->in, &in, sizeof(client->in));
	client->buffer = bufferevent_socket_new(tipc->base, client_fd, 0);
	if (!client->buffer) {
		log_warn_ex ("bufferevent_socket_new failed\n");
		goto out;
	}

	client->water_level =TIPC_HEADER_SIZE;
	client->event_type = TIPC_EVENT_RECV_HEAD;

	bufferevent_setcb(client->buffer, tipc_read, NULL, tipc_event, client);
	bufferevent_setwatermark(client->buffer, EV_READ, client->water_level, 0);
	bufferevent_enable(client->buffer, EV_READ);
	op_hash_insert(tipc->client_hash, client);

	log_debug_ex ("tipc accept client, fd=%d\n", client_fd);

	return;
out:
	rpc_free_client(client);
	return;
}

static unsigned long tipc_hash(const void *node)
{
	struct _tipc_client *client = NULL;
	client = (struct _tipc_client *)node;
	if (!client) {
		log_warn_ex("tipc hash : parameter is null\n");
		return 0;
	}

	return client->fd;
}

static int tipc_compare(const void *hash_node, const void *dest)
{
	struct _tipc_client *client = (struct _tipc_client *)hash_node;

	int * fd_dest = (int *)dest;
	if (!client || !fd_dest) {
		log_warn_ex("tipc compare : parameter is null\n");
		return 1;
	}

	return !(client->fd == *fd_dest);
}

int op_tipc_init(unsigned int module)
{
	log_debug_ex("tipc try register, module=%u\n", module);

	struct _op_tipc *tipc = NULL;
	tipc = op_calloc(1, sizeof(struct _op_tipc));
	if (!tipc) {
		log_warn_ex("tipc init failed, module=%u\n", module);
		goto out;
	}

	tipc->tipc_fd = tipc_socket(SOCK_STREAM);
	if (tipc->tipc_fd < 0) {
		log_warn_ex("tipc_socket failed, module=%u, errno=%d\n", module, errno);
		goto out;
	}

	tipc->sa.family = AF_TIPC;
	tipc->sa.addrtype = TIPC_ADDR_NAME;
	tipc->sa.addr.name.name.type = module;
	tipc->sa.addr.name.name.instance = 0;
	tipc->sa.addr.name.domain = 0;
	tipc->sa.scope = TIPC_ZONE_SCOPE;

	
	if (bind(tipc->tipc_fd, (struct sockaddr *)&tipc->sa, sizeof(tipc->sa)) < 0) {
		log_warn_ex("bind failed, module=%u, errno=%d\n", module, errno);
		goto out;
	}

	if (listen(tipc->tipc_fd, 5) < 0) {
		log_warn_ex("listen failed, module=%u, errno=%d\n", module, errno);
		goto out;
	}
	
	tipc->base = event_base_new();
	if (!tipc->base) {
		log_warn_ex ("event_base_new failed\n");
		goto out;
	}

	tipc->ev = event_new(tipc->base,tipc->tipc_fd, EV_READ|EV_PERSIST, rpc_tipc_accept__dispatch, tipc);
	if(!tipc->ev) {
		log_warn_ex ("event_new faild\n");
		goto out;
	}

	if(event_add(tipc->ev, NULL) < 0) {
		log_warn_ex ("event_add faild\n");
		goto out;
	}

	if(pthread_attr_init(&tipc->thread.thread_attr)) {
		log_warn_ex ("pthread_attr_init faild\n");
		goto out;
	}

	if(pthread_create(&tipc->thread.thread_id, &tipc->thread.thread_attr, rpc_tipc_routine, tipc->base)) {
		log_warn_ex ("pthread_create faild\n");
		goto out;
	}

	tipc->client_hash = op_hash_new(tipc_hash, tipc_compare);
	if (!tipc->client_hash) {
		log_warn_ex ("op_hash_new faild\n");
		goto out;
	}

	log_debug_ex ("op tipc init success\n");
	tipc->module = module;

	tipc_self = tipc;
	return 0;
out:
	op_tipc_exit(tipc);
	return -1;
}

int op_tipc_register(unsigned int type, rpc_cb cb)
{

	log_debug_ex ("tipc try register, type=%u\n", type);

	if (!tipc_self) {
		log_warn_ex ("tipc_register faild, type=%u, tipc not register\n", type);
		goto out;
	}

	if (type >= RPC_MAX_ELEMENT) {
		log_warn_ex ("type too large , type=%u\n", type);
		goto out;
	}

	tipc_self->cb[type] = cb;
	return 0;
out:
	return -1;
}

static int _op_tipc_send(unsigned int module,unsigned int type, unsigned char *req, unsigned int size, unsigned char *response, int response_size, int out)
{
	int tipc_fd = 0;
	struct sockaddr_tipc sa;
	int ret = 0;
	struct _tipc_header head;
	char *res = NULL;
	int copy_size = 0;

	memset(&sa, 0, sizeof(sa));

	log_debug_ex("tipc send: module:%u, type=%u\n", module, type);
	
	tipc_fd = tipc_socket(SOCK_STREAM);
	if (tipc_fd < 0) {
		log_warn_ex("tipc_socket failed, errno=%d\n", errno);
		goto out;
	}
	
	sa.family = AF_TIPC;
	sa.addrtype = TIPC_ADDR_NAME;
	sa.addr.name.name.type = module;
	sa.addr.name.name.instance = 0;
	sa.addr.name.domain = 0;
	sa.scope = TIPC_ZONE_SCOPE;

	ret = connect(tipc_fd, (struct sockaddr *)&sa, sizeof(sa));
	if (ret < 0) {
		log_warn_ex("connect failed, errno=%d\n", errno);
		goto out;
	}

	head.prefix = TIPC_HEAD_PREFIX_VALUE;
	head.module = module;
	head.type = type;
	if (!req || size <= 0)
		head.data_size = 0;
	else
		head.data_size = size;

	tipc_header_hton(&head);
	write(tipc_fd, &head, sizeof(head));

	if (head.data_size)
		write(tipc_fd, req, size);

	if (!response || response_size <= 0) {
		close(tipc_fd);
		return 0;
	}

	ret = usock_wait_ready(tipc_fd, TIPC_WAIT_TIMEOUT_MS);
	if (ret <= 0) {
		log_warn_ex("usock_wait_timeout\n");
		goto out;
	}

	log_debug_ex("try read head\n");

	ret = read(tipc_fd, &head, sizeof(head));
	if (ret <= 0 || ret != (int)sizeof(head)) {
		log_warn_ex("read header failed\n");
		goto out;
	}

	tipc_header_ntoh(&head);

	if (head.prefix != TIPC_HEAD_PREFIX_VALUE) {
		log_warn_ex("read header failed, prefix = %x\n", head.prefix);
		goto out;
	}

	if (!head.data_size) {
		close(tipc_fd);
		return 0;
	}

	if (head.data_size > RPC_RESPONSE_SIZE) {
		log_warn_ex("read header failed, data size = %u\n", head.data_size);
		goto out;
	}

	if (out)
		res = calloc(1, head.data_size);
	else
		res = op_calloc(1, head.data_size);
	if (!res) {
		log_warn_ex("op_calloc failed\n");
		goto out;
	}

	log_debug_ex("try read content, content size:%u\n", head.data_size);

	ret = read(tipc_fd, res, head.data_size);
	if (ret <= 0 || ret != (int)head.data_size) {
		log_warn_ex("read content failed, ret = %d\n", ret);
		goto out;
	}

	copy_size = response_size < ret?response_size:ret;

	if (copy_size > response_size)
		log_warn_ex("copy size truncate\n");

	memcpy(response, res, copy_size);
	close(tipc_fd);
	if (out)
		free(res);
	else
		op_free(res);
	return copy_size;
	
out:
	if (tipc_fd)
		close(tipc_fd);
	if (res) {
		if (out)
			free(res);
		else
			op_free(res);
	}

	return -1;

}

int op_tipc_send(unsigned int module, unsigned int type, unsigned char *req, unsigned int size)
{
	return _op_tipc_send(module, type, req, size, NULL, 0, 0);
}

int op_tipc_send_ex(unsigned int module,unsigned int type, unsigned char *req, unsigned int size, unsigned char *response, int response_size)
{
	return _op_tipc_send(module, type, req, size, response, response_size, 0);
}

int op_tipc_send_ex_out(unsigned int module, unsigned int type, unsigned char *req, unsigned int size, unsigned char *response, int response_size)
{
	return _op_tipc_send(module, type, req, size, response, response_size, 1);
}

static void op_local_exit(struct _op_local_rpc *local)
{
	if (!local)
		return;

	return;
}

int op_local_init(unsigned int module)
{
	struct _op_local_rpc *local =  NULL;

	local = op_calloc(1, sizeof(struct _op_local_rpc));
	if (!local) {
		log_warn_ex ("op_calloc faild\n");
		goto exit;
	}
	if(pthread_mutexattr_init(&local->attr)) {
		log_warn_ex ("pthread_mutexattr_init faild\n");
		goto exit;
	}

	if(pthread_mutex_init(&local->lock, &local->attr)) {
		log_warn_ex ("pthread_mutex_init faild\n");
		goto exit;
	}

	local->module = module;
	local_self = local;

	return 0;
exit:
	op_local_exit(local);
	return -1;
}

int op_local_register(unsigned int type, rpc_cb cb)
{
	if (!local_self)
		return -1;

	if (type >= RPC_MAX_ELEMENT) {
		log_warn_ex("type is too large, type=%u\n", type);
		return -1;
	}

	local_self->cb[type] = cb;

	return 0;
}

static int _op_local_send_ex(unsigned int module, unsigned int type, unsigned char *req, unsigned int size, unsigned char *response, int response_size)
{
	struct _op_local_rpc *local = local_self;
	int ret = 0;

	if (!local)
		goto out;

	if (local->module != module) {
		log_warn_ex("module %u is not register\n", module);
		goto out;
	}

	if (type >= RPC_MAX_ELEMENT) {
		log_warn_ex("type is too large, type=%u\n", type);
		goto out;
	}

	if (!local->cb[type]) {
		log_warn_ex("type handle is not register, type=%u\n", type);
		goto out;
	}
	
	pthread_mutex_lock(&local->lock);
	ret = local->cb[type](req, size, response, response_size);
	if (ret < 0)
		log_warn_ex("type handle exe failed, type=%u\n", type);
	pthread_mutex_unlock(&local->lock);
	return 0;
out:
	return -1;
}

int op_local_send(unsigned int module, unsigned int type, unsigned char *req, unsigned int size)
{
	return _op_local_send_ex(module, type, req, size, NULL, 0);
}

int op_local_send_ex(unsigned int module, unsigned int type, unsigned char *req, unsigned int size, unsigned char *response, int response_size)
{
	return _op_local_send_ex(module, type, req, size, response, response_size);
}


