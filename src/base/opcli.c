#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <pthread.h>
#include <signal.h>
#include <arpa/telnet.h>

#include "opcli.h"
#include "iniparser.h"
#include "opbox/usock.h"
#include "opbox/utils.h"
#include "event.h"
#include "config.h"
#include "opbox/list.h"
#include "opbox/ptelnet.h"
#include "opbox/hash.h"
#include "oplog.h"

static struct _opcli_struct *self = NULL;

#define CLI_SERVER "opcli:ip"
#define CLI_PORT "opcli:port"
#define CLI_OUT_BUF_SIZE 4096
#define CLI_HOST "opserver"

struct _node_prefix {
	char *prefix;
	char *cmd_in_enable;
	char *help_in_enable;
};

#define CMD_OPMGR_NAME "opmgr"
#define HELP_OPMGR_NAME "opmgr module\n"

#define CMD_OP4G_NAME "op4G"
#define HELP_OP4G_NAME "op4G module\n"

struct _node_prefix cli_prefix [node_max] = {
	[node_view] = {.prefix = "%s>"},
	[node_enable] = {.prefix = "%s#"},
	[node_opmgr] = {.prefix = "%s(opmgr)#", .cmd_in_enable= CMD_OPMGR_NAME, .help_in_enable = HELP_OPMGR_NAME},
	[node_op4g] = {.prefix = "%s(op4g)#", .cmd_in_enable= CMD_OP4G_NAME, .help_in_enable = HELP_OP4G_NAME},

};


struct _cli_socket {
	int sock_fd;
	char ip[16];
	unsigned short port;
};

struct _cli_thread {
	pthread_t thread_id;
	pthread_attr_t thread_attr;
};

struct _cli_job_ {
	struct event_base *base;
	pthread_t thread_id;
	pthread_attr_t thread_attr;
	pthread_mutex_t lock;
	pthread_mutexattr_t attr;
	struct list_head list;
};

struct _cli_node_ele {
	struct op_hash_st *hash_cmd;
	char *prefix;
};

struct _cli_node {
	pthread_mutex_t lock;
	pthread_mutexattr_t attr;
	struct cmd_node node_ele[node_max];
};

struct _opcli_struct {
	struct event_base *base;
	struct event *ev;
	struct _cli_socket sock;
	struct _cli_thread thread;
	struct _cli_job_ job;
	
	struct _cli_node node;
	vector vtyvec;
};

static int cmd_node_exit(int argc, const char **argv, struct cmd_element *ele, struct _vty * vty)
{
	switch (vty->node) {
		case node_view:
			vty->status = VTY_CLOSE;
			break;
		case node_enable:
			vty->node = node_view;
			break;
		case node_opmgr:
		case node_op4g:
			vty->node = node_enable;
			break;
	}
	return 0;
}

static int cmd_node_end(int argc, const char **argv, struct cmd_element *ele, struct _vty * vty)
{
	vty->node = node_view;
	return 0;
}

static int cmd_node_list(int argc, const char **argv, struct cmd_element *ele, struct _vty * vty)
{
	vty_list(vty);
	return 0;
}

static int cmd_node_enable(int argc, const char **argv, struct cmd_element *ele, struct _vty * vty)
{
	vty->node = node_enable;
	return 0;
}

struct cmd_in_node _cmd_in_node [] = {
	{.cmd = "exit", .help="exit to preview node\n", .cb = cmd_node_exit},
	{.cmd = "end", .help="end to first node\n", .cb = cmd_node_end},
	{.cmd = "list", .help="list install cmd in this node\n", .cb = cmd_node_list},
};

static int cmd_node_enable_module(int argc, const char **argv, struct cmd_element *ele, struct _vty * vty)
{
	unsigned int i = 0;
	unsigned int len = sizeof(cli_prefix)/sizeof(cli_prefix[0]);

	for (i = 0; i < len; i++) {
		if (!cli_prefix[i].cmd_in_enable)
			continue;

		if (!strcmp(ele->string, cli_prefix[i].cmd_in_enable))
			vty->node = i;
	}
	return 0;
}

struct cmd_in_node _cmd_in_node_enable [] = {
	{.cmd = CMD_OPMGR_NAME, .help=HELP_OPMGR_NAME, .cb = cmd_node_enable_module},
	{.cmd = CMD_OP4G_NAME, .help=HELP_OP4G_NAME, .cb = cmd_node_enable_module},

};


static int install_default_cmd(unsigned int node_type)
{
	int i =0;
	int len = sizeof(_cmd_in_node)/ sizeof(_cmd_in_node[0]);

	for (i = 0; i < len;i++)
		opcli_install_cmd(node_type, _cmd_in_node[i].cmd , _cmd_in_node[i].help, _cmd_in_node[i].cb);

	if (node_type == node_view)
		opcli_install_cmd(node_type, "enable", "into enable node\n", cmd_node_enable);
	else if (node_type == node_enable) {
		len = sizeof(_cmd_in_node_enable)/ sizeof(_cmd_in_node_enable[0]);
		for (i = 0; i < len;i++)
			opcli_install_cmd(node_type, _cmd_in_node_enable[i].cmd , _cmd_in_node_enable[i].help, _cmd_in_node_enable[i].cb);
	}

	return 0;
}

static void *opcli_routine (void *arg)
{
	if(event_base_loop(arg, EVLOOP_NO_EXIT_ON_EMPTY) < 0) {
		log_error ("opcli_routine failed\n");
		pthread_detach(pthread_self());
		pthread_exit(NULL);
		goto exit;
	}

exit:
	log_debug ("opcli_routine exit\n");
	return NULL;
}

static void opcli_client_free(struct _cli_client *client)
{
	log_debug ("client free,fd=%d\n", client->fd);
	close(client->fd);
	pthread_mutex_lock(&self->job.lock);
	list_del(&client->list);
	pthread_mutex_unlock(&self->job.lock);
	event_free(client->ev);
	vty_free(client->vty);
	free(client);
	return;
}
static void opcli_job_thread(evutil_socket_t fd,short what,void* arg)
{
	struct _cli_client *client = NULL;
	client = (struct _cli_client *)arg;
	int ret = 0;

	ret = read(fd, client->buf.buf_recv, _CLI_BUF_REQ_SIZE);
	if (ret < 0) {
		log_warn ("read faild, errno=%d\n",errno);
		goto out;
	}
	
	if (what == EV_READ && !ret) {
		opcli_client_free(client);
		goto out;
	}

	pthread_mutex_lock(&self->node.lock);
	vty_read(client->vty, client->buf.buf_recv, ret);
	if (client->vty->status == VTY_CLOSE)
		opcli_client_free(client);

	pthread_mutex_unlock(&self->node.lock);
out:
	return;

}

static unsigned long node_hash (const void *data)
{
	struct cmd_element *cli_cmd = NULL;
	unsigned long ret = 0;
	long n;
	unsigned long v;
	int r;
	char *c = NULL;
	
	cli_cmd = (struct cmd_element *)data;
	if (!cli_cmd) {
		printf ("%s %d node_hash faild data is unvalid\n",__FILE__,__LINE__);
		return 0;
	}

	c = cli_cmd->string;

	n = 0x100;
	while (*c) {
		v = n | (*c);
		n += 0x100;
		r = (int)((v >> 2) ^ v) & 0x0f;
		ret = (ret << r) | (ret >> (32 - r));
		ret &= 0xFFFFFFFFL;
		ret ^= v * v;
		c++;
	}
	return (ret >> 16) ^ ret;
}

static int node_compare (const void *data_in_list, const void *data)
{
	struct cmd_element *cli_cmd = NULL;
	struct cmd_element *cli_data = NULL;

	cli_cmd = (struct cmd_element *)data_in_list;
	cli_data = (struct cmd_element *)data;

	if (!cli_cmd || !cli_data || !cli_cmd->string || !cli_data->string )
		return 1;

	return (strcmp(cli_cmd->string, cli_data->string) | (cli_cmd->node != cli_data->node));
}

static int opcli_node_init(struct _cli_node *node, unsigned int node_max_num)
{
	unsigned int i = 0;

	if (!node || !node_max_num ) {
		printf ("%s %d opcli_node_init faild[%d]\n",__FILE__,__LINE__, node_max_num);
		goto failed;
	}

	if(pthread_mutexattr_init(&node->attr)) {
		printf ("%s %d opcli pthread_mutexattr_init faild\n",__FILE__,__LINE__);
		goto failed;
	}

	if(pthread_mutex_init(&node->lock, &node->attr)) {
		printf ("%s %d opcli pthread_mutex_init faild\n",__FILE__,__LINE__);
		goto failed;
	}

	for (i = 0 ; i < node_max_num; i++) {
		node->node_ele[i].cmd_hash = op_hash_new(node_hash, node_compare);
		if (!node->node_ele[i].cmd_hash) {
			printf ("%s %d op_hash_new faild\n",__FILE__,__LINE__);
			goto failed;
		}
		node->node_ele[i].node = i;
		
		node->node_ele[i].prompt = cli_prefix[i].prefix;
		
		install_node(&node->node_ele[i]);
		install_default_cmd(i);
	}

	return 0;

failed:
	return -1;
}

static void opcli_option_init(evutil_socket_t fd)
{
	char * str = NULL;

	str = ptelnet_will_echo();
	
	if (write(fd, str, strlen(str)) < 0) {
		printf ("%s %d write failed[%d]\n",__FILE__,__LINE__, errno);
		goto exit;
	}
	
	str = ptelnet_will_suppress_go_ahead();
	if (write(fd, str, strlen(str)) < 0) {
		printf ("%s %d write failed[%d]\n",__FILE__,__LINE__, errno);
		goto exit;
	}

	str = ptelnet_dont_linemode();
	if (write(fd, str, strlen(str)) < 0) {
		printf ("%s %d write failed[%d]\n",__FILE__,__LINE__, errno);
		goto exit;
	}

	str = ptelnet_do_window_size();
	if (write(fd, str, strlen(str)) < 0) {
		printf ("%s %d write failed[%d]\n",__FILE__,__LINE__, errno);
		goto exit;
	}

exit:
	return;
}

static void opcli_job(evutil_socket_t fd,short what,void* arg)
{
	int client_fd = 0;
	struct sockaddr_in addr;
	socklen_t len = 0;
	struct _cli_client *client = NULL;
	struct _opcli_struct *cli = NULL;

	cli = (struct _opcli_struct *)arg;
	if(!cli) {
		printf ("%s %d opcli_job parameter is unvalid\n",__FILE__,__LINE__);
		goto out;
	}

	client_fd = accept(fd, (struct sockaddr*)&addr, &len);
	if (client_fd < 0) {
		printf ("%s %d accept failed[%d]\n",__FILE__,__LINE__, errno);
		goto out;
	}

	client = calloc(1, sizeof(*client));
	if (!client) {
		close(client_fd);
		printf ("%s %d calloc failed[%d]\n",__FILE__,__LINE__, errno);
		goto out;
	}

	client->fd = client_fd;

	client->vty = vty_create(client_fd, node_view, CLI_HOST);
	if (!client->vty) {
		close(client_fd);
		free(client);
		printf ("%s %d vty_create failed[%d]\n",__FILE__,__LINE__, errno);
		goto out;
	}
	
	client->ev = event_new(cli->job.base, client->fd, EV_READ|EV_PERSIST, opcli_job_thread, client);
	if (!client->ev) {
		close(client_fd);
		free(client);
		printf ("%s %d event_new failed[%d]\n",__FILE__,__LINE__, errno);
		goto out;
	}

	INIT_LIST_HEAD(&client->list);

	pthread_mutex_lock(&cli->job.lock);
	list_add(&client->list, &cli->job.list);
	pthread_mutex_unlock(&cli->job.lock);

	opcli_option_init(client_fd);
	if(event_add(client->ev, NULL) < 0) {
		close(client_fd);
		pthread_mutex_lock(&cli->job.lock);
		list_del(&client->list);
		pthread_mutex_unlock(&cli->job.lock);
		free(client);
		printf ("%s %d opcli event_add faild[%d]\n",__FILE__,__LINE__, errno);
		goto out;
	}

	if(pthread_kill(cli->job.thread_id, SIGUSR1)) {
		printf ("%s %d pthread_kill[%x] faild[%d]\n",__FILE__,__LINE__, (unsigned int)cli->job.thread_id, errno);
		goto out;
	}

	opcli_out(client->vty, cli->node.node_ele[client->vty->node].prompt, CLI_HOST);
	return;
out:

	return;
}
void *opcli_init(void)
{
	struct _opcli_struct *cli = NULL;
	dictionary *dict = NULL;
	const char * str = NULL;
	int str_int = 0;

	cli = calloc(1, sizeof(*cli));
	if (!cli) {
		printf ("%s %d calloc failed[%d]\n", __FILE__, __LINE__, errno);
		goto exit;
	}

	self = cli;

	dict = iniparser_load(OPSERVER_CONF);
	if (!dict) {
		printf ("%s %d iniparser_load faild[%s]\n",__FILE__,__LINE__, OPSERVER_CONF);
		goto exit;
	}

	if(!(str = iniparser_getstring(dict,CLI_SERVER,NULL))) {
		printf ("%s %d iniparser_getstring faild[%s]\n",__FILE__,__LINE__, CLI_SERVER);
		iniparser_freedict(dict);
		goto exit;
	}

	op_strlcpy(cli->sock.ip, str, sizeof(cli->sock.ip));
	if ((str_int =iniparser_getint(dict,CLI_PORT,-1)) < 0) {
		printf ("%s %d iniparser_getint faild[%s]\n",__FILE__,__LINE__, CLI_PORT);
		iniparser_freedict(dict);
		goto exit;
	}

	cli->sock.port = str_int;

	iniparser_freedict(dict);
	
	if (vty_init(&cli->vtyvec) < 0) {
		printf ("%s %d vty_init faild\n",__FILE__,__LINE__);
		goto exit;
	}
	
	if (opcli_node_init(&cli->node, node_max) < 0) {
		printf ("%s %d opcli_node_init faild\n",__FILE__,__LINE__);
		goto exit;
	}

	cli->sock.sock_fd = usock(USOCK_IPV4ONLY|USOCK_TCP|USOCK_SERVER, cli->sock.ip, usock_port(cli->sock.port));
	if (cli->sock.sock_fd < 0) {
		printf ("%s %d usock faild[%d]\n",__FILE__,__LINE__,errno);
		goto exit;
	}

	cli->base = event_base_new();
	if (!cli->base) {
		printf ("%s %d opcli event_base_new faild\n",__FILE__,__LINE__);
		goto exit;
	}

	cli->ev = event_new(cli->base, cli->sock.sock_fd, EV_READ|EV_PERSIST, opcli_job, cli);
	if(!cli->ev) {
		printf ("%s %d opcli event_new faild\n",__FILE__,__LINE__);
		goto exit;
	}

	if(event_add(cli->ev, NULL) < 0) {
		printf ("%s %d opcli event_add faild\n",__FILE__,__LINE__);
		goto exit;
	}

	
	if(pthread_attr_init(&cli->thread.thread_attr)) {
		printf ("%s %d opcli pthread_attr_init faild\n",__FILE__,__LINE__);
		goto exit;
	}

	if(pthread_create(&cli->thread.thread_id, &cli->thread.thread_attr, opcli_routine, cli->base)) {
		printf ("%s %d opcli pthread_create faild\n",__FILE__,__LINE__);
		goto exit;
	}


	INIT_LIST_HEAD(&cli->job.list);

	if(pthread_mutexattr_init(&cli->job.attr)) {
		printf ("%s %d opcli pthread_mutexattr_init faild\n",__FILE__,__LINE__);
		goto exit;
	}

	if(pthread_mutex_init(&cli->job.lock, &cli->job.attr)) {
		printf ("%s %d opcli pthread_mutex_init faild\n",__FILE__,__LINE__);
		goto exit;
	}

	cli->job.base = event_base_new();
	if (!cli->job.base) {
		printf ("%s %d opcli event_base_new faild\n",__FILE__,__LINE__);
		goto exit;
	}

	if(pthread_attr_init(&cli->job.thread_attr)) {
		printf ("%s %d opcli pthread_attr_init faild\n",__FILE__,__LINE__);
		goto exit;
	}

	if(pthread_create(&cli->job.thread_id, &cli->job.thread_attr, opcli_routine, cli->job.base)) {
		printf ("%s %d opcli pthread_create faild\n",__FILE__,__LINE__);
		goto exit;
	}

	return cli;
exit:
	return NULL;
}

int opcli_install_cmd_ex(unsigned int node, struct cmd_element *cli_cmd)
{
	int ret = 0;
	void *data = NULL;

	if (node >= node_max || !cli_cmd) {
		printf ("%s %d opcli_install_cmd faild[node=%u]\n",__FILE__,__LINE__,node);
		return -1;
	}

	pthread_mutex_lock(&self->node.lock);
	data = op_hash_retrieve(self->node.node_ele[node].cmd_hash, cli_cmd);
	if (data) {
		printf ("%s %d element has exist\n",__FILE__,__LINE__);
		pthread_mutex_unlock(&self->node.lock);
		return -1;
	}

	op_hash_insert(self->node.node_ele[node].cmd_hash, cli_cmd);
	ret = install_element(node, cli_cmd);
	pthread_mutex_unlock(&self->node.lock);

	return ret;
}

int opcli_install_cmd(unsigned int node, char *cmd, char*help ,cmd_cb cb)
{
	struct cmd_element *cli_cmd = NULL;
	void *data = NULL;

	if (!cmd || !help || !cb || node >= node_max) {
		printf ("%s %d opcli_install_cmd faild[cmd=%s, node=%u, cb=%p]\n",__FILE__,__LINE__, cmd, node, cb);
		goto failed;
	}

	cli_cmd = calloc(1, sizeof(*cli_cmd));
	if (!cli_cmd) {
		printf ("%s %d calloc faild[%d]\n",__FILE__,__LINE__, errno);
		goto failed;
	}

	cli_cmd->node = node;
	cli_cmd->cb = cb;
	cli_cmd->string = strdup(cmd);
	if (!cli_cmd->string) {
		printf ("%s %d strdup faild[%d]\n",__FILE__,__LINE__, errno);
		goto failed;
	}

	cli_cmd->doc = strdup(help);
	if (!cli_cmd->doc) {
		printf ("%s %d strdup faild[%d]\n",__FILE__,__LINE__, errno);
		goto failed;
	}


	pthread_mutex_lock(&self->node.lock);
	data = op_hash_retrieve(self->node.node_ele[node].cmd_hash, cli_cmd);
	if (data) {
		printf ("%s %d element has exist[cmd=%s, node=%u, cb=%p]\n",__FILE__,__LINE__, cmd, node, cb);
		pthread_mutex_unlock(&self->node.lock);
		goto failed;
	}

	op_hash_insert(self->node.node_ele[node].cmd_hash, cli_cmd);
	install_element(node, cli_cmd);
	pthread_mutex_unlock(&self->node.lock);

	return 0;
failed:
	if (cli_cmd) {
		if (cli_cmd->string)
			free(cli_cmd->string);
		if (cli_cmd->doc)
			free(cli_cmd->doc);
		free(cli_cmd);
	}
	return -1;
}

void opcli_out(struct _vty *vty, const char *fmt, ...)
{
	va_list args;
	size_t size = 0;
	char *cli_buf = NULL;

	if (!vty)
		goto out;

	cli_buf = calloc(1, CLI_OUT_BUF_SIZE);
	if (!cli_buf) {
		printf ("%s %d calloc failed[%d]\n",__FILE__,__LINE__, errno);
		goto out;
	}

	va_start(args, fmt);
	size = vsnprintf(cli_buf, CLI_OUT_BUF_SIZE, fmt, args);
	va_end(args);

	if (write(vty->fd, (unsigned char*)cli_buf, size) < 0) {
		printf ("%s %d write failed[%d]\n",__FILE__,__LINE__, errno);
		goto out;
	}
out:
	if (cli_buf)
		free(cli_buf);
	return;
}

void opcli_exit(void *cli)
{
	return;
}


