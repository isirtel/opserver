#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "opbox/usock.h"
#include "opbox/utils.h"
#include "base/oplog.h"
#include "base/opcli.h"
#include "opmgr.h"
#include "op4g.h"
#include "event.h"
#include "base/opsql.h"
#include "config.h"
#include "base/opsql.h"
#include "timer_service.h"
#include "iniparser.h"
#include "spider.h"
#include "opmail.h"
#include "base/opmem.h"
#include "opbox/list.h"
#include "mqtt/mosquitto.h"
#include "base/oprpc.h"
#include "opfile.h"

#define OPSERVER_PATH "env:path"
#define OPSERVER_LIB "env:lib"
#define OPSERVER_UID "env:uid"

struct _op_child_process {
	struct list_head list;
	pid_t pid;
};

struct _opserver_struct_ {
	void *log;
	void *cli;
	void *mgr;
	void *_4g;
	void *sql;
	void *timer_service;
	void *spider;
	void *mail;
	void *mem;
	struct list_head process_list;
	struct event_base *base;
	struct event *process_watchd;
	struct event *opmem_watchd;
};

struct _opserver_struct_ *self = NULL;

static void opserver_process_watchd(evutil_socket_t fd , short what, void *arg)
{
	struct _opserver_struct_ *server = (struct _opserver_struct_ *)arg;
	struct _op_child_process *p_node;
	struct _op_child_process *p_node_tmp;
	char buf[512] = {};
	struct timeval tv;

	if (!server)
		goto out;

	if (list_empty(&server->process_list))
		goto out;

	list_for_each_entry_safe(p_node, p_node_tmp,&server->process_list, list) {
		snprintf(buf, sizeof(buf),"/proc/%u/exe", (unsigned int)p_node->pid);
		
		if (!access(buf, F_OK))
			continue;
		log_warn("wait opserver child process: %u\n", (unsigned int)p_node->pid);
		waitpid(p_node->pid, NULL, 0);
		list_del_init(&p_node->list);
		op_free(p_node);
	}

out:
	tv.tv_sec = 1;
	tv.tv_usec = 0;
	event_add(server->process_watchd, &tv);
	return;
}

static void opserver_opmem_watchd(evutil_socket_t fd , short what, void *arg)
{
	struct timeval tv;

	tv.tv_sec = 60;
	tv.tv_usec = 0;
	op_mem_release_check(arg);
	event_add(self->opmem_watchd, &tv);
	return;
}

int opserver_init(struct _opserver_struct_ *server)
{

	struct timeval tv;

	if (!server)
		return -1;

	mosquitto_lib_init();
	op_tipc_init(rpc_tipc_module_opserver);
	op_local_init(rpc_tipc_module_opserver);
	opfile_init();

	INIT_LIST_HEAD(&server->process_list);
	server->process_watchd = evtimer_new(server->base, opserver_process_watchd, server);
	if (!server->process_watchd) {
		log_warn("process watchd failed\n");
		return 0;
	}

	tv.tv_sec = 1;
	tv.tv_usec = 0;
	event_add(server->process_watchd, &tv);

	server->opmem_watchd = evtimer_new(server->base, opserver_opmem_watchd, server->mem);
	if (!server->opmem_watchd) {
		log_warn("process opmem failed\n");
		return 0;
	}

	tv.tv_sec = 60;
	tv.tv_usec = 0;
	event_add(server->opmem_watchd, &tv);
	return 0;
}

void signal_handle(int signal_no)
{
	return;
}
void opserver_exit(struct _opserver_struct_ *_op)
{
	if (_op)
		return ;

	log_debug("opserver_exit\n");
	timer_service_exit(_op->timer_service);
	oplog_exit(_op->_4g);
	opmgr_exit(_op->mgr);
	opsql_exit(_op->sql);
	opcli_exit(_op->cli);
	oplog_exit(_op->log);
	spider_exit(_op->spider);
	opmail_exit(_op->mail);;
	opmem_exit(_op->mem);
	free(_op);
	return;
}

int opserver_env_set(void)
{
	dictionary *dict;
	const char *str;
	char buf[2048] = {};
	dict = iniparser_load(OPSERVER_CONF);
	if (!dict) {
		printf ("%s %d iniparser_load faild[%s]\n",__FILE__,__LINE__, OPSERVER_CONF);
		goto out;
	}

	if(!(str = iniparser_getstring(dict,OPSERVER_PATH,NULL))) {
		printf ("%s %d iniparser_getstring faild[%s]\n",__FILE__,__LINE__, OPSERVER_PATH);
		iniparser_freedict(dict);
		goto out;
	}

	snprintf(buf, sizeof(buf), "%s:%s", getenv("PATH"), str);
	
	setenv("PATH", buf, 1);

	if(!(str = iniparser_getstring(dict,OPSERVER_LIB,NULL))) {
		printf ("%s %d iniparser_getstring faild[%s]\n",__FILE__,__LINE__, OPSERVER_LIB);
		iniparser_freedict(dict);
		goto out;
	}
	
	snprintf(buf, sizeof(buf), "%s:%s", getenv("LD_LIBRARY_PATH"), str);
	iniparser_freedict(dict);

	setenv("LD_LIBRARY_PATH", buf, 1);
	
	return 0;
out:
	return -1;
}

static void server_init(struct _opserver_struct_ *_op)
{
	dictionary *dict;
	int uid = -1;
	dict = iniparser_load(OPSERVER_CONF);
	if (!dict) {
		log_error ("iniparser_load faild[%s]\n", OPSERVER_CONF);
		goto out;
	}

	uid = iniparser_getint(dict,OPSERVER_UID,-1);
	iniparser_freedict(dict);
	if (uid <= 0) {
		printf ("%s %d uid get faild[%d]\n",__FILE__,__LINE__, uid);
		exit (0);
	}

	if (setuid(uid) < 0) {
		printf ("%s %d setuid failed[%d][%d]\n",__FILE__,__LINE__, uid, errno);
		exit(0);
	}

	if (!(_op->cli = opcli_init()))
		log_error("opcli init\n");
	
	if (!(_op->sql = opsql_init(OPSERVER_CONF)))
		log_error("opsql init\n\n");

	if (!(_op->mgr = opmgr_init()))
		log_error("opmgr init\n");

	if (!(_op->mail = opmail_init()))
		log_error("opmail init\n");
	
	if (!(_op->_4g = op4g_init()))
		log_error("op4g init\n");

	if (!(_op->timer_service = timer_service_init()))
		log_error("timer service init\n");

	if (!(_op->spider = spider_init()))
		log_error("spider init\n");

out:
	return;
}

static int run_server(struct event_base *base)
{
	log_debug("run server\n");

	if(event_base_loop(base, EVLOOP_NO_EXIT_ON_EMPTY) < 0) {
		log_error ("opserver failed\n");
		return -1;
	}

	return 0;
}

int main(int argc, char*argv[])
{
	struct _opserver_struct_ *_op = NULL;
	daemon(1,0);
	signal(SIGUSR1, signal_handle);
	signal(SIGPIPE, SIG_IGN);
	srand(time(NULL));
	signal_segvdump();
	_op = calloc(1, sizeof(struct _opserver_struct_));
	if (!_op) {
		printf("opserver calloc failed\n");
		goto exit;
	}

	self = _op;

	_op->base = event_base_new();
	if (!_op->base) {
		log_error("opserver event_base_new failed\n");
		goto exit;
	}

	if (opserver_env_set() < 0) {
		printf("opserver env set failed\n");
		goto exit;
	}

	if(!(_op->mem = opmem_init()))
		log_error("opmem init\n");

	if (!(_op->log = oplog_init()))
		log_error("oplog init\n");

	opserver_init(_op);

	server_init(_op);

	if (run_server(_op->base) < 0)
		goto exit;

	return 0;
exit:
	sleep(3);
	opserver_exit(_op);
	return -1;
}
