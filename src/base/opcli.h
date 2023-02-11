#ifndef __OPCLI_H__
#define __OPCLI_H__

#include "event.h"
#include "opbox/list.h"
#include "opbox/vty.h"

#define _CLI_BUF_REQ_SIZE 512

enum {
	node_view,
	node_enable,
	node_opmgr,
	node_op4g,
	node_max,
};

typedef int (*cmd_cb) (int argc, const char **argv, struct cmd_element *ele, struct _vty *vty);

struct cmd_in_node {
	char *cmd;
	char *help;
	cmd_cb cb;
};

struct _cli_buf {
	unsigned char buf_recv[_CLI_BUF_REQ_SIZE];
};

struct _cli_client {
	struct list_head list;
	int fd;
	struct event *ev;
	struct _cli_buf buf;
	struct _vty *vty;

};

void *opcli_init(void);
void opcli_exit(void *cli);

int opcli_install_cmd(unsigned int node, char *cmd, char*help ,cmd_cb cb);

int opcli_install_cmd_ex(unsigned int node, struct cmd_element *cli_cmd);

void opcli_out(struct _vty *vty, const char *fmt, ...);

#endif
