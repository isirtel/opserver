#ifndef __VTY_H__
#define __VTY_H__
#include <sys/types.h>

#define VTY_INPUT_BUF_SIZE 1024
#define VTY_HIST_CMD_SIZE 20
#define TELNET_NAWS_SB_LEN 5

typedef enum
{
	CMD_ATTR_DEPRECATED = 1,
	CMD_ATTR_HIDDEN,
}CMD_ATTR;

enum {
	VTY_TERM,
	VTY_FILE,
	VTY_SHELL, 
	VTY_SHELL_SERV,
	VTY_NORMAL, 
	VTY_CLOSE, 
	VTY_MORE, 
	VTY_MORELINE
};

struct _vector 
{
	unsigned int active;
	unsigned int alloced;
	void **index;
};

typedef struct _vector *vector;

struct cmd_node 
{
	unsigned int node;
	char *prompt;
	vector cmd_vector;
	void *cmd_hash;
};

struct _vty
{
	char hostname[64];
	int fd;
	int status;
	int type;
	unsigned int node;
	char buf[VTY_INPUT_BUF_SIZE];
	int cp;
	int length;
	int max;
	char *hist[VTY_HIST_CMD_SIZE];
	int hp;
	int hindex;
	unsigned char escape;
	unsigned char iac;
	unsigned char iac_sb_in_progress;
	unsigned char sb_buf[TELNET_NAWS_SB_LEN];
	size_t sb_len;
	int width;
	int height;
};

struct cmd_element 
{
	unsigned int node;
	char *string;
	char *doc;
	vector tokens;
	u_char attr;
	int daemon;
	int (*cb) (int argc, const char **argv, struct cmd_element *ele, struct _vty *vty);
};

struct cmd_token
{
	unsigned int  type;
	unsigned int terminal;
	vector multiple;
	vector keyword;
	char *cmd;
	char *desc;
};

int vty_init(vector *v);
void vty_exit(vector *v);
int install_element (unsigned int ntype, struct cmd_element *cmd);
int install_node (struct cmd_node *node);
struct _vty *vty_create (int vty_sock, unsigned int node_type, char *hostname);

void vty_free (struct _vty *vty);

void vty_list(struct _vty *vty);

int vty_read (struct _vty *vty, unsigned char *buf,int nbytes);

#endif

