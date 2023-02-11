#ifndef _OPRPC_H__
#define _OPRPC_H__

#define RPC_MAX_ELEMENT 1024
#define RPC_REQ_SIZE 4096
#define RPC_RESPONSE_SIZE 8192
typedef int (*rpc_cb)(unsigned char *req, int req_size, unsigned char *response, int res_size);

/********************tipc*******************************/

enum {
	rpc_tipc_module_none = 1000,
	rpc_tipc_module_opserver,
	rpc_tipc_module_opdpdk,
	rpc_tipc_module_max,
};

enum {
	// opserver
	tipc_opserver_none,
	tipc_opserver_cup_usage,
	tipc_opserver_show_mem_poll,
	tipc_opserver_send_quotes,
	tipc_opserver_check_stock,
	tipc_opserver_show_mem_poll_father_node,
	// opdpdk
	tipc_opdpdk_show_mem_poll,
	tipc_opdpdk_show_mem_poll_father_node,
	tipc_opserver_max,
};


int op_tipc_init(unsigned int module);
int op_tipc_register(unsigned int type, rpc_cb cb);
int op_tipc_send(unsigned int module, unsigned int type, unsigned char *req, unsigned int size);
int op_tipc_send_ex(unsigned int module, unsigned int type, unsigned char *req, unsigned int size, unsigned char *response, int response_size);
int op_tipc_send_ex_out(unsigned int module, unsigned int type, unsigned char *req, unsigned int size, unsigned char *response, int response_size);


/*********************tipc end****************************************/

/*****************************local rpc***************************************/
int op_local_init(unsigned int module);
int op_local_register(unsigned int type, rpc_cb cb);
int op_local_send(unsigned int module, unsigned int type, unsigned char *req, unsigned int size);
int op_local_send_ex(unsigned int module, unsigned int type, unsigned char *req, unsigned int size, unsigned char *response, int response_size);



#endif
