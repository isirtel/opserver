#include <stdio.h>
#include <unistd.h>
#include<getopt.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "opbox/utils.h"
#include "opbox/usock.h"
#include "base/oprpc.h"
#include "opmgr_bus.h"

unsigned char g_response[RPC_RESPONSE_SIZE];

typedef int (*pbus_send)(unsigned int module, unsigned int type, unsigned char *req, int size, unsigned char *response,int res_size);
typedef int (*pbus_format_res)(unsigned char *response,int res_size);

int format_cpu_usage(unsigned char *response,int res_size)
{
	struct cpu_info *cpu_usage = NULL;
	int i = 0;
	cpu_usage = (struct cpu_info *)response;
	printf("name      %%user       %%nice       %%system      %%iowait      %%steal      %%usage\n");

	for(i = 0; i <= cpu_usage->cpu_num;i++) {
		printf("%-6s    %-6.2f      %-6.2f      %-7.2f      %-7.2f      %-6.2f      %-6.2f\n",
				cpu_usage->usage[i].cpu_name, cpu_usage->usage[i].user,cpu_usage->usage[i].nice, cpu_usage->usage[i].system,
				cpu_usage->usage[i].iowait, cpu_usage->usage[i].steal, cpu_usage->usage[i].cpu_use);
	}

	return 0;

}

int format_mem_pool_usage(unsigned char *response,int res_size)
{
	printf("%s\n", response);
	return 0;
}


int pbus_send_busd(unsigned int module,unsigned int type, unsigned char *req, int size, unsigned char *response,int res_size)
{
	return op_tipc_send_ex_out(module, type, req, size, response, res_size);
}

struct _pbus_struct {
	unsigned int module;
	char *help;
	int use_req;
	pbus_send cb;
	pbus_format_res format_cb;
};

struct _pbus_struct pbus_map [tipc_opserver_max] = {
	[tipc_opserver_cup_usage] = {.module=rpc_tipc_module_opserver,.help = "get_cpu_usage", .cb = pbus_send_busd, .format_cb = format_cpu_usage},
	[tipc_opserver_send_quotes] = {.module=rpc_tipc_module_opserver,.help = "send_quotes", .cb = pbus_send_busd},
	[tipc_opserver_check_stock] = {.module=rpc_tipc_module_opserver,.help = "check_stock", .cb = pbus_send_busd},
	[tipc_opserver_show_mem_poll] = {.module=rpc_tipc_module_opserver,.help = "memory_pool_info_opserver",.cb = pbus_send_busd, .format_cb = format_mem_pool_usage},
	[tipc_opserver_show_mem_poll_father_node] = {.module=rpc_tipc_module_opserver,.help = "memory_pool_info_father_node_opserver",.cb = pbus_send_busd, .format_cb = format_mem_pool_usage},
	[tipc_opdpdk_show_mem_poll] = {.module=rpc_tipc_module_opdpdk,.help = "memory_pool_info_opdpdk",.cb = pbus_send_busd, .format_cb = format_mem_pool_usage},
	[tipc_opdpdk_show_mem_poll_father_node] = {.module=rpc_tipc_module_opdpdk,.help = "memory_pool_info_father_node_opdpdk",.cb = pbus_send_busd, .format_cb = format_mem_pool_usage},
};

static char *pbus_string = "h";

static struct option pbus_long_options[] =
{
	{"help", no_argument, NULL, 'h'},
	{NULL, 0, NULL, 0},
};

int pbus_help(char *prog)
{
	unsigned int i = 0;
	char buf_tmp[1024];

	printf ("usage:\n");
	for (i = 0; i < tipc_opserver_max; i++) {
		if (!pbus_map[i].help)
			continue;
		if (pbus_map[i].use_req)
			snprintf (buf_tmp, sizeof(buf_tmp), "%s %s [req string]\n", prog, pbus_map[i].help);
		else
			snprintf (buf_tmp, sizeof(buf_tmp), "%s %s\n", prog, pbus_map[i].help);

		printf("%s",buf_tmp);
	}

	return 0;
}

void pbus_handle (char *help, unsigned char *req, int req_size) {
	unsigned int i = 0;
	int ret = 0;

	
	for (i = 0; i < tipc_opserver_max; i++) {
		if (!pbus_map[i].help || strcmp(pbus_map[i].help, help))
			continue;
		if (pbus_map[i].use_req)
			ret = pbus_map[i].cb(pbus_map[i].module, i, req, req_size, g_response, RPC_RESPONSE_SIZE);
		else
			ret = pbus_map[i].cb(pbus_map[i].module, i, NULL, 0, g_response, RPC_RESPONSE_SIZE);

		if (ret  < 0) {
			printf("pbus called failed\n");
			return;
		}

		if (pbus_map[i].format_cb)
			pbus_map[i].format_cb(g_response, ret);

		break;
	}

	return;

}

int main(int argc, char *argv[])
{
	int long_index = 0;
	int c = 0;

	while((c = getopt_long(argc, argv, pbus_string, pbus_long_options, &long_index)) > 0) {
		switch(c) {
			case 'h':
				return pbus_help(argv[0]);
			default:
			break;
		}
	}

	if (argc == 1)
		return pbus_help(argv[0]);

	if (argc > 2)
		pbus_handle(argv[1], (unsigned char*)argv[2], strlen(argv[2]));
	else
		pbus_handle(argv[1], NULL, 0);
	return 0;
}
