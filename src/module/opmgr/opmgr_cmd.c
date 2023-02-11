#include "opmgr_cmd.h"
#include "opmgr_bus.h"
#include "base/opcli.h"
#include "base/opmem.h"
#include "base/oprpc.h"

static int cmd_mgr_cpu_usage(int argc, const char **argv, struct cmd_element *ele, struct _vty * vty)
{
	char buf[2048] = {};
	struct cpu_info *cpu_usage = NULL;
	int i = 0;
	op_local_send_ex(rpc_tipc_module_opserver,tipc_opserver_cup_usage, NULL, 0, (unsigned char*)buf, sizeof(buf)-1);
	cpu_usage = (struct cpu_info *)buf;
	
	opcli_out(vty ,"name      %%user       %%nice       %%system      %%iowait      %%steal      %%usage\r\n");

	for(i = 0; i <= cpu_usage->cpu_num;i++) {
		opcli_out(vty,"%-6s    %-6.2f      %-6.2f      %-7.2f      %-7.2f      %-6.2f      %-6.2f\r\n",
				cpu_usage->usage[i].cpu_name, cpu_usage->usage[i].user,cpu_usage->usage[i].nice, cpu_usage->usage[i].system,
				cpu_usage->usage[i].iowait, cpu_usage->usage[i].steal, cpu_usage->usage[i].cpu_use);
	}

	return 0;
}

static int cmd_mem_pool_information(int argc, const char **argv, struct cmd_element *ele, struct _vty * vty)
{
	char buf[4096] = {};

	op_local_send_ex(rpc_tipc_module_opserver,tipc_opserver_show_mem_poll, NULL, 0, (unsigned char*)buf, sizeof(buf)-1);

	opcli_out(vty ,"%s\r\n", buf);
	return 0;
}


struct cmd_in_node opmgr_cmd [] = {
	{.cmd = "show cpu usage", .help="show\n cpu\n usage\n", .cb = cmd_mgr_cpu_usage},
	{.cmd = "show memory pool information", .help="show\n memory \n pool\n information\n", .cb = cmd_mem_pool_information},
};

void opmgr_cmd_init(void)
{
	int i = 0;
	int len = 0;

	len = sizeof(opmgr_cmd) / sizeof(opmgr_cmd[0]);
	for (i = 0; i < len ; i++)
		opcli_install_cmd(node_opmgr, opmgr_cmd[i].cmd, opmgr_cmd[i].help, opmgr_cmd[i].cb);

	return;
}

