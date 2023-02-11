#ifndef _OPMGR_BUS_H__
#define _OPMGR_BUS_H__

#define MAX_CPU_CORE 64
struct cpu_info_usage {
	char cpu_name[64];
	float user;
	float nice;
	float system;
	float idle;
	float iowait;
	float irq;
	float softirq;
	float steal;
	float guest;
	float cpu_use;
};

struct cpu_info {
	int cpu_num;
	struct cpu_info_usage usage[MAX_CPU_CORE+1];
};

#endif