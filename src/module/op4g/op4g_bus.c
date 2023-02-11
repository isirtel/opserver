#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "op4g_bus.h"
#include "op4g.h"
#include "base/opsql.h"
#include "base/oplog.h"

int _4g_send_quotes(unsigned char *req, int req_size, unsigned char *response, int res_size)
{
	void *handle = NULL;
	int count = 0;
	char quota[400] = {};
	char nm[64] = {};
	char short_message[1024];
	int index = 0;
	log_debug("send quotes begin\n");

	handle = opsql_alloc();
	if (!handle) {
		log_warn("opsql_alloc failed\n");
		goto out;
	}

	log_debug("sql:%s\n","select quotations,name from quotes;");

	count = opsql_query(handle, "select quotations,name from quotes;");
	if (count <= 0) {
		log_warn("opsql_query failed\n");
		goto out;
	}

	opsql_bind_col(handle, 1, OPSQL_CHAR, quota, sizeof(quota));
	opsql_bind_col(handle, 2, OPSQL_CHAR, nm, sizeof(nm));

	index = rand()%count+1;
	log_debug("fetch index:%d,count=%d\n",index, count);
	if(opsql_fetch_scroll(handle, index) < 0) {
		log_warn("opsql_fetch_scroll failed[%d]\n", index);
		goto out;
	}

	snprintf(short_message, sizeof(short_message), "%s --- %s 【%s】", quota, nm, "露国宠儿");

	log_info("short message service: %s==>%s\n", "18519127396", short_message);
	op4g_send_message("18519127396",short_message);
out:
	if (handle)
		opsql_free(handle);

	return 0;
}

