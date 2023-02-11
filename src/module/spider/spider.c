#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>

#include "spider.h"
#include "event.h"
#include "base/oplog.h"
#include "opbox/list.h"
#include "opbox/utils.h"
#include "base/opsql.h"
#include "base/oprpc.h"
#include "base/opmem.h"
#include "op4g.h"

struct _spider_thread_ 
{
	pthread_t thread_id;
	pthread_attr_t thread_attr;
};

struct _spider_struct {
	struct event_base *base;
	struct _spider_thread_ thread;
	struct list_head head;
	pthread_mutex_t lock;
	pthread_mutexattr_t attr;
};

struct _spider_monitor {
	struct list_head list;
	char stock_code[20];
	char name[20];
	double buy_price;
	double sale_price;
#define STAT_BUY 0
#define STAT_SALE 1
	int stat;
};

static struct _spider_struct *self = NULL;

static void *spider_routine (void *arg)
{
	if(event_base_loop(arg, EVLOOP_NO_EXIT_ON_EMPTY) < 0) {
		log_error ("op4g_routine failed\n");
		pthread_detach(pthread_self());
		pthread_exit(NULL);
		goto exit;
	}

	log_debug ("op4g_routine exit\n");
exit:
	return NULL;
}

int spider_check_stock(unsigned char *req, int req_size, unsigned char *response, int res_size)
{
	void *handle = NULL;
	int count = 0;
	char sql[OPSQL_LEN];
	struct _spider_struct *spider = NULL;
	spider = self;
	struct _spider_monitor *item = NULL;
	double closing_price = 0.0;

	pthread_mutex_lock(&spider->lock);
	if (list_empty(&spider->head)) {
		goto out;
	}

	list_for_each_entry(item, &spider->head, list) {
		handle = opsql_alloc();
		if (!handle) {
			log_warn("opsql_alloc failed\n");
			goto out;
		}

		snprintf(sql, sizeof(sql),"select closing_price from stock_info where stock_code='%s' order by sdate desc limit 1;", item->stock_code);
		log_debug("sql:%s\n",sql);
		count = opsql_query(handle, sql);
		if (count <= 0) {
			log_warn("opsql_query failed\n");
			continue;
		}

		log_debug("count=%d\n", count);
		opsql_bind_col(handle, 1, OPSQL_DOUBLE, &closing_price, sizeof(closing_price));
		if(opsql_fetch_scroll(handle, count) < 0) {
			log_warn("opsql_fetch_scroll failed[%d]\n", count);
			goto out;
		}
		log_debug("stock_code=%s,buy_price=%lf, sale_price=%lf, closing_price=%lf\n", item->stock_code, item->buy_price, item->sale_price, closing_price);
		if (item->buy_price >= closing_price && item->stat != STAT_SALE) {
			item->stat = STAT_SALE;
			snprintf(sql, sizeof(sql),"update stock_spider set sta='%d' where stock_code='%s';", STAT_SALE, item->stock_code);
			if(opsql_exe_single(sql) < 0) {
				log_warn("opsql_exe_single[%s]\n", sql);
				goto out;
			}

			op4g_send_message_ex("18519127396", "购买股票: %s(%s)， 上一交易日收盘价:%lf 【露国宠儿】", item->stock_code, item->name,closing_price);
		}

		if (item->sale_price <= closing_price && item->stat != STAT_BUY) {
			item->stat = STAT_BUY;

			snprintf(sql, sizeof(sql),"update stock_spider set sta='%d' where stock_code='%s';", STAT_BUY, item->stock_code);
			if(opsql_exe_single(sql) < 0) {
				log_warn("opsql_exe_single[%s]\n", sql);
				goto out;
			}

			op4g_send_message_ex("18519127396", "出售股票: %s(%s)， 上一交易日收盘价:%lf 【露国宠儿】", item->stock_code, item->name, closing_price);
		}

		opsql_free(handle);
		handle = NULL;
	}

out:
	pthread_mutex_unlock(&spider->lock);
	if (handle)
		opsql_free(handle);
	return 0;
}

void spider_stock_load(struct list_head *head)
{
	void *handle = NULL;
	int count = 0;
	char sql[OPSQL_LEN];
	char stock_code[20] = {};
	char note_code[20] = {};
	double buy_price = 0.0;
	double sale_price = 0.0;
	int status = 0;
	int ret = 0;
	struct _spider_struct *spider = NULL;
	struct _spider_monitor *item = NULL;

	spider = self;
	
	pthread_mutex_lock(&spider->lock);
	if (!head) {
		pthread_mutex_unlock(&spider->lock);
		goto out;
	}

	if (!list_empty(head)) {
		item = list_first_entry(&spider->head, struct _spider_monitor , list);
		list_del(&item->list);
		free(item);
	}

	pthread_mutex_unlock(&spider->lock);
	
	handle = opsql_alloc();
	if (!handle) {
		log_warn("opsql_alloc failed\n");
		goto out;
	}

	snprintf(sql, sizeof(sql),"select stock_code,buy_price,sale_price,note,sta from stock_spider;");
	count = opsql_query(handle, sql);
	if (count <= 0) {
		log_warn("opsql_query failed\n");
		goto out;
	}
	
	log_debug("sql:%s\n",sql);
	log_debug("count=%d\n", count);

	opsql_bind_col(handle, 1, OPSQL_CHAR, stock_code, sizeof(stock_code));
	opsql_bind_col(handle, 2, OPSQL_DOUBLE, &buy_price, sizeof(buy_price));
	opsql_bind_col(handle, 3, OPSQL_DOUBLE, &sale_price, sizeof(sale_price));
	opsql_bind_col(handle, 4, OPSQL_CHAR, note_code, sizeof(note_code));
	opsql_bind_col(handle, 5, OPSQL_INTEGER, &status, sizeof(status));
	while(count--){
		ret = opsql_fetch(handle);
		if (ret < 0) {
			log_warn("fetch failed, current count=%d\n",count);
			goto out;
		}

		item = op_calloc(1, sizeof(*item));
		if (!item) {
			log_warn("calloc failed[%d]\n", errno);
			goto out;
		}

		INIT_LIST_HEAD(&item->list);
		op_strlcpy(item->stock_code , stock_code, sizeof(item->stock_code));
		op_strlcpy(item->name , note_code, sizeof(item->name));
		item->buy_price = buy_price;
		item->sale_price = sale_price;
		item->stat = status;
		pthread_mutex_lock(&spider->lock);
		list_add_tail(&item->list, head);
		pthread_mutex_unlock(&spider->lock);

		log_debug("stock_code=%s,buy_price=%lf, sale_price=%lf\n", stock_code, buy_price, sale_price);
	}

out:
	if (handle)
		opsql_free(handle);

	return;
}

void spider_bus_register(void)
{
	op_tipc_register(tipc_opserver_check_stock, spider_check_stock);
	
	op_local_register(tipc_opserver_check_stock, spider_check_stock);
	return;
}

void *spider_init(void)
{
	struct _spider_struct *spider = NULL;

	spider = op_calloc(1, sizeof(*spider));
	if (!spider) {
		log_error("calloc failed[%d]\n", errno);
		goto exit;
	}

	self = spider;

	spider->base = event_base_new();
	if (!spider->base) {
		log_error ("event_base_new faild\n");
		goto exit;
	}

	if(pthread_mutexattr_init(&spider->attr)) {
		log_error ("pthread_mutexattr_init faild\n");
		goto exit;
	}

	if(pthread_mutex_init(&spider->lock, &spider->attr)) {
		log_error ("pthread_mutex_init faild\n");
		goto exit;
	}

	INIT_LIST_HEAD(&spider->head);

	spider_stock_load(&spider->head);

	spider_bus_register();

	if(pthread_attr_init(&spider->thread.thread_attr)) {
		log_error ("pthread_attr_init faild\n");
		goto exit;
	}

	if(pthread_create(&spider->thread.thread_id, &spider->thread.thread_attr, spider_routine, spider->base)) {
		log_error ("pthread_create faild\n");
		goto exit;
	}

	return spider;

exit:
	spider_exit(spider);
	return NULL;
}

void spider_exit(void *spider)
{

	return;
}
  
