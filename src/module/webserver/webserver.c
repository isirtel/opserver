#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>

#include "webserver.h"
#include "nginx.h"
#include "base/oplog.h"
#include "config.h"
#include "opbox/utils.h"

#include "iniparser.h"
#include "base/oplog.h"
#include "opbox/utils.h"

#define WEBSERVER_CONF "webserver:path"
#define WEBSERVER_CONF_PREFIX "webserver:prefix"
#define WEBSERVER_CONF_ERROR_LOG "webserver:error_log"

void nginx_main_start(char *opserver_conf_path)
{
#define WEBSERVER_ARGV_NUM 7
#define WEBSERVER_ARGV_ELE_LENGTH 128
	const char *str = NULL;
	dictionary *dict = NULL;
	char web_conf_file[246] = {};
	char web_prefix[64] = {};
	char error_log[64] ={};
	int argc =0 ;
	char **argv = NULL;
	int i = 0;

	dict = iniparser_load(OPSERVER_CONF);
	if (!dict) {
		log_error ("iniparser_load faild[%s]\n", OPSERVER_CONF);
		goto out;
	}

	if(!(str = iniparser_getstring(dict,WEBSERVER_CONF,NULL))) {
		log_error_ex ("iniparser_getstring faild[%s]\n", WEBSERVER_CONF);
		goto out;
	}

	snprintf(web_conf_file, sizeof(web_conf_file), "%s/%s", str, "webserver.conf");

	if(!(str = iniparser_getstring(dict,WEBSERVER_CONF_PREFIX,NULL))) {
		log_error_ex ("iniparser_getstring faild[%s]\n", WEBSERVER_CONF_PREFIX);
		goto out;
	}
	
	op_strlcpy(web_prefix, str,sizeof(web_prefix));

	if(!(str = iniparser_getstring(dict,WEBSERVER_CONF_ERROR_LOG,NULL))) {
		log_error_ex ("iniparser_getstring faild[%s]\n", WEBSERVER_CONF_ERROR_LOG);
		goto out;
	}

	op_strlcpy(error_log, str, sizeof(error_log));
	iniparser_freedict(dict);

	argv = calloc(1, sizeof(char*) * WEBSERVER_ARGV_NUM);
	if (!argv) {
		log_error_ex ("calloc failed\n");
		goto out;
	}

	for(i = 0; i < WEBSERVER_ARGV_NUM; i++) {
		argv[i] = calloc(1, WEBSERVER_ARGV_ELE_LENGTH);
		if (!argv[i]) {
			log_error_ex ("calloc failed, index=%d\n",i);
			goto out;
		}
	}

	op_strlcpy(argv[0],"webserver", WEBSERVER_ARGV_ELE_LENGTH);
	op_strlcpy(argv[1],"-c", WEBSERVER_ARGV_ELE_LENGTH);
	op_strlcpy(argv[2],web_conf_file, WEBSERVER_ARGV_ELE_LENGTH);
	op_strlcpy(argv[3],"-p", WEBSERVER_ARGV_ELE_LENGTH);
	op_strlcpy(argv[4],web_prefix, WEBSERVER_ARGV_ELE_LENGTH);
	op_strlcpy(argv[5],"-e", WEBSERVER_ARGV_ELE_LENGTH);
	op_strlcpy(argv[6],error_log, WEBSERVER_ARGV_ELE_LENGTH);

	argc = WEBSERVER_ARGV_NUM;

	log_debug_ex("webserver init...,conf=%s\n",web_conf_file);
	nginx_main(argc, argv);
	return;

out:
	if (dict)
		iniparser_freedict(dict);
	if (argv)
		free(argv);
	return;
}

int main(int argc, char* argv[])
{
	signal(SIGPIPE, SIG_IGN);
	nginx_main_start(OPSERVER_CONF);
	return 0;
}

void webserver_exit(void *web)
{
	return;
}
