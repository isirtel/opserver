#include "mqtt.h"
#include "iniparser.h"
#include "opbox/utils.h"
#include "base/oplog.h"
#include "config.h"

#define MQTT_CONF "mqtt:path"

int main(int argc, char *argv[])
{
#define MQTT_ARGV_NUM 3
#define MQTT_ARGV_ELE_LENGTH 128
		const char *str = NULL;
		dictionary *dict = NULL;
		char mqtt_conf_file[246] = {};
		int argc_int =0 ;
		char **argv_str = NULL;
		int i = 0;

		op_daemon();
		dict = iniparser_load(OPSERVER_CONF);
		if (!dict) {
			log_error ("iniparser_load faild[%s]\n", OPSERVER_CONF);
			return -1;
		}

		if(!(str = iniparser_getstring(dict,MQTT_CONF,NULL))) {
			log_error_ex ("iniparser_getstring faild[%s]\n", MQTT_CONF);
			return -1;
		}

		snprintf(mqtt_conf_file, sizeof(mqtt_conf_file), "%s/%s", str, "mqtt.conf");
	
		iniparser_freedict(dict);

		argv_str = calloc(1, sizeof(char*) * MQTT_ARGV_NUM);
		if (!argv_str) {
			log_error_ex ("calloc failed\n");
			return -1;
		}
	
		for(i = 0; i < MQTT_ARGV_NUM; i++) {
			argv_str[i] = calloc(1, MQTT_ARGV_ELE_LENGTH);
			if (!argv_str[i]) {
				log_error_ex ("calloc failed, index=%d\n",i);
				return -1;
			}
		}
	
		op_strlcpy(argv_str[0],"mqtt", MQTT_ARGV_ELE_LENGTH);
		op_strlcpy(argv_str[1],"-c", MQTT_ARGV_ELE_LENGTH);
		op_strlcpy(argv_str[2],mqtt_conf_file, MQTT_ARGV_ELE_LENGTH);

	
		argc_int = MQTT_ARGV_NUM;

		mqtt_main(argc_int, argv_str);
		return 0;
}
