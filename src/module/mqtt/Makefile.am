AUTOMAKE_OPTIONS=foreign
bin_PROGRAMS=mqtt
mqtt_SOURCES=mosquitto.c \
		lib/alias_mosq.c \
		bridge.c \
		bridge_topic.c \
		conf.c \
		conf_includedir.c \
		context.c \
		control.c \
		database.c \
		handle_auth.c \
		handle_connack.c \
		handle_connect.c \
		handle_disconnect.c \
		lib/handle_ping.c \
		lib/handle_pubackcomp.c \
		handle_publish.c \
		lib/handle_pubrec.c \
		lib/handle_pubrel.c \
		lib/handle_suback.c \
		handle_subscribe.c \
		lib/handle_unsuback.c \
		handle_unsubscribe.c \
		keepalive.c \
		logging.c \
		loop.c \
		lib/memory_mosq.c \
		memory_public.c \
		lib/misc_mosq.c \
		mux.c \
		mux_epoll.c \
		mux_poll.c \
		net.c \
		lib/net_mosq.c \
		lib/net_mosq_ocsp.c \
		lib/packet_datatypes.c \
		lib/packet_mosq.c \
		password_mosq.c \
		property_broker.c \
		lib/property_mosq.c \
		persist_read.c \
		persist_read_v234.c \
		persist_read_v5.c \
		persist_write.c \
		persist_write_v5.c \
		plugin.c \
		plugin_public.c \
		read_handle.c \
		retain.c \
		security.c \
		security_default.c \
		send_auth.c \
		send_connack.c \
		lib/send_connect.c \
		lib/send_disconnect.c \
		lib/send_mosq.c \
		lib/send_publish.c \
		send_suback.c \
		lib/send_subscribe.c \
		send_unsuback.c \
		lib/send_unsubscribe.c \
		service.c \
		session_expiry.c \
		signals.c \
		lib/strings_mosq.c \
		subs.c \
		sys_tree.c \
		lib/time_mosq.c \
		topic_tok.c \
		lib/tls_mosq.c \
		lib/utf8_mosq.c \
		lib/util_mosq.c \
		lib/util_topic.c \
		websockets.c \
		will_delay.c \
		lib/will_mosq.c \
		xtreport.c \
		mqtt.c

mqtt_LDFLAGS =-L$(top_builddir)/src/base/.libs
mqtt_LDFLAGS +=-L$(top_builddir)/src/opbox/.libs
mqtt_LDFLAGS += -L$(prefix)/lib 

mqtt_LDADD = -lpthread  -ldl -lbase -liniparser -lopbox

A=$(top_srcdir)/src/module/mqtt/mqtt
mqtt_includedir=$(prefix)/include/module/mqtt
mqtt_include_HEADERS = $(A)/mosquitto_broker.h $(A)/mosquitto.h $(A)/mosquitto_plugin.h  $(A)/mqtt_protocol.h

mqtt_CFLAGS  = -I$(top_srcdir)/src/module/mqtt/mqtt
mqtt_CFLAGS  += -I$(top_srcdir)/src/module/mqtt/lib
mqtt_CFLAGS  += -I$(top_srcdir)/src/module/mqtt
mqtt_CFLAGS  += -I$(top_srcdir)/src/
mqtt_CFLAGS += -I$(prefix)/include
mqtt_CFLAGS += -g -DWITH_BROKER -W -Wall -Wchar-subscripts -Wcomment -Wformat -Wimplicit -Wmissing-braces \
	-Wno-error=unused-result -Wparentheses -Wswitch -Wno-unused-parameter  -Wfloat-equal -Wsign-compare -Wpointer-arith -Winline  -rdynamic -std=gnu99


mqttetcdir = $(prefix)/etc/mqtt
mqttetc_DATA=mqtt.conf 
mqtt1etcdir = $(prefix)/log/mqtt
mqtt1etc_DATA=.log

