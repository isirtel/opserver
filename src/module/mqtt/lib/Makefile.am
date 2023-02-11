ACLOCAL_AMFLAGS = -I m4

AUTOMAKE_OPTIONS=foreign
lib_LTLIBRARIES=libmqttbase.la

libmqttbase_la_SOURCES=mosquitto.c \
actions.c \
callbacks.c \
connect.c \
handle_auth.c \
handle_connack.c \
handle_disconnect.c \
handle_ping.c \
handle_pubackcomp.c \
handle_publish.c \
handle_pubrec.c \
handle_pubrel.c \
handle_suback.c \
handle_unsuback.c \
helpers.c \
logging_mosq.c \
loop.c \
memory_mosq.c \
messages_mosq.c \
misc_mosq.c \
net_mosq_ocsp.c \
net_mosq.c \
options.c \
packet_datatypes.c \
packet_mosq.c \
property_mosq.c \
read_handle.c \
send_connect.c \
send_disconnect.c \
send_mosq.c \
send_publish.c \
send_subscribe.c \
send_unsubscribe.c \
socks_mosq.c \
srv_mosq.c \
strings_mosq.c \
thread_mosq.c \
time_mosq.c \
tls_mosq.c \
utf8_mosq.c \
util_mosq.c \
util_topic.c \
will_mosq.c


libmqttbase_la_CFLAGS  = -I$(top_srcdir)/src/module/mqtt/mqtt
libmqttbase_la_CFLAGS  += -I$(top_srcdir)/src/module/mqtt/lib
libmqttbase_la_CFLAGS  += -I$(top_srcdir)/src
libmqttbase_la_CFLAGS  += -I$(top_srcdir)/src/module/mqtt
libmqttbase_la_CFLAGS += -I$(prefix)/include
libmqttbase_la_CFLAGS += -g  -W -Wall -Wchar-subscripts -Wcomment -Wformat -Wimplicit -Wmissing-braces \
	-Wno-error=unused-result -Wparentheses -Wswitch -Wno-unused-parameter  -Wfloat-equal -Wsign-compare -Wpointer-arith -Winline  -rdynamic -std=gnu99
libmqttbase_la_LIBADD = -lpthread


