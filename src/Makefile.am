AUTOMAKE_OPTIONS=foreign
bin_PROGRAMS=opserver
opserver_SOURCES= opserver.c
opserver_LDFLAGS=-L$(top_builddir)/src/opbox/.libs
opserver_LDFLAGS+=-L$(top_builddir)/src/base/.libs
opserver_LDFLAGS+=-L$(top_builddir)/src/module/opmgr/.libs
opserver_LDFLAGS+=-L$(top_builddir)/src/module/op4g/.libs
opserver_LDFLAGS+=-L$(top_builddir)/src/module/timer_service/.libs
opserver_LDFLAGS+=-L$(top_builddir)/src/module/spider/.libs
opserver_LDFLAGS+=-L$(top_builddir)/src/module/webserver/.libs
opserver_LDFLAGS+=-L$(top_builddir)/src/module/outer/.libs
opserver_LDFLAGS+=-L$(top_builddir)/src/module/mqtt/.libs
opserver_LDFLAGS+=-L$(top_builddir)/src/module/mqtt/lib/.libs
opserver_LDFLAGS+=-L$(top_builddir)/src/module/opfile/.libs
opserver_LDFLAGS+=-L$(top_builddir)/src/module/opids/.libs
opserver_LDFLAGS+=-L$(prefix)/lib

opserver_LDADD = -lopbox -liniparser -lbase -levent -lopmgr -lop4g -ltimer -lspider -louter -lpcap -lmqttbase -lopfile -ldl  -lpthread -lz -lopids
CFLAGS="-g"
opserver_CFLAGS = -I$(top_srcdir)/src
opserver_CFLAGS += -I$(top_srcdir)/src/module/opmgr
opserver_CFLAGS += -I$(top_srcdir)/src/module/op4g
opserver_CFLAGS += -I$(top_srcdir)/src/module/timer_service
opserver_CFLAGS += -I$(top_srcdir)/src/module/spider
opserver_CFLAGS += -I$(top_srcdir)/src/module/outer
opserver_CFLAGS += -I$(top_srcdir)/src/module/mqtt/
opserver_CFLAGS += -I$(top_srcdir)/src/module/opfile
opserver_CFLAGS += -I$(top_srcdir)/src/module/opids
opserver_CFLAGS += -I$(prefix)/include
opserver_CFLAGS += -I$(prefix)/include/module
opserver_CFLAGS += -I$(prefix)/include/libpcap
opserver_CFLAGS += -W -Wall -Wchar-subscripts -Wcomment -Wformat -Wimplicit -Wmissing-braces -Wparentheses -Wswitch -Wno-unused-parameter -Wfloat-equal -Wsign-compare -Wpointer-arith -Winline -Werror -rdynamic -g
opserveretcdir = $(prefix)/etc
opserveretc_DATA=opserver.conf
