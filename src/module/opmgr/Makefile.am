ACLOCAL_AMFLAGS = -I m4
AUTOMAKE_OPTIONS=foreign
lib_LTLIBRARIES=libopmgr.la
libopmgr_la_SOURCES=opmgr.c opmgr_cmd.c
libopmgr_la_includedir=$(prefix)/include/module
libopmgr_la_include_HEADERS=opmgr.h opmgr_bus.h

libopmgr_la_CFLAGS = -I$(top_srcdir)/src
libopmgr_la_CFLAGS += -I$(top_srcdir)/src/module/mqtt
libopmgr_la_CFLAGS += -I$(prefix)/include
libopmgr_la_CFLAGS += -I$(prefix)/include/module
libopmgr_la_CFLAGS += -W -Wall -Wchar-subscripts -Wcomment -Wformat -Wimplicit -Wmissing-braces -Wparentheses -Wswitch -Wno-unused-parameter  -Wfloat-equal -Wsign-compare -Wpointer-arith -Winline -Werror  -rdynamic -std=gnu99

libopmgr_la_LDFLAGS = -L$(top_builddir)/src/opbox/.libs
libopmgr_la_LDFLAGS += -L$(top_builddir)/src/base/.libs
libopmgr_la_LDFLAGS += -L$(prefix)/lib
libopmgr_la_LIBADD = -lpthread -levent -lbase