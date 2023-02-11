ACLOCAL_AMFLAGS = -I m4

AUTOMAKE_OPTIONS=foreign
lib_LTLIBRARIES=libop4g.la

libop4g_la_SOURCES=op4g.c u9300.c _4g_pdu.c op4g_bus.c
libop4g_la_includedir=$(prefix)/include/module
libop4g_la_include_HEADERS=op4g.h

libop4g_la_CFLAGS  = -I$(top_srcdir)/src
libop4g_la_CFLAGS += -I$(prefix)/include
libop4g_la_CFLAGS += -W -Wall -Wchar-subscripts -Wcomment -Wformat -Wimplicit -Wmissing-braces -Wno-error=unused-result -Wparentheses -Wswitch -Wno-unused-parameter  -Wfloat-equal -Wsign-compare -Wpointer-arith -Winline -Werror  -rdynamic -std=gnu99

libop4g_la_LDFLAGS = -L$(top_builddir)/src/opbox/.libs
libop4g_la_LDFLAGS += -L$(top_builddir)/src/base/.libs
libop4g_la_LDFLAGS += -L$(prefix)/lib
libop4g_la_LIBADD = -lpthread -levent -lbase