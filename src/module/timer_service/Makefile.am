ACLOCAL_AMFLAGS = -I m4

AUTOMAKE_OPTIONS=foreign
lib_LTLIBRARIES=libtimer.la

libtimer_la_SOURCES= timer_service.c
libtimer_la_includedir=$(prefix)/include/module
libtimer_la_include_HEADERS=timer_service.h

libtimer_la_CFLAGS  = -I$(top_srcdir)/src
libtimer_la_CFLAGS += -I$(prefix)/include
libtimer_la_CFLAGS += -W -Wall -Wchar-subscripts -Wcomment -Wformat -Wimplicit -Wmissing-braces -Wno-error=unused-result -Wparentheses -Wswitch -Wno-unused-parameter  -Wfloat-equal -Wsign-compare -Wpointer-arith -Winline -Werror  -rdynamic -std=gnu99

libtimer_la_LDFLAGS = -L$(top_builddir)/src/opbox/.libs
libtimer_la_LDFLAGS += -L$(top_builddir)/src/base/.libs
libtimer_la_LDFLAGS += -L$(prefix)/lib
libtimer_la_LIBADD = -lpthread -levent -lbase

libtimeretcdir = $(prefix)/etc/opcron
libtimeretc_DATA=timer_serv

