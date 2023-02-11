ACLOCAL_AMFLAGS = -I m4

AUTOMAKE_OPTIONS=foreign
lib_LTLIBRARIES=libopids.la

libopids_la_SOURCES=opids.c
libopids_la_includedir=$(prefix)/include/module
libopids_la_include_HEADERS=opids.h

libopids_la_CFLAGS  = -I$(top_srcdir)/src
libopids_la_CFLAGS += -I$(prefix)/include
libopids_la_CFLAGS += -W -Wall -Wchar-subscripts -Wcomment -Wformat -Wimplicit -Wmissing-braces -Wno-error=unused-result -Wparentheses -Wswitch -Wno-unused-parameter  -Wfloat-equal -Wsign-compare -Wpointer-arith -Winline -Werror  -rdynamic -std=gnu99

libopids_la_LDFLAGS = -L$(top_builddir)/src/opbox/.libs
libopids_la_LDFLAGS += -L$(top_builddir)/src/base/.libs
libopids_la_LDFLAGS += -L$(prefix)/lib
libopids_la_LIBADD = -lpthread -levent -lbase
