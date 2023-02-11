ACLOCAL_AMFLAGS = -I m4

AUTOMAKE_OPTIONS=foreign
lib_LTLIBRARIES=libspider.la

libspider_la_SOURCES= spider.c
libspider_la_includedir=$(prefix)/include/module
libspider_la_include_HEADERS=spider.h

libspider_la_CFLAGS  = -I$(top_srcdir)/src
libspider_la_CFLAGS += -I$(top_srcdir)/src/module/op4g
libspider_la_CFLAGS += -I$(prefix)/include
libspider_la_CFLAGS += -W -Wall -Wchar-subscripts -Wcomment -Wformat -Wimplicit -Wmissing-braces -Wno-error=unused-result -Wparentheses -Wswitch -Wno-unused-parameter  -Wfloat-equal -Wsign-compare -Wpointer-arith -Winline -Werror  -rdynamic -std=gnu99

libspider_la_LDFLAGS = -L$(top_builddir)/src/opbox/.libs
libspider_la_LDFLAGS += -L$(top_builddir)/src/base/.libs
libspider_la_LDFLAGS += -L$(prefix)/lib
libspider_la_LIBADD = -lpthread -levent -lbase

libspideretcdir = $(prefix)/script/spider
libspideretc_DATA=spider_stock.py


