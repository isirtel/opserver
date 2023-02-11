ACLOCAL_AMFLAGS = -I m4

AUTOMAKE_OPTIONS=foreign
lib_LTLIBRARIES=libouter.la

libouter_la_SOURCES=opmail.c
libouter_la_includedir=$(prefix)/include/module
libouter_la_include_HEADERS=opmail.h

libouter_la_CFLAGS  = -I$(top_srcdir)/src
libouter_la_CFLAGS += -I$(prefix)/include
libouter_la_CFLAGS += -W -Wall -Wchar-subscripts -Wcomment -Wformat -Wimplicit -Wmissing-braces -Wno-error=unused-result -Wparentheses -Wswitch -Wno-unused-parameter  -Wfloat-equal -Wsign-compare -Wpointer-arith -Winline -Werror  -rdynamic -std=gnu99

libouter_la_LDFLAGS = -L$(top_builddir)/src/opbox/.libs
libouter_la_LDFLAGS += -L$(top_builddir)/src/base/.libs
libouter_la_LDFLAGS += -L$(prefix)/lib
libouter_la_LIBADD = -lpthread -levent -lbase