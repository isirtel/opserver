ACLOCAL_AMFLAGS = -I m4
AUTOMAKE_OPTIONS=foreign
lib_LTLIBRARIES=libbase.la
libbase_la_SOURCES=oplog.c oprpc.c opcli.c opsql.c opmem.c libtipc.c hash_mem.c
libbase_la_includedir=$(prefix)/include/base
libbase_la_include_HEADERS=oplog.h oprpc.h opcli.h opsql.h sql_name.h opmem.h tipcc.h hash_mem.h

libbase_la_CFLAGS = -I$(top_srcdir)/src

libbase_la_CFLAGS += -I$(prefix)/include
libbase_la_CFLAGS += -W -Wall -Wchar-subscripts -Wcomment -Wformat -Wimplicit -Wmissing-braces -Wparentheses -Wswitch -Wno-unused-parameter  -Wfloat-equal -Wsign-compare -Wpointer-arith -Winline -Werror  -rdynamic -std=gnu99 -g

libbase_la_LDFLAGS = -L$(top_builddir)/src/opbox/.libs
libbase_la_LDFLAGS += -L$(prefix)/lib
libbase_la_LIBADD = -liniparser -lpthread -lopbox -levent -lodbcinst -lodbc
libbase_ladir = $(prefix)/etc
libbase_la_DATA=odbc.ini odbcinst.ini
libbase_la1dir = $(prefix)/log/prog
libbase_la1_DATA=.log