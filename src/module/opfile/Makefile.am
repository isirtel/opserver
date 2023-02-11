ACLOCAL_AMFLAGS = -I m4

AUTOMAKE_OPTIONS=foreign
lib_LTLIBRARIES=libopfile.la

libopfile_la_SOURCES=opfile.c opfile_text.c
libopfile_la_includedir=$(prefix)/include/module
libopfile_la_include_HEADERS=opfile.h opfile_pub.h

libopfile_la_CFLAGS  = -I$(top_srcdir)/src
libopfile_la_CFLAGS += -I$(prefix)/include
libopfile_la_CFLAGS += -g -W -DHAVE_CONFIG_H -Wall -Wchar-subscripts -Wcomment -Wformat -Wimplicit -Wmissing-braces -Wno-error=unused-result -Wparentheses -Wswitch -Wno-unused-parameter  -Wno-float-equal -Wsign-compare -Wpointer-arith -Winline -Werror  -rdynamic -std=gnu99
libopfile_la_LDFLAGS = -L$(top_builddir)/src/base/.libs
libopfile_la_LDFLAGS += -L$(top_builddir)/src/opbox/.libs
libopfile_la_LDFLAGS += -L$(prefix)/lib
libopfile_la_LIBADD = -lm -lbz2 -lbase -lopbox -lxml2 -liniparser -lhs -lhs_runtime 

libopfileetcdir = $(prefix)/etc/
libopfileetc_DATA=opfile_magic.xml
