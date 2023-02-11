AUTOMAKE_OPTIONS=foreign
bin_PROGRAMS=pbus
pbus_SOURCES=pbus.c
pbus_LDFLAGS=-L$(top_builddir)/src/opbox/.libs
pbus_LDFLAGS+=-L$(top_builddir)/src/base/.libs
pbus_LDFLAGS+=-L$(prefix)/lib

pbus_LDADD = -lopbox -lbase
pbus_CFLAGS = -I$(top_srcdir)/src
pbus_CFLAGS += -I$(top_srcdir)/src/module/opmgr
pbus_CFLAGS += -I$(prefix)/include
pbus_CFLAGS += -W -Wall -Wchar-subscripts -Wcomment -Wformat -Wimplicit -Wmissing-braces -Wparentheses -Wswitch -Wno-unused-parameter -Wfloat-equal -Wsign-compare -Wpointer-arith -Winline -Werror -rdynamic -g


