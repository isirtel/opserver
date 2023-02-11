AUTOMAKE_OPTIONS=foreign
bin_PROGRAMS=file_compile
file_compile_SOURCES=main.c file_compile.c

file_compile_CFLAGS = -I$(top_srcdir)/src/
file_compile_CFLAGS += -W -Wall -Wchar-subscripts -Wcomment -Wformat -Wimplicit -Wmissing-braces -Wparentheses -Wswitch -Wno-unused-parameter -Wfloat-equal -Wsign-compare -Wpointer-arith -Winline  -rdynamic -g

file_compile_LDFLAGS=-L$(top_builddir)/src/base/.libs
file_compile_LDFLAGS+=-L$(prefix)/lib

file_compile_LDADD = -lbase