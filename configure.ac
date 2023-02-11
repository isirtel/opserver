#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([opserver],[1.00],[itel@sina.com])
AM_INIT_AUTOMAKE([subdir-objects foreign])
AC_CONFIG_HEADERS([config.h])
# Checks for programs.
AC_PROG_CC
LT_INIT 
# Checks for libraries.
# Checks for header files.

# Checks for typedefs, structures, and compiler characteristics.
AC_DEFINE([OPSERVER_CONF],["/home/opserver/etc/opserver.conf"],["opserver config file"])
CFLAGS=""
# Checks for library functions.
AC_CONFIG_FILES([
src/base/Makefile
src/opbox/Makefile
src/module/Makefile
src/module/opmgr/Makefile
src/module/op4g/Makefile
src/module/outer/Makefile
src/module/timer_service/Makefile
src/module/spider/Makefile
src/module/webserver/Makefile
src/module/mqtt/Makefile
src/module/mqtt/lib/Makefile
src/module/opfile/Makefile
src/module/opids/Makefile
src/Makefile
src/tools/Makefile
src/tools/pbus/Makefile
src/tools/file_compile/Makefile
])
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
