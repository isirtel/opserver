#!/bin/sh
aclocal
autoconf
libtoolize
autoheader
automake --add-missing

