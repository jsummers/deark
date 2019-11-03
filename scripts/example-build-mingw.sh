#!/bin/bash

# This is an example script to build Deark using Mingw-w64.
# Run this script from your main deark directory, to create mingwobj/deark.exe.
#
# I know that a shell script is not very Windows-y. It's expected to be run
# via Cygwin. Otherwise, you may have to translate it to suit your needs.

set -e
export DEARK_OBJDIR="mingwobj"
# For 32-built builds, change "x86_64" to "i686".
TOOLSPREFIX="x86_64-w64-mingw32-"
export CC=${TOOLSPREFIX}gcc.exe
export AR=${TOOLSPREFIX}ar.exe
export DEARK_WINDRES=${TOOLSPREFIX}windres.exe
export LDFLAGS="-Wall -municode"

if [ "$1" = "clean" ]
then
 make clean
else
 mkdir -p $DEARK_OBJDIR/src
 mkdir -p $DEARK_OBJDIR/modules
 make -j4 dep
 make -j4
fi

