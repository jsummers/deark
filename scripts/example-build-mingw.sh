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
export DEARK_RC=src/_deark_a.rc
export DEARK_WINDRES=${TOOLSPREFIX}windres.exe
export LDFLAGS="-Wall -municode"

if [ "$1" = "clean" ]
then
 make clean
else
 mkdir -p $DEARK_OBJDIR/src
 mkdir -p $DEARK_OBJDIR/modules
 # (I don't know how to get windres to accept UTF-16 input.)
 iconv -f utf16 -t cp1252 < src/deark.rc > ${DEARK_RC}
 touch --reference=src/deark.rc ${DEARK_RC}
 make -j4 dep
 make -j4
 rm ${DEARK_RC}
fi

