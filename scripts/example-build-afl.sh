#!/bin/bash

# Example script to build Deark for testing with American fuzzy lop
# (http://lcamtuf.coredump.cx/afl/).
# Run this script from your main deark directory, to create aflobj/deark.
# Then, the steps to use it, in simplest form, are something like this:
#   mkdir -p testcase_dir findings_dir
#   [Copy some small test files into testcase_dir.]
#   afl-fuzz -i testcase_dir -o findings_dir -- aflobj/deark -fromstdin -l -q

set -e
export DEARK_OBJDIR="aflobj"
# Change the next line to point to your copy of afl-gcc, if needed.
export CC="afl-gcc"

if [ "$1" = "clean" ]
then
 make clean
else
 mkdir -p $DEARK_OBJDIR/src
 mkdir -p $DEARK_OBJDIR/modules
 make -j4 dep
 make -j4
fi

