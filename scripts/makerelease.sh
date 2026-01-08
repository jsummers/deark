#!/bin/bash

VER=1.7.2

if [ ! -f formats.txt ]
then
	echo "Run this script from the main directory"
	exit 1
fi

if [ -f src/deark-config2.h ]
then
	echo "Remove src/deark-config2.h first"
	exit 1
fi

rm -rf .build-tmp
mkdir .build-tmp

D=".build-tmp/deark-$VER"

#echo "Using temporary directory .build-tmp/deark-$VER"

mkdir $D

mkdir $D/src
cp -p src/*.c src/*.h src/*.rc src/*.ico src/*.manifest $D/src/

mkdir $D/modules
cp -p modules/*.c $D/modules/

mkdir $D/foreign
cp -p foreign/* $D/foreign/

mkdir $D/scripts
cp -p scripts/*.sh scripts/*.pl $D/scripts/

mkdir $D/proj
mkdir $D/proj/vs2022
cp -p proj/vs2022/*.sln proj/vs2022/*.vcxproj proj/vs2022/*.vcxproj.filters $D/proj/vs2022/

mkdir $D/obj
mkdir $D/obj/src
cp -p obj/src/.gitignore $D/obj/src/
mkdir $D/obj/modules
cp -p obj/modules/.gitignore $D/obj/modules/

cp -p readme.md technical.md formats.txt COPYING Makefile deps.mk .editorconfig $D/

mkdir $D/x64
cp -p Release64/deark.exe $D/x64/

echo "Writing deark-${VER}.tar.gz"
tar --directory .build-tmp -c --owner=root:0 --group=root:0 -O deark-$VER | gzip -9 > deark-${VER}.tar.gz

rm -rf .build-tmp

