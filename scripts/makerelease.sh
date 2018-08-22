#!/bin/bash

VER=1.4.7

if [ ! -f formats.txt ]
then
	echo "Run this script from the main directory"
	exit 1
fi

rm -rf .build-tmp
mkdir .build-tmp

D=".build-tmp/deark-$VER"

#echo "Using temporary directory .build-tmp/deark-$VER"

mkdir $D

mkdir $D/src
cp -p src/*.c src/*.h src/*.rc $D/src/

mkdir $D/modules
cp -p modules/*.c $D/modules/

mkdir $D/foreign
cp -p foreign/* $D/foreign/

mkdir $D/scripts
cp -p scripts/*.sh scripts/*.pl $D/scripts/

mkdir $D/proj
mkdir $D/proj/vs2008
cp -p proj/vs2008/*.sln proj/vs2008/*.vcproj $D/proj/vs2008/

mkdir $D/obj
mkdir $D/obj/src
cp -p obj/src/.gitignore $D/obj/src/
mkdir $D/obj/modules
cp -p obj/modules/.gitignore $D/obj/modules/

cp -p readme.md technical.md formats.txt COPYING Makefile deps.mk $D/

mkdir $D/x64
cp -p Release64/deark.exe $D/x64/

echo "Writing deark-${VER}.tar.gz"
tar --directory .build-tmp -c --owner=root --group=root -O deark-$VER | gzip -9 > deark-${VER}.tar.gz

rm -rf .build-tmp

