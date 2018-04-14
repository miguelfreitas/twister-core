#!/bin/sh

git submodule update --init

./autotool.sh
./configure $@

