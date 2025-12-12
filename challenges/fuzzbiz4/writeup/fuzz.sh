#!/bin/bash

afl-clang-fast ../src/fuzzbiz.c -o fuzzbiz
afl-fuzz -i ./inputs -o ./findings -- ./fuzzbiz