#!/bin/sh
# Builds probe.exe (Debian package gcc-mingw-w64-x86-64). The binary is not committed.
set -e
cd "$(dirname "$0")"
x86_64-w64-mingw32-gcc -O2 -s -municode -mwindows -o probe.exe probe.c -lws2_32 -lwinhttp 2>/dev/null \
  || x86_64-w64-mingw32-gcc -O2 -s -mwindows -o probe.exe probe.c -lws2_32 -lwinhttp
sha256sum probe.exe
