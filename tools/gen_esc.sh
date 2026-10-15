#!/usr/bin/env bash
# regenerate tools/esc.S + tools/esc.h from the verified target addresses
set -e
cd "$(dirname "$0")"
CC=/home/v/Android/Sdk/ndk/29.0.13846066/toolchains/llvm/prebuilt/linux-x86_64/bin/clang
OC=/home/v/Android/Sdk/ndk/29.0.13846066/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-objcopy
mkdir -p /tmp/esc
$CC -target aarch64-linux-android -c -o /tmp/esc/esc.o esc.S
$OC -O binary --only-section=.text /tmp/esc/esc.o /tmp/esc/esc.bin
