#!/usr/bin/env bash
# Build every native piece the shell scripts and the APK consume.
#
# Until now these were compiled by hand, one clang line at a time, which meant the
# source tree could not actually be rebuilt from a clean checkout: apk/build.sh copies
# the *binaries* tools/sud, tools/suc and tools/sumount into the APK's assets.
#
# -static is deliberate: the loader situation differs per SELinux domain on this device
# (the kernel-helper domain cannot resolve some shared libs), and every on-hardware
# measurement was taken with static binaries.
set -eu

SDK=${SDK:-/home/v/Android/Sdk}
NDK_VER=${NDK_VER:-29.0.13846066}
CC=$SDK/ndk/$NDK_VER/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android21-clang
ROOT=$(cd "$(dirname "$0")" && pwd)
OUT=${OUT:-$ROOT}
CFLAGS="-target aarch64-linux-android21 -O2 -Wall -static"

PIECES="sud suc sumount clobber sugate_probe elflush sgt_pay icache_sync rootsh"

[ -x "$CC" ] || { echo "no NDK clang at: $CC"; exit 1; }

for n in $PIECES; do
	src=$ROOT/$n.c
	[ -f "$src" ] || { echo "MISSING SOURCE: $n.c"; exit 1; }
	printf '[native] %-14s -> %s\n' "$n" "$OUT/$n"
	$CC $CFLAGS -o "$OUT/$n" "$src"
done

# The APK's own JNI half: the same clobber.c compiled a second way, plus the bridge.
# No -static here: this one has to be a shared object.
printf '[native] %-14s -> %s\n' libesc.so "$OUT/libesc.so"
$CC -target aarch64-linux-android21 -O2 -Wall -fPIC -shared -DESC_LIB \
	-o "$OUT/libesc.so" "$ROOT/clobber.c" "$ROOT/apk/jni/jni_esc.c"

echo
echo "built into $OUT"
echo "next: bash $ROOT/apk/build.sh"
