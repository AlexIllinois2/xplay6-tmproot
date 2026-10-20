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

PIECES="sud suc sumount swap calread calget clobber sugate_probe elflush sgt_pay icache_sync nsmbind rootsh broot socktrig kmodmark"

[ -x "$CC" ] || { echo "no NDK clang at: $CC"; exit 1; }

# broot7 = the whole 7 escalation in ONE process (needle + writes + synchronous reads + permissive_map
# + cred patch + fork/exec), which is what the APK ships.  It needs clobber's write primitive without
# its CLI main, so the two objects are compiled with different -Dmain and linked.
$CC -target aarch64-linux-android21 -O2 -Wall -static -c "$ROOT/broot7.c" -o "$ROOT/obj_broot7.o"
$CC -target aarch64-linux-android21 -O2 -Wall -static -DESC_LIB -Dmain=clobber_cli_main \
	-c "$ROOT/clobber.c" -o "$ROOT/obj_clobber_esc.o"
$CC -target aarch64-linux-android21 -static -o "$OUT/broot7" "$ROOT/obj_broot7.o" "$ROOT/obj_clobber_esc.o"
rm -f "$ROOT/obj_broot7.o" "$ROOT/obj_clobber_esc.o"
echo "built: broot7"

# relayd = the unix-stream relay the MANAGER APP runs so third-party apps get a kernel-given identity on the
# su channel (the borrowed cred cannot bind SOCK_STREAM on 7 -- ledger 623-626). Dev builds push it to
# /data/local/tmp; shipping it as an APK asset is the 1.9.5 step in task 27.
$CC -target aarch64-linux-android21 -O2 -Wall -static -o "$OUT/relayd" "$ROOT/relayd.c"
echo "built: relayd"
# tools/mpp ships as a binary only: it was built from modprobe_probe.c, which is not in this
# tree.  The leak/trigger pair the 7 chain uses is broot + socktrig, both built above.

for n in $PIECES; do
	src=$ROOT/$n.c
	[ -f "$src" ] || { echo "MISSING SOURCE: $n.c"; exit 1; }
	printf '[native] %-14s -> %s\n' "$n" "$OUT/$n"
	$CC $CFLAGS -o "$OUT/$n" "$src"
done

# umhraw is the no-libc witness: it has no crt and no libc, so it cannot go through the
# -static loop above (its entry is a hand-written _start).
printf '[native] %-14s -> %s\n' umhraw "$OUT/umhraw"
$CC -target aarch64-linux-android21 -O2 -Wall -nostdlib -static -Wl,-e,_start \
	-o "$OUT/umhraw" "$ROOT/umhraw.c"

# The APK's own JNI half: the same clobber.c compiled a second way, plus the bridge.
# No -static here: this one has to be a shared object.
printf '[native] %-14s -> %s\n' libesc.so "$OUT/libesc.so"
$CC -target aarch64-linux-android21 -O2 -Wall -fPIC -shared -DESC_LIB \
	-o "$OUT/libesc.so" "$ROOT/clobber.c" "$ROOT/apk/jni/jni_esc.c"

# Host-side arms for the two pieces of shared logic the daemon and its clients both use.
# They are compiled and RUN here, not left for a human to remember: the authorization rule and the
# client-delivery rule are exactly the kind of code whose failure the device only shows later
# (ledger 585's self-grant, ledger 595's zero-byte /sbin/su).
printf '[arms]   %-14s\n' 'host rule tests'
if ! python3 "$ROOT/sud_layout.py" --selftest >"$OUT/sud_layout.out" 2>&1; then
	echo "FAIL: the daemon and its clients do not agree on the socket layout -- see $OUT/sud_layout.out"
	tail -8 "$OUT/sud_layout.out"
	exit 1
fi
printf '           %-18s %s\n' sud_layout "$(tail -1 "$OUT/sud_layout.out")"
if ! bash "$ROOT/verify_approot.sh" --selftest >"$OUT/approot_cov.out" 2>&1; then
	echo "FAIL: the acceptance harness's own coverage gate is blind -- see $OUT/approot_cov.out"
	tail -8 "$OUT/approot_cov.out"
	exit 1
fi
printf '           %-18s %s\n' approot_coverage "$(tail -1 "$OUT/approot_cov.out")"
for t in grants_rule_test copy_atomic_test borrow_verdict_test; do
	if cc -Wall -Wextra -Werror -O1 -o "$OUT/$t" "$ROOT/$t.c" 2>"$OUT/$t.log"; then
		if ! "$OUT/$t" >"$OUT/$t.out" 2>&1; then
			echo "FAIL: $t arms -- see $OUT/$t.out"; tail -6 "$OUT/$t.out"; exit 1
		fi
		printf '           %-18s %s\n' "$t" "$(tail -1 "$OUT/$t.out")"
	else
		echo "FAIL: $t did not compile"; cat "$OUT/$t.log"; exit 1
	fi
done

echo
echo "built into $OUT"
echo "next: bash $ROOT/apk/build.sh"
