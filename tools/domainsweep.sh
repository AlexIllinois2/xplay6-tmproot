#!/usr/bin/env bash
# Which SELinux domain do we LAND IN when kmod exec's the payload, as a function of the
# payload's own type label? chcon gives us free choice of label while permissive, and the
# label is what the domain-transition rules key on -- so this sweeps the labels and reports
# (a) the resulting context, (b) how many AVC denials that context would eat under enforcing.
#
# Reading rule: the probe's errno values are MEANINGLESS here (permissive allows everything).
# The judge is the kernel's own log: every "avc: denied" whose scontext is the domain we landed
# in is a hard denial the moment enforcing is back on. Zero denials == that domain could host
# our daemon under enforcing without touching policy.
#
# memory-only: modprobe_path and the labels are RAM state; a reboot (or re-running
# run_temproot.sh) undoes it. Nothing here writes a partition.
set -u
SER=${1:-3e5a38a5}
T="$(cd "$(dirname "$0")" && pwd)"
ADB="adb -s $SER"
D=/data/local/tmp
PROBE=$T/ctxprobe
MODPROBE_ADDR=0xffffffc001635a30
LABELS="shell_data_file system_file shell_exec system_data_file app_data_file cache_file vendor_file radio_exec init_exec media_rw_data_file"

$ADB get-state >/dev/null 2>&1 || { echo "ABORT: $SER not on adb"; exit 2; }
Enf=$($ADB shell getenforce 2>/dev/null | tr -d '\r')
if [ "$Enf" != "Permissive" ]; then
	echo "need permissive first (run: DAEMON=sud bash tools/run_temproot.sh); got $Enf"
	exit 2
fi

step() { printf '\n=== %s\n' "$*"; }
rootsh() { # one command through the daemon's raw shell (port 12345): dmesg needs CAP_SYSLOG,
           # which uid 2000 does not have on this build -- shell-side dmesg is a known dead end.
	$ADB forward tcp:12345 tcp:12345 >/dev/null 2>&1
	{ printf '%s\n' "$*"; sleep 3; } | timeout 40 bash -c \
		'exec 3<>/dev/tcp/127.0.0.1/12345; cat >&3; cat <&3' 2>/dev/null | tr -d '\r'
}
for f in ctxprobe clobber mpp; do
	[ -x "$T/$f" ] || { echo "ABORT: $T/$f missing -- build it first"; exit 2; }
	# ctxprobe is staged AS "probe" because that exact path is what modprobe_path will
	# be written with below; a name mismatch here once made the whole sweep exec a
	# nonexistent file and every label looked like "chcon did not take".
	dst=$D/$f; [ "$f" = "ctxprobe" ] && dst=$D/probe
	$ADB push "$T/$f" "$dst" >/dev/null 2>&1 || { echo "ABORT: push $f failed"; exit 2; }
	$ADB shell "chmod 755 $dst" >/dev/null 2>&1
done
$ADB shell "ls -l $D/probe" 2>&1 | tr -d '\r' | sed -n '1p' | sed 's/^/  payload in place: /'

step "0. baseline: is the mark of this run separable from old log lines?"
$ADB shell "rm -f $D/ctxprobe.out" >/dev/null 2>&1
MARK=$(rootsh 'dmesg | wc -l' | grep -E "^[0-9]+$" | tail -1)
: "${MARK:=0}"
echo "  dmesg lines before sweep: $MARK"

step "1. repoint modprobe_path at the probe (padded 64B write, WQI=4)"
OUT=$($ADB shell "$D/clobber 12 kern $MODPROBE_ADDR str:$D/probe 4 0" 2>&1 | tr -d '\r')
printf '%s\n' "$OUT" | grep -E "readv|hit|RESULT|write" | tail -4
$ADB shell "cat /proc/sys/kernel/modprobe" 2>&1 | tr -d '\r' | sed -n '1p' | sed 's/^/  modprobe now: /'

step "2. sweep the payload label"
# Neither stat -c %C nor ls -Z reports a label on this build, so the witness is the probe
# itself: it prints its own /proc/self/attr/current. A label that took effect shows up as a
# CHANGED context; "no new block at all" means the exec never happened for that label.
for L in $LABELS; do
	BEFORE=$($ADB shell "grep -c '^---- probe' $D/ctxprobe.out 2>/dev/null || echo 0" | tr -d '\r' | tail -1)
	CRC=$($ADB shell "chcon u:object_r:$L:s0 $D/probe; echo rc=\$?" 2>&1 | tr -d '\r' | grep -o "rc=[0-9]*")
	$ADB shell "$D/mpp >/dev/null 2>&1" >/dev/null 2>&1
	sleep 2
	BLOCKS=$($ADB shell "grep -c '^---- probe' $D/ctxprobe.out 2>/dev/null || echo 0" | tr -d '\r' | tail -1)
	CTX=$($ADB shell "cat $D/ctxprobe.out 2>/dev/null" | tr -d '\r' | grep '^context=' | tail -1)
	if [ "$BLOCKS" = "$BEFORE" ]; then
		printf '  %-22s %s -- NO new probe run: kmod did not exec the payload (exec itself denied)\n' "$L" "${CRC:-?}"
	else
		printf '  %-22s %s -> %s\n' "$L" "${CRC:-?}" "${CTX:-<no context line>}"
	fi
done

step "3. judge each landed domain by its own denial count (enforcing preview)"
rootsh "dmesg > $D/dmesg.after; chmod 666 $D/dmesg.after; wc -l < $D/dmesg.after" >/dev/null
$ADB pull "$D/dmesg.after" "$T/_dmesg.after" >/dev/null 2>&1 || { echo "  ABORT: could not pull dmesg"; exit 2; }
python3 - "$T/_dmesg.after" "$MARK" <<'PY'
import re, sys, collections
path, mark = sys.argv[1], int(sys.argv[2])
lines = open(path, encoding="utf8", errors="replace").read().splitlines()[mark:]
by = collections.defaultdict(set)
for ln in lines:
    m = re.search(r"avc: denied \{ (\w+) \}.*scontext=u:r:([a-z_0-9]+):.*tcontext=(\S+) tclass=(\w+)", ln)
    if m:
        perm, sctx, tctx, tclass = m.groups()
        by[sctx].add((perm, tctx.split(":")[-2] if tctx.count(":") > 1 else "?", tclass))
print("  %d new denial lines after the mark" % len(lines))
for sctx in sorted(by, key=lambda k: -len(by[k])):
    print("  u:r:%-22s %d distinct denials" % (sctx, len(by[sctx])))
    if sctx in ("qti_init_shell", "kernel", "init"):
        for p, t, c in sorted(by[sctx])[:14]:
            print("        %s %s:%s" % (p, t, c))
PY

step "4. one full probe block (errno under permissive only reveals structural refusals)"
$ADB shell "cat $D/ctxprobe.out 2>/dev/null | tail -15" 2>&1 | tr -d '\r'
echo "  note: modprobe_path still points at $D/probe -- re-run run_temproot.sh or reboot to reset."
