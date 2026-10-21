#!/usr/bin/env bash
# Which SELinux domains still have to be made permissive for a GRANTED root to be useful?
#
# Why a script (ledger 2026-10-21 §707/§708): per-domain permissive is keyed on the SCONTEXT type, so
# every binder REPLY back to an su-served process is decided by the PEER's type.  Exempting one peer per
# guess costs a kernel write each, and "I think pm also needs system_server" is not a measurement.
# This tool fires a battery of the calls root apps and Shizuku clients actually make, then counts the
# REAL denials (permissive=0) whose tcontext is one of our domains.  Output = the peer set with a
# witness per peer, or "closed" when the battery produces none.
#
# usage: bash tools/binder_peers.sh [serial] [--dry]
#   --dry  prints the battery and the judgement rules without touching the device
set -u
SER=${1:-3e5a38a5}
ADB="adb -s $SER"
DRY=0
for a in "$@"; do [ "$a" = --dry ] && DRY=1; done
DEV=/data/local/tmp

# The battery.  Each entry: a command an unprivileged caller CANNOT do but a granted root must, and
# which must travel over binder (so it exercises a peer's reply path).  Kept read-mostly: nothing here
# changes user state except the two freeze/unfreeze pair, which is restored in the same line.
BATTERY='id
getenforce
service check cpuinfo
service check package
service check activity
service check window
pm list packages -3
pm print-disabled
settings get system airplane_mode_on
settings get secure default_input_method
dumpsys package com.android.shell | head -3
dumpsys window policy | head -2
wm size
am get-current-user
appops get com.android.shell
pm disable com.xplay6.granted
pm enable com.xplay6.granted
service check surfaceflinger
service check media.audio_flinger
service check audio
service check power
service check alarm
service check netstats
'

channel() { # one command through the daemon's raw root shell (TCP 12345)
	$ADB forward tcp:12345 tcp:12345 >/dev/null 2>&1
	{ printf '%s\nexit\n' "$1"; sleep 4; } | timeout 40 nc 127.0.0.1 12345 2>/dev/null | tr -d '\r'
}

if [ "$DRY" = 1 ]; then
	echo "battery ($(printf '%s' "$BATTERY" | grep -c .) commands), each fired as root over TCP 12345:"
	printf '%s' "$BATTERY" | sed 's/^/  /'
	echo "judgement: after the battery, dmesg lines matching tcontext=u:r:(init|shell|qti_init_shell|untrusted_app|kernel) AND permissive=0 name the peers still missing."
	exit 0
fi

state() { channel "id; getenforce"; }
BEFORE=$(channel "dmesg | grep -a -c 'permissive=0'")
echo "== pre-state: $(state | head -1)"
if ! printf '%s' "$(state)" | grep -q '^uid=0'; then
	echo "REFUSE: the raw root channel is not answering as uid 0 -- this measures nothing"
	exit 2
fi

echo "== firing the battery"
printf '%s' "$BATTERY" | while IFS= read -r c; do
	[ -n "$c" ] || continue
	out=$(channel "$c" | tr '\n' ' ' | cut -c1-110)
	printf '  %-42s %s\n' "$c" "$out"
done

echo "== denials against our domains, after the battery (permissive=0 only)"
$ADB shell "dmesg | grep -a 'permissive=0' > $DEV/bp.txt; chmod 644 $DEV/bp.txt" >/dev/null 2>&1
$ADB pull "$DEV/bp.txt" /tmp/bp.txt >/dev/null 2>&1
AFTER=$(wc -l </tmp/bp.txt 2>/dev/null || echo 0)
python3 - <<'EOF'
import re, collections
ours = re.compile(r'tcontext=u:r:(init|shell|qti_init_shell|untrusted_app|kernel|system)(:| )')
c = collections.Counter()
for L in open('/tmp/bp.txt', errors='ignore'):
    if 'avc:' not in L or 'denied' not in L:
        continue
    s = re.search(r'scontext=u:r:([\w-]+)', L)
    if not s or not ours.search(L):
        continue
    tc = re.search(r'tclass=(\S+)', L)
    p = re.search(r'denied \{ ([\w ]+)\}', L)
    c[(s.group(1), tc.group(1) if tc else '?', p.group(1) if p else '?')] += 1
if not c:
    print("  CLOSED: no real denial against any of our domains after the battery")
else:
    print("  peers still needing a permissive bit (scontext -> our domain), by class:")
    for k, v in c.most_common():
        print("    %5d  %s -> ours :%s {%s}" % (v, k[0], k[1], k[2]))
    print("  types to look up in the LIVE table (art/policy-types-7-live.tsv): %s"
          % ", ".join(sorted({k[0] for k in c})))
EOF
$ADB shell "rm -f $DEV/bp.txt" >/dev/null 2>&1
echo "== denial lines before=$BEFORE after=$AFTER (ring buffer, counts are cumulative)"
