#!/usr/bin/env bash
# bootcheck.sh -- one command that answers "did the phone let us start at boot, and did we root?"
# Clears logcat first so every line shown belongs to THIS boot, reboots, then reports:
#   * the entrance: our own log lines, or the system's own "Cancel launching app ..." verdict
#   * the outcome: whether the daemon came up, how long it took, and what getenforce says
set -u
S=${1:-3e5a38a5}
A="adb -s $S"
WAIT=${WAIT:-120}
timeout 30 $A logcat -c >/dev/null 2>&1
$A reboot >/dev/null 2>&1
sleep 22
timeout 120 $A wait-for-device >/dev/null 2>&1
i=0
while [ $i -lt 12 ]; do
	[ "$($A shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = 1 ] && break
	sleep 5
	i=$((i + 1))
done
echo "boot_completed=1 at +$((i * 5 + 22))s; polling ${WAIT}s for the daemon"
k=0
FIRST=never
while [ $k -lt $((WAIT / 15)) ]; do
	sleep 15
	k=$((k + 1))
	N=$($A shell 'ps -Z 2>/dev/null | grep -c "sud"' 2>/dev/null | tr -d '\r')
	[ "$N" -ge 1 ] && [ "$FIRST" = never ] && FIRST="+$((k * 15))s"
done
echo "  daemon first seen: $FIRST   getenforce: $($A shell getenforce 2>/dev/null | tr -d '\r')"
echo "  suid: $(timeout 30 $A shell '/data/local/tmp/sux -c id 2>&1' 2>/dev/null | tr -d '\r' | head -1)"
echo "entrance evidence from this boot:"
timeout 45 $A shell 'logcat -d -v brief 2>/dev/null | grep -E "TempRoot|Cancel launching app com.xplay6|forbid to start" | head -10' 2>&1 | tr -d '\r' | cut -c1-165 | sed 's/^/    /'
echo "reading: 'Cancel launching app com.xplay6.temproot ... BOOT_COMPLETED' = the phone refused to start us"
echo "         (iManager -> 应用启动管理 -> TempRoot: allow 自启动/后台活动; a pm uninstall resets that record)"
