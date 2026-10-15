#!/usr/bin/env bash
# How reliable is "boot -> root, no human"?  Reboot N times and record, per cycle:
#   device_up   seconds until adb reports the device again
#   root_at     seconds until `su -c id -u` answers 0 (0 = never within the budget)
#   attempt     which sugate attempt landed (from the app's own boot log)
#   gate_ok     1 if that attempt was rc=0
#   su_on_path  1 if /sbin/su is on PATH afterwards
# Deliberately does NOT force-stop the manager app: a force-stop suppresses the next
# BOOT_COMPLETED (Android's stopped state) and would make every cycle read as broken.
set -u
N=${1:-3}
OUT=${OUT:-/home/v/.local/project/xplay6/art/bootstats-$(date +%Y%m%d).txt}
BUDGET=${BUDGET:-24}			# x10s waiting for root
: > "$OUT"
for i in $(seq 1 "$N"); do
	adb reboot
	sleep 25
	up=0
	for a in $(seq 1 30); do
		if [ "$(adb get-state 2>/dev/null | tr -d '\r')" = device ]; then
			up=$((25 + a * 5))
			break
		fi
		sleep 5
	done
	root=0
	for b in $(seq 1 "$BUDGET"); do
		r=$(adb shell 'su -c "id -u"' 2>/dev/null | tr -d '\000\r' | grep -aE '^[0-9]+$')
		if [ "$r" = 0 ]; then
			root=$((b * 10))
			break
		fi
		sleep 10
	done
	last=$(adb shell 'logcat -d 2>/dev/null | grep -a "sugate attempt" | tail -1' 2>/dev/null | tr -d '\000\r')
	att=$(printf '%s\n' "$last" | sed -n 's/.*sugate attempt \([0-9]*\).*/\1/p')
	gok=$(printf '%s\n' "$last" | grep -ac "rc=0" || true)
	tries=$(adb shell 'logcat -d 2>/dev/null | grep -ac "sugate attempt"' 2>/dev/null | tr -d '\000\r' | grep -aE '^[0-9]+$')
	path=$(adb shell 'su -c "command -v su"' 2>/dev/null | tr -d '\000\r' | grep -ac "/su" || true)
	line="cycle=$i device_up=${up}s root_at=${root}s landed_on_attempt=${att:-?} gate_ok=$gok attempts_logged=${tries:-0} su_on_path=$path"
	printf '%s\n' "$line" | tee -a "$OUT"
done
echo "written: $OUT"
