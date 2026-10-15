#!/usr/bin/env bash
# Waits for the Xplay6 to come back on adb, then runs ONLY read-only measurement
# (surface2.sh) and pulls the result. No ioctl, no race: a live window is worth more
# as data than as another crash, and every panic costs a physical power cycle.
# usage: bash tools/wait_surface.sh [serial]
set -u
SER=${1:-3e5a38a5}
cd "$(dirname "$0")/.." || exit 1
LOG=art/surface_wait.log
: > "$LOG"
say() { printf '%s %s\n' "$(date +%H:%M:%S)" "$1" | tee -a "$LOG"; }

say "waiting for $SER on adb (up to 45 min)"
for i in $(seq 1 540); do
	if adb -s "$SER" shell echo ok >/dev/null 2>&1; then
		say "device up after $((i * 5)) s"
		break
	fi
	sleep 5
done
if ! adb -s "$SER" shell echo ok >/dev/null 2>&1; then
	say "TIMEOUT: device never appeared"
	exit 1
fi

sleep 6
adb -s "$SER" push tools/surface2.sh /data/local/tmp/surface2.sh >>"$LOG" 2>&1
adb -s "$SER" shell 'sh /data/local/tmp/surface2.sh' >>"$LOG" 2>&1
adb -s "$SER" pull /data/local/tmp/surface2.txt art/surface2.txt >>"$LOG" 2>&1
say "pulled: $(wc -l < art/surface2.txt 2>/dev/null || echo 0) lines"
echo "DONE-SURFACE" >> "$LOG"
