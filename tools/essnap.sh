#!/system/bin/sh
# tools/essnap.sh -- capture the ES9038 (Hi-Fi DAC) live surface while it is powered.
# Denominator is fixed by the driver: es9038_regdump_callback walks a static 47-entry table,
# so a shorter dump means missing items, not a smaller device. No awk on this device.
set -u
N=${1:-3}
GAP=${2:-600}
OUT=${OUT:-/data/local/tmp/essnap-$(date +%Y%m%d-%H%M%S).txt}
i=0
while [ "$i" -lt "$N" ]; do
	echo "===== sample $i $(cat /proc/uptime | cut -d' ' -f1) =====" >> "$OUT"
	echo "-- witnesses" >> "$OUT"
	getprop init.svc.audioserver >> "$OUT" 2>&1
	tinymix -D 0 "Playback Channel Map0" >> "$OUT" 2>&1
	tinymix -D 0 "SmartPA Switch" >> "$OUT" 2>&1
	tinymix -D 0 "headphone Switch" >> "$OUT" 2>&1
	tinymix -D 0 "HAIBAO Route Mode" >> "$OUT" 2>&1
	tinymix -D 0 "ES_DCDC_Enable" >> "$OUT" 2>&1
	echo "-- debugfs listing es9038 / es9028" >> "$OUT"
	ls -l /sys/kernel/debug/es9038 /sys/kernel/debug/es9028 >> "$OUT" 2>&1
	echo "-- es9038/reg" >> "$OUT"
	cat /sys/kernel/debug/es9038/reg >> "$OUT" 2>&1
	echo "-- hifi codec dapm" >> "$OUT"
	for f in /sys/kernel/debug/asoc/msm8996-tasha-cdp-snd-card/codec:hifi-codec/*; do
		[ -f "$f" ] && { echo "### $f"; cat "$f" 2>&1; } >> "$OUT"
	done
	i=$((i + 1))
	[ "$i" -lt "$N" ] && sleep 0."$GAP"
done
tinymix -D 0 > "${OUT}.tinymix" 2>&1
echo "count of reg lines: $(grep -ac 'reg' "$OUT")" >> "$OUT"
logcat -d -t 600 2>&1 | grep -aE 'hifi|HiFi|HIFI|HEADPHONE|es90|out_snd_device|select_devices' | tail -30 >> "$OUT"
echo ESSNAP_DONE "$OUT"
grep -ac 'reg{' "$OUT"
