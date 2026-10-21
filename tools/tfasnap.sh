#!/system/bin/sh
# tools/tfasnap.sh -- N samples of the PA-side live surface with witnesses, so volatile
# registers can be told apart from use-case writes. No awk on this device.
set -u
N=${1:-3}
GAP=${2:-700}
OUT=${OUT:-/data/local/tmp/tfasnap-$(date +%Y%m%d-%H%M%S).txt}
i=0
while [ "$i" -lt "$N" ]; do
	echo "===== sample $i $(cat /proc/uptime | cut -d' ' -f1) =====" >> "$OUT"
	echo "-- witness" >> "$OUT"
	tinymix -D 0 "SmartPA Switch" >> "$OUT" 2>&1
	tinymix -D 0 "TERT_MI2S_RX Audio Mixer MultiMedia1" >> "$OUT" 2>&1
	tinymix -D 0 "Playback Channel Map0" >> "$OUT" 2>&1
	echo "-- codec_reg" >> "$OUT"
	cat /sys/kernel/debug/tfa98xx/codec_reg >> "$OUT" 2>&1
	echo "-- calibrate" >> "$OUT"
	cat /sys/kernel/debug/tfa98xx/calibrate >> "$OUT" 2>&1
	i=$((i + 1))
	[ "$i" -lt "$N" ] && sleep 0."$GAP"
done
echo "TFASNAP_DONE $OUT"
wc -l "$OUT"
