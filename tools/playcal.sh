#!/system/bin/sh
# tools/playcal.sh -- run calget while audio is playing, with machine-side witnesses
# before and after, and grab the TFA/ALSA readback surfaces. No awk on this device.
set -u
CG=${CG:-/data/local/tmp/calget}
TS=$(date +%Y%m%d-%H%M%S)
OUT=${OUT:-/data/local/tmp/playcal-$TS}
mkdir -p "$OUT" || exit 1
echo "OUT=$OUT"

witness() {
	echo "=== $1 ==="
	tinymix -D 0 "SmartPA Switch" 2>&1
	tinymix -D 0 "TERT_MI2S_RX Audio Mixer MultiMedia1" 2>&1
	tinymix -D 0 "Playback Channel Map0" 2>&1
	tinymix -D 0 "Playback Device Channel Map" 2>&1
	getprop init.svc.audioserver
	cat /proc/asound/pcm 2>&1
}

witness before > "$OUT/witness-before.txt" 2>&1
tinymix -D 0 > "$OUT/tinymix-D0-before.txt" 2>&1
cat "$OUT/witness-before.txt"

echo "=== calget (8 reps, 500 ms apart) ==="
$CG all 8 500 2>&1 | tee "$OUT/calget.txt"

witness after > "$OUT/witness-after.txt" 2>&1
tinymix -D 0 > "$OUT/tinymix-D0-after.txt" 2>&1
cat "$OUT/witness-after.txt"

echo "=== debugfs hunt ==="
for D in /sys/kernel/debug /mnt/debugfs; do
	[ -d "$D" ] && echo "ROOT $D" && ls "$D" 2>&1 | head -30
done
for C in /sys/kernel/debug/asoc/* /mnt/debugfs/asoc/*; do
	[ -d "$C" ] && echo "CARD $C" && ls "$C" 2>&1 | head
done
for R in "$C"/codec:tfa98xx/* /mnt/debugfs/asoc/*/codec:tfa98xx/*; do
	[ -f "$R" ] && { echo "READ $R"; cat "$R" 2>&1 | head -40; }
done > "$OUT/tfa-debugfs.txt" 2>&1
head -60 "$OUT/tfa-debugfs.txt"

echo "=== HAL narration ==="
logcat -d -t 400 2>&1 | grep -aE 'select_devices|out_snd_device|App Type Cfg|spkr|spk_prot|smartpa|SmartPA|tfa' | tail -25 | tee "$OUT/logcat.txt"

echo "=== dmesg narration (by content only) ==="
dmesg 2>&1 | grep -aE 'audio_cal|afe_get_cal|spkr_prot|ioctl not found|Max is|tfa98' | tail -25 | tee "$OUT/dmesg.txt"

echo DONE_PLAYCAL "$OUT"
