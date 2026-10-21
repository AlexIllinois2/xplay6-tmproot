#!/system/bin/sh
# Third pass: the pieces shell uid cannot reach (adsp partition is vfat with fmask=0337)
# and the live device-tree, which is what a 7.x kernel has to keep compatible with.
set -u
P=/data/local/tmp/audlive
mkdir -p $P

echo "[1/4] adsp firmware partition (/firmware = by-name/modem, same blob as NON-HLOS.bin)"
tar -czf /data/local/tmp/firmware.tgz -C / firmware/image firmware/verinfo 2>/dev/null
ls -l /data/local/tmp/firmware.tgz
cp /data/local/tmp/firmware.tgz $P/firmware.tgz

echo "[2/4] live device-tree sound nodes"
for d in $(find /proc/device-tree -maxdepth 4 -type d \( -iname '*sound*' -o -iname '*audio*' -o -iname '*codec*' -o -iname 'wcd*' \) 2>/dev/null); do
	name=$(echo $d | tr '/' '_')
	tar -czf $P/dt_$(basename $d).tgz -C $(dirname $d) $(basename $d) 2>/dev/null
	ls -l $P/dt_$(basename $d).tgz 2>/dev/null
done
ls /proc/device-tree > $P/dt_root_listing.txt 2>&1
for f in $(find /proc/device-tree/sound -type f 2>/dev/null); do
	mkdir -p "$P/devicetree_raw/$(dirname $f)"
	cat $f > "$P/devicetree_raw$f" 2>/dev/null
done
find $P/devicetree_raw -type f 2>/dev/null | wc -l

echo "[3/4] /persist (qualcomm persistent area: cal overrides live here if any)"
du -sh /persist > $P/persist_du.txt 2>&1
find /persist -type f > $P/persist_files.txt 2>&1
wc -l < $P/persist_files.txt
mkdir -p $P/persist_audio
while read f; do
	case "$f" in
	*audio*|*acdb*|*wcd*|*cal*) mkdir -p "$P/persist_audio/$(dirname $f)"; cp -p $f "$P/persist_audio$f" 2>/dev/null ;;
	esac
done < $P/persist_files.txt
du -sh $P/persist_audio 2>/dev/null

echo "[4/4] what the running audio processes actually have mapped"
: > $P/loaders.txt
for p in $(ls /proc | grep -E '^[0-9]+$'); do
	if grep -aqi "audio.primary" /proc/$p/maps 2>/dev/null; then
		echo "== pid $p $(cat /proc/$p/cmdline 2>/dev/null | tr '\0' ' ')" >> $P/loaders.txt
		grep -aiE "audio|soundfx|acdb|sva|adsp|smartamp" /proc/$p/maps 2>/dev/null \
			| tr -s ' ' '\n' | grep -a '^/' | sort -u >> $P/loaders.txt
	fi
done
wc -l < $P/loaders.txt
echo DONE-PASS3
