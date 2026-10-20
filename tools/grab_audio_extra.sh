#!/system/bin/sh
# Extra sweep: everything audio-named that the first pass could not enumerate.
# (toybox find here has no -printf and does not survive grouped \( \) tests through
# the adb quoting layer, so each pattern gets its own plain find.)
set -u
P=/data/local/tmp/audlive/extra
mkdir -p $P/files
for d in /system/etc /system/share /system/usr /vendor/etc /media /system/media; do
	for pat in '*audio*' '*wcd*' '*tasha*' '*acdb*' '*sva*' '*fluence*' '*hifi*' '*vivo*' '*cal'; do
		find $d -type f -iname "$pat" 2>/dev/null
	done
done | sort -u > $P/list.txt
wc -l < $P/list.txt | tr -d '\n'
echo " unique files matched"
while read f; do
	mkdir -p "$P/files/$(dirname $f)"
	cp -p "$f" "$P/files$f" 2>/dev/null
done < $P/list.txt
mkdir -p $P/files/system/app/AudioEffect
cp -p /system/app/AudioEffect/AudioEffect.apk $P/files/system/app/AudioEffect/AudioEffect.apk 2>/dev/null
ls -lR /system/app/AudioEffect > $P/AudioEffect_dir.txt 2>&1
echo "== biggest =="
ls -lS $(cat $P/list.txt) 2>/dev/null | head -22
echo "== totals =="
du -sh $P/files
echo DONE-EXTRA
