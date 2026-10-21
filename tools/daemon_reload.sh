#!/system/bin/sh
# Reload the su daemon with a binary pushed to /data/local/tmp, and report the two things
# that decide whether a swap can work at all: is it serving, and did it land in the init
# domain (only init may mount over /system).
set -u
NEW=/data/local/tmp/sud-new
LOG=/data/local/tmp/sud-new.log

echo "[1] running daemon instances (whole /proc scan, by cmdline not comm)"
for d in /proc/[0-9]*; do
	if grep -aq sud "$d/cmdline" 2>/dev/null; then
		echo "    $d uid=$(grep -a '^Uid:' "$d/status" | tr -s ' \t' ' ') cmd=$(tr '\0' ' ' < "$d/cmdline") dom=$(cat "$d/attr/current" 2>/dev/null)"
	fi
done

echo "[2] stop them"
for d in /proc/[0-9]*; do
	if grep -aq sud "$d/cmdline" 2>/dev/null; then
		pid=$(basename $d)
		kill $pid 2>&1
		echo "    killed $pid"
	fi
done
sleep 1

echo "[3] start the new one"
: > $LOG
$NEW >> $LOG 2>&1 &
sleep 3
for d in /proc/[0-9]*; do
	if grep -aq sud-new "$d/cmdline" 2>/dev/null; then
		echo "    pid=$(basename $d) dom=$(cat $d/attr/current 2>/dev/null) listeners=$(grep -c ':3039\|:303A' /proc/net/tcp)"
	fi
done
echo "    log:"
tail -6 $LOG
echo DONE-RELOAD
