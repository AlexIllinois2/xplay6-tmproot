#!/system/bin/sh
# Reversible ACDB swap, arm B -- directory-mirror form.
#
# Why this shape: binding a FILE onto a file inside read-only /system was measured to fail
# with EPERM (mount rc=255), while the daemon's directory mirror works -- it is how /sbin/su
# lands every boot.  So mirror the calibration directory onto /data, bind through every
# entry we want unchanged, drop in the replacement as a real file, then bind the DIRECTORY
# over the original.  Nothing is written to any partition; `umount -l` or a reboot restores
# the shipped bytes.
set -u
D=/system/etc/acdbdata/PD1610
M=/data/local/tmp/acdbmirror/PD1610
ALT=/data/local/tmp/alt_MTP_Speaker_cal.acdb
REPL=Speaker_cal.acdb

if [ "${1:-}" = revert ]; then
	echo "[R] umount -l $D"
	umount -l $D 2>&1
	echo "[R] dir bind lines left: $(grep -c "$D" /proc/mounts)"
	echo "[R] readback now:"
	md5sum $D/$REPL
	setprop ctl.restart audioserver
	echo DONE-REVERT
	exit 0
fi

echo "[0] precondition (originals)"
ls -l $D
md5sum $D/$REPL $ALT

echo "[1] build the mirror"
rm -rf /data/local/tmp/acdbmirror
mkdir -p $M
n=0
for f in $(ls $D); do
	if [ "$f" = "$REPL" ]; then
		cp $ALT $M/$f && echo "    replaced  $f  <- $ALT"
	else
		touch $M/$f
		mount -o bind $D/$f $M/$f && n=$((n+1))
	fi
done
echo "    bound through $n unchanged entries; mirror content:"
ls -l $M

echo "[2] bind the directory over the original"
mount -o bind $M $D
rc=$?
echo "    mount rc=$rc"
[ $rc -ne 0 ] && { echo "    ABORT: directory bind refused"; exit 3; }

echo "[3] reconciliation -- a reader of /system must now see the ALT bytes, others unchanged"
md5sum $D/Bluetooth_cal.acdb $D/Handset_cal.acdb $D/$REPL
grep -a "$D" /proc/mounts
echo "    sizes seen through /system:"
ls -l $D

echo "[4] restart the consumer so the calibration is re-sent to the ADSP"
setprop ctl.restart audioserver
sleep 5
echo "    getenforce: $(getenforce)"
ps -A -o PID,NAME | grep -aw audioserver
echo DONE-ARM-B
