#!/system/bin/sh
# Reversible ACDB swap, arm B: put the generic MTP speaker calibration in front of the
# shipped PD1610 one by bind-mounting a single file.  Nothing is written to any partition;
# `umount -l` or a reboot restores the shipped bytes.  Every step reads back what the next
# step will believe, because "the mount succeeded" and "the reader sees it" are different
# claims.
set -u
TARGET=/system/etc/acdbdata/PD1610/Speaker_cal.acdb
ALT=/data/local/tmp/alt_MTP_Speaker_cal.acdb

echo "[0] precondition"
ls -l $TARGET $ALT
md5sum $TARGET $ALT
getenforce

if [ "${1:-}" = umount ]; then
	echo "[R] reverting"
	umount -l $TARGET 2>&1
	echo "[R] mounts line after revert: $(grep -c "$TARGET" /proc/mounts)"
	md5sum $TARGET
	setprop ctl.restart audioserver
	echo DONE-REVERT
	exit 0
fi

echo "[1] bind"
mount -o bind $ALT $TARGET
rc=$?
echo "    mount rc=$rc"
[ $rc -ne 0 ] && { echo "    ABORT: bind refused (errno shown above) -> fall back to the calfile-property route"; exit 3; }

echo "[2] reconciliation: source md5 == what a reader of the /system path now sees"
md5sum $ALT $TARGET
grep -a "$TARGET" /proc/mounts
echo "    stat of the covered file (size should match the ALT, not the original 423966):"
ls -l $TARGET

echo "[3] restart the consumer so it re-reads the calibration"
setprop ctl.restart audioserver
sleep 4
echo "    audioserver pid: $(pidof audioserver 2>/dev/null; ps -A -o PID,NAME | grep -aw audioserver | head -1)"
echo "    getenforce still: $(getenforce)"
echo DONE-ARM-B
