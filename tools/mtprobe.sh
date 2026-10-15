#!/system/bin/sh
# Read a running app's own env: this is what its Runtime.exec("su") actually sees.
# The pid is found by reading each /proc/*/cmdline through `case` -- `grep -a` on
# those files is unreliable here (toybox grep still calls them "binary").
pid=$1
if test -z "$pid"; then
	for p in /proc/[0-9]*; do
		test -r "$p/cmdline" || continue
		name=$(tr '\000' ' ' < "$p/cmdline")
		case "$name" in
		*bin.mt.plus*) pid=${p#/proc/} ;;
		esac
	done
fi
if test -z "$pid"; then
	echo "MT (bin.mt.plus) is not running"
	exit 3
fi
printf 'pid     : %s\n' "$pid"
printf 'domain  : '
cat /proc/$pid/attr/current
printf '\n'
printf 'uid     : '
grep -m1 '^Uid' /proc/$pid/status
printf 'started : '
stat -c %y /proc/$pid 2>&1
echo 'environ   :'
tr '\000' '\n' < /proc/$pid/environ 2>&1 | sed 's/^/    /'
echo 'su candidates:'
ls -l /sbin/su /system/bin/su /system/xbin/su /su/bin/su /debug_ramdisk/su /data/adb/magisk/su 2>&1
echo 'dir modes:'
ls -ld /data /data/data /sbin 2>&1
