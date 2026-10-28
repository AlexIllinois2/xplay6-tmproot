#!/system/bin/sh
# probe the state we need for the /system work
echo "=== processes (relayd / sud) ==="
for d in /proc/[0-9]*; do
	c=$(tr '\000' ' ' < "$d/cmdline" 2>/dev/null)
	case "$c" in
	*relayd*) echo "  relayd pid=$(basename $d) $c" ;;
	*sud*)    echo "  sud    pid=$(basename $d) $c" ;;
	esac
done

echo "=== abstract sockets ==="
cat /proc/net/unix 2>/dev/null | grep -iE "sud|trq" | sed 's/^/  /'

echo "=== listeners on 12345/12346 ==="
cat /proc/net/tcp 2>/dev/null | awk 'NR>1 { split($2,a,":"); p=strtonum("0x" a[2]); if (p==12345||p==12346) print "  port=" p " state=" $4 }'

echo "=== /system mount ==="
grep " /system " /proc/mounts | sed 's/^/  /'

echo "=== raw partition rw test ==="
if exec 3<>/dev/block/sde18 2>/dev/null; then
	echo "  /dev/block/sde18 opens rw: YES"
	exec 3<&- 2>/dev/null
else
	echo "  /dev/block/sde18 opens rw: NO"
fi

echo "=== dir mode of /system subdirs (for the mirror trick) ==="
ls -ld /system/etc /system/bin /system/xbin /system/lib 2>/dev/null | sed 's/^/  /'
