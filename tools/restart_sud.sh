#!/system/bin/sh
# restart the temproot daemon with the freshly built binaries, then leave the
# device in a state where `su` works and MSWAP reaches the daemon.
#
# relayd is stopped on purpose: it appends " TOK=<token>" to every request line
# it forwards, which is right for "SU <uid> <cmd>" but corrupts the fixed
# argument shape of MOUNT / MSWAP / UMSWAP.  With relayd gone the su client uses
# the peer channel instead (kernel SCM_CREDENTIALS), which needs no token.
#
# Everything here is memory state; `adb reboot` restores the factory setup.

echo "=== stop relayd + sud ==="
for d in /proc/[0-9]*; do
	c=$(tr '\000' ' ' < "$d/cmdline" 2>/dev/null)
	case "$c" in
	*relayd*) kill -9 "$(basename "$d")" 2>/dev/null; echo "  killed relayd $(basename "$d")" ;;
	*"/sud "*|*/sud) kill -9 "$(basename "$d")" 2>/dev/null; echo "  killed sud $(basename "$d")" ;;
	esac
done
sleep 1

echo "=== start the new sud ==="
cd /data/local/tmp || exit 1
setsid nohup ./sud >/data/local/tmp/sud-new.log 2>&1 </dev/null &
sleep 3

echo "=== state ==="
echo "  daemon log:"
sed 's/^/    /' /data/local/tmp/sud-new.log 2>/dev/null | head -8
echo "  abstract socket:"
cat /proc/net/unix 2>/dev/null | tr -d '\000' | grep -a sud | sed 's/^/    /'
echo "  domain of the daemon:"
for d in /proc/[0-9]*; do
	c=$(tr '\000' ' ' < "$d/cmdline" 2>/dev/null)
	case "$c" in
	*/sud) echo "    pid=$(basename "$d") domain=$(cat "$d/attr/current" 2>/dev/null)" ;;
	esac
done
echo "DONE-RELOAD"
