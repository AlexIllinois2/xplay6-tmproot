#!/system/bin/sh
# Root-side steps for verify_sweep.py, kept in one file so the python driver never
# has to nest quotes through `su -c`.
case "$1" in
zombies)
	z=0
	live=0
	for d in /proc/[0-9]*; do
		test -r $d/status || continue
		s=$(tr '\011' ' ' < $d/status)
		u=$(printf '%s\n' "$s" | grep -m1 '^Uid:' | cut -d' ' -f3)
		st=$(printf '%s\n' "$s" | grep -m1 '^State:' | cut -d' ' -f2)
		test "$u" = 0 || continue
		if test "$st" = Z; then z=$((z + 1)); else live=$((live + 1)); fi
	done
	echo "root_zombies=$z root_live=$live"
	;;
	logtail)
		tail -14 /data/local/tmp/.sud/sud.log
		;;
	revoke2000)
		G=/data/local/tmp/sud.grants
		grep -v '^2000$' $G > /data/local/tmp/g.tmp
		cat /data/local/tmp/g.tmp >$G
		rm -f /data/local/tmp/g.tmp
		echo "revoked $(date +%H:%M:%S) list=[$(tr '\n' ' ' <$G)]"
		sleep 6
		echo 2000 >>$G
		echo "restored $(date +%H:%M:%S) list=[$(tr '\n' ' ' <$G)] mode=$(stat -c %a $G)"
		;;
	sessdir)
		ls -l /data/local/tmp/.sud/sess 2>&1 | tail -6
		;;
	*)
		echo "usage: sweep_root.sh zombies|logtail|revoke2000|sessdir"
		;;
esac
