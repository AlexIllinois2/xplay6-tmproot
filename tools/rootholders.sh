#!/system/bin/sh
# Who holds a root session right now?  The su audit line is only written after
# waitpid(), so a live interactive shell is invisible in sud.log -- this answers
# the question from the process tree instead of from the log.
# /proc/*/status separates with TABs: squeeze spaces only and every field is empty.
for d in /proc/[0-9]*; do
	f=$d/status
	test -r $f || continue
	s=$(tr '\011' ' ' < $f)
	u=$(printf '%s\n' "$s" | grep -m1 '^Uid:' | cut -d' ' -f3)
	test "$u" = 0 || continue
	n=$(printf '%s\n' "$s" | grep -m1 '^Name:' | cut -d' ' -f2)
	pp=$(printf '%s\n' "$s" | grep -m1 '^PPid:' | cut -d' ' -f3)
	case "$n" in
	sh|su|mtio|busybox|toybox)
		cl=$(tr '\000' ' ' < $d/cmdline)
		pn=none
		test -r /proc/$pp/status && pn=$(tr '\011' ' ' < /proc/$pp/status | grep -m1 '^Name:' | cut -d' ' -f2)
		printf '%-7s pid=%-6s ppid=%-6s(%s) cmd=%s\n' "$n" "${d#/proc/}" "$pp" "$pn" "$cl"
		;;
	esac
done
echo "--- MT (bin.mt.plus) processes:"
for d in /proc/[0-9]*; do
	test -r $d/cmdline || continue
	c=$(tr '\000' ' ' < $d/cmdline)
	case "$c" in
	*bin.mt.plus*|*mtio*) printf 'pid=%-6s %s\n' "${d#/proc/}" "$c" ;;
	esac
done
