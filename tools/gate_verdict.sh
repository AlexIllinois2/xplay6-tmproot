#!/usr/bin/env bash
# One verdict, shared by the harness and its arms (ledger 691-704).
#
# The ROM's 「USB模拟点击」 flag (`Settings.Secure vivo_adb_simulate_input`) decides whether system_server
# grants INJECT_EVENTS to uid 2000.  While it is 0, `input tap`/`input keyevent` are refused and an adb
# install always dies in `Failure [-200]` after the on-screen timeout -- so a harness that pushes an APK
# and then tries to click is burning a 14 s window it cannot win.  Ask first, and say what to do instead.
#
# The flag cannot be written from here: shell has no WRITE_SECURE_SETTINGS while the flag is 0 (that is
# the same interception), and the daemon's root has no servicemanager at all.  So the fix is always a
# human flip -- the app (1.9.21) only removes the vivo-account demand in front of it.

gate_verdict() { # <flag-reading> <tap-backend> -> OK | REFUSE | NOTE
	local flag="$1" backend="${2:-adb}"
	case "$flag" in
		1) echo OK ;;
		0|null|"") [ "$backend" = uinput ] && echo NOTE || echo REFUSE ;;
		*) echo REFUSE ;;   # anything unparseable: the reading itself is not usable
	esac
}

if [ "${1:-}" = "--test" ]; then
	fail=0
	ck() { # ck <name> <want> <got>
		[ "$2" = "$3" ] && echo "  ok       $1" || { echo "  MISBEHAVED $1: want=$2 got=$3"; fail=1; }
	}
	ck "flag 1 + adb taps -> proceed"                OK     "$(gate_verdict 1 adb)"
	ck "flag 0 + adb taps -> refuse the window"      REFUSE "$(gate_verdict 0 adb)"
	ck "flag missing (null) + adb -> refuse"         REFUSE "$(gate_verdict null adb)"
	ck "empty reading is not a verdict of its own"   REFUSE "$(gate_verdict '' adb)"
	ck "garbage reading -> refuse"                   REFUSE "$(gate_verdict 'SecurityException' adb)"
	ck "flag 0 + uinput backend -> may still proceed" NOTE   "$(gate_verdict 0 uinput)"
	# the arms must be able to fail: an inverted flag has to change the verdict
	[ "$(gate_verdict 0 adb)" != "$(gate_verdict 1 adb)" ] \
		&& echo "  ok       the verdict moves with the flag" \
		|| { echo "  MISBEHAVED the verdict ignores the flag"; fail=1; }
	[ $fail -eq 0 ] && echo "gate_verdict: all arms ok" || echo "gate_verdict: ARMS FAILED"
	exit $fail
fi
