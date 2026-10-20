#!/usr/bin/env bash
# Root-channel synthetic tap for the vivo Xplay6, spoken in the touch controller's OWN protocol.
#
# Why this file exists (2026-10-20, measured this boot):
#   · `input tap` is useless here: it is an app_process, and as ROOT it gets SIGKILLed (rc=137) on
#     this device -- and as uid 2000 the InputDispatcher refuses it outright
#     ("Permission denied: injecting event from pid … uid 2000 to window … owned by uid …").
#   · /dev/input/event6 ("fts") is 0660 root:input, so a tap has to be written as root -- i.e. through
#     the daemon's raw channel, which is what tools/verify_approot.sh calls rootsh.
#   · Two shapes that look right and silently do NOTHING, both measured this boot:
#       - BTN_TOUCH (code 330): event6 does NOT advertise it (`getevent -p` KEY list has no 014a), so
#         input_core drops the write even though sendevent exits 0.  A tap built on BTN_TOUCH never
#         reaches userspace.
#       - ABS_MT_TRACKING_ID = -1: this driver declares 0039 min 0, so the "finger up" value is out of
#         range and the contact never ends.  The lift is ABS_MT_TOUCH_MAJOR = 0 for this driver.
#   · Coordinates are NOT the UI space: `getevent -p` gives 0035 max 1440 / 0036 max 2560 while the
#     display is 1080x1920 -- a 4/3 scale.  Every tap remembered in the ledger as (540,1662) was sent
#     unscaled and landed somewhere else; that is why "the screen has to be pressed by a human" looked
#     structural.  It was a units bug.
#
# So: scale by the ranges read off the device, drive the contact with TOUCH_MAJOR, and verify.
#
# usage:  tools/fts_tap.sh <ui_x> <ui_y> [ser]
# env:    KEEP=1 keeps the channel reply (default: discarded -- it can be megabytes of binary)
set -u
X=${1:?ui x}
Y=${2:?ui y}
SER=${3:-3e5a38a5}
ADB="adb -s $SER"
DEV=/dev/input/event6

chan() { # chan <lines...>  -- one shell session on the root channel
	$ADB forward tcp:12345 tcp:12345 >/dev/null 2>&1
	printf '%s\nexit\n' "$*" | timeout 40 bash -c \
		'exec 3<>/dev/tcp/127.0.0.1/12345; cat >&3; sleep 5; cat <&3' 2>/dev/null | tr -d '\r'
}

CAP=$(chan "getevent -p $DEV" | tr -cd '[:print:]\n')
XMAX=$(printf '%s\n' "$CAP" | sed -n 's/.*0035.*max \([0-9]*\).*/\1/p' | head -1)
YMAX=$(printf '%s\n' "$CAP" | sed -n 's/.*0036.*max \([0-9]*\).*/\1/p' | head -1)
# `wm size` is an app_process too, so it can be SIGKILLed right here exactly like `input`; sysfs knows
# the panel size without any Java.  Take whichever answers, and refuse if neither does.
SCREEN=$(chan "wm size; cat /sys/class/graphics/fb0/virtual_size" | tr -cd '[:print:]\n' \
	| sed -n 's/.*[Pp]hysical size: *\([0-9]*x[0-9]*\).*/\1/p; s/^\([0-9]*\),\([0-9]*\)$/\1x\2/p' \
	| grep -E "^[0-9]+x[0-9]+$" | tail -1)
[ -n "$XMAX" ] && [ -n "$YMAX" ] && [ -n "$SCREEN" ] || {
	echo "REFUSE: cannot read the tap geometry (absx_max=$XMAX absy_max=$YMAX screen=$SCREEN) --" \
		"guessing a scale is how a tap silently lands somewhere else"; exit 1; }
SW=${SCREEN%x*}; SH=${SCREEN#*x}
RX=$((X * (XMAX + 1) / SW)); RY=$((Y * (YMAX + 1) / SH))
[ "$RX" -le "$XMAX" ] && [ "$RY" -le "$YMAX" ] || {
	echo "REFUSE: ui ($X,$Y) maps to raw ($RX,$RY) outside [0,$XMAX]x[0,$YMAX]"; exit 1; }

# 47=ABS_MT_SLOT 57=TRACKING_ID 53=X 54=Y 58=WIDTH_MAJOR 48=TOUCH_MAJOR
OUT=$(chan "sendevent $DEV 3 47 0
sendevent $DEV 3 57 0
sendevent $DEV 3 53 $RX
sendevent $DEV 3 54 $RY
sendevent $DEV 3 58 20
sendevent $DEV 3 48 30
sendevent $DEV 0 0 0
usleep 120000
sendevent $DEV 3 48 0
sendevent $DEV 0 0 0
echo FTS_TAP_DONE")
case "$OUT" in
*FTS_TAP_DONE*) printf 'tapped ui(%s,%s) -> raw(%s,%s)  [screen %s, abs max %s x %s]\n' \
	"$X" "$Y" "$RX" "$RY" "$SCREEN" "$XMAX" "$YMAX" ;;
*) echo "REFUSE: the channel did not finish the tap sequence"; ${KEEP:-:} true ;;
esac
