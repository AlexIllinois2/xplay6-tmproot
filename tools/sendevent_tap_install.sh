#!/usr/bin/env bash
# ★MEASURED INEFFECTIVE on the Android 7 build (ledger 604/607) -- kept as the record of the attempt,
# not as the way in: with the root channel UP and the shape bugs fixed (raw coords are UI x 4/3; the
# fts node does not advertise BTN_TOUCH; lift = TOUCH_MAJOR 0) the injected touch produced no
# Android-side effect, and a control injection on the volume-key node did not change the volume either.
# Use tools/fts_tap.sh for the corrected geometry; the install confirmation itself must be pressed by
# a person, because system_server's VivoAdbInstallManager only accepts a callback from vivo's own
# component or a real installer package (ledger 606).  Original header follows.
# Install an APK on the vivo past its confirm dialog WITHOUT `input` (whose app_process gets SIGKILLed
# under this device's memory pressure) by synthesising the tap with `sendevent` through the daemon's
# root channel (/dev/input is 0660 root:input, so the tap has to be sent as root).
#
# usage: sendevent_tap_install.sh <device-apk-path> [ser]
#   -r is REQUIRED: this device already has the package, and `pm install` without -r answers
#   INSTALL_FAILED_ALREADY_EXISTS -- which used to be read here as "the dialog ate it" (ledger 598).
set -u
APK=${1:?device apk path}
SER=${2:-3e5a38a5}
DEV=/dev/input/event6           # "fts" -- the touchscreen (ABS 002f/0035/0036/0039/003a)
X=${X:-540}
Y=${Y:-1662}                    # the 继续安装 button's centre at density 4, 1080x1920

rootsh() {                      # run lines as root through port 12345
	printf '%s\nexit\n' "$*" | timeout 40 bash -c \
		'exec 3<>/dev/tcp/127.0.0.1/12345; cat >&3; sleep 6; cat <&3' 2>/dev/null | tr -d '\r'
}

tap() { # tap <x> <y>  -- B-type multitouch slot protocol
	rootsh "sendevent $DEV 3 47 0
sendevent $DEV 3 57 0
sendevent $DEV 3 53 $1
sendevent $DEV 3 54 $2
sendevent $DEV 3 58 1000
sendevent $DEV 1 330 1
sendevent $DEV 0 0 0
sendevent $DEV 1 330 0
sendevent $DEV 3 57 -1
sendevent $DEV 0 0 0"
}

echo "== dialog before"; adb -s $SER shell 'uiautomator dump /sdcard/t.xml >/dev/null 2>&1; grep -oE "text=\"[^\"]{1,20}\"|bounds=\"\[[0-9]+,1[5-9][0-9][0-9]\]\[[0-9,]+\]\"" /sdcard/t.xml | tail -6' | tr -d '\r'
adb -s $SER shell "chcon u:object_r:apk_data_file:s0 $APK 2>/dev/null; pm install -r -t $APK" > /tmp/si_pm.out 2>&1 &
PM=$!
sleep 4
echo "== dialog during"; adb -s $SER shell 'uiautomator dump /sdcard/t2.xml >/dev/null 2>&1; grep -oE "text=\"[^\"]{1,20}\"|continue_button|resource-id=\"[^\"]*continue_button[^\"]*\" bounds=\"[^\"]*\"" /sdcard/t2.xml | tail -8' | tr -d '\r'
echo "== tap sent: $(tap "$X" "$Y" | tr '\n' ' ')"
for i in 1 2 3 4 5 6 7 8; do
	sleep 5
	if ! kill -0 $PM 2>/dev/null; then break; fi
done
wait $PM 2>/dev/null
echo "== pm install output: $(cat /tmp/si_pm.out | tr -d '\r' | head -3)"
adb -s $SER shell 'dumpsys package com.xplay6.temproot 2>/dev/null | grep -E "versionName|versionCode"' | tr -d '\r'
