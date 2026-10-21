#!/usr/bin/env bash
# One entry point from "the APK is built" to "the acceptance verdict is on screen".
#
# Why a script and not a remembered command line (ledger 598): the install itself has three ways to
# fail that all LOOK like the device misbehaving -- (1) `pm install` without -r answers
# INSTALL_FAILED_ALREADY_EXISTS, (2) the file needs chcon apk_data_file or the installer reports a
# bogus BAD_MANIFEST, (3) the vivo confirm dialog dies in ~14 s if nobody taps it.  On top of that,
# release/ now holds several artifacts and one of them (1.8.7) is known-broken, so "install the newest"
# has to be DERIVED from the artifacts, not from memory or from a filename sort.
#
# usage: bash tools/install_and_verify.sh [--dry-run] [--yes] [serial]
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SER="3e5a38a5"; DRY=0; YES=0
for a in "$@"; do
	case "$a" in
		--dry-run) DRY=1 ;;
		--yes) YES=1 ;;
		*) SER="$a" ;;
	esac
done
ADB="adb -s $SER"
BT=${BT:-${SDK:-/home/v/Android/Sdk}/build-tools/35.0.0}
[ -x "$BT/aapt" ] || { echo "no aapt at $BT/aapt (set BT=)"; exit 2; }
$ADB get-state >/dev/null 2>&1 || { echo "ABORT: $SER not on adb"; exit 2; }

echo "== every release artifact this repo can offer (versionCode read from the APK, not the name) =="
declare -a CODES PATHS STATUSES DIRS
for d in "$ROOT"/release/*/; do
	apk=$(ls "$d"*-release.apk 2>/dev/null | head -1)
	[ -n "$apk" ] || continue
	code=$("$BT/aapt" dump badging "$apk" 2>/dev/null | sed -n "s/.*versionCode='\([0-9]*\)'.*/\1/p" | head -1)
	name=$("$BT/aapt" dump badging "$apk" 2>/dev/null | sed -n "s/.*versionName='\([^']*\)'.*/\1/p" | head -1)
	st="unmarked"
	[ -f "$d/STATUS" ] && st="$(head -1 "$d/STATUS")"
	printf '  code=%-4s %-8s %-24s %s\n' "$code" "$name" "$(basename "$d")" "$st"
	DIRS+=("$d"); CODES+=("$code"); PATHS+=("$apk"); STATUSES+=("$st")
done
n=${#PATHS[@]}
[ "$n" -gt 0 ] || { echo "ABORT: no release/*/*-release.apk found"; exit 2; }

best=-1; bestcode=0; i=0
while [ $i -lt $n ]; do
	c=${CODES[$i]:-0}
	[ "$c" -gt "$bestcode" ] 2>/dev/null && { best=$i; bestcode=$c; }
	i=$((i + 1))
done
[ "$best" -ge 0 ] || { echo "ABORT: no readable versionCode among $n artifact(s)"; exit 2; }
if printf '%s' "${STATUSES[$best]}" | grep -qi 'broken'; then
	echo "REFUSE: the newest artifact (code ${CODES[$best]}) is marked broken: ${STATUSES[$best]}"
	echo "        a newer-good artifact does not exist, so the product cannot be installed from here."
	exit 1
fi
if ! printf '%s' "${STATUSES[$best]}" | grep -qi 'current'; then
	echo "NOTE: ${DIRS[$best]} is not marked 'current' -- its STATUS says: ${STATUSES[$best]}"
	echo "      proceeding anyway because it is the highest versionCode -- confirm this is intended."
fi
APK=${PATHS[$best]}; CHOSEN=${DIRS[$best]}; VER=$(basename "${CHOSEN%/}")
echo "== chosen: $APK (versionCode ${CODES[$best]}, $VER)"

if [ "$DRY" = 1 ]; then
	echo "--dry-run: selection logic verified, nothing pushed, nothing installed"
	exit 0
fi

. "$ROOT/tools/gate_verdict.sh"
flag=$($ADB shell 'settings get secure vivo_adb_simulate_input' 2>/dev/null | tr -d '\r' | head -1)
verdict=$(gate_verdict "$flag" "${TAPBACKEND:-adb}")
echo "== ROM input gate: vivo_adb_simulate_input=${flag:-<unreadable>} backend=${TAPBACKEND:-adb} -> $verdict"
if [ "$verdict" = REFUSE ] && [ "${ALLOW_LOCKED:-0}" != 1 ]; then
	cat <<'EOT'
REFUSE: this ROM withholds INJECT_EVENTS from uid 2000 while 「USB模拟点击」 is off, so nothing here can
click the install confirmation and `pm install` would only end in `Failure [-200]` after the on-screen
timeout (ledger 691/696).  Unlock it once -- the flag then survives every reboot (ledger 701):
  1) python3 tools/unlock_adb_input.py --check     # reads the flag; also witnesses the app-planted record
  2) with 月虹提权助手 installed and escalated, the app plants Settings' own `account_verified_ok`
     itself on every run (1.9.21, Chain.unlockAdbInput) -- no vivo account is then required;
  3) a hand flips 设置 → 更多设置 → 开发者选项 → 「USB模拟点击」 on.
Neither shell (no WRITE_SECURE_SETTINGS while it is 0) nor the daemon's root (no servicemanager at all)
can write that value -- the flip is the one step that stays manual.  Re-run with ALLOW_LOCKED=1 to
install anyway through the uinput fallback (TAPBACKEND=uinput, needs the root channel).
EOT
	exit 2
fi

DEV=/data/local/tmp/temproot-$VER.apk
md5h=$(md5sum "$APK" | cut -d' ' -f1)
pushout=$($ADB push "$APK" "$DEV" 2>&1 | tr -d "\r" | head -2); rc=$?
[ $rc -eq 0 ] || { echo "ABORT: push failed (rc=$rc): $pushout"; exit 2; }
md5d=$($ADB shell "md5sum $DEV" 2>/dev/null | tr -d '\r' | cut -c1-32)
[ "$md5h" = "$md5d" ] || { echo "ABORT: pushed file differs (host $md5h vs device $md5d)"; exit 2; }
echo "== pushed $DEV, md5 matches ($md5h)"
$ADB shell "chcon u:object_r:apk_data_file:s0 $DEV" 2>&1 | tr -d '\r'
read_code() { # dumpsys prints versionCode=N plus minSdk/targetSdk: take ONLY the versionCode field
	$ADB shell 'dumpsys package com.xplay6.temproot' 2>/dev/null | tr -d '\r' | sed -n 's/.*versionCode=\([0-9][0-9]*\).*/\1/p' | head -1
}
before=$(read_code)
echo "== installed versionCode before: ${before:-none}"

if [ "$YES" != 1 ]; then
	echo
	echo "This ROM confirms every adb install on screen (two stages: 继续安装 then 安装, both at the same"
	echo "centre -- read them from a dump, never from a remembered coordinate).  Whether THIS run can press"
	echo "them depends on the gate reported above:"
	echo "  - gate on  -> tools/install_tap.py taps both stages with framework injection (measured: landed=2"
	echo "    refused=0 -> Success, ledger 697/703).  Run this script with --yes and nobody is needed."
	echo "  - gate off -> injection is refused for uid 2000 and the root channel cannot build a touchscreen"
	echo "    either unless the daemon is up; the pre-flight above already refused for that reason."
	echo "Either way the screen must be awake and unlocked, or the dialog is never rendered while"
	echo "uiautomator still dumps the launcher (ledger 618): adb shell svc power stayon true; adb shell wm dismiss-keyguard."
	echo "vivo's 「您的IMEI或MEID是无效的」 popup often sits on top -- dismiss its 知道了 first."
	echo "After it installs: EXPECT_ENFORCING=1 bash tools/verify_approot.sh"
fi

if [ "$YES" = 1 ]; then
	echo "== raising the dialog and best-effort tapping it (a finger may still be needed -- see ledger 607)"
	$ADB shell "nohup sh -c 'pm install -r -t $DEV > /data/local/tmp/pminst.out 2>&1' >/dev/null 2>&1 &" \
		>/dev/null 2>&1
	python3 "$ROOT/tools/install_tap.py" "$DEV" "$SER" || true
	after=$(read_code)
	echo "== versionCode after: ${after:-none} (want ${CODES[$best]})"
	if [ "${after:-}" != "${CODES[$best]}" ]; then
		echo "NOT INSTALLED: readback ${after:-none} != artifact ${CODES[$best]}; pm output:"
		$ADB shell cat /data/local/tmp/pminst.out 2>&1 | tr -d '\r' | head -3
		echo "This is the expected outcome with nobody at the screen (the ROM times out the confirmation)."
		exit 1
	fi
	echo "== installing this build succeeded; running the acceptance gate"
	EXPECT_ENFORCING=1 bash "$ROOT/tools/verify_approot.sh" "$SER"
fi
