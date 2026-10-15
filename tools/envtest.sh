#!/system/bin/sh
# Which environment variables do the app_process-backed tools actually need here?
# Run as: su -c "sh /data/local/tmp/envtest.sh"
t() {
	printf '%-34s ' "$1"
	shift
	eval "$@" >/dev/null 2>&1
	echo "rc=$?"
}
echo "--- env the su child starts with:"
env | sort | tr '\n' ' '
echo
echo "--- bare (what snub sees today):"
t 'pm list packages' 'pm list packages'
t 'am -h' 'am -h'
t 'appops list android' 'appops list android'
t 'svc -h' 'svc 2>&1'
echo "--- only ANDROID_DATA (snub's workaround):"
t 'ANDROID_DATA pm' 'export ANDROID_DATA=/data; pm list packages'
t 'ANDROID_DATA am' 'export ANDROID_DATA=/data; am -h'
t 'ANDROID_DATA appops' 'export ANDROID_DATA=/data; appops list android'
t 'ANDROID_DATA svc' 'export ANDROID_DATA=/data; svc'
echo "--- plus ANDROID_ROOT / ASSETS / STORAGE:"
E='export ANDROID_DATA=/data ANDROID_ROOT=/system ANDROID_ASSETS=/system/app ANDROID_STORAGE=/storage EXTERNAL_STORAGE=/sdcard'
t '5-var pm' "$E; pm list packages"
t '5-var appops' "$E; appops list android"
t '5-var svc' "$E; svc"
t '5-var input' "$E; input keyevent KEYCODE_UNKNOWN"
echo "--- with the caller BOOTCLASSPATH as well (if readable):"
BC=$(tr '\000' '\n' < /proc/1/environ 2>/dev/null | grep -m1 '^BOOTCLASSPATH=')
printf 'BOOTCLASSPATH found: %s\n' "${BC:+yes}${BC:-no}"
