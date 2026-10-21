#!/system/bin/sh
# tools/acdbdir.sh -- replay libacdbloader.so's OWN directory cascade on this machine, read-only.
# The loader (acdb_loader_init_v2) builds base="/etc/acdbdata/" and then tries, in order,
# ro.vivo.product.model / ro.vivo.product.platform / /sys/devices/soc0/hw_platform, each gated by
# access(dir, F_OK); the first one that exists is used, and every *.acdb inside it is loaded
# (readdir order, capped at 20). persist.audio.calfile0..19 bypass the cascade altogether.
# Printed one item per line so the host can apply the ordering; no awk on this device.
set -u
BASES="/etc/acdbdata /system/etc/acdbdata /vendor/etc/acdbdata"
M=$(getprop ro.vivo.product.model)
P=$(getprop ro.vivo.product.platform)
D=$(getprop ro.product.device)
DEV=/sys/devices/soc0/hw_platform
[ -r "$DEV" ] || DEV=/sys/devices/system/soc/soc0/hw_platform
H=$(cat "$DEV" 2>/dev/null)
# /etc is a symlink on Android; the loader's base string is "/etc/acdbdata" while md5sum on the
# host prints the resolved path, so the capture must carry where /etc actually points.
E=$(readlink /etc 2>/dev/null)
echo "ACDBDIR inputs model=$M platform=$P hw_platform=$H node=$DEV device=$D etcroot=$E"
i=0
while [ "$i" -lt 20 ]; do
	V=$(getprop "persist.audio.calfile$i")
	[ -n "$V" ] && echo "ACDBDIR calfile$i=$V"
	i=$((i + 1))
done
for b in $BASES; do
	for c in "$M" "$P" "$H"; do
		[ -n "$c" ] || continue
		d="$b/$c"
		if [ -e "$d" ]; then
			n=$(ls "$d" 2>/dev/null | grep -c "\.acdb")
			echo "ACDBDIR exists $d acdb=$n src=$c"
		fi
	done
done
echo "ACDBDIR_DONE"
