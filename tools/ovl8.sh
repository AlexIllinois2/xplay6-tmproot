#!/system/bin/sh
# Make the 7 "userdebug/eng" fingerprint paths exist for the 8.1 su gate.
# /system is ro (dm-0); overlay /system/bin and /system/xbin with symlink farms
# that point back into bind-mounted copies of the original directories.
set -u
PATH=/system/bin:/system/xbin
export PATH
T=/system/bin/toybox
R=/data/local/tmp/ovl

if [ -e /system/bin/gdbserver ] && [ -e /system/xbin/strace ]; then
	echo "already: overlay present"
	exit 0
fi

$T rm -rf "$R"
$T mkdir -p "$R/bin" "$R/xbin" "$R/rbin" "$R/rxbin" || exit 1
$T mount --bind /system/bin "$R/rbin" || { echo "bind rbin failed"; exit 1; }
$T mount --bind /system/xbin "$R/rxbin" || { echo "bind rxbin failed"; exit 1; }

for f in "$R"/rbin/*; do
	n=${f##*/}
	$T ln -sf "$f" "$R/bin/$n" || exit 1
done
for f in "$R"/rxbin/*; do
	n=${f##*/}
	$T ln -sf "$f" "$R/xbin/$n" || exit 1
done

for n in gdbserver keystore_cli pngtest tracepath; do
	: > "$R/bin/$n" || exit 1
	$T chmod 644 "$R/bin/$n"
done
for n in add-property-tag check-lost+found strace; do
	: > "$R/xbin/$n" || exit 1
	$T chmod 644 "$R/xbin/$n"
done

$T mount --bind "$R/bin" /system/bin || { echo "bind /system/bin failed"; exit 1; }
$T mount --bind "$R/xbin" /system/xbin || { echo "bind /system/xbin failed"; exit 1; }
echo "overlay ok"
for f in /system/bin/gdbserver /system/bin/keystore_cli /system/bin/pngtest \
	/system/bin/tracepath /system/xbin/add-property-tag \
	"/system/xbin/check-lost+found" /system/xbin/strace; do
	$T ls -l "$f"
done
