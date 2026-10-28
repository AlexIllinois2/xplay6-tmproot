#!/usr/bin/env bash
# Install (or reinstall) the magisk_runtime module on the device and verify it.
#
# The module is copied through a shell-writable staging directory because
# /data/adb/modules is 0700 root and adb push cannot write there; the final
# placement is done through the tmproot root channel.
#
# It also refreshes the sysoverlay binary the manager app runs, because the
# app keeps its own copy under files/ and only that copy is used.
#
# usage: bash tools/install_magisk_module.sh [--rebuild]
#   --rebuild  run build_magisk_module.sh first
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
REPO=$(cd "$ROOT/.." && pwd)
MODID=magisk_runtime
STAGE=/data/local/tmp/mgs_mod
DEV_MOD=/data/adb/modules/$MODID
APP_FILES=/data/data/com.xplay6.temproot/files

if [ "${1:-}" = "--rebuild" ]; then
    bash "$ROOT/tools/build_magisk_module.sh"
fi

echo "=== stage to $STAGE ==="
adb shell "rm -rf $STAGE && mkdir -p $STAGE/system_xbin $STAGE/system_lib && chmod 777 $STAGE $STAGE/*"
adb push "$ROOT/build/$MODID/module.prop" "$ROOT/build/$MODID/service.sh" "$STAGE/" >/dev/null
adb push "$ROOT/build/$MODID/system/xbin/"* "$STAGE/system_xbin/" >/dev/null
adb push "$ROOT/build/$MODID/system/lib/libmagisk_abs.so" "$STAGE/system_lib/" >/dev/null
echo "staged."

echo "=== place into $DEV_MOD ==="
python3 "$REPO/tools/rootcmd.py" "
D=$DEV_MOD; S=$STAGE
rm -rf \$D
mkdir -p \$D/system/xbin \$D/system/lib
cp \$S/module.prop \$S/service.sh \$D/
cp \$S/system_xbin/* \$D/system/xbin/
cp \$S/system_lib/libmagisk_abs.so \$D/system/lib/
chown -R 0:0 \$D
chmod 755 \$D/service.sh \$D/system/xbin/* \$D/system/lib/*.so
chmod 644 \$D/module.prop
echo INSTALLED
"

echo "=== refresh the app's sysoverlay copy ==="
adb push "$ROOT/tools/sysoverlay" /data/local/tmp/sysoverlay.new >/dev/null
python3 "$REPO/tools/rootcmd.py" "
T=/system/bin/toybox
\$T cp -f /data/local/tmp/sysoverlay.new $APP_FILES/sysoverlay
\$T chmod 755 $APP_FILES/sysoverlay
\$T cp -f /data/local/tmp/sysoverlay.new /data/local/tmp/sysoverlay
\$T chmod 755 /data/local/tmp/sysoverlay
echo SYSOVERLAY_UPDATED
"

echo "=== stop any previous daemon, then run service.sh ==="
python3 "$REPO/tools/rootcmd.py" "
for d in /proc/[0-9]*; do
  c=\$(tr '\0' ' ' < \$d/cmdline 2>/dev/null)
  case \"\$c\" in *magisk*--daemon*) kill -9 \${d#/proc/} 2>/dev/null;; esac
done
rm -rf /data/adb/magisk/runtime
sleep 1
sh $DEV_MOD/service.sh
echo '--- log:'
tail -3 /data/adb/tmproot/logs/magisk_runtime.log 2>&1
"

echo "=== verify ==="
python3 "$REPO/tools/rootcmd.py" "
T=/system/bin/toybox
RT=/data/local/tmp/magisk_rt
echo '--- daemon socket:'
grep -a magisk_abs /proc/net/unix 2>&1 | tr -d '\000'
echo '--- daemon exe (must be the same inode the clients use):'
for d in /proc/[0-9]*; do
  c=\$(tr '\0' ' ' < \$d/cmdline 2>/dev/null)
  case \"\$c\" in *magiskd*) echo \"  pid=\${d#/proc/} exe=\$(readlink /proc/\${d#/proc/}/exe 2>&1) \$(stat -c 'dev=%d ino=%i' /proc/\${d#/proc/}/exe 2>&1)\";; esac
done
echo \"--- \$RT/magisk:\"
stat -c '  dev=%d ino=%i' \$RT/magisk 2>&1
echo '--- magisk -v:'
cd \$RT && LD_PRELOAD=\$RT/libmagisk_abs.so ./magisk -v 2>&1
echo '--- magisk -V:'
cd \$RT && LD_PRELOAD=\$RT/libmagisk_abs.so ./magisk -V 2>&1
echo '--- su -c id (root):'
cd \$RT && LD_PRELOAD=\$RT/libmagisk_abs.so ./magisk su -c id 2>&1 | \$T head -1
"
