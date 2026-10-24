#!/system/bin/sh
# modlist.sh - machine-readable module inventory for the app's module page.
# One block per installed module:
#   ==MOD <id> / ==NAME / ==VER / ==AUTH / ==DESC / ==VC / ==ENABLED|==DISABLED
# terminated by ==END.  The app parses these lines; keep the format stable.
for d in /data/adb/modules/*/; do
    [ -d "$d" ] || continue
    m=${d#/data/adb/modules/}; m=${m%/}
    case "$m" in .*) continue ;; esac
    prop="$d/module.prop"
    [ -f "$prop" ] || continue
    echo "==MOD $m"
    echo "==NAME $(grep -m1 '^name=' "$prop" | cut -d= -f2-)"
    echo "==VER $(grep -m1 '^version=' "$prop" | cut -d= -f2-)"
    echo "==AUTH $(grep -m1 '^author=' "$prop" | cut -d= -f2-)"
    echo "==DESC $(grep -m1 '^description=' "$prop" | cut -d= -f2-)"
    echo "==VC $(grep -m1 '^versionCode=' "$prop" | cut -d= -f2-)"
    if [ -f "$d/disable" ]; then echo "==DISABLED"; else echo "==ENABLED"; fi
done
echo "==END"
