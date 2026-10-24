#!/system/bin/sh
# modboot.sh - boot-time module script runner (Magisk phase emulation).
# The mounts themselves are applied by the caller via modmount.sh; this runs
# only the scripts.  usage: modboot.sh postfs|service
#   postfs  - module post-fs-data.sh + global post-fs-data.d/*.sh, synchronous
#   service - module service.sh + global service.d/*.sh, detached (setsid,
#             ppid 1) so slow modules never block the boot chain
# Phase log: /data/adb/tmproot/logs/modboot.log
BASE=/data/adb/tmproot
MODS=/data/adb/modules
LOG=$BASE/logs/modboot.log

run() { # $1 script path, $2 sync|async
    [ -f "$1" ] || return 0
    echo "$(date '+%m-%d %H:%M:%S') run $1" >> "$LOG"
    if [ "$2" = sync ]; then
        sh "$1" >> "$LOG" 2>&1
    else
        setsid sh "$1" >> "$LOG" 2>&1 &
    fi
}

enabled() { # $1 module dir
    [ -f "$1/disable" ] && return 1
    [ -f "$1/remove" ] && return 1
    return 0
}

mkdir -p "$BASE/logs"
echo "===== $(date '+%m-%d %H:%M:%S') modboot $1 =====" >> "$LOG"
case "$1" in
    postfs)
        for d in "$MODS"/*/; do
            [ -d "$d" ] || continue
            enabled "$d" || continue
            run "$d/post-fs-data.sh" sync
        done
        for s in /data/adb/post-fs-data.d/*.sh; do run "$s" sync; done
        echo "===== modboot postfs done =====" >> "$LOG"
        echo "postfs done"
        ;;
    service)
        for d in "$MODS"/*/; do
            [ -d "$d" ] || continue
            enabled "$d" || continue
            run "$d/service.sh" async
        done
        for s in /data/adb/service.d/*.sh; do run "$s" async; done
        echo "===== modboot service done =====" >> "$LOG"
        echo "service started"
        ;;
    *)
        echo "usage: modboot.sh postfs|service"
        exit 1
        ;;
esac
