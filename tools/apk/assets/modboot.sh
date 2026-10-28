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
        # toybox is the multi-call binary on this ROM; the plain names (setsid,
        # rm, cp, ...) are symlinks with scrambled targets and resolve to
        # nothing, so every helper is invoked through toybox directly.
        #
        # closefds, when present, drops the /dev/binder fds this shell inherited
        # from the escalation ladder before exec'ing the script -- module
        # daemons are long-lived and must not carry the pile.  It only ever
        # closes COPIES here: sud still holds the originals, so no
        # binder_release fires (closing the last reference is what would walk
        # the poisoned queues).  Sync scripts exit immediately and are not
        # worth wrapping.
        CF=""
        for c in /data/user/0/com.xplay6.temproot/files/closefds \
                 /data/local/tmp/closefds; do
            [ -x "$c" ] && CF="$c" && break
        done
        if [ -n "$CF" ]; then
            /system/bin/toybox setsid "$CF" /system/bin/sh "$1" >> "$LOG" 2>&1 &
        else
            /system/bin/toybox setsid sh "$1" >> "$LOG" 2>&1 &
        fi
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

# The service phase runs DETACHED (setsid, ppid 1), so the chain that called
# this script may be gone by the time a module's service.sh has finished
# setting itself up.  The Magisk runtime module is the one case where that
# matters: it has to leave a daemon behind, and the caller has to be able to
# tell whether it worked.  So the service phase waits briefly for the daemon
# to answer and reports the result in the log.
if [ "$1" = service ]; then
    i=0
    while [ $i -lt 30 ]; do
        if /system/bin/toybox ls /data/local/tmp/magisk_rt/magisk >/dev/null 2>&1 \
           && /system/bin/toybox sh -c 'cd /data/local/tmp/magisk_rt && LD_PRELOAD=/data/local/tmp/magisk_rt/libmagisk_abs.so ./magisk -v' >/dev/null 2>&1; then
            echo "===== modboot: magisk daemon is up =====" >> "$LOG"
            break
        fi
        i=$((i + 1))
        /system/bin/toybox sleep 1
    done
fi
