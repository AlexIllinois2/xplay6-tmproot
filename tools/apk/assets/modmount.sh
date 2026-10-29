#!/system/bin/sh
# modmount.sh - tmproot module mount engine (Mountify-style pure bind, no overlayfs)
# vivo 8.1 blocks mount(2) whose target STRING starts with /system|/oem|/apps
# (runtime hook, LSM-independent). Bypass: bind targets passed as "//<abs path>".
# umount is not hooked -> plain paths work for cleanup.
# usage: modmount.sh mount|unmount|status     ('mount' = idempotent rebuild)
BASE=/data/adb/tmproot
MODS=/data/adb/modules
MNT=$BASE/.mnt
LOG=$BASE/logs/modmount.log
BINDS=$BASE/binds
MARK=$BASE/.active

log() { echo "$(date '+%m-%d %H:%M:%S') $*" >> "$LOG"; }

# nearest existing /system ancestor dir of rel path ($1 starts with /)
near_anc() {
    p=$1
    while :; do
        p=${p%/*}
        case "$p" in "") p=/ ;; esac
        [ -d "/system$p" ] && break
        [ "$p" = "/" ] && break
    done
    echo "$p"
}

enabled_mods() {
    ls -1 "$MODS" 2>/dev/null | sort | while read m; do
        case "$m" in .*) continue ;; esac
        [ -f "$MODS/$m/disable" ] && continue
        [ -f "$MODS/$m/remove" ] && continue
        [ -d "$MODS/$m/system" ] && echo "$m"
    done
}

do_unmount() {
    [ -f "$BINDS" ] || return 0
    sed -n '1!G;h;$p' "$BINDS" > "$BINDS.rev"
    while IFS='|' read kind tgt src; do
        case "$kind" in
            FB|A)
                if ! umount "$tgt" 2>/dev/null; then
                    if umount -l "$tgt" 2>/dev/null; then
                        log "lazy-unmounted $tgt"
                    else
                        log "WARN umount failed $tgt"
                    fi
                else
                    log "unmounted $tgt"
                fi
                ;;
        esac
    done < "$BINDS.rev"
    rm -f "$BINDS.rev" "$BINDS" "$MARK"
    if grep -q " $MNT " /proc/mounts 2>/dev/null; then
        umount "$MNT" 2>/dev/null || umount -l "$MNT" 2>/dev/null
        log "unmounted tmpfs $MNT"
    fi
    rm -rf "$MNT"
    return 0
}

do_mount() {
    if [ -f "$MARK" ]; then
        log "rebuild: unmounting previous set"
        do_unmount
    fi
    mkdir -p "$MNT" "$BASE/logs"
    : > "$BINDS"
    MODLIST=$(enabled_mods)
    if [ -z "$MODLIST" ]; then
        log "no enabled modules, nothing to mount"
        echo "no enabled modules"
        return 0
    fi

    # ---- scan phase (before any mounts; /system pristine) ----
    NEWF="$BASE/.newfiles";  : > "$NEWF"
    FILEB="$BASE/.filebinds"; : > "$FILEB"
    for m in $MODLIST; do
        find "$MODS/$m/system" -type f 2>/dev/null | while read f; do
            rel=${f#"$MODS/$m/system"}
            case "$rel" in ""|/) continue ;; esac
            if [ -f "/system$rel" ]; then
                echo "FB|$rel|$f" >> "$FILEB"
            else
                echo "$rel|$f" >> "$NEWF"
            fi
        done
    done
    # anchors: nearest existing ancestor of each new file; dedup + ancestor-prune
    cut -d'|' -f1 "$NEWF" | sort -u | while read rel; do near_anc "$rel"; done > "$BASE/.anchraw"
    ANCLIST=""
    while read a; do
        skip=0
        for b in $ANCLIST; do
            case "$a/" in "$b"/*) skip=1 ;; esac
        done
        if [ "$skip" = 0 ] && [ "$a" != "/" ]; then
            ANCLIST="$ANCLIST $a"
        elif [ "$a" = "/" ]; then
            log "WARN: module adds files at /system root, skipped (would snapshot whole /system)"
        fi
    done < "$BASE/.anchraw"
    rm -f "$BASE/.anchraw" "$NEWF"
    log "anchors:$ANCLIST"

    # ---- apply phase 1: tmpfs dir anchors ----
    if [ -n "$ANCLIST" ]; then
        if ! mount -t tmpfs -o mode=0755,gid=0 tmpfs "$MNT" 2>>"$LOG"; then
            log "FATAL tmpfs mount failed"
            echo "FATAL tmpfs"
            return 1
        fi
        for a in $ANCLIST; do
            # NEVER snapshot /system/lib or /system/lib64.
            # A tmpfs copy of these dirs gives libc.so (and every other .so) a
            # new inode.  Zygote has already loaded libc.so from dm-0; when an
            # app later dlopens a .so from this snapshot whose DT_NEEDED names
            # libc.so, the linker resolves it to the snapshot copy (different
            # inode), loads a SECOND libc, and __libc_preinit segfaults
            # (SEGV_ACCERR in __libc_init_globals).  Measured 2026-10-28: every
            # app that touched gralloc.msm8996.so crashed on launch.
            # New files directly under /system/lib cannot be added by this
            # engine; subdirs (e.g. /system/lib/soundfx) are safe and still
            # snapshotted because they do not contain libc.so.
            case "$a" in
                /lib|/lib64)
                    log "WARN: skipping anchor //system$a to avoid libc dedup crash (new files under /system/lib are not supported)"
                    continue
                    ;;
            esac
            T="$MNT/sys$a"
            mkdir -p "$T"
            cp -a "/system$a/." "$T/" 2>>"$LOG" || log "WARN snapshot $a rc=$?"
            for m in $MODLIST; do
                [ -d "$MODS/$m/system$a" ] && cp -a "$MODS/$m/system$a/." "$T/" 2>>"$LOG"
            done
            # A bind mount keeps the SOURCE inode's label, and toybox cp -a does
            # NOT preserve SELinux contexts -- every file in $T carries the
            # tmpfs default label (init_tmpfs) instead of system_file.  A domain
            # that may read system_file but not init_tmpfs (mediacodec) then
            # gets EACCES on the whole anchor: measured 2026-10-28, hw_get_module
            # ("gralloc") failed silently in every access() and media.codec
            # dereferenced the garbage module pointer and died at addr 0x4 --
            # which is how scrcpy/screenrecord lost every hardware encoder.
            # Relabel the snapshot BEFORE the bind; -h keeps symlinks intact.
            chcon -Rh u:object_r:system_file:s0 "$T" 2>>"$LOG" || log "WARN chcon $a rc=$?"
            if mount --bind "$T" "//system$a" 2>>"$LOG"; then
                echo "A|/system$a|$T" >> "$BINDS"
                log "anchor mounted: //system$a <- $T"
            else
                log "WARN anchor mount failed //system$a rc=$?"
            fi
        done
    fi

    # ---- apply phase 2: file binds for existing /system files not under an anchor ----
    nfb=0
    while IFS='|' read kind rel f; do
        skip=0
        for a in $ANCLIST; do
            case "$rel/" in "$a"/*) skip=1 ;; esac
        done
        [ "$skip" = 0 ] || continue
        if mount --bind "$f" "//system$rel" 2>>"$LOG"; then
            echo "FB|/system$rel|$f" >> "$BINDS"
            nfb=$((nfb+1))
        else
            log "WARN filebind failed //system$rel rc=$?"
        fi
    done < "$FILEB"
    rm -f "$FILEB"
    nfa=$(grep -c '^A|' "$BINDS" 2>/dev/null)
    nfb=$(grep -c '^FB|' "$BINDS" 2>/dev/null)
    : > "$MARK"
    log "apply done: anchors=$nfa filebinds=$nfb"
    echo "applied: anchors=$nfa filebinds=$nfb"
    return 0
}

do_status() {
    nfa=$(grep -c '^A|' "$BINDS" 2>/dev/null); nfa=${nfa:-0}
    nfb=$(grep -c '^FB|' "$BINDS" 2>/dev/null); nfb=${nfb:-0}
    live=$(grep -cE ' /(system|oem|apps)/[^ ]* ' /proc/mounts 2>/dev/null); live=${live:-0}
    echo "active=$([ -f "$MARK" ] && echo yes || echo no) anchors=$nfa filebinds=$nfb live_overlays=$live"
    [ -f "$BINDS" ] && grep -E '^(A|FB)\|' "$BINDS" | sed 's/^/  /'
    return 0
}

mkdir -p "$BASE/logs"
case "$1" in
    mount)   do_mount ;;
    unmount) do_unmount; log "unmount done"; echo "unmounted" ;;
    status)  do_status ;;
    *) echo "usage: modmount.sh mount|unmount|status"; exit 1 ;;
esac
