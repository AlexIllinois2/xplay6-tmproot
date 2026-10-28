#!/usr/bin/env bash
# Build the "magisk_runtime" module: Magisk 30.7 packaged as a Magisk-format
# module that the tmproot module engine can install and replay at boot.
#
# WHY A MODULE AND NOT A PLAIN INSTALL
# -------------------------------------
# Magisk normally starts from a patched boot image (magiskinit becomes PID 1's
# successor).  On this device the boot image cannot be modified -- vivo's aboot
# binds it to the unlocked-boot state in a way that survives a BL unlock, and a
# patched image fails to boot (measured: edl/mbwork/H_mtime_7x.img, a one-byte
# gzip MTIME change, produced a boot loop).  So Magisk has to live entirely in
# userspace, started by the tmproot module engine once the root channel is up.
#
# THE TWO BLOCKERS AND HOW THEY ARE SOLVED
# ----------------------------------------
# 1) The daemon's IPC socket is a FILESYSTEM AF_UNIX socket
#    (<magisk_tmp>/.magisk/device/socket).  On this kernel bind(2) on a
#    filesystem unix socket path fails with EPERM in every directory, in both
#    enforcing AND permissive SELinux mode, with no avc record -- a kernel hook,
#    not a policy decision.  The ABSTRACT namespace is unaffected.
#    Fix: tools/magisk_abs.so, an LD_PRELOAD shim that rewrites bind()/connect()
#    for that one path into an abstract socket whose name is a hash of the path.
#    Both daemon and client load it, so they agree on the name.
#
# 2) The daemon wants to run in the "magisk" SELinux domain and wants to relabel
#    its tmp root.  Injecting Magisk's own rules with `magiskpolicy --magisk
#    --live` makes vivo's watchdog reboot the device (reproduced twice), and
#    labelling /sbin (which is tmproot's own bind mount) is refused with
#    "associate" (permissive=0 -> hard kill).
#    Fix: none of it is needed.  The daemon tolerates a missing magisk domain
#    (the setcon is .log_ok()) and we simply never touch /sbin: the module
#    keeps its runtime under /data/local/tmp/magisk_rt, and the daemon is started
#    with that directory as its CWD.  With neither /sbin/.magisk nor
#    /debug_ramdisk/.magisk present, get_magisk_tmp() returns "" and every path
#    the daemon uses becomes relative to that CWD.
#
# OUTPUT
# ------
#   build/magisk_runtime/            the module directory (ready to zip)
#   build/magisk_runtime.zip         the same, as a Magisk-installable zip
#
# usage: bash tools/build_magisk_module.sh [--install]
#   --install  also push the module onto the device and place it under
#              /data/adb/modules/ (root channel required)
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BUILD=$ROOT/build
MODID=magisk_runtime
MODDIR=$BUILD/$MODID

SDK=${SDK:-/home/v/Android/Sdk}
NDK_VER=${NDK_VER:-29.0.13846066}
CC=$SDK/ndk/$NDK_VER/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android21-clang
TARGET=aarch64-linux-android21

APK=${MAGISK_APK:-$ROOT/../edl/Magisk-v30.7.apk}
if [ ! -f "$APK" ]; then
    echo "Magisk APK not found at: $APK" >&2
    echo "set MAGISK_APK=/path/to/Magisk.apk" >&2
    exit 1
fi

echo "=== 1/5  extract Magisk arm64 binaries ==="
rm -rf "$BUILD/mgextract"
mkdir -p "$BUILD/mgextract"
( cd "$BUILD/mgextract" && unzip -o -j "$APK" \
    'lib/arm64-v8a/libmagisk.so' \
    'lib/arm64-v8a/libmagiskinit.so' \
    'lib/arm64-v8a/libmagiskpolicy.so' \
    'lib/arm64-v8a/libbusybox.so' \
    'lib/arm64-v8a/libinit-ld.so' >/dev/null )
mv "$BUILD/mgextract/libmagisk.so"        "$BUILD/mgextract/magisk"
mv "$BUILD/mgextract/libmagiskinit.so"    "$BUILD/mgextract/magiskinit"
mv "$BUILD/mgextract/libmagiskpolicy.so"  "$BUILD/mgextract/magiskpolicy"
mv "$BUILD/mgextract/libbusybox.so"       "$BUILD/mgextract/busybox"
chmod 755 "$BUILD"/mgextract/*

echo "=== 2/5  build the LD_PRELOAD socket shim ==="
"$CC" -target $TARGET -O2 -Wall -fPIC -shared \
    -o "$BUILD/mgextract/magisk_abs.so" "$ROOT/tools/magisk_abs.c"
file "$BUILD/mgextract/magisk_abs.so"

echo "=== 3/5  lay out the module ==="
rm -rf "$MODDIR"
mkdir -p "$MODDIR/system/xbin" "$MODDIR/system/lib"

# Everything goes into system/xbin.  Not a stylistic choice: publishing a
# directory replaces it with a tmpfs and copies the original back, and on
# this ROM /system/bin holds 419 entries of which 151 are symlinks (149 of
# them dangling, because vivo scrambles the toybox applet targets on
# purpose).  Copying that tree back produces a /system/bin without a usable
# /system/bin/sh, which takes adb and every shell on the device down with it
# (measured 2026-10-27).  /system/xbin holds three plain files and no
# symlinks, so publishing it is safe.
cp "$BUILD/mgextract/magisk"       "$BUILD/mgextract/magisk.runtime"
cp "$BUILD/mgextract/magisk"       "$MODDIR/system/xbin/magisk32"
cp "$BUILD/mgextract/magisk"       "$MODDIR/system/xbin/magisk64"
cp "$BUILD/mgextract/magiskpolicy" "$MODDIR/system/xbin/magiskpolicy"
cp "$BUILD/mgextract/busybox"      "$MODDIR/system/xbin/busybox"
cp "$BUILD/mgextract/magisk_abs.so" "$MODDIR/system/lib/libmagisk_abs.so"
# The REAL binary, kept next to the wrapper: service.sh copies this one into
# the runtime directory, and that copy is what the daemon and the clients
# both exec.  The wrapper in system/xbin/magisk only points at it.
cp "$BUILD/mgextract/magisk"       "$MODDIR/system/xbin/magisk.real"
chmod 755 "$MODDIR/system/xbin/magisk32" "$MODDIR/system/xbin/magisk64"
chmod 755 "$MODDIR/system/xbin/magiskpolicy" "$MODDIR/system/xbin/busybox"
chmod 755 "$MODDIR/system/xbin/magisk.real"
chmod 755 "$MODDIR/system/lib/libmagisk_abs.so"

# The magisk CLIENT has to be the same inode the daemon runs, so it cannot be
# the shipped binary itself -- it is a wrapper that execs the runtime copy.
# (magisk32 / magisk64 stay real binaries: they are the 32/64-bit entry
# points Magisk installs for itself, and nothing here execs them.)
cat > "$MODDIR/system/xbin/magisk" <<'EOF'
#!/system/bin/sh
# Magisk client wrapper.
#
# execs the runtime copy of the magisk binary -- the SAME inode the daemon
# runs.  The daemon only accepts a client whose /proc/PID/exe has the same
# st_dev and st_ino as its own, and every mount namespace has its own tmpfs
# instance, so a copy of the binary (or another namespace's view of the
# overlay) is a different inode and gets "Accessed denied".
#
# The shim has to be preloaded: the daemon's socket is a filesystem AF_UNIX
# socket and this kernel refuses to bind one.
RUNTIME=/data/local/tmp/magisk_rt
export LD_PRELOAD=$RUNTIME/libmagisk_abs.so
exec "$RUNTIME/magisk" "$@"
EOF
chmod 755 "$MODDIR/system/xbin/magisk"

# Magisk's su applet is selected by argv[0]; the manager copies the daemon
# binary under the applet names.  We ship a wrapper script instead of the raw
# binary because the applet has to load the socket shim: without it the client
# would try to reach the filesystem socket, which this kernel refuses.
cat > "$MODDIR/system/xbin/su" <<'EOF'
#!/system/bin/sh
# Magisk su applet wrapper.
#
# The applet is the magisk binary dispatched by argv[0] ("su").  Two things
# are needed for it to work here:
#
#  1. The socket shim has to be preloaded.  The daemon listens on a
#     FILESYSTEM unix socket, and this kernel refuses bind(2) on one (EPERM,
#     in every directory, in both enforcing and permissive mode, with no avc
#     record -- a kernel hook).  The shim moves that one socket into the
#     abstract namespace, where it works.
#
#  2. The binary has to be the SAME INODE the daemon runs.  The daemon
#     accepts a client only when /proc/PID/exe has the same st_dev and st_ino
#     as the daemon's own exe.  A copy of the binary elsewhere, or another
#     namespace's view of a tmpfs overlay, has a different inode and every
#     request comes back as "Accessed denied".
#
# Both point at the runtime directory that service.sh creates under
# /data/local/tmp -- a real filesystem, so every namespace sees one inode.
RUNTIME=/data/local/tmp/magisk_rt
export LD_PRELOAD=$RUNTIME/libmagisk_abs.so
exec "$RUNTIME/magisk" su "$@"
EOF
chmod 755 "$MODDIR/system/xbin/su"

cat > "$MODDIR/module.prop" <<EOF
id=$MODID
name=Magisk Runtime (tmproot)
version=v30.7
versionCode=30700
author=tmproot
description=Magisk 30.7 running as a userspace module on the Xplay6. The daemon's
filesystem AF_UNIX socket is redirected to the abstract namespace by
libmagisk_abs.so, because this kernel refuses bind(2) on filesystem unix
sockets. Boot-time start is driven by tmproot's module engine, not by a patched
boot image.
EOF

cat > "$MODDIR/service.sh" <<'EOF'
#!/system/bin/sh
# Start the Magisk daemon for this module.
#
# ---------------------------------------------------------------------------
# WHERE THE DAEMON AND THE CLIENTS HAVE TO LIVE
# ---------------------------------------------------------------------------
# The daemon only accepts a client whose /proc/PID/exe is the SAME inode as
# its own (daemon.rs: is_client() compares st_dev and st_ino).  Two copies of
# the same binary do NOT qualify -- and neither do two views of one tmpfs
# overlay, because every mount namespace gets its OWN tmpfs instance with its
# own inodes (measured on this device: /system/xbin/magisk is dev=4/ino=229944
# in the daemon's namespace, dev=24/ino=106846 in the adb shell's, and
# dev=27/ino=111423 in the root channel's).
#
# So the daemon and the clients must exec one single file on a real
# filesystem, and every namespace must see the same inode there.  /data
# qualifies (measured: the same file is dev=65026/ino=6815746 from every
# namespace).  /data/adb does not qualify for the CLIENT side, because it is
# 0700 root and an app cannot even open it -- so the runtime lives under
# /data/local/tmp, which is 0771 and world-readable.
#
# The runtime directory is therefore created here at run time, and the `su`
# wrapper in it points at the very same magisk binary the daemon runs.
# ---------------------------------------------------------------------------
MODDIR=${0%/*}
RUNTIME=/data/local/tmp/magisk_rt
SHIM_SRC=$MODDIR/system/lib/libmagisk_abs.so
SHIM=$RUNTIME/libmagisk_abs.so
DAEMON=$RUNTIME/magisk

log() { echo "$(/system/bin/toybox date '+%m-%d %H:%M:%S') magisk_runtime: $*" >> /data/adb/tmproot/logs/magisk_runtime.log; }

mkdir -p /data/adb/tmproot/logs "$RUNTIME/.magisk/device"

# The daemon resolves its socket and its log FIFO relative to its CWD,
# because get_magisk_tmp() returns "" when neither /sbin/.magisk nor
# /debug_ramdisk/.magisk exists.  Creating either of those switches Magisk
# into the /sbin code path, which relabels /sbin -- refused with
# "associate" (permissive=0) on this device, and the daemon dies.  So the CWD
# is pinned here and the shim re-bases the relative socket path onto the same
# directory, which is what lets a client work from any CWD.
#
# The shim has to be copied next to the daemon: it is loaded via LD_PRELOAD,
# and the daemon is started from a shell that must not leak that variable
# into unrelated children (a `su` that exports LD_PRELOAD globally breaks
# every command it then runs -- "CANNOT LINK EXECUTABLE \"head\": library
# ... not found").
/system/bin/toybox cp -f "$MODDIR/system/xbin/magisk.real" "$DAEMON" 2>/dev/null
/system/bin/toybox cp -f "$SHIM_SRC" "$SHIM" 2>/dev/null
/system/bin/toybox chmod 755 "$DAEMON" "$SHIM" 2>/dev/null
/system/bin/toybox chmod 777 "$RUNTIME" "$RUNTIME/.magisk" "$RUNTIME/.magisk/device" 2>/dev/null

# The su wrapper: a script, not the raw binary.  The applet is selected by
# argv[0], and the wrapper is what lets it load the shim and point at the
# shared inode.
cat > "$RUNTIME/su" <<'WRAP'
#!/system/bin/sh
export LD_PRELOAD=/data/local/tmp/magisk_rt/libmagisk_abs.so
exec /data/local/tmp/magisk_rt/magisk su "$@"
WRAP
/system/bin/toybox chmod 755 "$RUNTIME/su" 2>/dev/null

# Already running?  Two things have to hold, and BOTH matter:
#
#  - the daemon has to answer (a leftover abstract socket from a killed daemon
#    makes the client spin in its connect loop, so the check needs a timeout);
#  - the running daemon has to be the SAME INODE as the file we just copied.
#    A daemon left over from an earlier run holds the OLD inode, and every
#    client that execs the current file is then rejected by is_client() with
#    "Accessed denied".  The daemon renames itself to "magiskd", so it is
#    matched by that name and not by the "--daemon" argument.
running_ok() {
    cd "$RUNTIME" || return 1
    LD_PRELOAD=$SHIM /system/bin/toybox timeout 5 "$DAEMON" -v >/dev/null 2>&1 || return 1
    # Compare the inode of the running daemon with the one on disk.
    for d in /proc/[0-9]*; do
        c=$(/system/bin/toybox tr '\0' ' ' < "$d/cmdline" 2>/dev/null)
        case "$c" in
            *magiskd*)
                a=$(/system/bin/toybox stat -c %i "$d/exe" 2>/dev/null)
                b=$(/system/bin/toybox stat -c %i "$DAEMON" 2>/dev/null)
                [ -n "$a" ] && [ "$a" = "$b" ] && return 0
                return 1
                ;;
        esac
    done
    return 1
}

if running_ok; then
    log "daemon already running"
    exit 0
fi

# A daemon from an earlier run is holding the old inode: kill it, or the
# clients will not be accepted.
for d in /proc/[0-9]*; do
    c=$(/system/bin/toybox cat "$d/cmdline" 2>/dev/null | /system/bin/toybox tr '\0' ' ')
    case "$c" in
        *magiskd*) /system/bin/toybox kill -9 "${d#/proc/}" 2>/dev/null ;;
    esac
done
sleep 1

cd "$RUNTIME" || { log "cannot enter $RUNTIME"; exit 1; }

# Start the daemon through closefds when it is available: this shell inherited
# the escalation ladder's binder fds, and a daemon should not hold them.  The
# wrapper only closes COPIES (sud keeps the originals), so no binder_release
# fires and none of the poisoned queues are walked.  Without the wrapper the
# daemon still starts, just with a polluted fd table (which is what broke
# gdbserver's event loop on 2026-10-28).
CF=""
for c in /data/user/0/com.xplay6.temproot/files/closefds /data/local/tmp/closefds; do
    [ -x "$c" ] && CF="$c" && break
done
if [ -n "$CF" ]; then
    LD_PRELOAD=$SHIM /system/bin/toybox setsid "$CF" "$DAEMON" --daemon >"$RUNTIME/daemon.log" 2>&1 </dev/null &
else
    LD_PRELOAD=$SHIM /system/bin/toybox setsid "$DAEMON" --daemon >"$RUNTIME/daemon.log" 2>&1 </dev/null &
fi
sleep 2
if LD_PRELOAD=$SHIM "$DAEMON" -v >/dev/null 2>&1; then
    log "daemon started"
else
    log "daemon FAILED to start (see $RUNTIME/daemon.log)"
fi
EOF
chmod 755 "$MODDIR/service.sh"

# post-fs-data.sh -- start the daemon EARLY.
#
# service.sh is the Magisk-native place for this, but on this device the boot
# chain can be interrupted: vivo's ABE kills the manager app during the boot
# storm, and the chain never reaches the service phase (measured: the boot
# log shows "modboot postfs done" and nothing after it).  post-fs-data runs
# SYNCHRONOUSLY, before the overlay is published, so it is the window that
# survives.
#
# Starting the daemon here is safe even though /system/xbin/su does not
# exist yet: the daemon and the clients share the runtime copy under
# /data/local/tmp, and the /system entries are only wrappers pointing at it.
cat > "$MODDIR/post-fs-data.sh" <<'EOF'
#!/system/bin/sh
# Start the Magisk daemon as early as the boot chain allows.
#
# See the note in build_magisk_module.sh: the service phase may never run on
# this device (vivo's ABE kills the manager app mid-boot), while the
# synchronous post-fs-data phase does.
MODDIR=${0%/*}
sh "$MODDIR/service.sh"
EOF
chmod 755 "$MODDIR/post-fs-data.sh"

echo "=== 4/5  package ==="
( cd "$BUILD" && rm -f "$MODID.zip" && zip -qr9 "$MODID.zip" "$MODID" )

echo "=== 5/5  done ==="
echo "module dir : $MODDIR"
echo "module zip : $BUILD/$MODID.zip"
echo
echo "contents:"
find "$MODDIR" -type f -o -type l | sed "s|$MODDIR|  magisk_runtime|" | sort
echo
du -sh "$BUILD/$MODID.zip" | sed 's/^/zip size: /'

if [ "${1:-}" = "--install" ]; then
    echo
    echo "=== installing onto the device ==="
    python3 "$ROOT/../tools/rootcmd.py" "true" >/dev/null 2>&1 || true
fi
