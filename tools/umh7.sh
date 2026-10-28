#!/system/bin/sh
# Exec'd by the KERNEL's call_usermodehelper() as uid 0 (kernel domain) after
# broot7's UMH7 delivery has aimed modprobe_path here and cleared
# selinux_enforcing.  Everything below is an ORDINARY userspace write: as uid 0
# with enforcing off, /proc/sys and selinuxfs are writable without any kernel
# primitive -- which is exactly why this delivery needs no task VA and no
# borrow window (see the UMH7 comment in broot7.c).
#
# The helper runs with no tty, no PATH and its stdio pointing at /dev/null, so
# every command is an absolute path and everything is logged.
LOG=/data/local/tmp/umh7.log
T=/system/bin/toybox
{
    echo "=== umh7 fired: uid=$($T id -u 2>&1) context=$($T ls -Zd /proc/self 2>&1) ==="
    # 1. restore modprobe_path FIRST: while it points here, any unregistered
    #    address family re-fires this script (harmless but dirty, and the
    #    restore is one procfs write).
    echo /sbin/modprobe > /proc/sys/kernel/modprobe
    echo "modprobe_path restored: $($T cat /proc/sys/kernel/modprobe)"
    # 2. start the root daemon the same way the app's restart script does.
    #    We are uid 0, so the daemon lands exactly like the kernel-helper
    #    route's own (this is what the ladder's borrow window used to build).
    /system/bin/sh /data/local/tmp/start_sud.sh
    echo "start_sud rc=$?"
    # 3. close the permissive window.  Only after the daemon is up: its own
    #    setup (the /sbin bind, listeners) runs before this line.
    echo 1 > /sys/fs/selinux/enforce
    echo "enforce now: $($T cat /sys/fs/selinux/enforce)"
    $T touch /data/local/tmp/umh7.done
    echo "=== umh7 done ==="
} >> "$LOG" 2>&1
