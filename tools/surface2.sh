#!/system/bin/sh
# Read-only attack-surface sweep for the Xplay6, run as uid 2000.
# Deliberately contains NO ioctl and NO race: a live window is precious (each panic
# costs a physical power cycle), so this only stats/reads.  It answers the question the
# ion route could not: is there a kernel object the shell may already WRITE?
#   - /dev nodes reachable by shell, incl. the Qualcomm diag/mem candidates
#   - anything world- or group-writable under /sys, /proc, /dev
#   - debugfs: proven READABLE by shell on this build -- is any node writable too?
#   - pstore: if it survives, the previous panic's log is free crash forensics
#   - the two preconditions of the modprobe_path route
OUT=/data/local/tmp/surface2.txt
{
echo "== id / groups =="
id
cat /proc/self/status | grep -E '^(Uid|Gid|Groups|CapEff|Seccomp)'
echo
echo "== candidate device nodes (mode owner group) =="
for n in /dev/diag /dev/diag_dbr /dev/mem /dev/kmem /dev/kmsg /dev/pmsg0 \
         /dev/ptx_cmdlog_boot /dev/hab /dev/smdmemd /dev/ram0 /dev/kgsl-3d0 \
         /dev/ion /dev/qseecom /dev/adsprpc-smd /dev/msmadsplibs /dev/uhid \
         /dev/bus/usb /dev/ttyMSM /dev/spcuse /dev/spkr /dev/vcap; do
	[ -e "$n" ] && ls -ldZ "$n" 2>&1
done
echo
echo "== world-writable regular files under /sys /proc /dev (first 120) =="
find /sys /proc /dev -type f -perm -002 2>/dev/null | head -120
echo
echo "== group-writable, excluding world-writable (first 120) =="
find /sys /proc /dev -type f -perm -020 ! -perm -002 2>/dev/null | head -120
echo
echo "== debugfs: writable anywhere? (proven readable by shell) =="
find /sys/kernel/debug -type f -perm -022 2>/dev/null | head -60
echo "-- kgsl debugfs listing --"
ls -lR /sys/kernel/debug/kgsl 2>&1 | head -30
echo
echo "== /sys/fs/pstore (previous panic log?) =="
ls -lZ /sys/fs/pstore 2>&1
for f in /sys/fs/pstore/*; do [ -f "$f" ] && { echo "-- $f"; head -40 "$f"; }; done
echo
echo "== modprobe_path route preconditions =="
echo -n "modules_disabled="; cat /proc/sys/kernel/modules_disabled 2>&1
echo -n "modprobe          ="; cat /proc/sys/kernel/modprobe 2>&1
echo -n "core_pattern      ="; cat /proc/sys/kernel/core_pattern 2>&1
echo -n "hotplug           ="; cat /proc/sys/kernel/hotplug 2>&1
echo "-- /data mount flags (noexec would kill the rootsh path) --"
grep -E ' /data | / ' /proc/mounts 2>&1
echo "-- /sys/fs/selinux --"
ls -lZ /sys/fs/selinux 2>&1 | head -20
echo -n "enforce readable? "; cat /sys/fs/selinux/enforce 2>&1
echo
echo "== /dev writable set, as the shell really sees it =="
for f in /dev/*; do [ -w "$f" ] && echo "WRITABLE $f"; done
echo "DONE"
} > "$OUT" 2>&1
echo "wrote $OUT"
