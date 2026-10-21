#!/usr/bin/env python3
"""mock adb: exercise tools/run_sugate.sh end to end without a phone.

Not a rubber stamp -- it *models the rules the script depends on* and keeps state, so a
wrong address, a wrong payload, or a verdict that is read from the wrong column shows up as
a failed run:

  - writes land (readv=WRI) only on: .bss/.data pages, the empty pgd slots we fill, and any
    address reached through an alias window that is currently open;
  - the primary .text VA is NOT writable until a window covering it is opened -- that is the
    §159 fact the whole plan rests on;
  - the gate starts denying on 'su'; it flips to allow only once the patch word has actually
    been written at the gate's PA (through whichever window) AND the caches have converged on
    the CPU the probe is pinned to -- a landed word in a stale L1I line still says errno=1,
    which is the difference between "the write failed" and "the write is not visible yet";
  - the caller stays uid 2000, and both control cases keep their semantics.

Knobs (env): MOCK_NO_ALIAS=1 (alias window never opens), MOCK_NO_ELFUSH=1 (EL0 cache ops
SIGILL), MOCK_EL0_NOPRIV=1 (they execute but are ignored for kernel lines -- the pessimistic
case the ladder must escalate past), MOCK_NO_SWEEP=1 (mmap(PROT_EXEC) denied, I-side sweep
dead), MOCK_NO_CONV=1 (nothing converges, ever), MOCK_ROOT=1 (cpuN/online writable),
MOCK_NO_HIT=1 (the binder channel never reclaims the slot), MOCK_WRONG=1 (a write lands but
as the wrong value -- getenforce moves, so step 2b's no-op sanity is the thing that catches it).

usage: PATH=$PWD/tools/mock:$PATH bash tools/run_sugate.sh mockdev
       (tools/mock/adb is a thin shim onto this file)
"""
import json
import os
import re
import sys

STATE = os.environ.get("MOCK_ADB_STATE", "/tmp/mock_adb_state.json")
M64 = (1 << 64) - 1
VA_BITS = 39
VA_START = (0xFFFFFFFFFFFFFFFF << VA_BITS) & M64
PAGE_OFFSET = (0xFFFFFFFFFFFFFFFF << (VA_BITS - 1)) & M64
GB = 1 << 30
PHYS = 0x40000000        # memstart, measured on device 2026-10-14 via /proc/iomem (System RAM 0x40000000-)
TEXT0 = 0xFFFFFFC000200000
# Two kernels, two address sets.  Every value here is one tools/pgdalias.py asserts on its own
# (image + kallsyms + /proc/iomem), so a mock disagreeing with the driver fails loudly instead of
# quietly letting an unwitnessed write through -- on 7 the witness is a STRING, and a mock that
# only models getenforce could never see it move.
PROFILES = {
    "6.0.1": dict(text1=0xFFFFFFC001400000, data0=0xFFFFFFC00161E000, end=0xFFFFFFC001B43000,
                  pgd0=0xFFFFFFC001B41000, gate=0xFFFFFFC0003326B4, island=0xFFFFFFC000339DB8,
                  kind="enforce", witness=0xFFFFFFC00189BE74,
                  gate_orig=0x54000121, gate_patch=0x14000009),
    "7": dict(text1=0xFFFFFFC001800000, data0=0xFFFFFFC001A31000, end=0xFFFFFFC001F4E000,
              pgd0=0xFFFFFFC001F4C000, gate=0xFFFFFFC000323400, island=0xFFFFFFC000342C88,
              kind="modprobe", witness=0xFFFFFFC001A499B8,
              # The LIVE site on 7 (ledger 664): the `tbnz w0,#0x1f` that consumes G@0x342b68's
              # verdict in do_execveat_common.  Patching it to a NOP makes the `mov w19,#-1`
              # (EPERM) producer unreachable.  Retired: 0x33f460 (§650) and 0x3416cc (§654).
              gate_orig=0x37F823A0, gate_patch=0xD503201F),
}
MP = PROFILES[os.environ.get("MOCK_PROFILE", "6.0.1")]
TEXT1, BSS0, BSS1 = MP["text1"], MP["data0"], MP["end"]
PGD0 = MP["pgd0"]
SWAP_NEXT = PGD0 + 0x1000                      # head.S's static pmd page (§173's candidate)
GATE_VA = MP["gate"]
SELINUX_ENF = MP["witness"]           # 6.0.1: the .bss enforce word; 7: the modprobe_path buffer
ISLAND_VA = MP["island"]
WITNESS_KIND = MP["kind"]
MOD_DEFAULT = "/sbin/modprobe"        # what the device reads today (measured 2026-10-20, uid 2000)
WRI, FAULT = 69644, 69632
GATE_ORIG, GATE_PATCH = MP["gate_orig"], MP["gate_patch"]


def st():
    try:
        with open(STATE) as fh:
            return json.load(fh)
    except Exception:
        return {"slots": {}, "gates": {}, "island": False, "flip": False, "patch": None,
                "wb": False, "conv": {}}


def save(s):
    with open(STATE, "w") as fh:
        json.dump(s, fh)


def in_range(v, lo, hi):
    return lo <= v < hi


def resolve(va, s):
    """which image VA does this address stand for, given the alias windows currently open?"""
    for base, pa_block in s["slots"].items():
        base, pa_block = int(base), int(pa_block)
        if base <= va < base + GB:
            return pa_block + (va - base) - PHYS + PAGE_OFFSET
    return va


def writable(va, s):
    # Reached through one of our own 1 GB windows => whatever the underlying page class is, the
    # window covers real RAM and writes.  This is what makes MOCK_FORCESLOT_PA (window opens on
    # the wrong physical page -- today's device bug) report "wrote but nothing changed" instead
    # of "the write missed".
    if os.environ.get("MOCK_NO_ALIAS") != "1":
        for base in s["slots"]:
            if int(base) <= va < int(base) + GB:
                return True
    real = resolve(va, s)
    if in_range(real, BSS0, BSS1):
        return True                      # measured writable (.bss/.data)
    if in_range(real, TEXT0, TEXT1):
        # .text is writable only through an open alias window, or after the §173 flip
        if os.environ.get("MOCK_NO_ALIAS") == "1":
            return bool(s["flip"])             # negative control: alias never works
        return bool(s["slots"]) or s["flip"]
    return False


def legal_block(d, level_shift):
    """the same field checks pgdalias.py applies -- a malformed entry opens nothing"""
    return (d & 3) == 1 and (d >> 10) & 1 and not ((d >> 12) & ((1 << (level_shift - 12)) - 1))


def write_string(s, data):
    """Land `data` at the head of the modprobe_path buffer, which is a fixed-size ARRAY: what the
    kernel prints afterwards is the bytes up to the FIRST NUL, so writing "/zz\0" hides the tail
    without erasing it -- restoring the first four bytes brings the whole path back.  Truncating
    the stored tail here would invent a device bug and make the driver's restore check refuse a
    window that is actually fine (which is exactly what it did the first time this arm ran)."""
    buf = bytearray(s.get("modbuf") or (MOD_DEFAULT + "\0" * 64).encode())
    buf[0:len(data)] = data[:len(buf)]
    s["modbuf"] = list(buf)
    s["mod"] = bytes(buf).split(b"\0", 1)[0].decode("ascii", "replace")


def do_clobber(args, s):
    if "kern" not in args:
        return 0
    if os.environ.get("MOCK_NO_HIT") == "1":
        print("no hit")                       # the batch never reclaimed the slot
        return 0
    ki = args.index("kern")
    va = int(args[ki + 1], 16)
    pay = args[ki + 2] if ki + 2 < len(args) else ""
    hexs = pay[4:] if pay.startswith("hex:") else ""
    nbytes = max(1, len(hexs) // 2)
    expected = 4047 + 65537 + 48 + 8 + nbytes   # padding + zeros + chunk + marker + payload
    if not writable(va, s):
        # a fault at the first payload byte stops the copy: payload and marker are missing,
        # so the shortfall is (nbytes + 8) -- 69632 for every payload length (measured §159)
        print("readv = %d (expected %d) errno=14" % (expected - (nbytes + 8), expected))
        print("RESULT: no hit")
        return 0
    # clobber's `hex:` payload is in memory order, so read it little-endian
    word = int.from_bytes(bytes.fromhex(hexs), "little") if hexs else 0
    real = resolve(va, s)

    if PGD0 <= va < PGD0 + 0x1000 and nbytes == 8 and word:
        slot = (va - PGD0) // 8
        base = VA_START + slot * GB
        if legal_block(word, 30):                # a field-legal 1 GB block descriptor opens a window
            # PA of a block descriptor lives in bits [47:30]; don't drag UXN/PXN along
            pa_block = (word & ((1 << 48) - 1) & ~(GB - 1))
            forced = os.environ.get("MOCK_FORCESLOT_PA")
            if forced:                           # the window opens, but on the WRONG page
                pa_block = int(forced, 16) & ~(GB - 1)   # (today's device bug: PA base 0x80000000)
            if os.environ.get("MOCK_NO_ALIAS") != "1":
                # negative control: this device simply refuses the alias, so nothing opens
                s["slots"][str(base)] = str(pa_block)
    if WITNESS_KIND == "modprobe":
        if real == SELINUX_ENF and hexs:
            write_string(s, bytes.fromhex(hexs))   # a string buffer: bytes land, NUL ends it
    elif real == SELINUX_ENF and nbytes == 4:
        s["enf"] = "Enforcing" if word else "Permissive"   # data writes are coherent: no cache fiction
    if SWAP_NEXT <= va < SWAP_NEXT + 0x1000 and nbytes == 8 and legal_block(word, 21):
        s["flip"] = True                         # the §173 pmd-flip fallback
    if nbytes == 4 and word == GATE_PATCH and real == GATE_VA:
        s["patch"] = GATE_PATCH
    if nbytes == 4 and word == GATE_ORIG and real == GATE_VA:
        s["patch"] = None
    if nbytes == 4 and word == 0 and abs(real - ISLAND_VA) < 0x60:
        s["island"] = True                     # the harmless proof-write landed
    if va == SELINUX_ENF and os.environ.get("MOCK_WRONG") == "1":
        # the no-op payload landed as something else -- step 2b exists precisely to catch this,
        # so it must be observable through BOTH witness shapes
        if WITNESS_KIND == "modprobe":
            write_string(s, b"/zz")
        else:
            s["enf"] = "Permissive"
    print("readv = %d (expected %d) errno=%d" % (expected, expected, 0))
    print("RESULT: PRIMITIVE WORKS")
    save(s)
    return 0


def do_elflush(rest, s, cpu):
    """EL0 line flush, modelled three ways, because the driver has to survive all three:
       MOCK_NO_ELFUSH -- dc cvau/ic ivau take SIGILL at EL0 (SCTLR_EL1.UCI=0);
       MOCK_EL0_NOPRIV -- the ops execute (selftest still says ALLOWED, which is the whole
           trap) but are ignored for TTBR1/kernel lines, so the patched line never
           converges and the run must escalate instead of declaring victory;
       default -- the named line converges on the CPU that issued the flush."""
    trapped = os.environ.get("MOCK_NO_ELFUSH") == "1" or os.environ.get("MOCK_NO_CONV") == "1"
    if "selftest" in rest:
        print("  none       stale=2000/2000 first_new=-1 warm_ok=20000/20000 -> L1I still holds the old line")
        print("  flush (both) stale=%s/2000" % ("2000" if trapped else "0"))
        print("  ops at EL0: %s" % ("TRAPPED -- user space cannot flush a kernel line here"
                                    if trapped else "ALLOWED (no signal on dc cvau / ic ivau)"))
        print("  ruler has teeth: YES (unflushed phase kept 2000/2000 calls on the old instruction)")
        print("  flush changes behaviour: %s" % ("NO -- the ops ran but stale lines survived" if trapped
                                                 else "YES (ic ivau made the new bytes visible)"))
        return 0
    if "probe" in rest:
        # capability check against a pristine kernel line: it reports, it converges nothing
        print("  probe dc cvau+ic ivau 0xffffffc0003326b4 -> %s" % ("TRAPPED" if trapped else "ALLOWED"))
        print("VERDICT: %s" % ("EL0 ops TRAPPED -> use icache_sync + cpu hotplug for convergence"
                               if trapped else "EL0 ops ALLOWED and no fault on those VAs"))
        return 1 if trapped else 0
    if trapped:
        print("VERDICT: EL0 ops TRAPPED -> use icache_sync + cpu hotplug for convergence")
        return 1
    print("VERDICT: EL0 ops ALLOWED and no fault on those VAs")
    if os.environ.get("MOCK_EL0_NOPRIV") != "1":
        s["wb"] = True                    # dc cvau wrote the dirty line back to L2
        s["conv"][str(cpu)] = True         # ic ivau threw out this core's stale line
        save(s)
    return 0


def do_probe(s, cpu):
    allow = (s["patch"] == GATE_PATCH and s.get("wb") and s.get("conv", {}).get(str(cpu)))
    if not allow and s["patch"] == GATE_PATCH:
        # say so out loud: "the write landed but this CPU still executes old bytes" is a
        # different failure from "the write never landed", and the driver's last message
        # leans on that distinction
        print("# mock: word at gate PA = patch, but wb=%s conv=%s cpu%s -> stale caches" %
              (s.get("wb"), sorted(s.get("conv", {})), cpu))
    yield "CASE control_sux                    -> RAN"
    yield "CASE control_su                     -> " + ("RAN" if allow else "errno=1(Operation not permitted)")


SHELL = {
    "id -u": "2000",
    "getenforce": "Enforcing",
    "cat /sys/devices/system/cpu/present": "0-7",
}


def main():
    argv = sys.argv[1:]
    if len(argv) >= 2 and argv[0] == "-s":
        argv = argv[2:]                        # run_sugate.sh calls: adb -s <serial> shell ...
    s = st()
    if not argv or argv[0] == "get-state":
        print("device")
        return 0
    if argv[0] == "push":
        return 0
    if argv[0] != "shell":
        return 0
    cmd = " ".join(argv[1:])
    mcpu = re.search(r"taskset -c (\d+)", cmd) or re.search(r"sugate_probe (\d+)", cmd)
    cpu = mcpu.group(1) if mcpu else "0"
    if "/online" in cmd:
        if "echo $?" in cmd:                    # the driver's "may I hotplug at all" probe
            print("0" if os.environ.get("MOCK_ROOT") == "1" else "1")
            return 0
        if os.environ.get("MOCK_ROOT") == "1" and os.environ.get("MOCK_NO_CONV") != "1":
            m = re.search(r"cpu(\d+)/online", cmd)
            if m and "echo 1 >" in cmd:
                s["conv"][m.group(1)] = True     # the up path runs ic iallu (cpu0 never)
                save(s)
        return 0
    if "/proc/sys/kernel/modprobe" in cmd:
        # stateful, exactly like getenforce: on 7 this string IS the witness, so a write that
        # does not land must leave it unchanged and a write that lands must show up here
        print(s.get("mod", MOD_DEFAULT))
        return 0
    for pat, out in SHELL.items():
        if pat in cmd:
            # getenforce is stateful: the driver's no-op sanity write must not flip it, and
            # MOCK_WRONG models exactly the case where the payload landed as something else
            print(s.get("enf", "Enforcing") if pat == "getenforce" else out)
            return 0
    if "icache_sync" in cmd:
        c = re.search(r"icache_sync (\S+)", cmd).group(1)
        if os.environ.get("MOCK_NO_SWEEP") == "1" or os.environ.get("MOCK_NO_CONV") == "1":
            print("  exec control: EXEC CONTROL FAIL (mmap(PROT_EXEC) refused)")
            print("ICACHE_SYNC cpu=%s ran_on=%s d_bytes=8388608 i_lines=0" % (c, cpu))
            if os.environ.get("MOCK_NO_SWEEP") == "1":
                s["wb"] = True                   # the D-side sweep still ran
                save(s)
            return 0
        if c != "-1":                            # -1 is the pre-flight self test only
            s["wb"] = True
            s["conv"][c] = True
            save(s)
        print("  exec control: ok (page0 probe returned 90), swept 98304 lines")
        print("ICACHE_SYNC cpu=%s ran_on=%s d_bytes=8388608 i_lines=98304 us=439759" % (c, cpu))
        return 0
    if "elflush" in cmd:
        return do_elflush(cmd[cmd.index("elflush") + 7:], s, cpu)
    m = re.search(r"clobber\b(.*)", cmd)
    if m:
        return do_clobber(m.group(1).split(), s)
    if "sugate_probe" in cmd:
        pinned = re.search(r"sugate_probe (\d+)", cmd)
        if pinned and os.environ.get("MOCK_NO_OUT") == "1":
            return 0      # the real 2026-10-14 failure: a pinned call that printed nothing
        if pinned:
            print("PIN cpu=%s ran_on=%s" % (pinned.group(1), pinned.group(1)))
        for line in do_probe(s, cpu):
            print(line)
        return 0
    print("")
    return 0


if __name__ == "__main__":
    sys.exit(main())
