#!/usr/bin/env python3
"""tools/devmem_read.py -- census the live-kernel-RAM surfaces, and read .bss/.data through /dev/mem on
builds that actually serve it (ledger 375).

Why: the last open items in §E are not inference problems but *observation* problems -- the Image's bytes
for a .bss object are all zero, so the runtime values of `integration_params.30051`, `vivo_codec`,
`vivo_hp_imped_fixed`, `hifi_mode_status` and `smart_pa_switch_enable`, and the {count, pairs *} payload
struct §351/§353/§359 left open, cannot come from any offline artifact.

Verdict for 6.0.1 (measured 2026-10-17 -- the reason this reader has never returned a byte): /proc/kcore,
/dev/kmem, /proc/dynamic_debug/control and ftrace kprobe events are all absent, the tracer list is only
`nop`, and a temporary `mknod /dev/mem c 1 1` opens with **ENXIO**.  ENXIO is explained by the source:
fw/caf8996.tgz `drivers/char/mem.c:800` guards the `devlist[1] = {"mem", &mem_fops}` entry with
`#ifdef CONFIG_DEVMEM`, and `memory_open()` returns -ENXIO at line 830 when `dev->fops` is NULL.  Two
independent methods agree: mem.c's DEVMEM-only functions (`read_mem`, `write_mem`, `mmap_mem`,
`open_mem`, `read_kmem`) are absent from the offline kallsyms while its unconditional ones
(`chr_dev_init`, `memory_lseek`, `read_null`, `write_full`, `mem_devnode`) are present -- the file is
built in, the door is compiled out.  RETRACTION of what this replaced: `mem_open`/`mem_read`/`mem_lseek`/
`proc_mem_open` are fs/proc/base.c's /proc/<pid>/mem, not drivers/char/mem.c, and "1 mem" in
/proc/devices is mem.c's shared major, which does not imply minor 1 serves anything.  So on 6.0.1 kernel
RAM is unreachable by every route, and for this build --probe is the deliverable.

What keeps the reader path worth having: 7 is a different kernel build whose config is unknown until
probed, and CONFIG_DEVMEM=y would make those slots directly readable.  The reader is therefore
unexercised on a device -- the pure parts (translation search, RAM-range gate, struct decode) are covered
by --selftest arms against a simulated reader, and every live read is gated twice: the direct map must be
pinned by an equality against fw/Image, and the physical address must fall inside a System RAM range from
/proc/iomem, because a wrong translation landing on a peripheral register can clear it on read.

Usage:
  python3 tools/devmem_read.py --probe                     surfaces + the ENXIO open test
  python3 tools/devmem_read.py --selftest                  offline arms, no device
  python3 tools/devmem_read.py --solve                     find + verify the translation, then stop
  python3 tools/devmem_read.py --sym jiffies --twice
  python3 tools/devmem_read.py --sym integration_params.30051@all --hex 16 --pairs
  python3 tools/devmem_read.py --sym vivo_codec@all --hex 8
"""
import argparse
import os
import re
import struct
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SU = os.environ.get("SU", "su")  # SU=sux on the 7.1.1 firmware (ledger 579: the vendor name gate)
KALL = os.path.join(ROOT, "art", "kallsyms_real.txt")
IMG = os.path.join(ROOT, "fw", "Image")
ADB = os.environ.get("ADB", "adb")
NODE = os.environ.get("NODE", "/dev/mem")
PAGE = 4096


# -------------------------------- device shell --------------------------------
def sh(cmd, binary=False, timeout=25):
    """run one root command.  The wrapper quotes with single quotes, so an inner single quote would
    unterminate the string and the device shell would wait for input forever -- that hang is what this
    guard prevents (measured 2026-10-17: `grep -E '^ +1 +mem *$'` inside su -c never returned)."""
    if "'" in cmd:
        sys.exit(f"gate: refusing to run a command containing a single quote -- the outer `su -c '…'` "
                 f"quoting would break and adb would hang: {cmd!r}.  Use double quotes inside.")
    try:
        p = subprocess.run([ADB, "exec-out", f"{SU} -c '" + cmd + "'"], capture_output=True,
                           timeout=timeout)
    except subprocess.TimeoutExpired:
        sys.exit(f"gate: {cmd!r} did not return in {timeout} s -- a hung root shell must not be waited "
                 "on, and the bytes it would have returned are not quotable")
    if p.returncode != 0:
        if binary:
            return b""
        sys.exit(f"gate: adb failed ({p.returncode}) on {cmd!r} :: "
                 f"{p.stderr.decode('utf-8', 'replace')[:200]}")
    return p.stdout if binary else p.stdout.decode("utf-8", "replace").replace("\r", "")


def ensure_node():
    """create $NODE only if the kernel has major 1 and the node is missing; caller removes it."""
    made = False
    out = sh(f"ls {NODE} 2>&1")
    if out and not re.search("No such file", out):
        return made
    if not re.search(r"^\s*1\s+mem\s*$", sh("cat /proc/devices"), re.M):
        sys.exit("gate: /proc/devices has no `1 mem` entry -- the memory driver is not registered, "
                 "so mknod would create a node nothing serves")
    out = sh(f"mknod {NODE} c 1 1 2>&1; ls -l {NODE} 2>&1")
    if "No such file" in out or "Permission denied" in out or "Operation not permitted" in out:
        sys.exit(f"gate: mknod {NODE} was refused -- {out.strip()[:160]}.  The node would live in tmpfs "
                 "(memory state only) and be removed afterwards, so this is a policy block, not a "
                 "capability gap: say so rather than working around it.  (SELinux is enforcing; "
                 "relaxing it globally is a consent decision, not this tool's to make.)")
    return True


def remove_node(made):
    if made:
        sh(f"rm -f {NODE}; ls -l {NODE} 2>&1 | tail -1")


LAST_ERR = [""]


def take(raw, off, n):
    """slice n bytes out of a block read, or None when the door answered short.  This is separated out
    because the first version's test (`len(raw) <= off`) did NOT fire in reality: su appends a newline,
    so a closed door returned exactly 1 byte, got sliced to 1 byte, and the failure surfaced as a
    translation mismatch instead of as the ENXIO it was."""
    return None if len(raw) - off < n else raw[off:off + n]


def dd_read(pa, n):
    """n bytes at physical `pa` via bs=4096 block skip (toybox dd has no skip_bytes)"""
    blk, off = pa // PAGE, pa % PAGE
    pages = (off + n + PAGE - 1) // PAGE
    p = subprocess.run([ADB, "exec-out", f"{SU} -c 'dd if={NODE} bs={PAGE} skip={blk} count="
                                      f"{pages} 2>&1 >/dev/null'"],
                       capture_output=True, timeout=60)
    LAST_ERR[0] = p.stdout.decode("utf-8", "replace").strip()
    raw = sh(f"dd if={NODE} bs={PAGE} skip={blk} count={pages} 2>/dev/null", binary=True)
    got = take(raw, off, n)
    if got is None:
        sys.exit(f"gate: dd at PA {pa:#x} gave {max(len(raw) - off, 0)} of {n} requested bytes "
                 f"(block offset {off}) -- the door does not answer.  Device said: "
                 f"{LAST_ERR[0][:160]!r}  (run --probe: ENXIO there means CONFIG_DEVMEM is compiled "
                 "out, and no translation can fix a door that is not there)")
    return got



# -------------------------------- pure parts --------------------------------
def parse_iomem(text):
    """System RAM ranges as (start, end) inclusive, physical"""
    return [(int(m.group(1), 16), int(m.group(2), 16))
            for m in re.finditer(r"^([0-9a-f]+)-([0-9a-f]+)\s*:\s*System RAM\s*$", text, re.M)]


def symbols():
    """name -> list of (va, type) from the offline-recovered kallsyms"""
    out = {}
    for line in open(KALL, encoding="utf-8", errors="replace"):
        p = line.split()
        if len(p) == 3:
            out.setdefault(p[2], []).append((int(p[0], 16), p[1]))
    return out


def page_offsets():
    """the VA_BITS family for aarch64: PAGE_OFFSET = -(1 << VA_BITS) as u64"""
    return {b: ((1 << 64) - (1 << b)) & 0xFFFFFFFFFFFFFFFF for b in range(32, 49)}


def in_ranges(pa, n, ranges):
    return any(s <= pa and pa + n - 1 <= e for s, e in ranges)


def solve(ranges, text_va, image, read_fn, width=64):
    """the only (PAGE_OFFSET, memstart) whose PA(_text) is System RAM and matches Image[0:width]"""
    ok = []
    for bits, po in sorted(page_offsets().items()):
        for base, _ in ranges:
            pa = (text_va - po + base) & 0xFFFFFFFFFFFFFFFF
            if not in_ranges(pa, width, ranges):
                continue
            got = read_fn(pa, width)
            if got and got == image[:width]:
                ok.append((bits, po, base, pa))
    return ok


def decode_pairs(data, count, ptr, image_base_va):
    """{u32 count, u8 pairs[][2]} witness: count pairs read from the table the pointer names"""
    rows = []
    for i in range(count):
        rows.append((f"{data[i * 2]:#04x}", f"{data[i * 2 + 1]:#04x}"))
    return rows


def fmt(data):
    return " ".join(f"{b:02x}" for b in data)


# -------------------------------- selftest --------------------------------
def selftest():
    """offline arms: the gates must be able to reject.  No device, no writes."""
    bad = []
    iomem = ("40000000-833fffff : System RAM\n"
             "83401000-857fffff : System RAM\n"
             "91500000-1bcf3bfff : System RAM\n"
             "00624000-006264ff : /soc/ufshc@624000\n")
    r = parse_iomem(iomem)
    if len(r) != 3 or r[0][0] != 0x40000000 or r[2][1] != 0x1BCF3BFFF:
        bad.append(f"parse_iomem gave {r} -- must be the 3 System RAM ranges, device nodes excluded")
    if in_ranges(0x83400000, 16, r):
        bad.append("the hole 83400000-83400fff between two RAM ranges was accepted -- a read there is "
                   "not proven to be RAM, which is the whole point of the gate")

    syms = symbols()
    text_va = min(v for v, _ in syms["_text"])
    image = open(IMG, "rb").read()
    # the simulated device maps the kernel at PA 0x40080000, so a reader must answer Image[pa-PA(_text)]
    # -- exactly what dd on real RAM would return for the text segment
    def fake_read(pa, n):
        k = pa - 0x40080000
        return image[k:k + n] if k >= 0 else b""
    hits = solve(r, text_va, image, fake_read)
    if len(hits) != 1:
        bad.append(f"the translation search returned {len(hits)} candidates from a simulated reader "
                   "that has exactly one correct pair -- the search is not decisive")
    else:
        bits, po, base, pa = hits[0]
        if (po, base, pa) != (0xFFFFFFC000000000, 0x40000000, 0x40080000):
            bad.append(f"solved translation {po:#x}/{base:#x} -> PA(_text) {pa:#x} does not equal the "
                       "value /proc/iomem and the Image layout imply")

    # rejection arm 1: an Image edited at offset 0 must leave the search with nothing to publish
    doctored = bytearray(image)
    doctored[0] ^= 0xFF
    if solve(r, text_va, bytes(doctored), fake_read):
        bad.append("a doctored Image still let the translation search pass -- the positive control is "
                   "not tied to the bytes it claims to compare")
    # rejection arm 2: a reader that returns RAM-shaped zeros everywhere must not pass either
    if solve(r, text_va, image, lambda pa, n: b"\x00" * n):
        bad.append("an all-zero reader passed the _text equality -- .bss-shaped silence would be "
                   "reported as a successful read")
    # rejection arm 3: a vmalloc VA (the payload pointers at runtime) is NOT in the direct map
    if in_ranges((0xffffffc001b242c0 - 0xFFFFFF8000000000 + 0x40000000) & 0xFFFFFFFFFFFFFFFF, 16, r):
        bad.append("the wrong PAGE_OFFSET still produced an in-RAM PA -- the gate accepts a translation "
                   "it cannot have meant")

    rows = decode_pairs(bytes([0x14, 0x24, 0x17, 0x00, 0x19, 0x00]), 3, 0x179d7d0, 0)
    if rows != [("0x14", "0x24"), ("0x17", "0x00"), ("0x19", "0x00")]:
        bad.append(f"--pairs decoded {rows} -- must give the 3 (addr,value) rows §369 printed")
    # the short-read gate, which the first version let walk right past (su appends a newline)
    if take(b"\n", 0, 64) is not None:
        bad.append("a 1-byte answer from a closed door was accepted -- that is exactly the shape that "
                   "turned an ENXIO into a bogus 'translation not pinned' message on 2026-10-17")
    if take(b"\x00" * (PAGE + 1), 0, 64) is None or take(b"x" * 12, 8, 4) is None:
        bad.append("take() rejected a complete read -- a gate that fires on good data rejects everything")
    if take(b"x" * 12, 8, 4) != b"xxxx":
        bad.append(f"take() sliced the wrong window out of the block: {take(b'x' * 12, 8, 4)!r}")
    if take(b"x" * 12, 8, 5) is not None:
        bad.append("take() accepted a read that stops 1 byte short of the request")
    print(f"selftest: {len(bad)} arm(s) failed" + ("" if not bad else " -- " + "; ".join(bad)))
    return 1 if bad else 0


# -------------------------------- live modes --------------------------------
def probe():
    """which live-RAM surfaces exist -- every path checked, and the probe itself proven able to see"""
    rows = []
    for name, path in (("/proc/kcore", "/proc/kcore"), ("/dev/mem", "/dev/mem"),
                       ("/dev/kmem", "/dev/kmem"), ("dynamic_debug", "/proc/dynamic_debug/control"),
                       ("kprobe_events", "/sys/kernel/debug/tracing/kprobe_events"),
                       ("function tracer", "/sys/kernel/debug/tracing/available_tracers")):
        out = sh(f"ls -l {path} 2>&1")
        exists = "No such file" not in out
        detail = ""
        if exists and name == "function tracer":
            detail = sh(f"cat {path}").strip()[:60]
            exists = detail.split() != ["nop"]
        rows.append((name, path, "present" if exists else "ABSENT", detail))
    for line in rows:
        print(f"  {line[0]:<17} {line[1]:<44} {line[2]:<8} {line[3]}")
    # the census has to be proven able to see before its "ABSENT" lines mean anything: two paths that
    # must be there go through the same call, and a blind probe would report all six absent
    control = [(p, "ABSENT" if "No such file" in sh(f"ls -l {p} 2>&1") else "present")
               for p in ("/proc/kallsyms", "/proc/devices")]
    if any(v == "ABSENT" for _, v in control):
        sys.exit(f"gate: the probe's positive control is blind -> {control} -- the ABSENT lines above "
                 "would then report the absence of the shell, not of the instruments")
    print("  positive control (same call, known present): "
          + ", ".join(f"{p}={v}" for p, v in control))
    mem = sh('grep -E "^ +1 +mem *$" /proc/devices')
    print(f"  char major 1 named 'mem' registered: {bool(mem.strip())} -- that is mem.c's shared major "
          "(register_chrdev at chr_dev_init), so it does NOT mean minor 1 serves anything; the open "
          "test below decides")
    # the decisive test: does the node answer, and if not, what does errno say
    made = ensure_node()
    try:
        ranges = parse_iomem(sh("cat /proc/iomem"))
        if not ranges:
            sys.exit("gate: /proc/iomem listed no System RAM range -- the open test must read a page "
                     "proven to be RAM, not a device register")
        pa = ranges[0][0]
        blk = pa // PAGE
        err = sh(f"dd if={NODE} bs={PAGE} skip={blk} count=1 2>&1 1>/dev/null").strip()
        got = sh(f"dd if={NODE} bs={PAGE} skip={blk} count=1 2>/dev/null", binary=True)
        print(f"  open test: dd at PA {pa:#x} (first System RAM page) -> "
              f"{err[:120] if err else 'no error text'}; {len(got)} bytes returned")
        print("  " + ("DOOR OPEN (CONFIG_DEVMEM=y): proceed with --solve / --sym" if len(got) >= 512
                      else "DOOR CLOSED -- that errno is memory_open() finding devlist[1].fops == NULL, "
                           "because the `mem` entry sits inside #ifdef CONFIG_DEVMEM "
                           "(fw/caf8996.tgz drivers/char/mem.c:800, -ENXIO returned at line 830).  "
                           "Kernel RAM is not readable on this build by this route."))
    finally:
        remove_node(made)
        if made:
            print(f"  {NODE} removed again (it was not there before this run)")
    ctl = sh("cat /proc/sys/kernel/kptr_restrict").strip()
    print(f"  kptr_restrict={ctl} -- /proc/kallsyms prints zeros, which is why the symbol table here "
          "is art/kallsyms_real.txt recovered offline from fw/Image")
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--probe", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--solve", action="store_true", help="find and verify the translation, then stop")
    ap.add_argument("--sym", action="append", help="kallsyms name, repeatable; --nth picks among "
                                                   "same-named copies (0-based, address order)")
    ap.add_argument("--va", help="explicit kernel virtual address")
    ap.add_argument("--hex", type=int, default=16, help="bytes to read")
    ap.add_argument("--deref", type=int, default=0, help="read this pointer, then +OFFSET for LEN")
    ap.add_argument("--offset", type=int, default=0)
    ap.add_argument("--twice", action="store_true", help="read twice -- liveness control")
    ap.add_argument("--pairs", action="store_true", help="decode 2-byte (addr,value) rows after count")
    a = ap.parse_args()

    if a.selftest:
        return selftest()
    if a.probe:
        return probe()

    syms = symbols()
    image = open(IMG, "rb").read()
    ranges = parse_iomem(sh("cat /proc/iomem"))
    if not ranges:
        sys.exit("gate: /proc/iomem listed no System RAM range -- with nothing proven to be RAM every "
                 "read would be unrestricted, so the tool stops")
    text_va = min(v for v, _ in syms["_text"])
    made = ensure_node()
    try:
        hits = solve(ranges, text_va, image, dd_read)
        if len(hits) != 1:
            sys.exit(f"gate: {len(hits)} (PAGE_OFFSET, memstart) pairs made the bytes at PA(_text) "
                     "equal Image[0:64] -- the direct map is not pinned down, so any read would be "
                     "at an unproven physical address")
        bits, po, memstart, pa_text = hits[0]
        print(f"  translation: PA = VA - {po:#x} + {memstart:#x}  (VA_BITS={bits}, "
              f"PA(_text)={pa_text:#x} verified against fw/Image[0:64])")
        if a.solve:
            return 0

        def read_va(va, n):
            pa = (va - po + memstart) & 0xFFFFFFFFFFFFFFFF
            if not in_ranges(pa, n, ranges):
                sys.exit(f"gate: VA {va:#x} -> PA {pa:#x} falls outside every System RAM range "
                         f"({', '.join(f'{s:#x}-{e:#x}' for s, e in ranges)}) -- refusing to read "
                         "somewhere that is not proven RAM")
            return dd_read(pa, n)

        if a.va:
            targets = [(int(a.va, 16), a.va, "")]
        else:
            targets = []
            for s in (a.sym or []):
                nm, _, k = s.partition("@")
                if nm not in syms:
                    sys.exit(f"gate: {nm!r} is not in the offline kallsyms -- name the symbol exactly "
                             "as art/kallsyms_real.txt gives it (same-named copies take name@N, or "
                             "name@all to read every one)")
                copies = syms[nm]
                for i in (range(len(copies)) if k in ("", "all") else [int(k)]):
                    targets.append((copies[i][0], f"{nm}[{i}]", copies[i][1]))
        if not targets:
            sys.exit("nothing to read: give --sym or --va (see --probe / --selftest)")

        for va, label, typ in targets:
            data = read_va(va, a.hex)
            kind = ("b/B = .bss/.data -- the Image holds zero here, so only a live read can answer"
                    if typ in "bB" else "d/D = .data" if typ in "dD" else "r/R = .rodata")
            print(f"  {label} = {va:#018x} type {typ!r}  [{kind}]")
            print(f"    live {fmt(data)}")
            if a.twice:
                again = read_va(va, a.hex)
                print(f"    again: {fmt(again)}   "
                      f"{'CHANGED -> live RAM, not a cached image' if again != data else 'identical'}")
            if a.hex % 4 == 0:
                print("    u32s: " + " ".join(f"{v:#x}" for v in struct.unpack(f"<{a.hex // 4}I", data)))
            if a.hex % 8 == 0:
                print("    u64s: " + " ".join(f"{v:#x}" for v in struct.unpack(f"<{a.hex // 8}Q", data)))
            if a.pairs and a.hex >= 12:
                count, ptr = struct.unpack_from("<IQ", data, 0)
                print(f"    payload: count={count} pairs*={ptr:#x}")
                if count and count <= 64:
                    rows = read_va(ptr, count * 2)
                    print("    pairs  : " + " ".join(f"({rows[i * 2]:#04x},{rows[i * 2 + 1]:#04x})"
                                                    for i in range(count)))
                    for tab in ("integration_params_normal", "integration_params_headphone",
                                "integration_params_dsd_normal", "integration_params_dsd_headphone"):
                        for i, (v, _) in enumerate(syms.get(tab, [])):
                            if v == ptr:
                                print(f"    ★the pairs pointer IS {tab} copy {i} at {v:#x}")
                elif count == 0:
                    print("    count==0 -> es9038_one_enable takes its skip branch (§351)")
            if a.deref:
                base = struct.unpack("<Q", read_va(va, 8))[0]
                if base == 0:
                    print(f"    [{va:#x}] -> NULL -- nothing published in this slot right now (§369: "
                          "the enable path fills it only during a stream start)")
                else:
                    sub = read_va(base + a.offset, a.deref)
                    print(f"    [{va:#x}] -> {base:#x} + {a.offset:#x}: {fmt(sub)}")
            txt = re.sub(rb"[^\x20-\x7e]", b".", data).decode()
            if set(txt) - set("."):
                print(f"    text: {txt}")
    finally:
        remove_node(made)
        if made:
            print(f"  {NODE} removed again (it was not there before this run)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
