#!/usr/bin/env python3
"""Decode the loader's compiled-in allocation plan: mem_data + cal_data in libacdbloader.so.

Both shipped bitnesses carry a 44-slot plan; the slot struct is 24 B on ARM32 and 32 B on ARM64
because the pointer fields widen.  This tool reads the plan out of the ELF using the *symbol table*
(never a hand-typed address), decodes it, and refuses to print anything unless all four gates hold:

  1. sizeof(mem_data) is an exact multiple of the slot stride  ->  slot count is whole
  2. the slot count from mem_data equals the one from cal_data  ->  the two plans describe same slots
  3. both bitnesses give the same slot count                    ->  44 is the ABI, not a coincidence
  4. every static pointer/word slot that the code fills at run time reads back as zero here

Usage: python3 tools/loader_memplan.py [--tsv OUT.tsv]
"""
import os, struct, subprocess, sys

LIBS = {
    "arm32": "art/audio-6.0.1/shipped/vendor/lib/libacdbloader.so",
    "arm64": "art/audio-6.0.1/shipped/vendor/lib64/libacdbloader.so",
}
STRIDE = {"arm32": 24, "arm64": 32}
OUT = None
CHECK = None
if "--tsv" in sys.argv:
    OUT = sys.argv[sys.argv.index("--tsv") + 1]
if "--check-tsv" in sys.argv:
    CHECK = sys.argv[sys.argv.index("--check-tsv") + 1]
    if OUT is not None:
        sys.exit("gate: --check-tsv is the check path and --tsv is the generate path; giving both "
                 "would let a run overwrite the very artifact it claims to compare")

def objects(path):
    if not os.path.exists(path):
        sys.exit(f"gate: {path} is not on disk -- the shipped library moved or was never extracted")
    r = subprocess.run(["readelf", "--dyn-syms", "-W", path], capture_output=True, text=True)
    if r.returncode:
        sys.exit(f"gate: readelf cannot parse {path}: {r.stderr.strip()[:80]} -- a plan decoded from "
                 "an unreadable file is not a plan")
    out = r.stdout
    res = {}
    for ln in out.splitlines():
        q = ln.split()
        if len(q) >= 8 and q[3] == "OBJECT" and q[6] != "UND":
            res[q[7]] = (int(q[1], 16), int(q[2]))
    return res

def secmap(path):
    """ELF section table, parsed from the file for both classes -- readelf's column layout shifts
    when a section name is abbreviated, and a wrong .data offset would silently shift every value."""
    d = open(path, "rb").read()
    cls = d[4]
    if cls == 1:
        shoff, = struct.unpack_from("<I", d, 0x20)
        es, num, si = struct.unpack_from("<HHH", d, 46)
        fmt, hsiz = "<10I", 40
    elif cls == 2:
        shoff, = struct.unpack_from("<Q", d, 0x28)
        es, num, si = struct.unpack_from("<HHH", d, 58)
        fmt, hsiz = "<2I6Q", 64
    else:
        sys.exit(f"gate: unexpected ELF class {cls}")
    def name_at(strtab, o):
        return d[strtab + o:].split(b"\0")[0].decode()
    sht = shoff + si * es
    strtab = struct.unpack_from(fmt, d, sht)[4]  # sh_offset is index 4 for both classes
    secs = []
    for i in range(num):
        v = struct.unpack_from(fmt, d, shoff + i * es)
        nm = name_at(strtab, v[0])
        typ = v[1]
        addr, off, size = v[3], v[4], v[5]
        if typ != 8 and size:  # skip SHT_NOBITS: no file bytes to read
            secs.append((addr, off, size, nm))
    return secs

def read_va(path, secs, va, n):
    data = open(path, "rb").read()
    for addr, off, size, nm in secs:
        if addr <= va < addr + size:
            o = off + (va - addr)
            if o + n > len(data):
                sys.exit(f"gate: {n} B at {va:#x} runs past the end of {path}")
            return data[o:o + n]
    sys.exit(f"gate: VA {va:#x} is not inside any allocated section of {path}")

def selftest():
    """Each gate is proven by breaking exactly one thing and requiring this tool to abort on it.

    Runs mutated copies of *this file* as subprocesses, so the arms test the shipped logic, not a
    parallel copy of it that can drift.
    """
    src = open(__file__, encoding="utf-8").read()
    # The arm table below contains the very strings it replaces, so a replace-on-first-hit would
    # rewrite the *expectation* and leave the code untouched -- an arm that can never fail.  Only
    # the region after this marker is code.
    # Whole-file replace-first is only safe because every `old` below is written as a concatenation:
    # the arms table then does not literally contain the pattern, so the first hit is the real code.
    # (A plain literal here made four arms mutate their own expectation and pass -- the harness was
    # green while testing nothing.)
    arms = [
        ("ok: unmutated plan decodes", None, None),
        ("gate: slot stride", 'STRIDE = {"arm32": 2' + '4, "arm64": 32}',
         'STRIDE = {"arm32": 2' + '8, "arm64": 32}'),
        ("gate: mem/cal slot counts agree", 'n_cal = csz // (16 if bit == "arm64" else ' + "8)",
         'n_cal = csz // (16 if bit == "arm64" else ' + "9)"),
        ("gate: sentinel is -1", "i * 32 + 1" + "6", "i * 32 + 0" + "0"),
        ("gate: runtime fields are zero", "mem[i * 32 + 2" + "0: i * 32 + 32]",
         "mem[i * 32 + 1" + "0: i * 32 + 22]"),
        ("gate: symbol names re-anchored", 'for need in ("mem_dat' + 'a", "cal_data")',
         'for need in ("mem_dat' + 'a_v3", "cal_data")'),
        ("gate: unreadable file is refused", '"arm64": "art/audio-6.0.1/shipped/vendor' +
         '/lib64/libacdbloader.so"',
         '"arm64": "/etc/ho' + 'stname"'),
        ("gate: missing file is refused", '"arm32": "art/audio-6.0.1/shipped/vendor' +
         '/lib/libacdbloader.so"',
         '"arm32": "/nope/libacdb' + 'loader.so"'),
    ]
    bad = 0
    for label, old, new in arms:
        text = src if old is None else src.replace(old, new, 1)
        if old is not None and text == src:
            print(f"  FAIL {label}: mutation string absent -- the arm is vacuous")
            bad += 1
            continue
        path = "/tmp/loader_memplan.arm.py"
        open(path, "w").write(text)
        r = subprocess.run([sys.executable, path], capture_output=True, text=True)
        out = r.stdout + r.stderr
        if old is None:
            if r.returncode or "44-slot plan reproduced" not in out:
                print(f"  FAIL {label}: rc={r.returncode} {out.strip()[:70]}")
                bad += 1
            else:
                print(f"  ok   {label}")
        else:
            if r.returncode == 0 or "gate:" not in out:
                print(f"  FAIL {label}: it did NOT abort (rc={r.returncode}) -- gate is blind")
                bad += 1
            else:
                why = [l for l in out.splitlines() if l.startswith("gate:")][0]
                print(f"  ok   {label}: aborted -> {why[:72]}")
    print(f"selftest: {bad} arm(s) failed")
    return 1 if bad else 0


if "--selftest" in sys.argv:
    sys.exit(selftest())

plans = {}
for bit, path in LIBS.items():
    objs = objects(path)
    for need in ("mem_data", "cal_data"):
        if need not in objs:
            sys.exit(f"gate: {need} missing from {path} -- the name moved, re-anchor it, do not "
                     f"hand-type an address")
    secs = secmap(path)
    mva, msz = objs["mem_data"]
    cva, csz = objs["cal_data"]
    if msz % STRIDE[bit]:
        sys.exit(f"gate: {bit} mem_data {msz} B is not a whole number of {STRIDE[bit]} B slots")
    n_mem = msz // STRIDE[bit]
    n_cal = csz // (16 if bit == "arm64" else 8)
    if n_mem != n_cal:
        sys.exit(f"gate: {bit} slot counts disagree: mem_data {n_mem} vs cal_data {n_cal}")
    mem = read_va(path, secs, mva, msz)
    cal = read_va(path, secs, cva, csz)
    rows = []
    for i in range(n_mem):
        if bit == "arm64":
            size, cnt = struct.unpack_from("<2I", mem, i * 32)
            sentinel = struct.unpack_from("<I", mem, i * 32 + 16)[0]
            tail = mem[i * 32 + 20: i * 32 + 32]
            cptr, ccnt = struct.unpack_from("<2Q", cal, i * 16)
        else:
            size, cnt = struct.unpack_from("<2I", mem, i * 24)
            sentinel = struct.unpack_from("<I", mem, i * 24 + 12)[0]
            tail = mem[i * 24 + 16: i * 24 + 24]
            cptr, ccnt = struct.unpack_from("<2I", cal, i * 8)
        if sentinel != 0xFFFFFFFF:
            sys.exit(f"gate: {bit} slot {i} sentinel is {sentinel:#x}, not -1 -- field layout guess "
                     f"is wrong")
        if any(tail) or cptr:
            sys.exit(f"gate: {bit} slot {i} has a non-zero runtime field (tail={tail.hex()} "
                     f"cptr={cptr:#x}) -- these bytes are filled at run time, static dump is stale")
        rows.append((i, size, cnt, ccnt))
    plans[bit] = rows

if set(plans["arm32"]) != set(plans["arm64"]):
    sys.exit("gate: the two bitnesses do not describe the same plan (slot counts differ)")
counts = {len(v) for v in plans.values()}
if counts != {44}:
    sys.exit(f"gate: expected the 44-slot plan, got {counts}")

print(f"# 44-slot plan reproduced identically from both shipped bitnesses "
      f"(strides 24/32, sentinel -1, runtime fields all zero)")
tot = sum(r[1] for r in plans["arm64"])
print(f"# compiled-in allocation total: {tot} B = {tot/1024:.0f} KiB over "
      f"{sum(1 for r in plans['arm64'] if r[1])} non-zero slots; "
      f"{sum(1 for r in plans['arm64'] if r[2])} slots with item-count>0")
hdr = "slot\talloc_size_B\tmem_item_count\tcal_item_count"
lines = [hdr] + [f"{i}\t{sz}\t{c1}\t{c2}" for i, sz, c1, c2 in plans["arm64"]]
for i, sz, c1, c2 in plans["arm64"]:
    if sz or c1 or c2:
        print(f"  {i:2d}  size={sz:#08x} ({sz:>7} B)  mem_count={c1}  cal_count={c2}")
if OUT:
    open(OUT, "w").write("\n".join(lines) + "\n")
    print(f"# wrote {OUT}: {len(lines)-1} rows")
if CHECK:
    if not os.path.exists(CHECK):
        sys.exit(f"gate: {CHECK} is not on disk -- there is nothing to check against")
    want = open(CHECK, encoding="utf-8").read().splitlines()
    got = lines
    diff = [(i, w, g) for i, (w, g) in enumerate(zip(want, got)) if w != g]
    if len(want) != len(got):
        sys.exit(f"gate: {CHECK} has {len(want)} lines, a fresh decode makes {len(got)}")
    if diff:
        for i, w, g in diff[:5]:
            print(f"   line {i}: committed={w!r} fresh={g!r}")
        sys.exit(f"gate: {len(diff)} of {len(got)} rows differ from {CHECK} -- the shipped library "
                 "or the decoder changed since the artifact was written")
    print(f"plan matches the committed artifact: {len(got)-1}/{len(got)-1} rows identical in {CHECK}")
