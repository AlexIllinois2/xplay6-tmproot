#!/usr/bin/env python3
"""Which functions read a preemptible exported data symbol, found through its GOT slot.

`tools/loader_memplan.py`'s companion: the plan is only worth comparing if something reads it.  The
first attempt at that question folded `adrp -> object page -> [base, #imm]` and printed "0 references"
for mem_data in the ARM64 loader -- confidently wrong, because a preemptible EXPORTED global is read
as `adrp xN, <GOT page>; ldr xM, [xN, #slot]` and the slot's identity comes from `.rela.dyn`, not from
the object page.  This tool therefore takes its targets from `readelf -r` first and only then matches
the instruction pair, and it refuses to answer "0 readers" when it has no slots to look for.

The earlier scan folded `adrp -> object page -> [base, #imm]` and concluded "0 references".  That was
wrong by construction: these two globals are preemptible EXPORTED data, so every reader goes through
a GOT slot -- `adrp xN, <GOT page>; ldr xM, [xN, #slot]` -- and the slot addend, not the object page,
is what names them.  This script derives the slots from `readelf -r` instead of guessing, then matches
the local adrp/ldr pair and reports the enclosing exported function.

Coverage is reported as slots-found / sites-matched so a 0 here is distinguishable from a blind scan.
"""
import re, struct, subprocess, sys
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

SO = sys.argv[1] if len(sys.argv) > 1 else "art/audio-6.0.1/shipped/vendor/lib64/libacdbloader.so"
WANT = [x for x in sys.argv[1:] if not x.startswith("--")] or ["mem_data", "cal_data"]



def _selftest():
    """The arm that matters: the ARM64 loader MUST show readers of mem_data, because a previous
    version of this question answered 0 and was wrong.  Also requires the scan to say NO-SLOTS rather
    than 0 readers when the symbol is not preemptible data."""
    import subprocess
    bad = 0
    so = "art/audio-6.0.1/shipped/vendor/lib64/libacdbloader.so"
    r = subprocess.run([sys.executable, __file__, so, "mem_data"], capture_output=True, text=True)
    out = r.stdout + r.stderr
    if "readers of mem_data: 0 site" in out or r.returncode:
        print(f"  FAIL known-reader arm: {out.strip().splitlines()[-1:]!r}")
        bad += 1
    else:
        n = [l for l in out.splitlines() if "readers of mem_data" in l][0]
        print(f"  ok   {so} -> {n.split('# ')[-1]}  (the case the page-fold scan missed)")
    r = subprocess.run([sys.executable, __file__, so, "no_such_symbol_xyz"],
                       capture_output=True, text=True)
    out = r.stdout + r.stderr
    if "NO-SLOTS" not in out:
        print(f"  FAIL no-slot refusal: rc={r.returncode} {out.strip()[:70]}")
        bad += 1
    else:
        print("  ok   an unknown symbol is refused as NO-SLOTS instead of answering '0 readers'")
    print(f"selftest: {bad} arm(s) failed")
    return 1 if bad else 0


if "--selftest" in sys.argv:
    sys.exit(_selftest())

d = open(SO, "rb").read()
cls = d[4]
assert cls == 2, "this scanner is ARM64-only (the ARM32 form is ldr rN,[pc,#imm]; add rN,pc)"
shoff, = struct.unpack_from("<Q", d, 0x28)
es, num, si = struct.unpack_from("<HHH", d, 58)
st = struct.unpack_from("<2I4Q2I2Q", d, shoff + si * es)[4]
secs = {}
for i in range(num):
    v = struct.unpack_from("<2I4Q2I2Q", d, shoff + i * es)
    secs[d[st + v[0]:].split(b"\0")[0].decode()] = (v[3], v[4], v[5])

# --- GOT slot -> symbol, straight from the relocations ------------------------------------------
symtab_off, strtab_off = None, None
for i in range(num):
    v = struct.unpack_from("<2I4Q2I2Q", d, shoff + i * es)
    nm = d[st + v[0]:].split(b"\0")[0].decode()
    if nm == ".dynsym":
        symtab_off, syment = v[4], v[9]  # sh_entsize is field 9 (link is 6)
    if nm == ".dynstr":
        strtab_off = v[4]
rela = secs[".rela.dyn"]
slots = {}
for i in range(rela[2] // 24):
    off, info, addend = struct.unpack_from("<2Qq", d, rela[1] + i * 24)
    sidx = info >> 32
    name = d[strtab_off + struct.unpack_from("<I", d, symtab_off + sidx * syment)[0]:].split(b"\0")[0].decode()
    if name in WANT:
        slots[off] = (name, addend)
print(f"# {SO}")
print(f"# GOT slots for {WANT}: " + ", ".join(f"{n}@{o:#x}(addend {a:#x})" for o, (n, a) in slots.items()))
if not slots:
    sys.exit("NO-SLOTS gate: no relocations name those symbols -- either they are not preemptible data here or "
             "the symbol list changed; do not report '0 readers' from a scan with no slots to look for")

# --- exported functions for attribution ---------------------------------------------------------
out = subprocess.run(["readelf", "--dyn-syms", "-W", SO], capture_output=True, text=True).stdout
funcs = []
for ln in out.splitlines():
    q = ln.split()
    if len(q) >= 8 and q[3] == "FUNC" and q[6] != "UND":
        funcs.append((int(q[1], 16), int(q[2]) or 4, q[7].split("@")[0]))
funcs.sort()

def owner(a):
    for s, sz, n in funcs:
        if s <= a < s + sz:
            return n
    return "(local/unnamed)"

TEXT = secs[".text"]
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
window = []          # last few (addr, mnemonic, op_str)
hits = {}
decoded = 0
pos = 0
while pos < TEXT[2]:
    n = 0
    for ins in md.disasm(d[TEXT[1] + pos:TEXT[1] + TEXT[2]], TEXT[0] + pos):
        n += 1
        decoded += 1
        window.append((ins.address, ins.mnemonic, ins.op_str))
        if len(window) > 14:
            window.pop(0)
        if ins.mnemonic.startswith("ldr"):
            m = re.search(r"\[([xw]\d+), #0x([0-9a-f]+)\]", ins.op_str)
            if not m:
                continue
            base, imm = m.group(1), int(m.group(2), 16)
            slot = TEXT[0] + 0  # placeholder to keep the shape obvious
            va = None
            for a, mn, o in reversed(window[:-1]):
                # window holds (addr, mnemonic, op_str); the mnemonic is NOT part of op_str -- matching
                # "adrp x14, #0x24000" against op_str alone can never fire, which is how this scan
                # first reported 0 readers for a pattern visible in the raw dump.
                if mn == "adrp" and o.startswith(base + ","):
                    mm = re.search(r"#0x([0-9a-f]+)", o)
                    if mm:
                        va = int(mm.group(1), 16) + imm
                        break
            if va is None:
                continue
            for off, (name, addend) in slots.items():
                if va == off:
                    hits.setdefault(name, []).append((ins.address, owner(ins.address)))
    pos += n * 4 if n else 4

for name in WANT:
    hs = hits.get(name, [])
    print(f"# readers of {name}: {len(hs)} site(s)")
    by = {}
    for a, fn in hs:
        by.setdefault(fn, []).append(a)
    for fn, addrs in sorted(by.items()):
        print(f"   {fn:38s} {len(addrs)} site(s): " + " ".join(f"{a:#x}" for a in addrs[:6]))
print(f"# {decoded} instructions decoded across .text (a count of 0 would mean the scan never ran)")
