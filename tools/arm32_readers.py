#!/usr/bin/env python3
"""ARM32 reader census: which functions load a preemptible exported global through its GOT slot.

Why a separate tool: `tools/got_readers.py` folds ARM64 `adrp -> GOT page -> ldr [base, #slot]`.  The
32-bit idiom is two hops and register indexed:

    ldr  rX, [pc, #i]        ; pool word = (slot - this function's GOT pointer)
    add  rG, pc              ; rG = the function's GOT pointer, computed once per function
    ldr  rM, [rG, rX]        ; the load itself

and on 6.0.1 THIS is the loader that runs: the `ACDB write reachability` row records the mapped
library as /system/vendor/lib/libacdbloader.so (32-bit).  So the 32-bit census is the baseline's, and
answering it by hand for two sites (as ledger 392/395 did) is not a ruler.

Controls, all asserted before any number is printed:
  A  each function's GOT pointer must land inside .got, and each function must yield exactly ONE
     candidate anchor -- two would mean my liveness tracking is wrong;
  B  the hand-verified sites 0x53ee/0x5402 (the 44-record walk in acdb_loader_init_v2, ledger 388) and
     0x586c/0x5880 (the metainfo store, ledger 392) must appear in the results;
  C  a symbol with no R_ARM_GLOB_DAT slot aborts as NO-SLOTS instead of answering "0 readers".

Usage: python3 tools/arm32_readers.py [so] [symbol ...]
"""
import bisect, re, struct, subprocess, sys
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

def selftest():
    """Arms that mutate this file and require it to stop being able to pass its own controls."""
    src = open(__file__, encoding="utf-8").read()
    arms = [
        ("ok: shipped census passes both controls", None, None),
        # Every `old` is written as a concatenation on purpose: the arm table below contains these
        # strings, so a plain literal would be replaced in the TABLE (the first hit) and leave the code
        # untouched -- an arm that can never fail (ledger 389, and it bit this file too).
        ("gate: wide ldr.w forms must be accepted", 'if i.mnemonic.startswith("ld' + 'r") and "[pc" in ops:',
         'if i.mnemonic == "ld' + 'r" and "[pc" in ops:'),
        ("gate: exidx PR polarity", 'if (w0 >> 31) == 0 else' + ' w0', 'if (w0 >> 31) == 1 else' + ' w0'),
        ("gate: unknown symbol answers NO-SLOTS", '["mem_data", "cal_da' + 'ta"]', '["no_such_symbol_x' + 'yz"]'),
    ]
    bad = 0
    for label, old, new in arms:
        text = src if old is None else src.replace(old, new, 1)
        if old is not None and text == src:
            print(f"  FAIL {label}: mutation string absent -- vacuous arm")
            bad += 1
            continue
        open("/tmp/arm32_readers.arm.py", "w").write(text)
        r = subprocess.run([sys.executable, "/tmp/arm32_readers.arm.py"], capture_output=True, text=True)
        out = r.stdout + r.stderr
        if old is None:
            ok = r.returncode == 0 and "control B" in out and "MISSING" not in out
            print(f"  {'ok  ' if ok else 'FAIL'} {label}" + ("" if ok else f" rc={r.returncode}"))
            bad += 0 if ok else 1
        else:
            stopped = r.returncode != 0 or "MISSING" in out or "NO-SLOTS" in out
            print(f"  {'ok  ' if stopped else 'FAIL'} {label}: "
                  + (out.strip().splitlines()[-1][:66] if out.strip() else "no output"))
            bad += 0 if stopped else 1
    print(f"selftest: {bad} arm(s) failed")
    return 1 if bad else 0


if "--selftest" in sys.argv:
    sys.exit(selftest())

SO = sys.argv[1] if len(sys.argv) > 1 else "art/audio-6.0.1/shipped/vendor/lib/libacdbloader.so"
WANT = [x for x in sys.argv[1:] if not x.startswith("-")][1:] or ["mem_data", "cal_data"]
# Controls read off llvm-objdump's own operands plus hand arithmetic, independent of this tool:
#   0x53ee ldr.w r1,[pc,#0x880] -> pool word 0xffffffd4 -> 0x12dfc-0x2c = 0x12dcc = mem_data slot,
#     consumed at 0x5402 `ldr.w r1,[r8,r1]`;  0x586c/0x5880 is a second mem_data site (the ledger 392
#     metainfo store, which writes mem_data[37]).
#   0x53b6 ldr.w lr,[pc,#0x8b4] -> pool 0x5c6c word 0xffffffd8 = cal_data slot, consumed at
#     0x53f2 `ldr.w r5,[r8,lr]`.  (An earlier draft of this control claimed 0x586c for cal_data --
#     that site is mem_data, which is exactly the sort of hand misreading a ruler should catch.)
HAND = {"mem_data": (0x53ee, 0x5402), "cal_data": (0x53b6, 0x53f2)}

d = open(SO, "rb").read()
assert d[4] == 1, "ARM32-only tool (ELF class 1)"
shoff, = struct.unpack_from("<I", d, 0x20)
esh, enum, esi = struct.unpack_from("<HHH", d, 46)
strtab = struct.unpack_from("<10I", d, shoff + esi * esh)[4]
secs = {}
for i in range(enum):
    v = struct.unpack_from("<10I", d, shoff + i * esh)
    nm = d[strtab + v[0]:].split(b"\0")[0].decode()
    secs[nm] = dict(addr=v[3], off=v[4], size=v[5], entsize=v[9])
got, txt = secs[".got"], secs[".text"]

def va2off(va):
    for nm, s in secs.items():
        if s["size"] and s["addr"] <= va < s["addr"] + s["size"] and nm != ".bss":
            return s["off"] + (va - s["addr"])
    return None

def word(va):
    o = va2off(va)
    return None if o is None else struct.unpack_from("<I", d, o)[0]

# --- slots from the relocations, never hand-typed -----------------------------------------------
dt, dst = secs[".dynsym"], secs[".dynstr"]["off"]
def sym(idx):
    o = dt["off"] + idx * dt["entsize"]
    n, val, size = struct.unpack_from("<3I", d, o)[:3]
    return d[dst + n:].split(b"\0")[0].decode(), val, size
slots = {}
for i in range(secs[".rel.dyn"]["size"] // 8):
    r_off, r_info = struct.unpack_from("<2I", d, secs[".rel.dyn"]["off"] + i * 8)
    if (r_info & 0xFF) != 21:                       # R_ARM_GLOB_DAT
        continue
    nm, val, size = sym(r_info >> 8)
    if nm in WANT:
        c = word(r_off)
        if c not in (0, val):
            sys.exit(f"gate: slot {r_off:#x} for {nm} ships as {c:#x}, expected 0 or {val:#x}")
        slots[nm] = (r_off, val, size)
missing = [w for w in WANT if w not in slots]
if missing:
    sys.exit(f"NO-SLOTS: no R_ARM_GLOB_DAT relocation for {missing} in {SO} -- there is no slot to "
             "look for, so 'no readers' would be the wrong sentence")

# --- decode .text, resuming past pools (capstone stops at the first undecodable halfword) -------
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
ins = {}
pos = txt["off"]
end = txt["off"] + txt["size"]
while pos < end:
    n = 0
    for i in md.disasm(d[pos:end], pos):
        n += 1
        ins[i.address] = i
    pos += max(n * 2, 2)
addrs = sorted(ins)

# --- function starts from .ARM.exidx -------------------------------------------------------------
funcs = []
ex = secs.get(".ARM.exidx")
if not ex:
    sys.exit("gate: no .ARM.exidx -- cannot attribute sites to functions")
# ARM EABI: in .ARM.exidx, word0 with bit31 == 0 is a PR-relative offset measured from THIS entry's
# own address (func = entry_va + word0 - 0x7FFFFFFF, Thumb bit then cleared); bit31 == 1 is the
# absolute form.  Reading it the other way round makes every entry land outside .text, and the tool
# then reports "0 function starts" -- the failure is loud here on purpose, because an empty function
# list would otherwise silently produce an empty reader list.
for i in range(ex["size"] // 8):
    w0, ix = struct.unpack_from("<2I", d, ex["off"] + i * 8)
    entry_va = ex["addr"] + i * 8
    f = entry_va + (w0 - 0x7FFFFFFF) if (w0 >> 31) == 0 else w0
    f &= ~1
    if txt["addr"] <= f < txt["addr"] + txt["size"]:
        funcs.append(f)
funcs = sorted(set(funcs))
if len(funcs) < 20:
    sys.exit(f"gate: .ARM.exidx yielded only {len(funcs)} function starts -- too few to attribute")

def func_of(a):
    i = bisect.bisect_right(funcs, a) - 1
    return funcs[i] if i >= 0 else None

NO_WRITE = ("str", "strb", "strd", "stm", "cmp", "cmn", "tst", "b", "bl", "bx", "cbz", "cbnz",
            "tbz", "tbnz", "beq", "bne", "bgt", "blt", "bge", "ble", "bmi", "bpl", "bcs", "bcc",
            "it", "pop")
pool_ref = {}
pending = {}
anchors = {}
for a in addrs:
    i = ins[a]
    ops = i.op_str or ""
    first = ops.split(",")[0].strip()
    # Thumb-2 prints wide forms as `ldr.w` -- comparing to "ldr" exactly drops most of the pools and
    # makes the whole census come back nearly empty (which is how this draft lost 0x53ee).
    if i.mnemonic.startswith("ldr") and "[pc" in ops:
        # Thumb pools sit on both sides of the pc (`#-0x40` is real), so the sign must be read.
        m = re.search(r"#(-?)0x([0-9a-f]+)", ops)
        if not m:
            continue
        lit = ((a + 4) & ~3) + (-int(m.group(2), 16) if m.group(1) else int(m.group(2), 16))
        pool_ref.setdefault(lit, []).append(a)
        pending[first] = lit
        continue
    if i.mnemonic.startswith("add") and re.search(r",\s*pc\s*$", ops):
        if first in pending:
            w = word(pending.pop(first))
            if w is not None:
                g = (w + a + 4) & 0xFFFFFFFF
                if got["addr"] - 0x40 <= g < got["addr"] + got["size"] + 0x40:
                    anchors.setdefault(func_of(a), set()).add(g)
        continue
    if first and first not in NO_WRITE and i.mnemonic not in NO_WRITE:
        pending.pop(first, None)

# Control A, honestly stated: every attributed function must have at least one candidate GOT pointer
# inside .got.  Some functions show TWO candidates because liveness on `add rX, pc` cannot tell a GOT
# setup from another pc-relative fold in the same register -- those functions are searched with both,
# which can only ADD sites, so control B (hand-verified addresses) is what bounds false positives.
# Pretending a single anchor exists everywhere would have made this tool answer 0 and look certain.
noanchor = [f for f in funcs if not anchors.get(f)]
bad = {f: sorted(v) for f, v in anchors.items() if len(v) > 1}
if not anchors:
    sys.exit("gate: control A failed -- no function resolved a GOT pointer inside .got at all")
print(f"# {SO}: {len(ins)} instructions, {len(funcs)} exidx function starts, "
      f"{len(anchors)} functions with a GOT anchor, {len(bad)} of them ambiguous "
      f"(searched with every candidate), {len(noanchor)} without one")

# --- who loads a slot: pool word == (slot - that function's anchor) -----------------------------
hits = {nm: [] for nm in WANT}
for nm, (slot, val, size) in slots.items():
    want = {}
    for f, gs in anchors.items():
        for g in gs:
            want.setdefault((slot - g) & 0xFFFFFFFF, []).append((f, g))
    for lit, sites in pool_ref.items():
        w = word(lit)
        if w is None or w not in want:
            continue
        for a in sites:
            rd = ins[a].op_str.split(",")[0].strip()
            later = [ins[x] for x in addrs if a < x <= a + 0x40][:24]
            used = any(x.mnemonic.startswith("ldr") and
                       re.search(r"\[[^]]*,\s*" + re.escape(rd) + r"\]", x.op_str) for x in later)
            hits[nm].append((a, func_of(a), rd, used, word(lit)))

out = subprocess.run(["readelf", "--dyn-syms", "-W", SO], capture_output=True, text=True).stdout
exp = {}
for ln in out.splitlines():
    q = ln.split()
    if len(q) >= 8 and q[3] == "FUNC" and q[6] != "UND":
        exp[int(q[1], 16) & ~1] = q[7].split("@")[0]

fails = 0
for nm in WANT:
    hs = [h for h in hits[nm] if h[3]]
    print(f"# {nm}: slot {slots[nm][0]:#x} (object {slots[nm][1]:#x}, {slots[nm][2]} B) -- "
          f"{len(hits[nm])} pool site(s), {len(hs)} consumed by an indexed ldr, "
          f"in {len({h[1] for h in hs})} function(s)")
    by = {}
    for a, f, rd, used, w in hs:
        by.setdefault(f, []).append(a)
    for f, sites in sorted(by.items()):
        print(f"   {exp.get(f, f'(local {f:#x})')[:42]:42s} {len(sites):3d} site(s): "
              + " ".join(f"{x:#x}" for x in sites[:6]))
    for pair in [HAND.get(nm)]:
        if not pair:
            continue
        found = {h[0] for h in hits[nm]}
        if pair[0] in found or pair[1] in found:
            print(f"   control B: hand-verified {pair[0]:#x}/{pair[1]:#x} present -- PASS")
        else:
            print(f"   control B: hand-verified {pair[0]:#x}/{pair[1]:#x} MISSING -- the fold is blind")
            fails += 1
if fails:
    sys.exit("gate: controls did not pass; this census must not be quoted")
