#!/usr/bin/env python3
"""tools/kssym_blr.py -- which struct offsets are called through, and from where.

The vivo codec layer hands codecs a function-pointer table (vivo_codec_fun -> an ops struct; see
ledger 287/288): es9038 stores its enable at ops+0x48 and mute at ops+0x50, and every later call is
`ldr xN, [base, #disp] ; blr xN`.  Those edges are invisible to a symbol-name xref, so this tool maps
them directly: for every `blr`/`bra` it reports the register it branches through and, when that
register was loaded from a memory operand, the displacement (the slot in the struct) -- plus the
owning function, so the caller side is named too.

Model (deliberately narrow, and honest about it): a register -> last-load map (base reg, displacement)
is kept across the linear pass; any write to the register that is not that load drops it.  A `blr`
whose register has no recorded load is still counted (shape indirect), just without a slot number.

usage: tools/kssym_blr.py [--disp HEX] [--control FUNCTION[,FUNCTION]] [--top N]
  --disp     print every site for this struct offset instead of the histogram
  --control  these functions MUST appear among blr sites -- without a passing control a short list
             means this tool is blind, not that nobody calls through (same rule as kobj_span_refs)
"""
import bisect
import re
import sys
from collections import Counter, defaultdict

from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, Cs
from capstone.arm64 import ARM64_REG_INVALID

ROOT = "/home/v/.local/project/xplay6"
TEXT = 0xFFFFFFC000080000
IMG = f"{ROOT}/fw/Image"
KALL = f"{ROOT}/art/kallsyms_real.txt"


def load_syms():
    s = []
    for ln in open(KALL, encoding="utf-8", errors="replace"):
        p = ln.split()
        if len(p) != 3:
            continue
        try:
            v = int(p[0], 16)
        except ValueError:
            continue
        if v >= TEXT:
            s.append((v, p[2]))
    s.sort()
    return s


def main():
    disp_want = None
    controls = []
    top = 25
    if "--disp" in sys.argv:
        disp_want = int(sys.argv[sys.argv.index("--disp") + 1], 0)
    if "--control" in sys.argv:
        controls = [c.strip() for c in sys.argv[sys.argv.index("--control") + 1].split(",") if c.strip()]
    if "--top" in sys.argv:
        top = int(sys.argv[sys.argv.index("--top") + 1])

    syms = load_syms()
    vas = [a for a, _ in syms]

    def owner(a):
        i = bisect.bisect_right(vas, a) - 1
        return syms[i][1] if i >= 0 else "?"

    data = open(IMG, "rb").read()
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True

    loads = {}                     # register name -> (base reg, displacement) of its last load
    hist = Counter()
    sites = defaultdict(list)
    n = indirect = 0
    i = 0
    end = len(data)
    while i < end:
        chunk = data[i:i + 4]
        if len(chunk) < 4:
            break
        for ins in md.disasm(chunk, TEXT + i):
            n += 1
            try:
                ops = ins.operands
            except Exception:
                ops = []
            mn = ins.mnemonic
            dst = None
            if mn in ("blr", "br", "bra"):
                r = ops[0].reg if ops and ops[0].type == 1 else ARM64_REG_INVALID
                rn = ins.reg_name(r) if r != ARM64_REG_INVALID else "?"
                if rn in loads:
                    base, disp = loads[rn]
                    hist[disp] += 1
                    sites[disp].append((ins.address, owner(ins.address), rn, base, disp, ins.op_str))
                else:
                    hist["no-load"] += 1
                    indirect += 1
            elif ops and ops[0].type == 1 and any(o.type == 3 for o in ops):
                mem = next(o.mem for o in ops if o.type == 3)
                if mn.startswith(("ldr", "ldur")):
                    if mem.base != ARM64_REG_INVALID:
                        loads[ins.reg_name(ops[0].reg)] = (ins.reg_name(mem.base), mem.disp)
                        dst = ins.reg_name(ops[0].reg)
                    else:
                        loads.pop(ins.reg_name(ops[0].reg), None)
                        dst = ins.reg_name(ops[0].reg)
                else:
                    dst = ins.reg_name(ops[0].reg)
            try:
                _rd, wr = ins.regs_access()
            except Exception:
                wr = ()
            for r in wr:
                rn = ins.reg_name(r)
                if r != ARM64_REG_INVALID and rn in loads and rn != dst:
                    del loads[rn]
        i += 4

    print(f"scanned {n} instructions; blr/br sites with a recorded load: {sum(v for k, v in hist.items() if k != 'no-load')}, "
          f"without: {indirect}")
    if disp_want is None:
        print(f"top {top} struct offsets called through (displacement, sites):")
        for d, c in [x for x in hist.most_common() if x[0] != "no-load"][:top]:
            who = {o for _a, o, _r, _b, _d, _s in sites[d]}
            print(f"  +{d:#05x} {c:5}  callers: {', '.join(sorted(who)[:4])}"
                  + (f" (+{len(who) - 4} more)" if len(who) > 4 else ""))
    else:
        rows = sites.get(disp_want, [])
        print(f"sites branching through +{disp_want:#x}: {len(rows)}")
        for a, o, rn, base, d, ostr in rows:
            print(f"  {a:#x} in {o:36} {rn}<-[{base}+{d:#x}]   {ostr}")
    if controls:
        owners = {o for d in sites for _a, o, _r, _b, _dd, _s in sites[d]}
        miss = [c for c in controls if c not in owners]
        if miss:
            sys.exit(f"CONTROL FAILED: {miss} never appears as a branch-through site -- this tool is "
                     "blind to at least one load/blr shape, so the lists above prove nothing")
        print(f"control ok: {controls} all present among the branch-through sites")


if __name__ == "__main__":
    main()
