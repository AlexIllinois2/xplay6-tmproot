#!/usr/bin/env python3
"""tools/kobj_span_refs.py -- every code site that materialises an address INSIDE a kernel object.

tools/xrefs.py and xref2.py key on ONE exact VA, so they answer "who loads dac_parameters at +0x00"
but not "who ever touches the second byte of each pair".  This tool takes an object (symbol name or
VA) and reports every site that computes ANY address in [obj, obj+span), where span is the distance
to the next kallsyms symbol (or --span N).

Three kinds of reference are counted, because missing any one of them produces a confident "nobody
uses this":
  * bl / b            -- the branch target is the address itself (capstone returns it SIGNED: mask 64)
  * adrp + add/sub    -- a base register walked to an offset inside the object
  * adrp + ldr/str    -- a load/store whose address IS the object (the only way a plain global like
                         vivo_codec_fun shows up)

Order matters: register invalidation must happen AFTER the instruction's own address is evaluated,
otherwise `ldr x0, [x0, #off]` deletes x0 before it is used and the site vanishes -- that bug produced
a false "0 sites" for vivo_codec_fun (ledger 288).

capstone is fed instruction by instruction and the pointer always advances 4 bytes, so a data blob
cannot truncate the scan; the "scanned N instructions" line is the denominator.

usage: tools/kobj_span_refs.py <symbol-name-or-VA> [--span N] [--control SYM[,SYM...]]
  --control  symbols that MUST appear among the sites; a 0-hit answer without a passing control is
             not an answer, it is this tool being blind.
"""
import bisect
import re
import sys

from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, Cs
from capstone.arm64 import ARM64_REG_INVALID

ROOT = "/home/v/.local/project/xplay6"
TEXT = 0xFFFFFFC000080000
IMG = f"{ROOT}/fw/Image"
KALL = f"{ROOT}/art/kallsyms_real.txt"
MASK64 = 0xFFFFFFFFFFFFFFFF


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
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    key = sys.argv[1]
    span = int(sys.argv[sys.argv.index("--span") + 1], 0) if "--span" in sys.argv else None
    controls = [c.strip() for c in sys.argv[sys.argv.index("--control") + 1].split(",")] \
        if "--control" in sys.argv else []

    syms = load_syms()
    vas = [a for a, _ in syms]

    def owner(a):
        i = bisect.bisect_right(vas, a) - 1
        return syms[i][1] if i >= 0 else "?"

    if re.fullmatch(r"0x[0-9a-fA-F]+", key):
        obj, label = int(key, 16), owner(int(key, 16))
    else:
        hits = [v for v, n in syms if n == key]
        if not hits:
            sys.exit(f"no kallsyms symbol named {key}")
        if len(hits) > 1:
            print(f"NOTE: {len(hits)} symbols share the name {key} ({[hex(v) for v in hits]}) "
                  "-- scanning the first; run once per address")
        obj, label = hits[0], key
    nxt = [v for v, _ in syms if v > obj]
    if span is None:
        span = (nxt[0] - obj) if nxt else 0
    if span <= 0:
        sys.exit("cannot size the object: no following symbol and no --span")

    data = open(IMG, "rb").read()
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    lo, hi = obj, obj + span
    print(f"object {label} @{obj:#x} span {span} B -> range {lo:#x}..{hi:#x}")

    pages = {}                     # register name -> absolute VA it currently holds
    sites, n, errs = [], 0, 0
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
            dst0 = None

            if mn in ("bl", "b") and ops and ops[0].type == 2:
                val = ops[0].imm & MASK64
                if lo <= val < hi:
                    sites.append((ins.address, owner(ins.address), "branch", val, val - lo,
                                  mn, ins.op_str))
            elif mn == "adrp" and len(ops) == 2:
                pages[ins.reg_name(ops[0].reg)] = ops[1].imm & MASK64 & ~0xFFF
            elif mn in ("add", "sub") and len(ops) == 3 and ops[2].type == 2:
                base = ins.reg_name(ops[1].reg)
                dst0 = ins.reg_name(ops[0].reg)
                if base in pages:
                    val = pages[base] + (ops[2].imm if mn == "add" else -ops[2].imm)
                    pages[dst0] = val
                    if lo <= val < hi:
                        sites.append((ins.address, owner(ins.address), dst0, val, val - lo,
                                      mn, ins.op_str))
            else:
                # ARM64 puts the memory operand SECOND (`ldr x0, [x1, #8]`, `str w2, [x1, #8]`), so the
                # mem operand has to be searched for instead of assumed to be ops[0].  Its fields live
                # under .mem (an Arm64OpDetail), and any AttributeError here is counted -- a silent
                # except would turn a broken scan into another false "0 sites".
                try:
                    mem = next((o.mem for o in ops if o.type == 3), None)
                    if mem is not None and mem.base != ARM64_REG_INVALID:
                        bn = ins.reg_name(mem.base)
                        if bn in pages:
                            val = pages[bn] + mem.disp
                            if lo <= val < hi:
                                sites.append((ins.address, owner(ins.address), f"[{bn}]", val, val - lo,
                                              mn, ins.op_str))
                except Exception as e:
                    errs += 1
                    if errs <= 3:
                        print(f"  operand error at {ins.address:#x} {ins.mnemonic} {ins.op_str}: {e!r}")

            # invalidate only after this instruction's own address was evaluated -- see docstring.
            # adrp/add/sub must keep their destination: that IS the address just seeded (CS_OP_REG==1,
            # CS_OP_IMM==2, CS_OP_MEM==3).  A load's destination is NOT exempt -- after `ldr x0,[x0,#i]`
            # x0 holds loaded data, not a page.
            try:
                _rd, wr = ins.regs_access()
            except Exception:
                wr = ()
            dst_exempt = ins.reg_name(ops[0].reg) if (mn in ("adrp", "add", "sub") and ops
                                                     and ops[0].type == 1) else None
            for r in wr:
                rn = ins.reg_name(r)
                if r != ARM64_REG_INVALID and rn in pages and rn != dst_exempt:
                    del pages[rn]
        i += 4
    print(f"scanned {n} instructions ({errs} operand errors); sites materialising an address "
          f"inside the object: {len(sites)}")
    if errs:
        sys.exit(f"gate: {errs} operand parses failed -- the site list above is "
                 "incomplete, so a 0 or a small number here is this tool, not the kernel")
    for a, o, reg, val, off, mn, ostr in sites:
        print(f"  {a:#x} +{off:#04x} in {o:34} {mn:5} {ostr}")
    offs = sorted({off for _a, _o, _r, _v, off, _m, _s in sites})
    print(f"offsets touched: {['+%#x' % o for o in offs] or 'NONE'}")
    if controls:
        got = {o for _a, o, _r, _v, _off, _m, _s in sites}
        miss = [c for c in controls if c not in got]
        if miss:
            sys.exit(f"CONTROL FAILED: expected sites in {miss}, saw {sorted(got) or 'nothing'} -- "
                     "this scan is blind to at least one reference shape, so its 0-hit answers "
                     "prove nothing")
        print(f"control ok: {controls} all appear among the sites -- every reference shape is visible")


if __name__ == "__main__":
    main()
