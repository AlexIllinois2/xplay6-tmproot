#!/usr/bin/env python3
"""tools/kssym_writes.py -- list the (register, value) pairs a kernel function writes through a
byte-write helper, with the instructions the answer was read from.

Built for the ES9038 driver (ledger 285/286): es9038_one_enable() calls
  es9038_i2c_write_byte(client, w1=reg, w2=val)  and  do_reg_write_check(client, w1=reg, w2=val)
with the arguments set by `mov w1,#imm` / `mov w2,#imm` a few instructions earlier -- one pair inside
the dac_parameters loop (values come from the table, so they are NOT constants and are reported as
TABLE), the rest as literal constants after the loop.  Every site prints its own preceding window so a
reader can check the attribution instead of trusting it.

usage: tools/kssym_writes.py <symbol> [--call REGEX] [--window N]
"""
import re
import sys

from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, Cs
from capstone.arm64 import ARM64_REG_X0, ARM64_REG_INVALID

ROOT = "/home/v/.local/project/xplay6"
TEXT_BASE = 0xFFFFFFC000080000
IMG = f"{ROOT}/fw/Image"
KALL = f"{ROOT}/art/kallsyms_real.txt"


def sym_range(name):
    syms = []
    for ln in open(KALL, encoding="utf-8", errors="replace"):
        p = ln.split()
        if len(p) == 3 and int(p[0], 16) >= TEXT_BASE:
            syms.append((int(p[0], 16), p[2]))
    syms.sort()
    vas = [v for v, _ in syms]
    hits = [v for v, n in syms if n == name]
    if not hits:
        sys.exit(f"no symbol {name}")
    va = hits[0]
    i = syms.index((va, name))
    end = syms[i + 1][0] if i + 1 < len(syms) else va + 0x400
    return va, end, [(v, n) for v, n in syms]


def reg_id(ins, idx):
    try:
        r = ins.operands[idx].reg
    except Exception:
        return None
    if r == ARM64_REG_INVALID:
        return None
    n = ins.reg_name(r) or ""
    m = re.fullmatch(r"[xw](\d+)", n)
    return int(m.group(1)) if m else None


def main():
    name = sys.argv[1]
    call = sys.argv[sys.argv.index("--call") + 1] if "--call" in sys.argv else r"i2c_write_byte|reg_write_check"
    win = int(sys.argv[sys.argv.index("--window") + 1]) if "--window" in sys.argv else 10
    syms = None
    va, end, syms = sym_range(name)
    blob = open(IMG, "rb").read()
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    code = blob[va - TEXT_BASE:end - TEXT_BASE]
    ins = list(md.disasm(code, va))
    if len(ins) * 4 < len(code) * 0.9:
        sys.exit(f"gate: decoded {len(ins)} of {len(code)//4} words in {name} -- truncated decode, "
                 "a missing write site would look like 'not written'")
    by_addr = {i.address: i for i in ins}
    owners = {v: n for v, n in syms}

    def owner(a):
        cand = [v for v, _ in syms if v <= a]
        return owners.get(max(cand), "?") if cand else "?"

    rx = re.compile(call)
    n = 0
    print(f"=== {name} @ {va:#x} ({len(ins)} instructions, span {end - va} B) ===")
    for k, i in enumerate(ins):
        if i.mnemonic != "bl":
            continue
        try:
            # capstone returns the bl target as a SIGNED 64-bit value (kernel VA 0xffffffc0........
            # prints as -0x3fff........), so an unmasked lookup resolves NOTHING and the function looks
            # like it writes no registers at all -- the same trap as ledger 248's op.imm note
            tgt = i.operands[0].imm & 0xFFFFFFFFFFFFFFFF
        except Exception:
            continue
        o = owner(tgt)
        if not rx.search(o):
            continue
        n += 1
        arg = {}
        for j in range(max(0, k - win), k):
            p = by_addr[ins[j].address]
            if p.mnemonic == "mov" and reg_id(p, 0) in (1, 2) and p.operands[1].type == 2:
                arg[reg_id(p, 0)] = (f"{p.operands[1].imm & 0xff:#04x}", ins[j].address, p.op_str)
        window = [f"{ins[j].address - va:#04x} {ins[j].mnemonic} {ins[j].op_str}"
                  for j in range(max(0, k - win), k)]
        print(f"\n site +{i.address - va:#04x} -> {o}")
        for rnum, rn in ((1, "reg"), (2, "val")):
            if rnum in arg:
                v, a, txt = arg[rnum]
                print(f"   {rn} = {v:>6}  (from +{a - va:#04x}: {txt})")
            else:
                print(f"   {rn} =   TABLE  (no constant mov in the {win}-instruction window)")
        print("   window: " + " | ".join(window[-6:]))
    print(f"\n{n} write/verify call site(s) matched /{call}/ in {name}")


if __name__ == "__main__":
    main()
