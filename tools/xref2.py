#!/usr/bin/env python3
"""Second, independent way to locate a kernel VA: find every adrp that lands on its 4K
page, then disassemble only the instructions after it and follow the register.

tools/xrefs.py was both slow (per-instruction Python decode) and blind: it required the
dereference to be `[reg, #imm]` with imm == offset, so it missed `adrp x0,pg ; add x0,x0,#off
; str w1,[x0]` -- the most common way a scalar global address is materialised.

Usage: tools/xref2.py <hex-va>
"""
import bisect
import os
import sys

from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, Cs

# Defaults are the 6.0.1 baseline; point the same two at a second firmware's own artifacts (§470).
TEXT = int(os.environ.get("KS_TEXT_BASE", "0xFFFFFFC000080000"), 0)
IMG = os.environ.get("KS_IMG", "/home/v/.local/project/xplay6/fw/Image")
KALL = os.environ.get("KS_KALL", "/home/v/.local/project/xplay6/art/kallsyms_real.txt")
M64 = (1 << 64) - 1

data = open(IMG, "rb").read()
S = []
for ln in open(KALL):
    p = ln.split()
    if len(p) == 3:
        try:
            v = int(p[0], 16)
        except ValueError:
            continue
        if v >= TEXT:
            S.append((v, p[2]))
S.sort()
vas = [a for a, _ in S]


def owner(a):
    i = bisect.bisect_right(vas, a) - 1
    return S[i][1] if i >= 0 else "?"


def adrp_page(addr, w):
    """Page base an ADRP at `addr` produces, or None if w is not adrp.
    Encoding: bit31=1, immlo=bits30:29, fixed bits28:24=10000, immhi=bits23:5, Rd=bits4:0."""
    if (w & 0x9F000000) != 0x90000000:
        return None
    immlo = (w >> 29) & 3
    immhi = (w >> 5) & 0x7FFFF
    imm = (immhi << 2) | immlo
    if imm & (1 << 20):
        imm -= (1 << 21)
    return ((addr & ~0xFFF) + (imm << 12)) & M64


def main():
    target = int(sys.argv[1], 16)
    tpage = target & ~0xFFF
    toff = target & 0xFFF
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True

    n_text = len(data) - (TEXT & 0xFFF)
    cands = []
    w = None
    for off in range(0, n_text - 4, 4):
        addr = TEXT + off
        w = int.from_bytes(data[off:off + 4], "little")
        if (w & 0x9F000000) != 0x90000000:      # adrp opcode bits only (Rd is free)
            continue
        if adrp_page(addr, w) == tpage:
            cands.append((addr, w & 31))
    print("adrp-to-page candidates: %d" % len(cands))

    found = 0
    for addr, rd in cands:
        off = addr - TEXT
        win = data[off:off + 40 * 4]
        base = {("x%d" % rd): addr & ~0xFFF | 0}
        known = {"x%d" % rd: tpage}
        for ins in md.disasm(win, addr):
            mn = ins.mnemonic
            ops = ins.operands
            if not ops:
                continue
            txt = "%s %s" % (mn, ins.op_str)
            hit = None
            if mn in ("add", "sub", "orr") and len(ops) == 3 \
                    and ops[1].type == 1 and ops[2].type == 2:
                src = ins.reg_name(ops[1].reg)
                if src in known:
                    v = known[src]
                    if mn == "add":
                        v += ops[2].imm
                    elif mn == "sub":
                        v -= ops[2].imm
                    else:
                        v |= ops[2].imm
                    known[ins.reg_name(ops[0].reg)] = v & M64
                    if (v & M64) == target:
                        hit = "MAT(full addr)"
            elif mn == "mov" and len(ops) == 2 and ops[1].type == 1:
                src = ins.reg_name(ops[1].reg)
                if src in known:
                    known[ins.reg_name(ops[0].reg)] = known[src]
            elif mn in ("ldr", "str", "ldur", "stur", "ldrb", "strb", "ldrsb", "ldrsw",
                        "cmp", "cmn", "tst"):
                for o in ops:
                    if o.type == 3 and o.mem.base:
                        b = ins.reg_name(o.mem.base)
                        if b in known:
                            if known[b] + o.mem.disp == target:
                                hit = "DEREF(+0x%x)" % (o.mem.disp & 0xfff)
                        break
            if hit:
                found += 1
                print("  %-16s %016x  %-34s in %s" % (hit, ins.address, txt, owner(ins.address)))
    print("total sites: %d" % found)


main()
