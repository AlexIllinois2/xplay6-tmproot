#!/usr/bin/env python3
"""Disassemble a VA range of the kernel Image with data references resolved.

Every adrp+add/ldr pair is annotated with the absolute VA it materialises and, when that
VA is inside .rodata, the printable string sitting there.  That is how a name needle is
found even when it is not an immediate: the compare reads it out of memory.

usage: tools/disreg.py <start-hex> <end-hex> [--calls]
"""
import argparse
import os
import struct
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import blsweep as B  # noqa: E402

from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs  # noqa: E402

IMG = os.path.join(ROOT, "fw", "Image")
TEXT = B.TEXT


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("start")
    ap.add_argument("end")
    ap.add_argument("--calls", action="store_true", help="only print bl/b lines and their targets")
    a = ap.parse_args()
    B.load()
    data = open(IMG, "rb").read()
    st = int(a.start, 16)
    en = int(a.end, 16)
    raw = data[st - TEXT:en - TEXT]
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True

    # pending adrp: reg -> page base
    page_of = {}
    lines = []
    for ins in md.disasm(raw, st):
        note = ""
        w = struct.unpack("<I", ins.bytes)[0]
        mn = ins.mnemonic
        if (w & 0x9F000000) == 0x90000000:
            ok, imm = B.adrp_imm(w)
            if ok:
                page_of[w & 0x1F] = ((ins.address & ~0xFFF) + (imm << 12)) & ((1 << 64) - 1)
        if mn in ("add", "ldr", "ldrb", "str", "strb", "ldur", "ldrh", "ldp") and page_of:
            m = None
            # find [xN, #imm] or xN, xN, #imm
            if (w & 0xFFC00000) in (0x91000000, 0xF9400000, 0xF9000000, 0xB9400000, 0xB9000000,
                                    0x38400400, 0xF8400400, 0x78400400, 0x38800400, 0xF8500400):
                rn = (w >> 5) & 0x1F
                imm12 = (w >> 10) & 0xFFF
                if rn in page_of:
                    m = (page_of[rn] + imm12) if page_of.get(rn) is not None else None
            if m is not None:
                if mn == "add":
                    page_of[w & 0x1F] = m
                off = m - TEXT
                s = ""
                if 0 <= off < len(data):
                    if all(0x20 <= c < 0x7F for c in data[off:off + 3]) and data[off:off + 3]:
                        j = off
                        while j < len(data) and 0x20 <= data[j] < 0x7F:
                            j += 1
                        if j - off >= 2:
                            s = " str=%r" % data[off:j]
                    sym = B.owner(m)
                    if sym[0] != "?":
                        s += " sym=%s+%#x" % sym
                note = "  -> VA %#x%s" % (m, s)
        if mn in ("bl", "b"):
            for from_va, t, kind in B.branches(ins.address, ins.address + 4):
                s, d = B.owner(t)
                note = "  -> %s%s+%#x" % (kind, s, d)
        if a.calls and mn not in ("bl", "b") and "-> VA" not in note:
            continue
        lines.append("%#x  %-9s %-32s%s" % (ins.address, mn, ins.op_str, note))
    print("\n".join(lines))
    print("# %d instructions decoded over [%#x,%#x)" % (len(lines), st, en))
    return 0


if __name__ == "__main__":
    sys.exit(main())
