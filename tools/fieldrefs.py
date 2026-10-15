#!/usr/bin/env python3
"""Who reads and who writes each field of a kernel global struct, straight from the Image.

Models a tiny abstract machine over the 31 general registers: ADRP plants a page, ADD/MOV
propagate "page + delta", LDR/STR/etc. are reported with the resolved VA.  Any instruction
whose destination register is a tracked one -- and which this script does not model --
invalidates it, so stale tracking cannot invent a reference (tools/blsweep.py's dataxref
did exactly that: it kept a register "alive" across redefinitions and annotated e.g.
`ldr x1,[x0,#0x4a8]` with a bogus VA from an unrelated page).

positive control: run it on the guard control block and check that the known sites show up
(0x33852c reads +0x74, 0x338594 writes +0x74, 0xd9b298 reads +0x13c).

usage: tools/fieldrefs.py <base-hex-va> [span-hex] [--list]
"""
import argparse
import os
import struct
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import blsweep as B  # noqa: E402

TEXT = B.TEXT

# unsigned-offset load/store forms, keyed by (word & 0xFFC00000) -> access size in bytes
LOADS = {0xF9400000: 8, 0xB9400000: 4, 0x38400000: 1, 0x78400000: 2}
STORES = {0xF9000000: 8, 0xB9000000: 4, 0x38000000: 1, 0x78000000: 2}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("base")
    ap.add_argument("span", nargs="?", default="0x400")
    ap.add_argument("--list", action="store_true")
    a = ap.parse_args()
    B.load()
    words = B.words
    base = int(a.base, 16)
    span = int(a.span, 16)
    page = base & ~0xFFF
    lo, hi = base, base + span

    reg = [None] * 32         # reg[r] = absolute VA it points at, or None (31 == xzr, unused)
    reads, writes = [], []
    for wi in range(len(words)):
        pc = TEXT + wi * 4
        w = words[wi]
        rd = w & 0x1F
        rn = (w >> 5) & 0x1F
        rm = (w >> 16) & 0x1F
        top = w & 0xFFC00000

        handled = False
        if (w & 0x9F000000) == 0x90000000:                       # adrp
            ok, imm = B.adrp_imm(w)
            if ok:
                reg[rd] = ((pc & ~0xFFF) + (imm << 12)) & ((1 << 64) - 1)
                handled = True
        elif top in (0x91000000, 0x91400000):                    # add xd, xn, #imm12{,lsl #12}
            sh = 12 if top == 0x91400000 else 0
            if reg[rn] is not None:
                reg[rd] = reg[rn] + (((w >> 10) & 0xFFF) << sh)
            else:
                reg[rd] = None
            handled = True
        elif (w & 0xFFE0FC00) == 0x8B000000:                     # add xd, xn, xm
            if reg[rn] is not None and reg[rm] is not None:
                reg[rd] = reg[rn] + reg[rm]
            elif reg[rn] is not None and (w >> 16) & 0x1F == 31:
                reg[rd] = reg[rn]
            else:
                reg[rd] = None
            handled = True
        elif (w & 0xFFE0FFE0) == 0xAA0003E0:                     # mov xd, xm (orr xd,xzr,xm)
            reg[rd] = reg[rm]
            handled = True
        elif (w & 0xFFC00000) in LOADS:                          # ldr/ldrb/ldrh unsigned imm
            scale = LOADS[w & 0xFFC00000]
            addr = reg[rn] + ((w >> 10) & 0xFFF) * scale if reg[rn] is not None else None
            if addr is not None and lo <= addr < hi:
                reads.append((pc, addr, "ldr%d" % scale))
            if rd < 31 and reg[rd] is not None:
                reg[rd] = None
            handled = True
        elif (w & 0xFFC00000) in STORES:                         # str/strb/strh unsigned imm
            scale = STORES[w & 0xFFC00000]
            addr = reg[rn] + ((w >> 10) & 0xFFF) * scale if reg[rn] is not None else None
            if addr is not None and lo <= addr < hi:
                writes.append((pc, addr, "str%d" % scale))
            handled = True

        if not handled and rd < 31 and reg[rd] is not None:
            # unmodelled instruction that may overwrite the destination register
            reg[rd] = None

    print("# base %#x span %#x   reads=%d writes=%d" % (base, span, len(reads), len(writes)))
    for tag, items in (("READ", reads), ("WRITE", writes)):
        for pc, addr, kind in items:
            s, d = B.owner(pc)
            print("  %-5s %#x  (+0x%x)  @ %#x  %s+%#x  %s" % (tag, addr, addr - base, pc, s, d, kind))
    return 0


if __name__ == "__main__":
    sys.exit(main())
