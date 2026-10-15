#!/usr/bin/env python3
"""Numeric whole-image sweep for single-character immediate compares ('s' / 'u' and friends).

Why numeric: tools/find_sugate.py used capstone over 0x200000..0x1400000 and reported 81%
decode coverage -- a "0 hits" from that scan is not evidence of absence.  Here the encodings
are matched by bit masks over every word of the image, so coverage is 100% by construction.

Families matched (all carry the compared value directly in the instruction):
  CMP/SUBS immediate  32/64-bit : (w & 0xFFC00000) in (0x71000000, 0xF1000000), imm12 = (w>>10)&0xFFF
  ADD/SUB immediate   32/64-bit : bases 0x11000000/0x91000000/0x31000000/0xD1000000
  MOVZ                32/64-bit : (w & 0xFF800000) in (0x52800000, 0xD2800000), imm16 = (w>>5)&0xFFFF

usage: tools/immscan.py [--chars 73,75] [--near <symbol>] [--list]
"""
import argparse
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import blsweep as B  # noqa: E402

TEXT = B.TEXT


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--chars", default="73,75")
    ap.add_argument("--near", default=None, help="only report hits inside this symbol's image region")
    ap.add_argument("--list", action="store_true", help="print every hit, not one line per function")
    ap.add_argument("--window", type=int, default=10 ** 9, help="max instruction gap for a pair")
    a = ap.parse_args()

    want = [int(x, 16) for x in a.chars.split(",")]
    B.load()
    words = B.words
    lo = hi = None
    if a.near:
        lo, hi = B.extent(B.resolve(a.near))

    # per-function accumulation: sym -> {char: [va,...]}
    per = {}
    order = []
    for wi in range(len(words)):
        w = words[wi]
        top = w & 0xFFC00000
        if top in (0x71000000, 0xF1000000, 0x11000000, 0x91000000, 0x31000000, 0xD1000000):
            imm = (w >> 10) & 0xFFF
        elif w & 0xFF800000 in (0x52800000, 0xD2800000):
            imm = (w >> 5) & 0xFFFF
        else:
            continue
        hit = None
        for c in want:
            if imm == c:
                hit = c
        if hit is None:
            continue
        va = TEXT + wi * 4
        if lo is not None and not (lo <= va < hi):
            continue
        s, d = B.owner(va)
        e = per.setdefault(s, {c: [] for c in want})
        e[hit].append(va)
        if len(e[hit]) == 1:
            order.append(s)

    print("# functions containing ALL of %s: " % ",".join("%02x" % c for c in want))
    n = 0
    for s in order:
        e = per[s]
        if all(e[c] for c in want):
            n += 1
            start, end = B.extent(B.byname.get(s, 0)) if s in B.byname else (0, 0)
            print("  %-40s  %s" % (s, " ".join("%02x:%d" % (c, len(e[c])) for c in want)))
            if a.list:
                for c in want:
                    for va in e[c]:
                        print("      %02x @ %#x" % (c, va))
    print("# %d functions with every requested character" % n)
    return 0


if __name__ == "__main__":
    sys.exit(main())
