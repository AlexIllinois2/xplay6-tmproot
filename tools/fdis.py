#!/usr/bin/env python3
"""Disassemble a kernel function from our Image and list its call targets by symbol.

Robust to data blobs / bad encodings: one instruction at a time, skip 4 bytes on
failure (capstone's generator otherwise stops at the first invalid encoding, which
reads as "no calls" -- a false negative that already burned a conclusion once).

usage: tools/fdis.py <hex-va> [nbytes]
"""
import bisect
import sys

from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, Cs

TEXT = 0xFFFFFFC000080000
IMG = "/home/v/.local/project/xplay6/fw/Image"
KALL = "/home/v/.local/project/xplay6/art/kallsyms_real.txt"

syms = []
for ln in open(KALL):
    p = ln.split()
    if len(p) != 3:
        continue
    try:
        v = int(p[0], 16)
    except ValueError:
        continue
    if v >= TEXT:
        syms.append((v, p[2]))
syms.sort()
vas = [a for a, _ in syms]


def owner(a):
    i = bisect.bisect_right(vas, a) - 1
    return syms[i][1] if i >= 0 else "?"


data = open(IMG, "rb").read()
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
md.detail = True

start = int(sys.argv[1], 16)
n = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0x400
off = start - TEXT
print("=== %s (%s) nbytes=%x ===" % (sys.argv[1], owner(start), n))

ins_count = 0
bad = 0
calls = []
first = []
i = 0
while i < n - 3:
    got = False
    for ins in md.disasm(data[off + i:off + i + 4], start + i):
        got = True
        ins_count += 1
        if len(first) < 12:
            first.append("  %x  %s %s" % (ins.address, ins.mnemonic, ins.op_str))
        if ins.mnemonic in ("bl", "b"):
            try:
                op = ins.operands[0]
                if op.type == 2:
                    t = op.imm & 0xFFFFFFFFFFFFFFFF
                    calls.append((ins.address, t, owner(t)))
            except Exception:
                pass
        break
    if not got:
        bad += 1
    i += 4

for l in first:
    print(l)
print("  decoded=%d undecodable=%d calls=%d" % (ins_count, bad, len(calls)))
seen = {}
for a, t, nm in calls:
    seen.setdefault(nm, []).append("%x" % a)
for nm in sorted(seen):
    print("   %-30s %s" % (nm, " ".join(seen[nm])))
