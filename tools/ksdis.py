#!/usr/bin/env python3
"""Annotated disassembly of one symbol from our stock arm64 Image.

Usage: tools/dis.py <symbol> [num_instr]
VA = file_offset + TEXT_BASE (0xffffffc000080000); symbols from art/kallsyms_real.txt.
"""
import re
import sys

from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, Cs

TEXT_BASE = 0xFFFFFFC000080000
IMG = "/home/v/.local/project/xplay6/fw/Image"
KALL = "/home/v/.local/project/xplay6/art/kallsyms_real.txt"


def load_syms():
    by_va, name_of = {}, {}
    for line in open(KALL):
        p = line.split()
        if len(p) != 3:
            continue
        try:
            va = int(p[0], 16)
        except ValueError:
            continue
        if va >= TEXT_BASE:
            by_va.setdefault(va, p[2])
            name_of[p[2]] = va
    return by_va, name_of


def main():
    sym = sys.argv[1]
    n = int(sys.argv[2]) if len(sys.argv) > 2 else 120
    by_va, name_of = load_syms()
    if sym not in name_of:
        print("unknown symbol; prefixes present:")
        print(", ".join(sorted(k for k in name_of if k.startswith(sym[:6]))[:40]))
        return 1
    start = name_of[sym]
    data = open(IMG, "rb").read()
    off = start - TEXT_BASE
    code = data[off:off + n * 4]
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    hits = []
    for ins in md.disasm(code, start):
        note = ""
        if ins.mnemonic in ("bl", "b") and ins.operands:
            t = ins.operands[0].imm
            note = "  ; " + (by_va.get(t, "?") if t in by_va else "?0x%x" % t)
        m = re.search(r"#(0x[0-9a-f]+|\d+)$", ins.op_str)
        if ins.mnemonic in ("mov", "add", "ldr", "str", "stp") and m:
            note += "   <== imm"
        print("%08x  %-8s %-40s%s" % (ins.address - start, ins.mnemonic, ins.op_str, note))
    return 0


sys.exit(main())
