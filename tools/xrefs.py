#!/usr/bin/env python3
"""Who materialises a given kernel VA in code?  (adrp + add/ldr/str with that page)

Usage: tools/xrefs.py <hex-va> [name-filter-regex]

Robust to data blobs: disassembles instruction by instruction and skips 4 bytes on
failure (capstone's generator stops at the first invalid encoding otherwise).
"""
import bisect
import re
import sys

from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, Cs

TEXT = 0xFFFFFFC000080000
IMG = "/home/v/.local/project/xplay6/fw/Image"
KALL = "/home/v/.local/project/xplay6/art/kallsyms_real.txt"


def load():
    s = []
    for ln in open(KALL):
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
    target = int(sys.argv[1], 16)
    filt = re.compile(sys.argv[2]) if len(sys.argv) > 2 else None
    syms = load()
    vas = [a for a, _ in syms]

    def owner(a):
        i = bisect.bisect_right(vas, a) - 1
        return syms[i][1] if i >= 0 else "?"

    data = open(IMG, "rb").read()
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    tpage = target & ~0xFFF
    toff = target & 0xFFF

    # pass 1: adrp results per (address, register)
    hits = []
    i = 0
    n = 0
    span_end = len(data)
    while i < span_end:
        chunk = data[i:i + 4]
        if len(chunk) < 4:
            break
        got = False
        for ins in md.disasm(chunk, TEXT + i):
            got = True
            n += 1
            try:
                ops = ins.operands
            except Exception:
                ops = []
            if ins.mnemonic == "adrp" and len(ops) == 2:
                try:
                    val = ops[1].imm
                except Exception:
                    val = None
                if val is not None:
                    hits.append(("adrp", ins.address, ins.reg_name(ops[0].reg), val, ins.mnemonic, ins.op_str))
            else:
                if ins.mnemonic in ("add", "ldr", "str", "ldur", "stur", "ldrb", "strb"):
                    hits.append(("use", ins.address, ins.mnemonic, None, ins.mnemonic, ins.op_str))
        i += 4
    print("scanned %d instructions, %d interesting records" % (n, len(hits)))

    # pass 2: replay tracking adrp bases per register, report uses of target
    base = {}
    found = 0
    for kind, addr, a, b, mn, txt in hits:
        if kind == "adrp":
            base[a] = b
            continue
        mn2 = a  # for "use" records we stored mnemonic in a
        # re-disassemble to get operands lazily is wasteful; parse the text instead
        m = re.search(r"#(0x[0-9a-f]+)", txt)
        imm = int(m.group(1), 16) if m else 0
        mreg = re.search(r"\[([wx]\d+)", txt)
        if not mreg:
            continue
        rn = mreg.group(1)
        mm = re.search(r"\[[^,]+, #(0x[0-9a-f]+|\d+)\]", txt)
        off = int(mm.group(1), 16) if mm and mm.group(1).startswith("0x") else (int(mm.group(1)) if mm else 0)
        bv = base.get(rn)
        if bv is None:
            continue
        if bv == tpage and off == toff and (mn2.startswith("ldr") or mn2.startswith("str") or mn2 in ("add", "ldur", "stur", "ldrb", "strb")):
            ow = owner(addr)
            if filt and not filt.search(ow):
                continue
            found += 1
            print("  %016x  %-5s %-30s  in %s" % (addr, mn2, txt, ow))
        if mn2 == "add" and bv + off == target:
            ow = owner(addr)
            if filt and not filt.search(ow):
                continue
            found += 1
            print("  %016x  add-full %s  in %s" % (addr, txt, ow))
    print("total candidate sites: %d" % found)


main()
