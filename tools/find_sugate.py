#!/usr/bin/env python3
"""Locate the vivo exec-path "su" name gate inside fw/Image by its immediate compares.

The gate leaves no "su" string literal in the image (measured), so it must compare
characters as immediates.  Two shapes are searched:
  A. one 16-bit compare against 0x7573 / 0x7375  ("su" / "us" read as halfword)
  B. an imm8 0x73 ('s') and an imm8 0x75 ('u') within WINDOW instructions of each other
Only compares/movs/subs that can carry such an immediate are considered.

usage: python3 tools/find_sugate.py [--full]
"""
import sys, os, bisect, re

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

IMG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "fw", "Image")
KALLSYMS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "art", "kallsyms_real.txt")
WINDOW = 12

# instruction mnemonics whose operand we accept an immediate in
CMP_MN = {"cmp", "cmn", "subs", "cbnz", "cbz", "tbz", "tbnz", "mov", "movz", "movk",
          "sub", "add", "and", "orr", "eor", "bic", "orn", "eon", "bfi", "ccmp"}


def load_syms(path):
    addrs, names = [], {}
    with open(path, "r", errors="replace") as fh:
        for line in fh:
            m = re.match(r"^([0-9a-fA-F]{8,16}) ([a-zA-Z]) (\S+)", line.strip())
            if not m:
                continue
            a = int(m.group(1), 16)
            addrs.append(a)
            names.setdefault(a, m.group(3))
    order = sorted(set(addrs))
    return order, names


def sym_of(va, addrs, names):
    i = bisect.bisect_right(addrs, va) - 1
    if i < 0:
        return "?", 0
    return names[addrs[i]], va - addrs[i]


def main():
    full = "--full" in sys.argv
    base = 0xffffffc000080000          # _text, per kallsyms
    with open(IMG, "rb") as fh:
        img = fh.read()
    # .text (excluding init text) from kallsyms boundaries
    stext, etext = 0xffffffc000200000, 0xffffffc001400000
    if full:
        stext, etext = base, len(img) + base
    off_s, off_e = stext - base, etext - base
    code = img[off_s:off_e]
    print("image=%d bytes  scanning %#x..%#x (%d insns)" % (len(img), stext, etext, len(code) // 4))

    addrs, names = load_syms(KALLSYMS)
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True

    shape_a, shape_b = [], []
    c73 = c75 = 0
    pend = []  # (idx, va, reg, mnemonic) for recent 0x73 compares

    # chunked with resume: capstone's generator STOPS at the first bad encoding,
    # and a silent stop here would read as "no gate found" (a false negative this
    # repo has been burned by before).  Decode a chunk, jump to where it stopped.
    n = 0
    total = len(code)
    pos = 0
    CHUNK = 1 << 16
    while pos < total:
        got = 0
        for ins in md.disasm(code[pos:min(total, pos + CHUNK)], stext + pos):
            got += 1
            n += 1
            mn = ins.mnemonic
            if mn not in CMP_MN:
                continue
            try:
                ops = ins.operands
            except Exception:
                continue
            imm = None
            for o in ops:
                if o.type == 2:  # CS_OP_IMM
                    imm = o.value.imm
                    break
            if imm is None:
                continue
            txt = mn + " " + ins.op_str
            if imm == 0x73:
                c73 += 1
            if imm == 0x75:
                c75 += 1
            if imm in (0x7573, 0x7375, 0x75730000, 0x73750000):
                shape_a.append((ins.address, txt))
            if imm == 0x73:
                pend.append((n, ins.address, txt))
            if imm == 0x75:
                for pn, pa, pt in pend:
                    if n - pn <= WINDOW:
                        shape_b.append((pa, pt, ins.address, txt))
            pend = [p for p in pend if n - p[0] <= WINDOW]
        nxt = stext + pos + max(got, 1) * 4
        pos = (nxt - stext + 3) & ~3
    cov = 100.0 * n / (total / 4)
    print("decoded %d instructions, coverage %.1f%% of the scanned span" % (n, cov))
    if cov < 99.0:
        print("WARNING: coverage below 99%% -- this scan can under-report; do not read 0 hits as absence")

    print("\n== shape A: halfword compare against 0x7573/0x7375 (%d) ==" % len(shape_a))
    for va, txt in shape_a[:40]:
        s, d = sym_of(va, addrs, names)
        print("  %#x  %-28s  in %s+%#x" % (va, txt, s, d))

    print("\n== shape B: 's' then 'u' within %d insns (%d) ==" % (WINDOW, len(shape_b)))
    seen = set()
    for pa, pt, ua, ut in shape_b:
        s, d = sym_of(pa, addrs, names)
        if s in seen:
            continue
        seen.add(s)
        print("  pair %#x / %#x   %s | %s   in %s+%#x" % (pa, ua, pt, ut, s, d))
    print("\n(does not dedupe multiple pairs inside one function beyond first hit; %d raw)" % len(shape_b))


if __name__ == "__main__":
    main()
