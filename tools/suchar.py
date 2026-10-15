#!/usr/bin/env python3
"""Find every 's'/('u') character-compare pair in kernel .text -- numerically, 100% coverage.

Why this exists as its own tool: tools/immscan.py (and my first attempt today) extracted the
immediate from the wrong bits.  CMP/SUBS immediate is **imm12 in bits[21:10]** with an LSL#12
flag at bit 22, and the fixed-pattern mask has to be 0xFFC0001F -- reading 16 bits at [25:10]
swallows the always-set bit 24 and finds *nothing*, which looks exactly like "there is no such
check in the kernel".  That false negative is what made §103/§155 claim the gate was not a
per-character compare, when it is (`cmp w1,#0x73` / `cmp w1,#0x75`).

The four positive controls are the sites read straight out of the disassembly, so a broken
ruler cannot silently report 0.

usage: python3 tools/suchar.py [--window 12]
"""
import array
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
IMG = os.path.join(ROOT, "fw", "Image")
KALLSYMS = os.path.join(ROOT, "art", "kallsyms_real.txt")
TEXT_BASE = 0xFFFFFFC000080000      # fw/Image byte 0
T0, T1 = 0xFFFFFFC000200000, 0xFFFFFFC001400000

CONTROLS = {
    0xFFFFFFC0003326B0: 0x73,   # gate: cmp w1,#'s'
    0xFFFFFFC0003326BC: 0x75,   # gate: cmp w1,#'u'
    0xFFFFFFC000339D94: 0x73,   # Y:    cmp w1,#'s'
    0xFFFFFFC000339DA0: 0x75,   # Y:    cmp w1,#'u'
}


def cmp_imm12(w):
    """(imm, is64) for CMP/SUBS immediate with LSL#0, else None."""
    if w & 0x00400000:        # sh == 1 => imm<<12, never a plain ASCII compare
        return None
    if (w & 0xFFC0001F) == 0x7100001F:
        return ((w >> 10) & 0xFFF, False)
    if (w & 0xFFC0001F) == 0xF100001F:
        return ((w >> 10) & 0xFFF, True)
    return None


def load_syms(path):
    addrs, names = [], {}
    with open(path, "r", errors="replace") as fh:
        for line in fh:
            m = re.match(r"^([0-9a-fA-F]{8,16}) (.) (\S+)", line.strip())
            if m:
                a = int(m.group(1), 16)
                if a not in names:
                    addrs.append(a)
                    names[a] = m.group(3)
    return sorted(set(addrs)), names


def sym_of(va, addrs, names):
    import bisect
    i = bisect.bisect_right(addrs, va) - 1
    if i < 0:
        return "?"
    s, d = names[addrs[i]], va - addrs[i]
    return s if d == 0 else "%s+0x%x" % (s, d)


def main():
    window = 12
    for i, a in enumerate(sys.argv):
        if a == "--window":
            window = int(sys.argv[i + 1])
    with open(IMG, "rb") as fh:
        img = fh.read()
    words = array.array("I")
    words.frombytes(img[T0 - TEXT_BASE:T1 - TEXT_BASE])
    h73, h75 = {}, {}
    for i, w in enumerate(words):
        r = cmp_imm12(w)
        if not r:
            continue
        imm, _ = r
        va = T0 + i * 4
        if imm == 0x73:
            h73[va] = w
        elif imm == 0x75:
            h75[va] = w
    print("scanned %d instructions of .text (numeric, no decoder -- coverage by construction 100%%)"
          % len(words))
    print("cmp #0x73 sites: %d    cmp #0x75 sites: %d" % (len(h73), len(h75)))

    addrs, names = load_syms(KALLSYMS)
    bad = [va for va, want in CONTROLS.items()
           if (want == 0x73 and va not in h73) or (want == 0x75 and va not in h75)]
    print("positive controls: %d/%d hit" % (len(CONTROLS) - len(bad), len(CONTROLS)))
    for va in bad:
        print("  MISSING CONTROL %#x -- ruler is broken, read no further" % va)
    if bad:
        return 1

    pairs = sorted((a, b) for a in h73 for b in h75 if 0 < (b - a) // 4 <= window)
    print("pairs within %d instructions: %d" % (window, len(pairs)))
    for a, b in pairs:
        d = (b - a) // 4
        sa, sb = sym_of(a, addrs, names), sym_of(b, addrs, names)
        print("  %#x .. %#x  delta=%-2d  %s | %s%s"
              % (a, b, d, sa, sb, "   <-- known su-compare" if a in CONTROLS else ""))
    print("\nnote: an unrelated pair (printf format / mount-token / property switches) compares the")
    print("SAME register against 's' then 'u' as case labels -- check the disasm, not the count.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
