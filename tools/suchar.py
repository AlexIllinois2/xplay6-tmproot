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
       # 6.0.1 defaults: fw/Image + art/kallsyms_real.txt, calibrated by CONTROLS
       python3 tools/suchar.py --image fw/7/Image --kallsyms art/kallsyms-7-real.txt \
           --text-base fffffffc000080000 --t0 fffffffc00200000 --t1 fffffffc01800000 \
           --controls none --plant
       # --controls none refuses to run unless --plant calibrates the ruler on THIS image
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
    addrs, names, by_name = [], {}, {}
    with open(path, "r", errors="replace") as fh:
        for line in fh:
            m = re.match(r"^([0-9a-fA-F]{8,16}) (.) (\S+)", line.strip())
            if m:
                a = int(m.group(1), 16)
                by_name.setdefault(m.group(3), a)   # several symbols share one address; keep both views
                if a not in names:
                    addrs.append(a)
                    names[a] = m.group(3)
    return sorted(set(addrs)), names, by_name


def sym_of(va, addrs, names):
    import bisect
    i = bisect.bisect_right(addrs, va) - 1
    if i < 0:
        return "?"
    s, d = names[addrs[i]], va - addrs[i]
    return s if d == 0 else "%s+0x%x" % (s, d)


def scan(buf, base, t0, t1):
    """h73, h75 over the instruction window [t0,t1) of a raw Image whose byte 0 sits at `base`."""
    if not (base <= t0 < t1 <= base + len(buf)):
        # A mistyped VA used to silently truncate the slice and report "0 sites" -- that reads
        # exactly like "the kernel has no such check", so refuse instead.
        raise SystemExit("REFUSED: window %#x..%#x is not inside the image (%#x..%#x) -- check the VAs"
                         % (t0, t1, base, base + len(buf)))
    if (t0 - base) % 4 or (t1 - base) % 4:
        raise SystemExit("REFUSED: window bounds must be 4-byte aligned")
    words = array.array("I")
    words.frombytes(buf[t0 - base:t1 - base])
    assert len(words) * 4 == t1 - t0, "window is not 4-byte aligned"
    h73, h75 = {}, {}
    for i, w in enumerate(words):
        r = cmp_imm12(w)
        if not r:
            continue
        imm, _ = r
        va = t0 + i * 4
        if imm == 0x73:
            h73[va] = w
        elif imm == 0x75:
            h75[va] = w
    return h73, h75, len(words)


# cmp w1,#'s' and cmp w1,#'u' -- the shape the 6.0.1 gate is made of (mask keeps only the fixed
# pattern, so Rn does not matter; Rd=SP because it is a CMP).
CMP_S_W1 = 0x7100001F | (0x73 << 10) | (1 << 5)
CMP_U_W1 = 0x7100001F | (0x75 << 10) | (1 << 5)


def plant_check(buf, base, t0, t1):
    """Calibrate the ruler on THIS image when it carries no known-answer site.

    Positive arm: write a synthetic 's'/'u' pair into padding and require the scanner to report it
    as a pair.  Negative arm: change the planted 's' to 'r' and require the pair to disappear --
    without this the arm would also pass if the letters were ignored."""
    spot = None
    for i in range(32, (t1 - t0) // 4 - 40):   # >=128B inside the window: the 64B probe needs room
        j = (t0 - base) + i * 4
        if buf[j:j + 32] == b"\0" * 32:
            spot = t0 + i * 4
            break
    if spot is None:
        return "REFUSED: no 32-byte zero run inside the window to plant into -- ruler is uncalibrated"
    off = spot - base
    for imm, label in ((0x73, "positive"), (0x72, "negative")):
        mutated = bytearray(buf)
        mutated[off:off + 4] = array.array("I", [0x7100001F | (imm << 10) | (1 << 5)]).tobytes()
        mutated[off + 4:off + 8] = array.array("I", [CMP_U_W1]).tobytes()
        h73, h75, _ = scan(mutated, base, spot - 64, spot + 64)
        hit = (spot in h73 and spot + 4 in h75)
        if label == "positive" and not hit:
            return "FAIL: planted 's'/'u' pair at %#x was NOT found -- the ruler is blind" % spot
        if label == "negative" and hit:
            return "FAIL: pair still found after changing the planted letter to 'r'"
    base73, base75, _ = scan(buf, base, spot - 64, spot + 64)
    if spot in base73 or spot + 4 in base75:
        return "FAIL: the plant spot was not empty to begin with"
    return "ok   plant at %#x: 's'+'u' pair found, 'r'+'u' pair refused" % spot


def main():
    window, image, kallsyms = 12, IMG, KALLSYMS
    base, t0, t1, controls, plant = TEXT_BASE, T0, T1, "6.0.1", False
    a = sys.argv[1:]
    for i in range(len(a)):
        if a[i] == "--window":
            window = int(a[i + 1])
        elif a[i] == "--image":
            image = a[i + 1]
        elif a[i] == "--kallsyms":
            kallsyms = a[i + 1]
        elif a[i] == "--text-base":
            base = int(a[i + 1], 16)
        elif a[i] == "--t0":
            t0 = int(a[i + 1], 16)
        elif a[i] == "--t1":
            t1 = int(a[i + 1], 16)
        elif a[i] == "--controls":
            controls = a[i + 1]
        elif a[i] == "--plant":
            plant = True

    with open(image, "rb") as fh:
        img = fh.read()
    addrs, names, by_name = load_syms(kallsyms)
    # Cross-check the VA convention against the symbol table: a base off by one hex digit still
    # gives a self-consistent window over the right file bytes, and then every reported VA is wrong.
    if "_text" not in by_name:
        print("REFUSED: %s has no `_text`, so --text-base cannot be checked" % kallsyms)
        return 2
    if by_name["_text"] != base:
        print("REFUSED: --text-base %#x != kallsyms _text %#x from %s"
              % (base, by_name["_text"], kallsyms))
        return 2
    h73, h75, n = scan(img, base, t0, t1)
    print("image=%s  window=%#x..%#x" % (image, t0, t1))
    print("scanned %d instructions of .text (numeric, no decoder -- coverage by construction 100%%)" % n)
    print("cmp #0x73 sites: %d    cmp #0x75 sites: %d" % (len(h73), len(h75)))

    if controls == "6.0.1":
        bad = [va for va, want in CONTROLS.items()
               if (want == 0x73 and va not in h73) or (want == 0x75 and va not in h75)]
        print("positive controls: %d/%d hit" % (len(CONTROLS) - len(bad), len(CONTROLS)))
        for va in bad:
            print("  MISSING CONTROL %#x -- ruler is broken, read no further" % va)
        if bad:
            return 1
    elif controls == "none":
        if not plant:
            print("REFUSED: this image has no known-answer site and --plant was not given; "
                  "a blind scan reporting 0 pairs means nothing")
            return 2
        print(plant_check(img, base, t0, t1))
    else:
        print("REFUSED: unknown --controls %r (use 6.0.1 or none)" % controls)
        return 2

    pairs = sorted((a2, b2) for a2 in h73 for b2 in h75 if 0 < (b2 - a2) // 4 <= window)
    print("pairs within %d instructions: %d" % (window, len(pairs)))
    for a2, b2 in pairs:
        d = (b2 - a2) // 4
        sa, sb = sym_of(a2, addrs, names), sym_of(b2, addrs, names)
        print("  %#x .. %#x  delta=%-2d  %s | %s%s"
              % (a2, b2, d, sa, sb, "   <-- known su-compare" if a2 in CONTROLS else ""))
    print("\nnote: an unrelated pair (printf format / mount-token / property switches) compares the")
    print("SAME register against 's' then 'u' as case labels -- check the disasm, not the count.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
