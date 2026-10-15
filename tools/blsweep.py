#!/usr/bin/env python3
"""Whole-image BL sweep: who calls a function, and what a function calls.

Branch targets are decoded numerically (mask 0x7C000000 == 0x94000000), so this is not
subject to capstone's stop-on-bad-encoding behaviour that made an earlier "0 hits" read
like absence.  Also resolves ADRP+ADD/ADRP+LDR data references so a string or global can
be xref'd back to the function that uses it.

usage:
  tools/blsweep.py callers <hex-va|symbol>      who branches to it
  tools/blsweep.py callees <hex-va|symbol>      what it branches to (with extents)
  tools/blsweep.py dataxref <hex-va>            code that materialises this VA (adrp+add/ldr)
"""
import bisect
import os
import re
import struct
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IMG = os.path.join(ROOT, "fw", "Image")
KALL = os.path.join(ROOT, "art", "kallsyms_real.txt")
TEXT = 0xFFFFFFC000080000

words = None
vas, names, byname = [], [], {}


def load():
    global words
    if words is None:
        data = open(IMG, "rb").read()
        words = memoryview(data).cast("I")
        for ln in open(KALL, errors="replace"):
            m = re.match(r"^([0-9a-fA-F]{8,16}) ([a-zA-Z]) (\S+)$", ln.strip())
            if not m:
                continue
            v = int(m.group(1), 16)
            if v < TEXT:
                continue
            vas.append(v)
            names.append(m.group(3))
            byname.setdefault(m.group(3), v)
        order = sorted(set(vas))
        d = {}
        for v, n in zip(vas, names):
            d.setdefault(v, n)
        vas[:] = order
        names[:] = [d[v] for v in order]


def owner(a):
    i = bisect.bisect_right(vas, a) - 1
    if i < 0:
        return "?", 0
    return names[i], a - vas[i]


def extent(a):
    """[start, next-symbol-start) -- symbol-delimited, so blobs inside are included."""
    i = bisect.bisect_right(vas, a) - 1
    if i < 0:
        return a, a
    start = vas[i]
    end = vas[i + 1] if i + 1 < len(vas) else start + 4
    return start, end


def resolve(s):
    if re.fullmatch(r"0x[0-9a-f]+", s):
        return int(s, 16)
    load()
    if s not in byname:
        raise SystemExit("symbol %s not in kallsyms" % s)
    return byname[s]


def branches(start, end):
    """(from_va, target, kind) for BL and B (tail call) inside [start,end).
    B matters: open_exec -> do_open_exec is a tail call, BL-only recall loses callers."""
    out = []
    for wi in range((start - TEXT) // 4, (end - TEXT) // 4):
        w = words[wi]
        op = w & 0xFC000000
        if op == 0x94000000 or op == 0x14000000:
            pass
            imm = w & 0x03FFFFFF
            if imm & 0x02000000:
                imm -= 0x04000000
            pc = TEXT + wi * 4
            out.append((pc, pc + imm * 4, "bl" if op == 0x94000000 else "b"))
    return out


def bl_targets(start, end):
    return [(a, b) for a, b, _ in branches(start, end)]


def callers(target):
    load()
    st, en = extent(target)
    res = []
    for wi in range(0, len(words)):          # words[0] == VA TEXT; not TEXT//4
        w = words[wi]
        op = w & 0xFC000000
        if op != 0x94000000 and op != 0x14000000:
            continue
        imm = w & 0x03FFFFFF
        if imm & 0x02000000:
            imm -= 0x04000000
        pc = TEXT + wi * 4
        t = pc + imm * 4
        if st <= t < en and not (st <= pc < en):
            res.append((pc, t, "bl" if op == 0x94000000 else "b"))
    return res


def adrp_imm(w):
    """(is_adrp, imm21_signed)"""
    if w & 0x9F000000 != 0x90000000:
        return False, 0
    lo = (w >> 29) & 3
    hi = (w >> 5) & 0xFFFFF
    imm = (hi << 2) | lo
    if imm & 0x100000:
        imm -= 0x200000
    return True, imm


def dataxref(target, window=40):
    """Find adrp landing on target's page, then follow the same register for the exact
    offset (ADD gives the address itself; LDR/STR reads/writes it)."""
    load()
    page = target & ~0xFFF
    off = target & 0xFFF
    hits = []
    for wi in range(len(words)):
        w = words[wi]
        ok, imm = adrp_imm(w)
        if not ok:
            continue
        va = TEXT + wi * 4
        base = ((va & ~0xFFF) + (imm << 12)) & ((1 << 64) - 1)
        if base != page:
            continue
        rd = w & 0x1F
        follow = []
        for j in range(wi + 1, min(wi + 1 + window, len(words))):
            w2 = words[j]
            rn = (w2 >> 5) & 0x1F
            rdn = w2 & 0x1F
            if (w2 & 0x9F000000) == 0x90000000 and rdn == rd:
                break                                   # register redefined
            if rn != rd:
                continue
            top = w2 & 0xFFC00000
            imm12 = (w2 >> 10) & 0xFFF
            if top == 0x91000000 and imm12 == off:       # add xd, rd, #off  (rd==rn)
                follow.append(("add", TEXT + j * 4))
            elif top in (0xF9400000, 0xF9500000, 0xB9400000, 0xB9500000,
                         0xF8400000, 0xF8500000) and imm12 == off:
                follow.append(("ldr", TEXT + j * 4))
            elif top in (0xF9000000, 0xB9000000, 0xF8000000) and imm12 == off:
                follow.append(("str", TEXT + j * 4))
        if follow:
            hits.append((va, follow))
    return hits


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    cmd = sys.argv[1]
    load()
    target = resolve(sys.argv[2])
    if cmd == "callers":
        st, en = extent(target)
        print("# %s  [%#x, %#x)  %d bytes" % (names[bisect.bisect_right(vas, target) - 1], st, en, en - st))
        for from_va, t, kind in callers(target):
            s, d = owner(from_va)
            print("  %-2s from %#x  in %s+%#x" % (kind, from_va, s, d))
    elif cmd == "callees":
        st, en = extent(target)
        print("# %s [%#x,%#x) %d insns" % (names[bisect.bisect_right(vas, target) - 1], st, en, (en - st) // 4))
        seen = {}
        for from_va, t in bl_targets(st, en):
            s, d = owner(t)
            seen.setdefault(s, []).append(from_va)
        for s, fr in sorted(seen.items(), key=lambda kv: -len(kv[1])):
            print("  %-40s %d  from %#x" % (s, len(fr), fr[0]))
    elif cmd == "dataxref":
        hits = dataxref(target)
        print("# %d adrp sites on page of %#x" % (len(hits), target))
        for va, follow in hits:
            s, d = owner(va)
            print("  adrp %#x in %s+%#x   follow=%s" % (va, s, d, follow))
    else:
        print(__doc__)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
