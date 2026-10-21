#!/usr/bin/env python3
"""tools/kstr_refs.py -- find every in-image pointer to a given string, then DERIVE the array that holds them.

Used to attribute live DAPM edges to a route table without trusting a symbol name (ledger 293): the
machine driver's route array is anonymous in kallsyms, but its rows point at the same widget-name
strings the running card printed, so clustering those pointers gives both the object and the stride.

For each string it prints the hit addresses, the deltas between consecutive hits, and the most common
delta -- the candidate stride.  It never claims a stride it has not seen at least --min-times times,
and with --derive it exits non-zero unless a single stride explains the majority of the gaps.

usage: tools/kstr_refs.py <string> [<string> ...] [--derive] [--min-times 3] [--image PATH]
"""
import argparse
import re
import struct
import sys
from collections import Counter

ROOT = "/home/v/.local/project/xplay6"
TEXT = 0xFFFFFFC000080000


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("strings", nargs="+")
    ap.add_argument("--derive", action="store_true")
    ap.add_argument("--min-times", type=int, default=3)
    ap.add_argument("--image", default=f"{ROOT}/fw/Image")
    ap.add_argument("--kall", default=f"{ROOT}/art/kallsyms_real.txt")
    a = ap.parse_args()
    data = open(a.image, "rb").read()

    syms = []
    for ln in open(a.kall, encoding="utf-8", errors="replace"):
        p = ln.split()
        if len(p) == 3:
            try:
                v = int(p[0], 16)
            except ValueError:
                continue
            if v >= TEXT:
                syms.append((v, p[2]))
    syms.sort()
    vas = [x for x, _ in syms]

    import bisect

    def owner(x):
        i = bisect.bisect_right(vas, x) - 1
        return f"{syms[i][1]}@{syms[i][0]:#x}" if i >= 0 else "?"

    all_gaps = Counter()
    found_any = False
    for want in a.strings:
        # EVERY copy of the string: .rodata holds duplicates (identical literals from different
        # translation units), and the array may point at a copy that is not the first one found.
        # Searching only the first produced a false "nothing references 'Speaker'" while the widget
        # decoder had plainly read that name out of an array -- ledger 293.
        pat = want.encode() + b"\x00"
        offs, start = [], 0
        while len(offs) < 12:
            h = data.find(pat, start)
            if h < 0:
                break
            # do NOT require a preceding NUL: the linker pools literals, so "Speaker" can legally be
            # the tail of "SmartPA Speaker" and a struct field can point at that tail. Requiring it
            # made a real copy look absent (ledger 293); instead each copy is tagged whole/suffix.
            offs.append(h)
            start = h + 1
        if not offs:
            print(f"{want!r}: the NUL-terminated literal is not in the image at all -- so the widget/"
                  "route name genuinely differs (truncation? another spelling?), which is a finding "
                  "about the search term, not about the tables")
            continue
        print(f"{want!r}: {len(offs)} occurrence(s) of the NUL-terminated literal, at "
              + ", ".join(f"{TEXT + o:#x}{'(whole)' if o == 0 or data[o - 1] == 0 else '(pooled tail)'}"
                          for o in offs) + " -- scanning pointers to each")
        ptrs, sva = [], TEXT + offs[0]
        for o in offs:
            one = TEXT + o
            needle = struct.pack("<Q", one)
            hits, start = [], 0
            while True:
                h = data.find(needle, start)
                if h < 0:
                    break
                hits.append(TEXT + h)
                start = h + 1
            print(f"   copy {one:#x}: {len(hits)} pointer(s) {[hex(x) for x in hits[:6]]}"
                  + (f" (+{len(hits) - 6} more)" if len(hits) > 6 else ""))
            ptrs += hits
            if hits and sva == TEXT + offs[0]:
                sva = one
        ptrs = sorted(set(ptrs))
        if not ptrs:
            print(f"{want!r}: 0 pointers to ANY of its {len(offs)} copies -- the string exists but "
                  "nothing references it by absolute address (relocatable build? a table built at "
                  "runtime? say which before drawing a conclusion)")
            continue
        found_any = True
        deltas = [ptrs[i + 1] - ptrs[i] for i in range(len(ptrs) - 1)]
        common = Counter(deltas)
        print(f"\n{want!r} @ {sva:#x}: {len(ptrs)} pointers")
        for p in ptrs[:12]:
            print(f"   ptr @{p:#x}  in {owner(p)}  (+{p - ptrs[0]:#x} from first)")
        print(f"   deltas: {[hex(d) for d in deltas[:12]]}")
        for d, c in common.most_common(3):
            print(f"   gap {d:#x} occurs {c}x")
            all_gaps[d] += c
    if a.derive:
        best = all_gaps.most_common(2)
        if not best or best[0][1] < a.min_times:
            sys.exit(f"DERIVE FAILED: no stride explains >= {a.min_times} gaps (best {best}) -- "
                     "refusing to name an array")
        if len(best) > 1 and best[1][1] * 2 > best[0][1]:
            sys.exit(f"DERIVE AMBIGUOUS: {best[0][0]:#x} occurs {best[0][1]}x but {best[1][0]:#x} "
                     f"occurs {best[1][1]}x -- two candidate strides, do not pick one silently")
        print(f"\nderived stride {best[0][0]:#x} ({best[0][1]} of the gaps); safe to decode with it")
    if not found_any:
        sys.exit("no string produced any pointer: nothing was attributed")


if __name__ == "__main__":
    main()
