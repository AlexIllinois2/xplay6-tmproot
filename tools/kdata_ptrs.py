#!/usr/bin/env python3
"""tools/kdata_ptrs.py -- find STATIC (in-image) pointers to a kernel symbol and show their neighbours.

Function-pointer tables are data, not code: the 40-byte ATP table of ledger 281 and the ASoC DAPM
widget arrays both hold the callback as an absolute 8-byte little-endian address in .rodata/.data.
A code xref cannot see those, so this tool greps the image bytes for the address itself and reports
every occurrence with the kallsyms object that contains it, plus the strings reachable from the
surrounding qwords -- which is how a widget name gets tied to its event callback.

Caveat stated openly: an unlinked byte sequence can equal an address by accident.  A hit is only
taken as a pointer when the containing object is a plausible table (>= one more qword in range) AND
the neighbourhood decodes as a struct (string pointers next to the callback).  The tool prints both
so a reader can judge; --struct tightens to hits with at least one decoded neighbour string.

usage: tools/kdata_ptrs.py <symbol-name-or-VA> [--radius N] [--struct] [--all]
"""
import bisect
import re
import struct
import sys

ROOT = "/home/v/.local/project/xplay6"
TEXT = 0xFFFFFFC000080000
IMG = f"{ROOT}/fw/Image"
KALL = f"{ROOT}/art/kallsyms_real.txt"


def load():
    s = []
    for ln in open(KALL, encoding="utf-8", errors="replace"):
        p = ln.split()
        if len(p) == 3:
            try:
                v = int(p[0], 16)
            except ValueError:
                continue
            if v >= TEXT:
                s.append((v, p[2]))
    s.sort()
    return s


def main():
    key = sys.argv[1]
    radius = int(sys.argv[sys.argv.index("--radius") + 1]) if "--radius" in sys.argv else 96
    want_struct = "--struct" in sys.argv
    syms = load()
    vas = [a for a, _ in syms]

    def owner(a):
        i = bisect.bisect_right(vas, a) - 1
        return syms[i][1] if i >= 0 else "?"

    data = open(IMG, "rb").read()

    def deref(va):
        """a NUL-terminated printable string at this VA, or None"""
        if not (TEXT <= va < TEXT + len(data)):
            return None
        o = va - TEXT
        end = data.find(b"\x00", o, o + 200)
        if end < 0 or end - o < 3:
            return None
        chunk = data[o:end]
        if all(32 <= b < 127 for b in chunk):
            return chunk.decode("latin-1")
        return None

    if re.fullmatch(r"0x[0-9a-fA-F]+", key):
        targets = [(int(key, 16), owner(int(key, 16)))]
    else:
        targets = [(v, n) for v, n in syms if n == key]
        if not targets:
            sys.exit(f"no symbol {key}")
    if len(targets) > 1:
        print(f"NOTE: {len(targets)} objects named {key}: {[hex(v) for v, _ in targets]} -- scanning all")

    shown = skipped = 0
    for va, name in targets:
        pat = struct.pack("<Q", va)
        start = 0
        while True:
            hit = data.find(pat, start)
            if hit < 0:
                break
            hva = TEXT + hit
            hname = owner(hva)
            lo = max(0, hit - radius)
            hi = min(len(data), hit + radius)
            neigh = []
            for off in range(lo - (lo % 8), hi, 8):
                if off == hit:
                    continue
                q = struct.unpack_from("<Q", data, off)[0]
                s = deref(q)
                if s:
                    neigh.append((off - hit, q, s))
            if want_struct and not neigh:
                skipped += 1          # NEVER let a filter turn into a 0: a dropped hit is not an
                start = hit + 1        # absent reference (this exact silence made hifi_codec_dac_event
                continue               # look unreferenced for a round -- ledger 290)
            shown += 1
            print(f"\nhit @{hva:#x} (file {hit:#x}) inside {hname} @  (offset in object "
                  f"{hva - [v for v, _ in syms if v <= hva][-1]:#x})")
            print(f"  points to {name} @{va:#x}")
            if neigh:
                print(f"  neighbour qwords that decode as strings ({len(neigh)}):")
                for d, q, s in neigh[:8]:
                    print(f"    {d:+#04x} -> {q:#x} {s[:70]!r}")
            else:
                print("  no neighbour qword decodes as a string (bare pointer occurrence)")
            before = [(d, s) for d, q, s in neigh if d < 0]
            if before:
                d, s = max(before)          # closest string BEFORE the pointer: a struct's name field
                print(f"  nearest preceding string: {d:+#x} {s!r}")
            start = hit + 1
    if skipped:
        print(f"NOTE: {skipped} occurrence(s) were filtered out by --struct (no neighbour string); "
              "they are NOT evidence of absence -- re-run without --struct for the raw count")
    if not shown:
        print(f"0 in-image pointer occurrences for {key} -- so either the table is built at runtime "
              "(writes a pointer into a struct) or this symbol is never taken by address")


if __name__ == "__main__":
    main()
