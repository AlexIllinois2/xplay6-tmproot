#!/usr/bin/env python3
"""tools/kstruct_dump.py -- print a kernel image region qword by qword, resolving each to a string or a symbol.

Made for reading struct arrays out of the stripped Image (the DAPM widget table in ledger 291, the
control arrays in §290): a row of qwords is meaningless until each one is labelled STR (it points at
a printable string) or SYM (it equals/lands inside a known object).  Zeros are skipped because in a
static array they mean "field unset" and say nothing.

usage: tools/kstruct_dump.py <VA> <count-in-bytes> [--stride 8] [--zeros] [--kall PATH]
  --zeros prints the NULL qwords too -- without them a struct layout cannot be derived,
  because 'field absent' and 'field zero' look the same in the default output (ledger 292)
"""
import bisect
import struct
import sys

TEXT = 0xFFFFFFC000080000
ROOT = "/home/v/.local/project/xplay6"


def main():
    args = sys.argv[1:]
    if len(args) < 2:
        sys.exit(__doc__)
    kall = args[args.index("--kall") + 1] if "--kall" in args else f"{ROOT}/art/kallsyms_real.txt"
    img = args[args.index("--image") + 1] if "--image" in args else f"{ROOT}/fw/Image"
    stride = int(args[args.index("--stride") + 1], 0) if "--stride" in args else 8
    show_zero = "--zeros" in args      # a static array hides which fields are NULL, and a
                                      # NULL IS information when deriving a struct layout
    base = int(args[0], 16)
    n = int(args[1], 0)

    syms = []
    for ln in open(kall, encoding="utf-8", errors="replace"):
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
        return syms[i] if i >= 0 else (0, "?")

    data = open(img, "rb").read()

    def deref(va):
        if not (TEXT <= va < TEXT + len(data)):
            return None
        o = va - TEXT
        e = data.find(b"\x00", o, o + 160)
        if e < 0 or e - o < 1:
            return None
        c = data[o:e]
        return c.decode("latin-1") if all(32 <= b < 127 for b in c) else None

    print(f"# {hex(base)} + {hex(n)}  (stride {stride})  zero qwords omitted: they mean 'field unset'")
    for off in range(0, n, stride):
        va = base + off
        q = struct.unpack_from("<Q", data, va - TEXT)[0]
        if q == 0:
            if show_zero:
                print(f"  {va:#x} +{off:#05x}  0  NULL")
            continue
        s = deref(q)
        if s:
            print(f"  {va:#x} +{off:#05x}  {q:#018x}  STR {s[:60]!r}")
        else:
            ov, on = owner(q)
            print(f"  {va:#x} +{off:#05x}  {q:#018x}  SYM {on} @{ov:#x} (+{q - ov:#x})")


if __name__ == "__main__":
    main()
