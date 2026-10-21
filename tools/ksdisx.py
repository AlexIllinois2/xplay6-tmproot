#!/usr/bin/env python3
"""tools/ksdisx.py -- ksdis output with every bl/b target resolved through the recovered kallsyms.

Usage: tools/ksdisx.py <symbol> [num_instr] [addr_start]
Needed because tools/ksdis.py leaves call targets as raw addresses.
"""
import bisect
import re
import subprocess
import sys

KALL = "art/kallsyms_real.txt"


def load():
    syms = []
    for line in open(KALL, encoding="utf-8", errors="replace"):
        p = line.split()
        if len(p) != 3:
            continue
        try:
            syms.append((int(p[0], 16), p[2]))
        except ValueError:
            pass
    syms.sort()
    return syms, [a for a, _ in syms]


def main():
    if len(sys.argv) < 2:
        sys.exit("usage: ksdisx.py <symbol> [num_instr] [addr_start]")
    sym = sys.argv[1]
    n = sys.argv[2] if len(sys.argv) > 2 else "80"
    rest = sys.argv[3:] if len(sys.argv) > 3 else []
    cmd = ["python3", "tools/ksdis.py", sym, n] + rest
    out = subprocess.run(cmd, capture_output=True, text=True).stdout
    syms, addrs = load()

    def near(va):
        i = bisect.bisect_right(addrs, va) - 1
        if i < 0:
            return "?"
        name, base = syms[i][1], syms[i][0]
        return name if va == base else f"{name}+{va-base:#x}"

    for ln in out.splitlines():
        m = re.search(r'\b(?:bl|b|b\.eq|b\.ne|b\.hs|b\.lo|cbz|cbnz|tbz|tbnz)\s+#(0x[0-9a-f]+)', ln)
        print(ln + (f"   ; -> {near(int(m.group(1), 16))}" if m else ""))


if __name__ == "__main__":
    main()
