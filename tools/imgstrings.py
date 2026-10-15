#!/usr/bin/env python3
"""Dump the kernel Image's string records over a VA range, decoding ascii/gbk/utf-8.

String pooling puts same-translation-unit literals next to each other, so this is how a
vendor-added source file is recognised from the image alone.

usage: tools/imgstrings.py <start-hex-va> [end-hex-va]
"""
import os
import sys

BASE = 0xFFFFFFC000080000
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IMG = os.path.join(ROOT, "fw", "Image")


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    start = int(sys.argv[1], 16)
    end = int(sys.argv[2], 16) if len(sys.argv) > 2 else start + 0x400
    data = open(IMG, "rb").read()
    o0, o1 = start - BASE, end - BASE
    seg = data[o0:o1]
    recs, s = [], 0
    for i, b in enumerate(seg):
        if b == 0:
            if i > s:
                recs.append((start + s, seg[s:i]))
            s = i + 1
    for va, b in recs:
        used, txt = "?", None
        for enc in ("ascii", "utf-8", "gbk"):
            try:
                txt = b.decode(enc)
                used = enc
                break
            except Exception:
                continue
        if txt is None:
            txt = b.hex()
        print("%#x  [%s]  %s" % (va, used, txt))
    return 0


if __name__ == "__main__":
    sys.exit(main())
