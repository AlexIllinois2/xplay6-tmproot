#!/usr/bin/env python3
"""tools/cnt_scan.py -- find block headers in a NXP PCAP221 container without assuming them.

Prints every offset where a 4-byte printable marker occurs, plus the following bytes, and
tests whether a {magic4, type, id, version, size3} header shape chains through the file.
"""
import sys
from collections import Counter


def printable(b):
    return all(32 <= x < 127 for x in b)


def main(path):
    data = open(path, "rb").read()
    print(f"file={path} len={len(data)} (0x{len(data):x})")
    print("head:", data[:64].hex(" "))
    print("ascii:", "".join(chr(c) if 32 <= c < 127 else "." for c in data[:64]))

    # candidate markers: any 4-byte printable run that repeats or looks like a tag
    seen = {}
    for i in range(len(data) - 4):
        w = data[i:i + 4]
        if printable(w):
            seen.setdefault(w, []).append(i)
    top = sorted(seen.items(), key=lambda kv: -len(kv[1]))[:12]
    print("\nmost frequent 4-byte printable windows:")
    for w, offs in top:
        print(f"  {w!r} count={len(offs)} first={hex(offs[0]) if len(offs)<=6 else [hex(o) for o in offs[:6]]}")

    for tag in (b"[NXP", b"PM1_", b"devkit", b"seltech"):
        offs = [i for i in range(len(data) - len(tag)) if data[i:i + len(tag)] == tag]
        print(f"\ntag {tag!r}: {len(offs)} at {[hex(o) for o in offs[:12]]}")
        for o in offs[:8]:
            ctx = data[max(0, o - 8):o + 24]
            print(f"   {hex(o)}: {ctx.hex(' ')}  |{ ''.join(chr(c) if 32<=c<127 else '.' for c in data[o:o+24])}|")

    # header-shape hypothesis: 4 magic + type + id + version + size[3] LE
    print("\nheader-shape walk from each [NXP occurrence:")
    offs = [i for i in range(len(data) - 4) if data[i:i + 4] == b"[NXP"]
    for o in offs:
        hdr = data[o:o + 10]
        if len(hdr) < 10:
            continue
        size = int.from_bytes(hdr[7:10], "little")
        alt = int.from_bytes(hdr[6:9], "little")
        print(f"   {hex(o)} hdr={hdr.hex(' ')} size@[7:10]={size} size@[6:9]={alt} next={[hex(x) for x in offs if x > o][:1]}")

    # byte-value histogram of every 3rd byte to catch a stride
    print("\nstride check: distinct 2-byte patterns at even offsets in first 0x400:")
    c = Counter(data[i:i + 2] for i in range(0x40, 0x400, 2))
    print("   top:", [(k.hex(), v) for k, v in c.most_common(8)])


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "art/audio-6.0.1/live/tfa98xx/tfa98xx_PD1610.cnt")
