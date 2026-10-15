#!/usr/bin/env python3
"""Map the shape of a leaked kernel-heap stream: object stride, live vs free
blocks, and pointer clustering. Input = raw bytes captured by tools/broot.c."""
import sys, collections

path = sys.argv[1]
base_hint = int(sys.argv[2], 16) if len(sys.argv) > 2 else None
marker = sys.argv[3].encode() if len(sys.argv) > 3 else None
data = open(path, 'rb').read()
print("file=%s len=%d" % (path, len(data)))


def q(b, o):
    return int.from_bytes(b[o:o + 8], 'little')


if marker:
    hits, i = [], 0
    while True:
        j = data.find(marker, i)
        if j < 0:
            break
        hits.append(j)
        i = j + 1
    print("marker %r hits=%d at stream offsets %s" % (marker, len(hits), hits[:12]))

# Window is self-describing: search ANY offset for two equal qwords that are
# (512-aligned linear-map VA) - 0x50.  That value is the copy's own source address,
# so it gives slotVA = S - 0x50 without knowing the segment layout.
lin = 0xffffffc000000000
cand = []
single = []
# byte-granular scan: seg4 delivers the lock value 0x10001 (ODD), so the window
# starts at 0x1000+65537 = 69633 and every qword in it is misaligned by one byte.
for o in range(0, len(data) - 16):
    v = q(data, o)
    if v >= lin and v < lin + 0x4000000000 and (v - 0x50) % 512 == 0:
        (cand if q(data, o + 8) == v else single).append((o, v))
print("paired self-describing candidates: %d ; single-pointer candidates: %d" % (
    len(cand), len(single)))
for o, v in single[:6]:
    print("   single@%6d = %#x  slotVA=%#x  next_word=%#x" % (o, v, v - 0x50, q(data, o + 8)))
for o, v in cand[:4]:
    slot = v - 0x50
    page = slot & ~0xfff
    print("  stream+%d  S=%#x  slotVA=%#x  page=%#x  phys=%#x (%.2f GB)" % (
        o, v, slot, page, v - lin + 0x80000000, (v - lin + 0x80000000) / 2**30))
    nf = 0
    for a in range(page, page + 0x1000, 512):
        off = o + (a - v)
        if off < 0 or off + 8 > len(data):
            continue
        w = q(data, off)
        if page <= w < page + 0x1000 and w % 512 == 0:
            print("      obj %#x: first=%#x  <-- SLUB next (FREE, offset 0)" % (a, w))
            nf += 1
    print("      free objects visible in that page: %d" % nf)
    if marker:
        for h in [m for m in range(len(data)) if data.startswith(marker, m)][:8]:
            print("      marker at stream+%d -> absolute %#x (offset in object %d)" % (
                h, v0 if False else v + (h - o), v + (h - o)))
cands = cand
if marker and cands:
    o0, v0 = cands[0]
    for h in [m for m in range(len(data)) if data.startswith(marker, m)]:
        rel = h - o0
        if rel >= 0:
            print("   marker at stream+%d -> absolute %#x (obj+%d, in-object offset %d)" % (
                h, v0 + rel, (v0 + rel) // 512 - (v0 - 0x50) // 512, (v0 + rel) % 512))

def q(b, o):
    return int.from_bytes(b[o:o+8], 'little')

# 1) where does the leaked slot live? kernel VAs are 0xffffff80.. / 0xffffffc0..
ptrs = []
for o in range(0, len(data) - 8, 8):
    v = q(data, o)
    if v >= 0xffff800000000000:
        ptrs.append((o, v))
print("kernel-looking qwords: %d" % len(ptrs))
for o, v in ptrs[:20]:
    print("   off=%6d (%%512=%3d)  val=%016x  val%%512=%3d  region=%s" % (
        o, o % 512, v, v % 512,
        "linear" if (v >> 40) == 0xffffffc0 else ("vmalloc" if (v >> 40) < 0xffffffc0 else "?")))
if ptrs:
    lo = min(v for _, v in ptrs)
    hi = max(v for _, v in ptrs)
    print("  VA span: %x .. %x  (delta %x)" % (lo, hi, hi - lo))
    # most common low-12-bits value = the page's object layout fingerprint
    low12 = collections.Counter(v & 0xfff for _, v in ptrs)
    print("  top (VA & 0xfff): " + ", ".join("0x%03x:%d" % (k, c) for k, c in low12.most_common(6)))
    # offset-in-stream mod 512 for the dominant pointer value
    vals = collections.Counter(v for _, v in ptrs)
    for v, c in vals.most_common(4):
        offs = [o for o, x in ptrs if x == v]
        mod = collections.Counter(o % 512 for o in offs)
        print("  value %x seen %d times at stream offsets %s" % (v, c,
              ",".join(str(o) for o in offs[:6])))
        print("     mod512 histogram: %s" % dict(mod.most_common(4)))

# 2) poison / free detection
for pat, name in ((0x6b, "POISON_FREE(0x6b)"), (0xcc, "POISON_INUSE/redzone(0xcc)"),
                  (0x00, "zero"), (0x5a, "my-marker 0x5a")):
    runs = []
    i = 0
    while i < len(data):
        j = i
        while j < len(data) and data[j] == pat:
            j += 1
        if j - i >= 64:
            runs.append((i, j - i))
        i = j + 1 if j == i else j
    tot = sum(r for _, r in runs)
    print("  %-24s runs>=64B: %2d  total=%7d  first=%s" % (
        name, len(runs), tot, runs[:3]))

# 3) per-512B block summary
STRIDE = 512
nb = len(data) // STRIDE
print("  %d blocks of %d bytes:" % (nb, STRIDE))
kind = collections.Counter()
rows = []
for b in range(min(nb, 200)):
    blk = data[b*STRIDE:(b+1)*STRIDE]
    nz = sum(1 for x in blk if x)
    printable = sum(1 for x in blk if 32 <= x < 127)
    ptrc = sum(1 for o in range(0, STRIDE-8, 8)
               if 0xffffff8000000000 <= q(blk, o) <= 0xffffffffffffffff)
    if nz == 0:
        k = "ALLZERO"
    elif all(x == 0x6b for x in blk):
        k = "POISON6B"
    elif printable > 300:
        k = "ASCII-ish"
    elif ptrc >= 3:
        k = "ptr-heavy"
    elif nz < 64:
        k = "sparse"
    else:
        k = "opaque"
    kind[k] += 1
    if b < 24:
        head = blk[:16].hex()
        rows.append("    blk%3d @%#x  %-9s nonzero=%3d ascii=%3d ptrs=%2d head=%s" % (
            b, (base_hint + 0x50 + b*STRIDE) if base_hint else b*STRIDE, k, nz, printable, ptrc, head))
print("  class counts: %s" % dict(kind))
print("\n".join(rows))
