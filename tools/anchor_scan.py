#!/usr/bin/env python3
"""Two independent paths to kernel symbol addresses, cross-checked.

A) scan the Image for kallsyms_addresses[] = longest ascending run of 8-byte
   values inside the arm64 linear map; align by index with the device's masked
   /proc/kallsyms order.
B) DTB gives memstart_addr; with VA_BITS=39 the linear map is
   PAGE_OFFSET(0xffffff8000000000) + (phys - memstart), and the flat Image is
   loaded in that map, so VA ~= PAGE_OFFSET + kimage_phys - memstart + foff.
   Check whether A's recovered VAs match B's prediction.
"""
import struct, sys

img = open('fw/Image', 'rb').read()
n = len(img)
LIN = 0xffffff8000000000
WIN_HI = LIN + 0x200000000          # allow up to 8 GB of RAM in the linear map

dev = [ln.split() for ln in open('art/kallsyms_masked.txt') if ln.strip()]
devn = [p[2] for p in dev]; devt = [p[1] for p in dev]
ND = len(devn)

def run_from(o):
    prev = None; i = o; cnt = 0
    while i + 8 <= n:
        v = struct.unpack_from('<Q', img, i)[0]
        if not (LIN <= v < WIN_HI) or (prev is not None and v < prev):
            break
        prev = v; i += 8; cnt += 1
    return cnt, o, i - 8

best = (0, 0, 0)
for o in range(0, n - 16, 8):
    a = struct.unpack_from('<Q', img, o)[0]
    b = struct.unpack_from('<Q', img, o + 8)[0]
    if LIN <= a < WIN_HI and LIN <= b < WIN_HI and b >= a:
        c, s, e = run_from(o)
        if c > best[0]:
            best = (c, s, e)
            if c > ND * 0.5:
                break
cnt, s, e = best
print('longest ascending VA run: %d entries, file 0x%x..0x%x' % (cnt, s, e))
if cnt < 5000:
    sys.exit('A) failed - no address-array signature found')
v0 = struct.unpack_from('<Q', img, s)[0]
print('   first value 0x%016x  (implied foff-base 0x%x)' % (v0, s))
# index of the run start inside the device name order: find by searching where
# the run's values are consistent with type stratification
print('   device names near run: index guess = %d' % (s // 8))

# ---- B) DTB: memstart / chosen ------------------------------------------
def fdt_walk(blob):
    magic, totalsz, off_struct = struct.unpack_from('>III', blob, 0)
    assert magic == 0xd00dfeed, hex(magic)
    p = off_struct; depth = 0; out = []
    while p < len(blob):
        tok = struct.unpack_from('>I', blob, p)[0]; p += 4
        if tok == 1:
            depth += 1
        elif tok == 3:
            depth -= 1
            if depth < 0:
                break
        elif tok == 2:
            q = p
            while blob[q] not in (0,):
                q += 1
            name = blob[p:q].decode(); p = q + 1
            namelen, proplen = struct.unpack_from('>II', blob, p); p += 8
            prop = blob[p:p + proplen]; p += proplen
            while (p - off_struct) % 4: p += 1
            out.append((depth, name, prop))
        elif tok == 9:
            break
    return out

try:
    props = fdt_walk(open('fw/dtb.dtb', 'rb').read())
    for d, nm, pr in props:
        if nm in ('device_type', 'name') and pr.startswith(b'memory'):
            print('B) memory node at depth', d, pr)
    for d, nm, pr in props:
        if nm == 'reg' and len(pr) in (24, 16, 32):
            print('B) candidate reg:', [hex(x) for x in struct.unpack('>%dQ' % (len(pr)//8), pr)])
        if nm == 'bootargs':
            print('B) bootargs:', pr.split(b'\0')[0][:200])
except Exception as ex:
    print('B) DTB parse issue:', ex)

# ---- strings that mark writable .data targets ---------------------------
for pat in (b'/sbin/modprobe\0', b'system.conf\0', b'|core\0', b'%e\0'):
    i = img.find(pat)
    print('string %-18r at foff %s' % (pat, hex(i) if i >= 0 else 'NOT FOUND'))
