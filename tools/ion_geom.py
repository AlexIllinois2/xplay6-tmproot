#!/usr/bin/env python3
"""Binary-side confirmation of the ion geometry + the racy FREE shape.

1. sizeof(struct ion_buffer): the kmalloc immediate inside ion_buffer_create.
   (Source from the LineageOS HB branch suggests 184 -> kmalloc-192, but vivo's
   config could shift struct mutex, so read it from THIS kernel.)
2. ion_ioctl's ION_IOC_FREE case must be get_by_id -> ion_free -> ion_handle_put
   with no f_mode gate.
Prints bl targets resolved through the recovered kallsyms.
"""
import struct, sys
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

C = 0xffffffc000080000
img = open('fw/Image', 'rb').read()
sym = sorted((int(l.split()[0], 16), l.split()[2]) for l in open('art/kallsyms_real.txt'))
A = [a for a, _ in sym]
byaddr = dict(sym)
name_of = {}
for a, n in sym:
    name_of.setdefault(a, n)
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)

def rng(nm):
    va = name_of_inv[nm]
    i = A.index(va); j = i + 1
    while j < len(A) and A[j] <= va:
        j += 1
    return va, (A[j] if j < len(A) else va + 0x600)

name_of_inv = {v: k for k, v in name_of.items()}

def callee(addr):
    if addr in name_of:
        return name_of[addr]
    i = max(k for k in A if k <= addr)
    return '%s+0x%x' % (byaddr[i], addr - i)

def show(nm, want_mov=False):
    if nm not in name_of_inv:
        print('  %-24s ABSENT from kallsyms' % nm); return
    lo, hi = rng(nm)
    print('\n--- %s [%s,0x%x) size=0x%x ---' % (nm, hex(lo), hi, hi - lo))
    lastmov = None
    for ins in md.disasm(img[lo - C:hi - C], lo):
        m, s = ins.mnemonic, ins.op_str
        if m == 'mov' and '#' in s and want_mov:
            print('   %016x  %-7s %s' % (ins.address, m, s))
            lastmov = s.split('#')[1]
        if m == 'bl':
            t = int(s.lstrip('#'), 0) if s.startswith('#') else None
            print('   %016x  %-7s %s%s' % (ins.address, m, callee(t) if t else s,
                                           ('   <== arg ' + lastmov) if (want_mov and lastmov) else ''))
            if want_mov:
                lastmov = None
        if m in ('cmp', 'subs') and want_mov is False:
            print('   %016x  %-7s %s' % (ins.address, m, s))

for nm in ('ion_buffer_create', 'ion_buffer_alloc'):
    if nm in name_of_inv:
        show(nm, want_mov=True)
        break
else:
    print('ion_buffer_create not in kallsyms; searching ion_* creators:')
    print([n for n in name_of_inv if n.startswith('ion_')][:40])

print('\n=== ion_* symbols present ===')
print(sorted([n for n in name_of_inv if n.startswith('ion')])[:60])
