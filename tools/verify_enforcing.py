#!/usr/bin/env python3
"""Verify selinux_enforcing with function-bounded disassembly.

enforcing_setup() must STORE to it; context_struct_compute_av() must LOAD it
(the 3.18 "if (!selinux_enforcing) avd->allowed = ~0;" shape). Two independent
readers/writers agreeing on one .data word, whose Image value is 1, is the bar.
"""
import struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

C = 0xffffffc000080000
img = open('fw/Image', 'rb').read()
sym = sorted((int(l.split()[0], 16), l.split()[2]) for l in open('art/kallsyms_real.txt'))
addrs = [a for a, _ in sym]
name = dict(sym)
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)

def fn_range(va):
    i = addrs.index(va)
    j = i + 1
    while j < len(addrs) and addrs[j] == va:
        j += 1
    nxt = addrs[j] if j < len(addrs) else va + 0x400
    # skip zero-size aliases
    while j < len(addrs) and addrs[j] == nxt:
        j += 1
    return va, nxt

def dump(nm):
    va = name_inv[nm]
    lo, hi = fn_range(va)
    print('\n--- %s  [%s .. %s)  len=0x%x ---' % (nm, hex(lo), hex(hi), hi - lo))
    o = lo - C
    hits = []
    page = {}
    for ins in md.disasm(img[o:o + (hi - lo)], lo):
        s = ins.op_str
        if ins.mnemonic == 'adrp':
            page[s.split(',')[0].strip()] = int(s.split('#')[1].split(',')[0].strip(), 0)
        line = '  %016x: %-8s %s' % (ins.address, ins.mnemonic, s)
        if ins.mnemonic in ('str', 'ldr', 'add', 'ldrb', 'strb') and '[' in s or ins.mnemonic == 'add':
            inner = s[s.index('[') + 1:s.index(']')] if '[' in s else None
            if inner:
                ip = [x.strip() for x in inner.split(',')]
                if ip[0] in page:
                    a = page[ip[0]] + (int(ip[1].lstrip('#'), 0) if len(ip) > 1 else 0)
                    hits.append((a, ins.mnemonic))
                    line += '   ;-> %016x val=%d' % (a, struct.unpack_from('<I', img, a - C)[0]
                                                     if C <= a < C + len(img) else -1)
            elif '#' in s:
                p = [x.strip() for x in s.split(',')]
                if len(p) > 2 and p[1].startswith('x') and p[1] in page and '#' in p[2]:
                    a = page[p[1]] + int(p[2].lstrip('#'), 0)
                    hits.append((a, ins.mnemonic))
                    line += '   ;-> %016x' % a
        if ins.mnemonic in ('stp', 'ldp', 'ret', 'b') and len(line) < 52:
            continue
        if ins.mnemonic in ('mov', 'cmp', 'ccmp', 'csel', 'bl', 'b', 'ret', 'sub', 'add',
                            'stp', 'ldp', 'cbz', 'b.ne', 'b.eq', 'ldp', 'and'):
            print(line)
    return hits

name_inv = {v: k for k, v in name.items()}
for nm in ('enforcing_setup', 'context_struct_compute_av'):
    if nm not in name_inv:
        print('%s absent' % nm); continue
    h = dump(nm)
    data = [(a, m) for a, m in h if 0xffffffc001600000 <= a < 0xffffffc001700000]
    print('  DATA refs:', [('0x%x' % a, m) for a, m in data])

tgt = 0xffffffc001657b40
print('\n=== verdict on candidate selinux_enforcing = %s ===' % hex(tgt))
print('  Image value at foff 0x%x = %d' % (tgt - C, struct.unpack_from('<I', img, tgt - C)[0]))
print('  neighbours  %s' % img[tgt - C - 16:tgt - C + 24].hex(' '))
