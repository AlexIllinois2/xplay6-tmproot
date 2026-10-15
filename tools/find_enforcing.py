#!/usr/bin/env python3
"""Pin down selinux_enforcing (a plain int in .data) by xref, then confirm it.

In 3.18 SELinux the flag is read by context_struct_compute_av()
  "if (!selinux_enforcing) avd->allowed = ~0;"
and written by enforcing_setup(). Both are in kallsyms, so fold adrp + the
following base-register load/store (base is INSIDE the brackets) into a VA and
require it to land in .data and to hold the value 1 in the Image.
"""
import struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

C = 0xffffffc000080000
img = open('fw/Image', 'rb').read()
ks = {}
for ln in open('art/kallsyms_real.txt'):
    a, t, nm = ln.split(); ks[nm] = int(a, 16)
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)

DATA_LO, DATA_HI = 0xffffffc001600000, 0xffffffc001700000

def xrefs(va, nbytes=0x400):
    o = va - C
    page = {}
    out = []
    for ins in md.disasm(img[o:o + nbytes], va):
        m, s = ins.mnemonic, ins.op_str
        if m == 'adrp':
            rd = s.split(',')[0].strip()
            page[rd] = int(s.split('#')[1].split(',')[0].strip(), 0)
            for k in list(page):
                if k != rd and m == 'adrp':
                    pass
        elif m in ('add', 'ldr', 'str', 'ldrb', 'strb', 'ldur', 'stur'):
            parts = [p.strip() for p in s.split(',')]
            if m == 'add':
                rd, base = parts[0], None
                if rd in page and '#' in s:
                    out.append((page[rd] + int(s.rsplit('#', 1)[1].split(',')[0].strip(), 0),
                               ins.address, m, s))
            else:
                if '[' not in s:
                    continue
                inner = s[s.index('[') + 1:s.index(']')]
                ip = [x.strip() for x in inner.split(',')]
                base = ip[0]
                if base not in page:
                    continue
                add = int(ip[1].lstrip('#'), 0) if len(ip) > 1 and ip[1].startswith('#') else 0
                out.append((page[base] + add, ins.address, m, s))
    return out

cands = {}
for anchor in ('enforcing_setup', 'context_struct_compute_av', 'security_compute_av',
               'sel_write_load', 'ss_policy_load'):
    if anchor not in ks:
        print('%-28s (absent)' % anchor); continue
    hits = [(t, a, m, s) for t, a, m, s in xrefs(ks[anchor]) if DATA_LO <= t < DATA_HI]
    print('%-28s @ %s  data-window refs: %d' % (anchor, hex(ks[anchor]), len(hits)))
    for t, a, m, s in hits:
        w = struct.unpack_from('<I', img, t - C)[0]
        mark = '  <== int 1' if w == 1 else ''
        print('     %s  %-6s %s   val=%d%s' % (hex(t), m, s[:44], w, mark))
        if w == 1:
            cands[t] = cands.get(t, 0) + 1

print('\nanchors whose data ref holds 1:')
for t, c in sorted(cands.items(), key=lambda x: -x[1]):
    print('   %s  hits=%d  ctx=%s' % (hex(t), c, img[t - C - 16:t - C + 16].hex(' ')))

print('\n=== .data scan around selinux_enabled (0x%x) for int==1 ===' % ks['selinux_enabled'])
b = ks['selinux_enabled'] - C
for i in range(b - 0x400, b + 0x400, 4):
    if 0 <= i < len(img) and struct.unpack_from('<I', img, i)[0] == 1:
        print('   %016x  %s' % (i + C, img[i - 8:i + 12].hex(' ')))
