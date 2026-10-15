#!/usr/bin/env python3
"""Robust ADRP-page tracking (both `add rd,rn,#lo12` and `ldr rt,[rn,#imm]`
forms) to find every reader/writer of the SELinux globals page 0x189b000.

Purpose: confirm 0xffffffc00189be74 is the enforcing flag by showing that the
AVC/security-server code that decides "deny vs allow" loads exactly that word.
"""
import sys
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

C = 0xffffffc000080000
img = open('fw/Image', 'rb').read()
sym = sorted((int(l.split()[0], 16), l.split()[2]) for l in open('art/kallsyms_real.txt'))
A = [a for a, _ in sym]
nm = {v: k for k, v in sym}
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
PAGE = 0xffffffc00189b000
TARGET = PAGE + 0xe74

def fn_range(va):
    i = A.index(va); j = i + 1
    while j < len(A) and A[j] <= va:
        j += 1
    return va, (A[j] if j < len(A) else va + 0x400)

def tracked(fn):
    va = nm[fn]; lo, hi = fn_range(va)
    page = {}          # reg -> absolute page base from adrp
    off  = {}          # reg -> full address materialized by add
    refs = []
    for ins in md.disasm(img[lo - C:hi - C], lo):
        s = ins.op_str; m = ins.mnemonic
        try:
            if m == 'adrp':
                r, imm = s.split(', ')
                page[r.strip()] = int(imm.split('#')[1], 0)
                off.pop(r.strip(), None)
            elif m == 'add':
                p = [x.strip() for x in s.split(',')]
                dst = p[0]
                if len(p) == 3 and p[1] in page and p[2].startswith('#'):
                    off[dst] = page[p[1]] + int(p[2].lstrip('#'), 0)
                    page.pop(dst, None)
                elif len(p) == 4 and p[1] in page and p[3].startswith('#'):
                    off[dst] = page[p[1]] + int(p[3].lstrip('#'), 0)
            elif m in ('ldr', 'str', 'ldrb', 'strb', 'ldur', 'stur', 'ldrsb', 'ldrsw') and '[' in s:
                inner = s[s.index('[') + 1:s.index(']')]
                ip = [x.strip() for x in inner.split(',')]
                base = ip[0].lstrip('#')
                imm = int(ip[1].lstrip('#'), 0) if len(ip) > 1 and ip[1].startswith('#') else 0
                if base in page:
                    refs.append((page[base] + imm, m, hex(ins.address)))
                elif base in off:
                    refs.append((off[base] + imm, m, hex(ins.address)))
            elif m in ('cbz', 'cbnz', 'tbz', 'tbnz') and False:
                pass
        except Exception as e:
            pass
    return lo, hi, refs

cands = {}
for fn in list(sys.argv[1:]) or ['context_struct_compute_av', 'security_compute_av',
                                 'avc_has_perm', 'avc_has_perm_noaudit', 'selinux_init',
                                 'services_name_to_sid', 'security_get_sid_from_context',
                                 'policydb_read', 'sel_write_load', 'ss pol']:
    if fn not in nm:
        continue
    lo, hi, refs = tracked(fn)
    samepage = [(hex(a), m, ad) for a, m, ad in refs if PAGE <= a < PAGE + 0x1000]
    tgt = [x for x in samepage if int(x[0], 16) == TARGET]
    for a, m, ad in samepage:
        cands.setdefault(a, set()).add(fn + ':' + m)
    print('%-30s size=0x%-6x page-refs=%-3d TARGET-hit=%s' % (fn, hi - lo, len(samepage), tgt or '-'))

print('\n=== who touches the enforcing word 0x%x ===' % TARGET)
for a, who in sorted(cands.items()):
    if a == TARGET:
        print('  HIT %s <- %s' % (hex(a), sorted(who)))
print('\n=== all 0x189b000-page globals referenced by the SELinux code ===')
for a, who in sorted(cands.items()):
    print('  %s  %s' % (hex(a), sorted(who)[:3]))
