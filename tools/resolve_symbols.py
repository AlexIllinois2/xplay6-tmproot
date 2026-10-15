#!/usr/bin/env python3
"""Resolve the symbols this build hides from kallsyms (NON-KALLSYMS_ALL).

Two independent, purely offline methods:
  1. exported functions -> __ksymtab pairing: struct kernel_symbol{value,name},
     the name string is in __ksymtab_strings, so a qword equal to that string's VA
     sits right after the function VA.
  2. non-exported data (selinux_enforcing) -> disassemble its only writer
     (enforcing_setup) with capstone and fold adrp/add|ldr pairs into a VA.

Identity mapping (measured earlier): foff = VA - 0xffffffc000080000, _text at foff 0.
"""
import struct, sys
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

C = 0xffffffc000080000
img = open('fw/Image', 'rb').read()
ks = {}
for ln in open('art/kallsyms_real.txt'):
    a, t, nm = ln.split()
    ks[nm] = int(a, 16)

def off2va(o): return o + C
def va2off(v): return v - C

def read_str(name):
    lit = name.encode() + b'\0'
    hits, i = [], 0
    while True:
        i = img.find(lit, i)
        if i < 0: break
        prev = img[i-1] if i else 0
        ok = not (48 <= prev <= 57 or 65 <= prev <= 90 or 97 <= prev <= 122 or prev == 95)
        if ok: hits.append(i)
        i += 1
    return hits

def ksymtab(name):
    out = []
    for o in read_str(name):
        sva = off2va(o)
        for p in range(0, len(img) - 8, 8):
            if struct.unpack_from('<Q', img, p)[0] == sva:
                val = struct.unpack_from('<Q', img, p - 8)[0]
                if C <= val < C + len(img):
                    out.append((val, p - 8, o))
    return out

md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
md.detail = False

def data_refs(va, nbytes=512):
    """Fold adrp+add/ldr/str into referenced data VAs for a function."""
    o = va2off(va)
    refs = {}
    page = {}
    for ins in md.disasm(img[o:o + nbytes], va):
        m, ops = ins.mnemonic, ins.op_str
        if m == 'adrp':
            rd = ops.split(',')[0].strip()
            imm = int(ops.split('#')[1].split(',')[0].strip(), 0)
            page[rd] = imm
        elif m in ('add', 'ldr', 'str', 'ldrb', 'strb', 'ldur', 'stur') and ops.split(',')[0].strip() in page:
            rd = ops.split(',')[0].strip()
            base = page[rd]
            rest = ops.split(',', 1)[1]
            k = rest.find('#')
            addend = 0
            if '[' in rest:
                j = rest.find('#', rest.find('['))
                if j >= 0:
                    t = rest[j+1:].split(']')[0].split(',')[0].strip()
                    addend = int(t, 0) if t else 0
            elif k >= 0:
                t = rest[k+1:].split(',')[0].strip()
                try: addend = int(t, 0)
                except ValueError: addend = 0
            tgt = base + addend
            if C <= tgt < C + len(img):
                refs.setdefault(tgt, []).append(hex(ins.address) + ':' + m + ' ' + ops)
    return refs

def probe(v, width=8):
    o = va2off(v)
    return img[o:o + width].hex(' ') if 0 <= o < len(img) else 'out-of-image'

print('=== 1) exported via __ksymtab ===')
want = ['commit_creds', 'prepare_kernel_cred', 'override_creds', 'call_usermodehelper',
        'copy_from_user', 'copy_to_user', 'find_task_by_vpid', 'set_fs', 'kmalloc_caches',
        'selinux_inode_setsecurity']
res = {}
for w in want:
    c = ksymtab(w)
    uniq = sorted({v for v, p, so in c})
    if uniq:
        res[w] = uniq[0]
        print('  %-24s %s  %s' % (w, [hex(x) for x in uniq], 'codebytes=' + probe(uniq[0], 16)))
    else:
        print('  %-24s not found via ksymtab' % w)

print('\n=== 2) selinux_enforcing via xref from its writer ===')
for anchor in ('enforcing_setup', 'selinux_enabled_setup'):
    if anchor not in ks:
        print('  anchor %s absent from kallsyms' % anchor); continue
    print('  anchor %s @ %s' % (anchor, hex(ks[anchor])))
    for tgt, uses in sorted(data_refs(ks[anchor]).items()):
        print('     -> %s  Image[] = %s   (refs: %s)' % (hex(tgt), probe(tgt, 8), uses[0]))
print('  known selinux_enabled @ %s Image[] = %s'
      % (hex(ks.get('selinux_enabled', 0)), probe(ks['selinux_enabled'], 16)) if 'selinux_enabled' in ks else '')

print('\n=== 3) sanity on the .data levers we already have ===')
for w in ('modprobe_path', 'core_pattern', 'orderly_poweroff'):
    if w in ks:
        print('  %-14s %s Image[] = %r' % (w, hex(ks[w]), img[va2off(ks[w]):va2off(ks[w]) + 32].split(b'\0')[0]))
with open('art/kernel_offsets.txt', 'w') as f:
    for k, v in sorted(res.items()): f.write('%-24s %016x\n' % (k, v[0] if isinstance(v, list) else v))
    for k in ('modprobe_path', 'core_pattern', 'selinux_enabled', 'avc_has_perm',
              'kgsl_fops', 'binder_fops', 'ion_fops'):
        if k in ks: f.write('%-24s %016x\n' % (k, ks[k]))
print('\nwrote art/kernel_offsets.txt')
