#!/usr/bin/env python3
"""Locate kallsyms_addresses[] in the stock kernel Image and print real VAs.

Why this works: arm64 3.18 has no KASLR, so the table stores final link-time
virtual addresses. kptr_restrict masks /proc/kallsyms *values* but preserves
*order*, so the device dump is the authoritative name sequence and we can align
to the array by index.

Validation is independent of the anchor: recovered VAs must stratify by symbol
type (text < rodata/data < bss) and the vast majority must sit in the arm64
linear-map window. Note CONFIG_KALLSYMS_ABSOLUTE_PERCPU makes per-cpu entries
small positive numbers, so we tolerate a minority of non-VA entries.
"""
import struct, sys
from collections import defaultdict

img = open('fw/Image', 'rb').read()
n = len(img)
LIN_LO, LIN_HI = 0xffffff8000000000, 0xffffffc000000000
print('Image size', n)

dev = [ln.split() for ln in open('art/kallsyms_masked.txt') if ln.strip()]
devn = [p[2] for p in dev]
devt = [p[1] for p in dev]
ND = len(devn)

def plausible(v):
    return (LIN_LO <= v < LIN_HI) or v < 0x200000      # percpu-absolute entries

# ---- candidate uint32 symbol counts -------------------------------------
cands = []
for off in range(0, n - 4, 4):
    v = struct.unpack_from('<I', img, off)[0]
    if not (20000 < v <= ND):
        continue
    start = off - 8 * v
    if start < 0:
        continue
    pv = [struct.unpack_from('<Q', img, start + 8 * k)[0]
          for k in (0, v // 3, v // 2, v - 1)]
    if sum(plausible(x) for x in pv) >= 3:
        cands.append((off, v, start))
print('candidates:', len(cands))

def score(start, v):
    vals = struct.unpack_from('<%dQ' % v, img, start)
    good = sum(plausible(x) for x in vals)
    if good < v * 0.97:
        return None
    g = defaultdict(list)
    for t, x in zip(devt[:v], vals):
        c = t.lower()
        if c in ('t',):
            g['text'].append(x)
        elif c in ('r', 'd'):
            g['ro'].append(x)
        elif c in ('b',):
            g['bss'].append(x)
    if not (g['text'] and g['ro'] and g['bss']):
        return None
    tx, ro, bs = (min(g['text']), max(g['text'])), (min(g['ro']), max(g['ro'])), (min(g['bss']), max(g['bss']))
    strat = tx[0] < tx[1] <= ro[0] < ro[1] <= bs[1]
    return (strat, good, vals, tx, ro, bs)

best = None
tried = 0
for off, v, start in cands:
    tried += 1
    if tried > 400:
        break
    s = score(start, v)
    if not s:
        continue
    strat, good, vals, tx, ro, bs = s
    if best is None or (strat, good) > (best[0], best[1]):
        best = (strat, good, v, start, off, vals, tx, ro, bs)
if not best:
    sys.exit('FAILED: no address table candidate survived validation')

strat, good, v, start, off, vals, tx, ro, bs = best
print('HIT num_syms=%d at 0x%x, array at 0x%x, plausible=%d/%d, stratified=%s'
      % (v, off, start, good, v, strat))
print('  text 0x%016x-0x%016x' % tx)
print('  ro   0x%016x-0x%016x' % ro)
print('  bss  0x%016x-0x%016x' % bs)

with open('art/kallsyms_real.txt', 'w') as f:
    for nm, ty, va in zip(devn[:v], devt[:v], vals):
        f.write('%016x %s %s\n' % (va, ty, nm))
print('wrote art/kallsyms_real.txt (%d rows, device had %d)' % (v, ND))

idx = {}
for ln in open('art/kallsyms_real.txt'):
    a, t, nm = ln.split()
    idx[nm] = int(a, 16)
for w in ['efi_head', '_text', 'stext', '_etext', 'selinux_enforcing', 'selinux_enabled',
          'sel_state', 'commit_creds', 'prepare_kernel_cred', 'override_creds',
          'init_task', 'init_cred', 'modprobe_path', 'core_pattern', 'orderly_poweroff',
          'poweroff_cmd', 'call_usermodehelper', 'kgsl_fops', 'adreno_fops', 'binder_fops',
          'binder_ioctl', 'ion_fops']:
    print('  %-22s %s' % (w, hex(idx[w]) if w in idx else 'MISSING'))
