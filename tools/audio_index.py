#!/usr/bin/env python3
"""Build the Android-6 audio tuning baseline index, and prove which control names the
shipped configs actually reference against the controls the live card exposes.

Why this direction: the portable unit for a 7.x port is the (control, value) pair, not the
file.  A mixer_paths XML that names a control the kernel does not expose is dead weight on
6 and a guaranteed miss on 7 -- so the diff has to be measured, not assumed.
Re-run it later with --live pointing at an Android 7 dump to get the port gap list.
"""
import argparse, os, re, sys, hashlib, tarfile, collections

CTL_RE = re.compile(r'<ctl\s+name="([^"]+)"')   # only real mixer ops: name="..." alone also
                                                 # matches MediaProfile/@name and friends, which
                                                 # inflated the gap to 858 on the first run


def live_controls(path):
    """tinymix -D <card> output: 'N\\tTYPE\\tnum\\tname   value...' header then rows."""
    out = {}
    rows = open(path, encoding='utf-8', errors='replace').read().split('\n')
    hdr = next((i for i, l in enumerate(rows) if l.startswith('ctl\t') or l.startswith('ctl ')), None)
    if hdr is None:
        sys.exit("FLOOR FAIL: no 'ctl' header row in %s -- the ruler cannot read its own input" % path)
    for line in rows[hdr + 1:]:
        if not line.strip():
            continue
        parts = line.split('\t')
        if len(parts) < 4:
            parts = line.split(None, 3)
        try:
            idx, typ, num = int(parts[0]), parts[1], parts[2]
        except (ValueError, IndexError):
            continue
        rest = parts[3] if len(parts) > 3 else ''
        nm, _, val = rest.partition('  ')
        out[nm.strip()] = (typ, num, val.strip())
    return out


def referenced(root):
    """control names referenced by the shipped xml/txt configs."""
    hits = collections.defaultdict(set)
    for dirpath, _, files in os.walk(root):
        for fn in files:
            if not fn.endswith(('.xml', '.txt', '.conf')):
                continue
            p = os.path.join(dirpath, fn)
            try:
                txt = open(p, encoding='utf-8', errors='replace').read()
            except OSError:
                continue
            for m in CTL_RE.finditer(txt):
                hits[m.group(1)].add(os.path.relpath(p, root))
    return hits


def unpack(tgz, dest):
    if os.path.isdir(dest) and os.listdir(dest):
        return
    with tarfile.open(tgz) as tf:
        tf.extractall(dest)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--base', default='art/audio-6.0.1')
    ap.add_argument('--live', default=None, help='dir holding tinymix output + shipped/ (default: --base/live)')
    a = ap.parse_args()
    live = a.live or os.path.join(a.base, 'live')

    for name in ('etc_audio.tgz', 'hal_audio.tgz'):
        t = os.path.join(live, name)
        if os.path.exists(t):
            unpack(t, os.path.join(a.base, 'shipped'))
    shipped = os.path.join(a.base, 'shipped')

    mix = os.path.join(live, 'tinymix-D0.txt')
    if not os.path.exists(mix):
        mix = os.path.join(live, 'extra', 'tinymix-D0.txt')
    lv = live_controls(mix)
    rf = referenced(shipped)

    names = set(lv)
    refs = set(rf)
    missing = sorted(r for r in refs if r not in names)
    print('live controls            : %d' % len(names))
    print('names referenced by configs: %d' % len(refs))
    print('referenced but NOT exposed : %d' % len(missing))
    for m in missing[:15]:
        print('   MISS %-46s <- %s' % (m[:46], ', '.join(sorted(rf[m]))[:90]))
    # per-file: only ONE mixer_paths is loaded on a given machine, so the aggregate gap
    # above is not the port denominator.  The file with the smallest gap is the one this
    # machine's HAL actually reads -- prove it, do not assume it.
    print('\nper-config-file gap (sorted by misses):')
    per = collections.defaultdict(set)
    for ctl, srcs in rf.items():
        for s in srcs:
            per[s].add(ctl)
    rows = []
    for s, ctls in per.items():
        miss = sorted(c for c in ctls if c not in names)
        rows.append((len(miss), len(ctls), s, miss))
    for nmiss, ntot, s, miss in sorted(rows)[:10]:
        print('   %-58s ctl=%-5d misses=%-5d %s' % (s, ntot, nmiss, ('e.g. ' + miss[0][:40]) if miss else ''))
    if len(rows) > 10:
        print('   ... %d more config files with larger gaps (other codecs/machines)' % (len(rows) - 10))
    unused = sorted(n for n in names if n not in refs)
    print('exposed but never named in configs: %d (kernel/DSP surface a port must not assume)' % len(unused))

    with open(os.path.join(a.base, 'controls-live.tsv'), 'w') as f:
        for k in sorted(lv):
            typ, num, val = lv[k]
            srcs = ', '.join(sorted(rf.get(k, []))) or '-'
            f.write('%s\t%s\t%s\t%s\t%s\n' % (k, typ, num, val, srcs))
    print('wrote %s' % os.path.join(a.base, 'controls-live.tsv'))

    man = os.path.join(a.base, 'MANIFEST.txt')
    with open(man, 'w') as out:
        for dirpath, _, files in os.walk(a.base):
            for fn in files:
                if fn == 'MANIFEST.txt':
                    continue
                p = os.path.join(dirpath, fn)
                h = hashlib.sha256(open(p, 'rb').read()).hexdigest()[:16]
                out.write('%s\t%d\t%s\n' % (h, os.path.getsize(p), os.path.relpath(p, a.base)))
    n = sum(1 for _ in open(man))
    print('wrote %s (%d entries)' % (man, n))


if __name__ == '__main__':
    main()
