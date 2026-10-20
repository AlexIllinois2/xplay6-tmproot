#!/usr/bin/env python3
"""Rank the candidate mixer_paths files by how well their INITIAL block explains a live
card snapshot, because this device ships seven of them and nothing says which one the HAL
reads.  More than one snapshot makes it a classifier: a file must match the idle state AND
the playing state, so routing-dependent drift cannot be mistaken for a wrong file.

Honest limit: the initial block is written at module init and other actors (ADSP topology,
acdb, the amp driver) rewrite some controls afterwards -- so a top rank is evidence of
"which file was applied", not proof.  Report the residual, not just the winner.
"""
import argparse, os, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from audio_paths import parse, assemble_init, load_enum_table, canon


def read_snapshot(path):
    vals, types = {}, {}
    lines = open(path, encoding='utf-8', errors='replace').read().split('\n')
    hdr = next((i for i, l in enumerate(lines) if l.startswith('ctl')), None)
    if hdr is None:
        sys.exit('FLOOR FAIL: no ctl header in %s' % path)
    for l in lines[hdr + 1:]:
        if not l.strip():
            continue
        p = l.split('\t')
        if len(p) < 4:
            p = l.split(None, 3)
        try:
            int(p[0])
        except (ValueError, IndexError):
            continue
        nm, _, val = p[3].partition('  ')
        vals[nm.strip()] = val.strip()
        types[nm.strip()] = p[1]
    return vals, types


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--etcdir', default='art/audio-6.0.1/shipped/system/etc')
    ap.add_argument('--snap', action='append', required=True,
                    help='label=path, repeatable (idle and playing together is the point)')
    ap.add_argument('--enum', default='art/audio-6.0.1/live/enum-items.tsv')
    a = ap.parse_args()

    etbl = load_enum_table(a.enum)
    snaps = []
    for s in a.snap:
        label, _, path = s.partition('=')
        vals, types = read_snapshot(path)
        snaps.append((label, vals, types))
        print('snapshot %-10s controls=%d' % (label, len(vals)))

    files = sorted(f for f in os.listdir(a.etcdir) if f.endswith('.xml'))
    rows = []
    for f in files:
        try:
            init, _cases = parse(os.path.join(a.etcdir, f))
        except Exception as e:
            print('  skip %s: %s' % (f, e))
            continue
        xin = assemble_init(init)
        if not xin:
            continue
        score = []
        for label, vals, types in snaps:
            both = [n for n in xin if n in vals]
            if not both:
                score.append((0, 0))
                continue
            ok = sum(1 for n in both if canon(n, types[n], xin[n], etbl) == canon(n, types[n], vals[n], etbl))
            score.append((ok, len(both)))
        tot_ok = sum(s[0] for s in score)
        tot_n = sum(s[1] for s in score)
        resid = ', '.join('%s %d/%d' % (snaps[i][0], s[0], s[1]) for i, s in enumerate(score))
        rows.append((tot_ok / max(tot_n, 1), f, tot_ok, tot_n, resid, len(_cases)))

    print('\nranked by agreement with the card (%d snapshots combined):' % len(snaps))
    for rate, f, ok, n, resid, paths in sorted(rows, reverse=True):
        print('  %5.1f%%  %-42s %4d/%-4d  %-28s paths=%d' % (100 * rate, f, ok, n, resid, paths))

    best = sorted(rows, reverse=True)[:2]
    if len(best) >= 2 and best[0][0] - best[1][0] < 0.01:
        print('\nNOTE: top two differ by <1%% -- the snapshots cannot separate them yet; '
              'add a use-case that only one file defines.')


if __name__ == '__main__':
    main()
