#!/usr/bin/env python3
"""Diff two or more card snapshots and print the portable unit: (control, value per state).

This is what a cross-ROM port actually compares -- not file bytes, but which controls move
when the same use case runs.  --label the states so the output reads as a route table.
With --attrib, each changed control is also checked against the use-case paths of a
mixer_paths XML, so a route's own ctl set can be confirmed (or refuted) from the card side.
"""
import argparse, os, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from audio_paths import parse, flatten
from audio_whichfile import read_snapshot


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--snap', action='append', required=True, help='label=path')
    ap.add_argument('--attrib', default=None, help='mixer_paths XML to attribute changes against')
    ap.add_argument('--out', default=None)
    a = ap.parse_args()

    snaps = []
    for s in a.snap:
        label, _, path = s.partition('=')
        snaps.append((label, path))
    base_label, base_path = snaps[0]
    bvals, btypes = read_snapshot(base_path)
    print('base %s controls=%d' % (base_label, len(bvals)))

    tables = []
    for label, path in snaps[1:]:
        vals, types = read_snapshot(path)
        moved = [(n, bvals[n], vals.get(n, '')) for n in bvals if n in vals and bvals[n] != vals[n]]
        added = [n for n in vals if n not in bvals]
        print('\n== %s: 相对 %s 变化 %d 枚（缺席 %d）==' % (label, base_label, len(moved), len(added)))
        for n, x, y in sorted(moved):
            print('   %-44s %-16s -> %s' % (n[:44], (x or '<none>')[:16], y or '<none>'))
        tables.append((label, vals, moved))

    if a.attrib:
        init, cases = parse(a.attrib)
        flat = flatten(cases)
        # which single use-case path explains a given (control -> new value) move?
        def explain(n, v):
            hits = [p for p, body in flat.items()
                    if any(c == n and (val is None or str(val) == v) for c, i, val in body)]
            return hits
        print('\n== 用 %s 的 use-case 表反查每处变化 ==' % os.path.basename(a.attrib))
        for label, vals, moved in tables:
            for n, x, y in sorted(moved):
                h = explain(n, y)
                print('   [%s] %-40s -> %-10s 出现在 %d 条 path: %s'
                      % (label, n[:40], y[:10], len(h), ', '.join(sorted(h)[:6]) or '无'))

    if a.out:
        with open(a.out, 'w') as f:
            f.write('control\ttype\t%s\n' % '\t'.join(l for l, _ in snaps))
            for n in bvals:
                row = [n, btypes[n], bvals[n]]
                for _, vals, _m in tables:
                    row.append(vals.get(n, ''))
                f.write('\t'.join(row) + '\n')
        print('\nwrote %s' % a.out)


if __name__ == '__main__':
    main()
