#!/usr/bin/env python3
"""Read a QACT workspace (.qwsp, plain XML) + the sibling .acdb files and emit the
tuning dictionary: which interfaces/params exist, their ranges, which module/topology
owns them, and the fingerprint of every calibration file.

Measured limit, stated up front: the workspace holds DEFINITIONS only -- 798
CONFIG_ELEMENT rows carry name/type/min/max and no value.  The shipped values live in
the .acdb binaries, so this table is the "what can be tuned" denominator, not the
"what it is tuned to" answer.  Do not let a later reader call this the tuning itself.
"""
import argparse, collections, hashlib, os, re, struct, xml.etree.ElementTree as ET


def walk_ws(path):
    r = ET.parse(path).getroot()
    rows_if = []
    for iface in r.iter('INTERFACE'):
        iid = iface.get('I_id')
        nm = iface.get('name') or ''
        hexs = iface.get('hexStr') or ''
        mx = iface.get('maxSize') or ''
        els = [c for c in iface if c.tag == 'CONFIG_ELEMENT']
        if not els:
            rows_if.append((iid, nm, hexs, mx, 0, ''))
        for e in els:
            rows_if.append((iid, nm, hexs, mx, len(els),
                            '%s|%s|%s..%s' % (e.get('name'), e.get('type'), e.get('min'), e.get('max'))))
    blocks = [(b.get('name'), b.get('ID'), b.get('dataView_ID'), b.get('type'),
               b.get('gain_dependant', ''), b.get('dynamicModule', ''), b.get('volumeModule', ''))
              for b in r.iter('Block')]
    tops = [(t.get('name'), t.get('ID'), t.get('type')) for t in r.iter('TOPOLOGY')]
    areas = [(a.get('type'), a.get('name')) for a in r.iter('AREA')]
    container = r.find('ACDBFile_Paths')
    files = [f.get('path') for f in container] if container is not None else []
    return r, rows_if, blocks, tops, areas, files


def acdb_head(path):
    """QCMSNDDB files: 8-byte magic, 8 zero bytes, then a sub-block {tag, len, len} and a
    MODIFIED stamp plus build string.  Report what is actually readable, nothing more."""
    d = open(path, 'rb').read()
    magic = d[:8]
    tag = d[16:20]
    try:
        l1, l2 = struct.unpack('<2I', d[20:28])
    except struct.error:
        l1 = l2 = 0
    m = re.search(rb'MODIFIED(.{0,40})', d[:200])
    stamp = m.group(1).decode('latin1').strip(' \x00') if m else ''
    h = hashlib.sha256(d).hexdigest()
    return magic.decode('latin1'), tag.decode('latin1'), l1, l2, stamp[:24], len(d), h


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('ws')
    ap.add_argument('--outdir', default=None)
    a = ap.parse_args()
    outdir = a.outdir or os.path.dirname(a.ws)
    stem = re.sub(r'[^A-Za-z0-9_.-]', '_', os.path.basename(os.path.dirname(a.ws)))

    root, rows_if, blocks, tops, areas, files = walk_ws(a.ws)
    n_if = len(set(r[0] for r in rows_if))
    named_if = sum(1 for i in root.iter('INTERFACE') if i.get('name'))
    print('workspace %s  WSVersID=%s' % (os.path.basename(a.ws), root.get('WSVersID')))
    print('  INTERFACE 元素: 带名字 %d / 只带 I_id %d   去重 I_id=%d   参数行=%d  blocks=%d  topologies=%d  areas=%d'
          % (named_if, len(list(root.iter('INTERFACE'))) - named_if, n_if,
             sum(1 for r in rows_if if r[5]), len(blocks), len(tops), len(areas)))
    print('  声明引用的 cal 文件: %s' % ', '.join(files))

    p1 = os.path.join(outdir, 'acdb-params.' + stem + '.tsv')
    with open(p1, 'w') as f:
        f.write('interface_id\tinterface_name\thexStr\tmaxSize\tparam_count_in_interface\tparam|type|range\n')
        for row in rows_if:
            f.write('\t'.join(str(x) for x in row) + '\n')
    p2 = os.path.join(outdir, 'acdb-blocks.' + stem + '.tsv')
    with open(p2, 'w') as f:
        f.write('block\tmodule_id\tdataView_ID\tdirection\tgain_dependant\tdynamicModule\tvolumeModule\n')
        for row in blocks:
            f.write('\t'.join(str(x) for x in row) + '\n')
    p3 = os.path.join(outdir, 'acdb-topologies.' + stem + '.tsv')
    with open(p3, 'w') as f:
        f.write('topology\tid\tdirection\n')
        for row in tops:
            f.write('\t'.join(str(x) for x in row) + '\n')
    print('  wrote %s / blocks / topologies' % p1)

    p4 = os.path.join(outdir, 'acdb-files.' + stem + '.tsv')
    with open(p4, 'w') as f:
        f.write('file\tmagic\tsubblock\tsizes\tmodified_stamp\tbytes\tsha256\n')
        for fn in sorted(os.listdir(os.path.dirname(a.ws))):
            if not fn.endswith('.acdb'):
                continue
            magic, tag, l1, l2, stamp, size, h = acdb_head(os.path.join(os.path.dirname(a.ws), fn))
            f.write('%s\t%s\t%s\t%d/%d\t%s\t%d\t%s\n' % (fn, magic, tag, l1, l2, stamp, size, h))
            print('  %-22s %s/%s len=%d/%d  modified=%s  %d B' % (fn, magic, tag, l1, l2, stamp, size))
    print('  wrote %s' % p4)


if __name__ == '__main__':
    main()
