#!/usr/bin/env python3
"""Turn a QC mixer_paths XML into a comparable + replayable tuning table.

Two outputs, because the port needs both:
  1) initial-block vs live-card delta  -- which of the shipped "initial" settings are
     actually on the card when idle, and which are applied by somebody else (voice
     calibration, ADSP) and therefore read something else until a call starts;
  2) per-use-case ctl sets with nested <path> includes flattened -- so a 7.x port can
     replay one named use case verbatim instead of guessing from control names.
"""
import argparse, os, re, xml.etree.ElementTree as ET, collections


def parse(path):
    root = ET.parse(path).getroot()
    init = []                      # top-level <ctl> = initial block
    cases = collections.OrderedDict()

    def walk(node, bucket):
        for ch in node:
            if ch.tag == 'ctl':
                bucket.append((ch.get('name'), ch.get('id'), ch.get('value')))
            elif ch.tag == 'path':
                nm = ch.get('name')
                if len(list(ch)) == 0:           # include reference, no body
                    bucket.append(('INCLUDE', nm, None))
                else:
                    sub = []
                    walk(ch, sub)
                    cases.setdefault(nm, []).extend(sub)

    for ch in root:
        if ch.tag == 'ctl':
            init.append((ch.get('name'), ch.get('id'), ch.get('value')))
        elif ch.tag == 'path':
            nm = ch.get('name')
            sub = []
            walk(ch, sub)
            cases[nm] = sub
    return init, cases


def assemble_init(init):
    """<ctl name=X id=i value=v> rows -> {X: {i: v}} -> {X: 'v0 v1 v2'}."""
    per = collections.defaultdict(dict)
    for nm, idx, val in init:
        if nm is None:
            continue
        per[nm][int(idx) if idx is not None else 0] = val
    out = {}
    for nm, d in per.items():
        out[nm] = ' '.join(str(d[i]) for i in sorted(d))
    return out


def norm(s):
    if s is None:
        return ''
    return ' '.join(str(s).split()).lower()


def load_enum_table(path):
    """live/enum-items.tsv rows: 'NAME<TAB>NAME:<TAB>>cur<TAB>item...' -> {NAME: [items]}."""
    tbl = {}
    if not os.path.exists(path):
        return tbl
    for line in open(path, encoding='utf-8'):
        p = line.rstrip('\n').split('\t')
        if len(p) < 2:
            continue
        items = [x.lstrip('>').strip() for x in p[2:]] if p[1].startswith(p[0] + ':') else [x.lstrip('>').strip() for x in p[1:]]
        tbl[p[0]] = items
    return tbl


def canon(name, typ, val, enum_tbl):
    """mixer_paths writes an enum INDEX ('0'), the card reports the ITEM NAME ('Off').
    Comparing them raw produced 250 fake differences on the first run -- map both to the
    index whenever the control is an enum and the table is known."""
    if val is None:
        return ''
    v = ' '.join(str(val).split())
    if typ == 'BOOL':                      # the card renders bools as On/Off, XML writes 0/1
        return ' '.join(x if x not in ('0', '1') else ('off' if x == '0' else 'on')
                        for x in v.lower().split())
    if typ == 'ENUM' and name in enum_tbl:
        items = enum_tbl[name]
        if v.lstrip('-').isdigit():
            i = int(v)
            return '%d:%s' % (i, items[i] if 0 <= i < len(items) else '?')
        low = v.lower()
        for i, it in enumerate(items):
            if it.lower() == low:
                return '%d:%s' % (i, it)
        return 'unknown-item:' + low
    return ' '.join(v.lower().split())


def flatten(cases):
    """Expand INCLUDE refs one table deep; flag cycles rather than recursing forever."""
    flat = {}
    for nm, body in cases.items():
        acc, stack = [], set()

        def expand(items):
            for entry in items:
                if entry[0] == 'INCLUDE':
                    ref = entry[1]
                    if ref in stack or ref not in cases:
                        acc.append(('MISSING-OR-CYCLE', ref, None))
                        continue
                    stack.add(ref)
                    expand(cases[ref])
                else:
                    acc.append(entry)
        expand(body)
        flat[nm] = [e for e in acc if e[0] != 'INCLUDE']
    return flat


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('xml')
    ap.add_argument('--live', default='art/audio-6.0.1/controls-live.tsv')
    ap.add_argument('--outdir', default='art/audio-6.0.1')
    a = ap.parse_args()

    init, cases = parse(a.xml)
    xmlinit = assemble_init(init)
    live, livetyp = {}, {}
    for line in open(a.live, encoding='utf-8'):
        p = line.rstrip('\n').split('\t')
        if len(p) >= 4:
            live[p[0]] = p[3]
            livetyp[p[0]] = p[1]
    etbl = {}
    for cand in (os.path.join(os.path.dirname(a.live), 'enum-items.tsv'),
                 os.path.join(a.base if hasattr(a, 'base') else 'art/audio-6.0.1', 'live', 'enum-items.tsv')):
        etbl = load_enum_table(cand)
        if etbl:
            break
    print('%s: initial ctl=%d distinct names=%d, use-case paths=%d, enum tables=%d'
          % (os.path.basename(a.xml), len(init), len(xmlinit), len(cases), len(etbl)))

    both = [n for n in xmlinit if n in live]
    same = [n for n in both if canon(n, livetyp[n], xmlinit[n], etbl) == canon(n, livetyp[n], live[n], etbl)]
    diff = [n for n in both if canon(n, livetyp[n], xmlinit[n], etbl) != canon(n, livetyp[n], live[n], etbl)]
    ghost = [n for n in xmlinit if n not in live]
    print('   vs idle card snapshot: 可比 %d · 一致 %d · 不同 %d · XML 写了但卡上没有 %d'
          % (len(both), len(same), len(diff), len(ghost)))
    stem = re.sub(r'[^A-Za-z0-9_.-]', '_', os.path.splitext(os.path.basename(a.xml))[0])
    dn = os.path.join(a.outdir, 'initial-vs-idle.' + stem + '.tsv')
    with open(dn, 'w') as f:
        f.write('control\txml_initial\tidle_value\tverdict\n')
        for n in sorted(xmlinit):
            if n not in live:
                f.write('%s\t%s\t-\tnot-on-card\n' % (n, xmlinit[n]))
            elif canon(n, livetyp[n], xmlinit[n], etbl) == canon(n, livetyp[n], live[n], etbl):
                f.write('%s\t%s\t%s\tmatch\n' % (n, xmlinit[n], live[n]))
            else:
                f.write('%s\t%s\t%s\tDIFFERS\n' % (n, xmlinit[n], live[n]))
    print('   wrote %s' % dn)

    flat = flatten(cases)
    un = os.path.join(a.outdir, 'usecase-table.' + stem + '.tsv')
    with open(un, 'w') as f:
        f.write('use_case\tctl\tid\tvalue\ton-card\n')
        for nm, body in flat.items():
            for ctl, idx, val in body:
                if ctl == 'MISSING-OR-CYCLE':
                    f.write('%s\t!include-unresolved\t-\t%s\t?\n' % (nm, idx))
                    continue
                f.write('%s\t%s\t%s\t%s\t%s\n' % (nm, ctl, idx or '', val,
                                                  'yes' if ctl in live else 'NO'))
    offcard = set()
    for nm, body in flat.items():
        for ctl, idx, val in body:
            if ctl != 'MISSING-OR-CYCLE' and ctl not in live:
                offcard.add(ctl)
    print('   wrote %s (%d paths, %d ctl sets, %d distinct controls not on card)'
          % (un, len(flat), sum(len(b) for b in flat.values()), len(offcard)))

    rp = os.path.join(a.outdir, 'replay', stem)
    os.makedirs(rp, exist_ok=True)
    for nm, body in flat.items():
        safe = re.sub(r'[^A-Za-z0-9_.-]', '_', nm)
        with open(os.path.join(rp, safe + '.sh'), 'w') as f:
            f.write('#!/system/bin/sh\n# use case "%s" from %s -- apply verbatim on the target card\n' % (nm, os.path.basename(a.xml)))
            for ctl, idx, val in body:
                if ctl == 'MISSING-OR-CYCLE':
                    continue
                if idx:
                    f.write("tinymix -D 0 '%s' %s %s\n" % (ctl, idx, val))
                else:
                    f.write("tinymix -D 0 '%s' '%s'\n" % (ctl, val))


if __name__ == '__main__':
    main()
