#!/usr/bin/env python3
"""tools/tfa_bf_family.py -- which field-numbering family does the RUNNING driver's bitfield table follow?

Open since ledger 250/251: the captured PA registers 0x00-0x0f could be TFA1-style (the flat
nxpTfa1 field enum, address = the byte the driver sends to regmap) or N1C/TFA2-style, and the first flat
scan of the container scored 59% 'legal' so it proved nothing (ledger 251).  This answers it from the one
object that matters -- the 220-row table compiled into our kernel Image (tools/tfa_bf_table.py) -- by
voting against every field family in fw/tfa-ref: a row counts for a family only when the reference header
declares the SAME (name, addr, pos, len) quadruple, not merely the same name.

Measured on this device: every exact match belongs to TFA1 (167/220) or the tfa9896 table that inherits
it (159/220); the N1C/TFA2 table contributes ZERO exact matches in any address bucket, including
0x00-0x0f.  So the low addresses are TFA1-numbered, and the residue is named per row rather than
extrapolated (PWMDEL/PWMSH/PWMRE at 0x41, TCC at 0x48, VERSION at 0x8f, TDMCOMP, REV91 are declared in
no reference header at all).

usage: tools/tfa_bf_family.py [--tsv art/audio-6.0.1/tfa-bf.TfaBfNames.tsv] [--out TSV] [--selftest]
"""
import argparse
import collections
import glob
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REF = os.path.join(ROOT, "fw", "tfa-ref", "inc")
ART = os.path.join(ROOT, "art/audio-6.0.1")
ENUM = re.compile(r"\b([A-Za-z0-9_]+_BF_([A-Za-z0-9_]+))\s*=\s*(0x[0-9a-fA-F]+)")
FIELD = re.compile(r"_TFA_FIELD_\s*\(\s*([A-Za-z0-9_]+)\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)", re.S)
BUCKETS = ["0x00-0x0f", "0x10-0x3f", "0x40-0x7f", ">=0x80"]


def bucket(a):
    return (BUCKETS[0] if a <= 0x0f else BUCKETS[1] if a <= 0x3f else
            BUCKETS[2] if a <= 0x7f else BUCKETS[3])


def families():
    fam = collections.defaultdict(dict)
    for path in sorted(glob.glob(os.path.join(REF, "*.h"))):
        base = os.path.basename(path)
        text = open(path, encoding="latin-1").read()
        for m in ENUM.finditer(text):
            v = int(m.group(3), 16)
            fam[f"{base}:{m.group(1).split('_BF_')[0]}"][(m.group(2), v >> 8, (v >> 4) & 0xf,
                                                          (v & 0xf) + 1)] = int(m.group(3), 16)
        for m in FIELD.finditer(text):
            fam[f"{base}:field-macro"][(m.group(1), int(m.group(2)), int(m.group(3)), int(m.group(4)))] = 0
    if not fam:
        sys.exit("gate: no _BF_ enums and no _TFA_FIELD_ macros parsed out of fw/tfa-ref -- the vote "
                 "would have no ballot, so no family may be declared")
    return fam


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tsv", default=os.path.join(ART, "tfa-bf.TfaBfNames.tsv"))
    ap.add_argument("--out")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if not os.path.exists(a.tsv):
        sys.exit(f"gate: {a.tsv} missing -- run tools/tfa_bf_table.py first; without the driver's own "
                 "table there is nothing to vote on")
    rows = []
    for line in open(a.tsv, encoding="utf-8").read().splitlines()[1:]:
        ad, p, ln, en, nm = line.split("\t")
        rows.append((nm, int(ad, 16), int(p), int(ln), int(en, 16)))
    fam = families()
    print(f"driver table {len(rows)} rows; {len(fam)} reference families "
          f"({sum(len(v) for v in fam.values())} declared fields)")
    exact = collections.defaultdict(collections.Counter)
    per_family = collections.Counter()
    unres = collections.defaultdict(list)
    for (nm, ad, p, ln, en) in rows:
        b = bucket(ad)
        hits = sorted(k for k, v in fam.items() if (nm, ad, p, ln) in v)
        exact[b]["all"] += 1
        for h in hits:
            exact[b][h] += 1
            per_family[h] += 1
        if not hits:
            named_any = sorted({k for k, v in fam.items() if any(x[0] == nm for x in v)})
            why = ("name exists elsewhere with different (addr,pos,len): " + ",".join(named_any[:2])
                   if named_any else "declared in NO reference header")
            if nm != nm.rstrip():
                if any((nm.rstrip(), ad, p, ln) in v for v in fam.values()):
                    sys.exit(f"gate: row {nm!r} matches a family once the trailing whitespace is stripped "
                             "-- the exact-name vote was being defeated by padding, not by numbering")
                why += "; driver name carries trailing whitespace, stripping it matches nothing either"
            unres[b].append((nm, f"0x{ad:02x}", p, ln, why))
    padded = [nm for (nm, _a, _p, _l, _e) in rows if nm != nm.rstrip()]
    npad_res = sum(1 for v in unres.values() for u in v if u[0] != u[0].rstrip())
    nres = sum(len(v) for v in unres.values())
    print(f"driver names carrying trailing whitespace: {len(padded)} rows, {npad_res} of them inside the "
          f"{nres}-row residue -- none gains a match after stripping, so the residue is a numbering/"
          "naming gap and not a whitespace artifact")

    winners = {b: [k for k, v in exact[b].most_common() if k != "all"][:1] for b in BUCKETS}
    print("\naddress bucket   rows  exact-with-leading-family   that family's share   runners-up")
    for b in BUCKETS:
        if not exact[b]["all"]:
            continue
        lead = winners[b][0] if winners[b] else "-"
        share = exact[b][lead] / exact[b]["all"] if lead else 0.0
        rest = ", ".join(f"{k}={v}" for k, v in exact[b].most_common(4) if k not in ("all", lead))
        print(f"  {b:12} {exact[b]['all']:5} {lead:34} {share:6.1%}   {rest}")
    print(f"\nfamilies by exact matches over all {len(rows)} rows: "
          + ", ".join(f"{k}={v}" for k, v in per_family.most_common(4)))
    n1c = sum(v for k, v in per_family.items() if "N1C" in k or k.endswith(":TFA2"))
    tfa1 = sum(v for k, v in per_family.items() if k.endswith(":TFA1"))
    print(f"  TFA1 family {tfa1}, N1C/TFA2 family {n1c} -- a zero on the N1C side is what settles the "
          "numbering question, so it is printed explicitly rather than left to be inferred")
    if tfa1 == 0 and n1c == 0:
        sys.exit("gate: neither family matched a single row -- the reference tree or the enum decode is "
                 "wrong, so no verdict may be printed")
    for b in BUCKETS:
        if not exact[b]["all"] or not winners[b]:
            continue
        if exact[b][winners[b][0]] / exact[b]["all"] < 0.20:
            print(f"  NOTE {b}: fewer than 20% of rows match any single family -- the numbering there is "
                  "NOT established by this vote")
    unmatched = sum(len(v) for v in unres.values())
    print(f"rows with no exact family match: {unmatched}/{len(rows)} "
          f"({unmatched/len(rows):.1%}) -- listed, not extrapolated")
    # the ballot must be able to reject: the same rows re-voted against (name, pos, len) only,
    # ignoring the address, must find MORE matches than the strict quadruple vote -- otherwise the
    # strict test is inert and the N1C zero proves nothing.  Counted always, not only under
    # --selftest, so the artifact carries its own control and the table row can read it.
    loose = collections.Counter()
    for (nm, ad, p, ln, en) in rows:
        for k, v in fam.items():
            if any(x[0] == nm and x[2] == p and x[3] == ln for x in v):
                loose[k] += 1
    l1c = sum(v for k, v in loose.items() if "N1C" in k or k.endswith(":TFA2"))
    lt1 = sum(v for k, v in loose.items() if k.endswith(":TFA1"))
    if a.out:
        w = set()

        def emit(fh, line):
            w.add(len(line.split("\t")))
            fh.write(line + "\n")
        with open(a.out, "w", encoding="utf-8") as fh:
            hdr = "scope\tfamily\texact\trows\tshare\trow_name\taddr\tpos\tlen\twhy_unmatched"
            emit(fh, hdr)
            for b in BUCKETS:
                if not exact[b]["all"]:
                    continue
                lead = winners[b][0] if winners[b] else "-"
                for k, v in exact[b].most_common():
                    if k == "all":
                        continue
                    emit(fh, f"{b}\t{k}\t{v}\t{exact[b]['all']}\t{v/exact[b]['all']:.4f}\t-\t-\t-\t-\t-")
                for (nm, ad, p, ln, why) in unres[b]:
                    emit(fh, f"{b}\tno-family\t0\t{exact[b]['all']}\t0.0000\t{nm}\t{ad}\t{p}\t{ln}\t{why}")
            emit(fh, f"all\t{' '.join(f'{k}={v}' for k, v in per_family.most_common(3))}\t"
                      f"{tfa1}\t{len(rows)}\t{tfa1/len(rows):.4f}\tTFA1-total\t-\t-\t-\t-")
            emit(fh, f"all\tN1C/TFA2-total\t{n1c}\t{len(rows)}\t{n1c/len(rows):.4f}\t-\t-\t-\t-\t-")
            emit(fh, f"all\tN1C/TFA2-no-addr-ballot\t{l1c}\t{len(rows)}\t{l1c/len(rows):.4f}\t"
                      f"{l1c}\t-\t-\t-\tnames and bit positions exist in N1C but at another address")
            emit(fh, f"all\tTFA1-no-addr-ballot\t{lt1}\t{len(rows)}\t{lt1/len(rows):.4f}\t"
                      f"{lt1}\t-\t-\t-\tnames and bit positions exist in TFA1")
        if len(w) != 1:
            sys.exit(f"gate: {a.out} rows disagree on column count {sorted(w)}")
        print(f"wrote {a.out} (every row {next(iter(w))} columns)")
    if a.selftest:
        if l1c <= n1c:
            sys.exit(f"gate: dropping the address from the ballot does not increase N1C matches "
                     f"({l1c} <= {n1c}) -- the strict vote could not have distinguished anything")
        print(f"selftest: strict (name+addr+pos+len) vote gives TFA1 {tfa1} / N1C {n1c}; loosening the "
              f"ballot to ignore addr lifts N1C to {l1c} -- so the 0 is the address numbering, not a "
              "missing name list")


if __name__ == "__main__":
    main()
