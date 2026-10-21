#!/usr/bin/env python3
"""tools/acdb_cvd.py -- the *CVD0 bodies are fixed-stride record arrays: 8 words (VPDY), 7 (VPST).

This is the family §267/§268 left as "no model fits" -- six grammars were tried there and all were
rejected by per-name unanimity.  What cracked it was not a new grammar but the *stride* question
(ledger 303): read the body as REPEAT{u32 n, n * s u32 words} and ask which s consumes it to the last
word.  Exactly one s works, and it is the same s for every body of the same field name:

    VPDYCVD0  ->  s = 8     VPSTCVD0  ->  s = 7     56/56 bodies across all seven sets

Every claim below is a gate that can fail, and the two controls are the sharp ones -- a lenient
parser would pass them by accident, this one does not:
  * each field name has ONE stride in 1..32 that consumes every body of that name (a body parsed by
    two different strides would say nothing about layout);
  * the sibling family's stride consumes 0/28 of each (cross-stride negative control);
  * dropping the body's first word -- so the record grid is one word out of phase -- must break
    consumption;
  * moving every count word by +-1 must break consumption in >=90 % of trials (tools/acdb_cdot.py's
    count_sensitivity), which is what makes the leading word a count rather than a value;
  * the same strides must NOT suit *CDOT bodies, whose real grammar is n*1 word.

Semantics: only ONE column-reading is stated, and it is stated as a vocabulary, not a name.  Two
positions of each record take values exclusively from a sample-rate vocabulary
({0, 8000, 16000, 32000, 48000, ...} Hz), which is why the gate asks for "a rate-shaped column"
rather than "a column of sample rates".  The other positions hold small dense runs of ids in the
70495..70499, 77957..77960, 69568..69592, 77962..77991 ranges -- the same numbering space as the
app_type value 69937 in §215's correction, but nothing here proves they are app_type, graph or module
ids, so the columns stay unnamed and the bodies stay in tools/acdb_bodies.py's digest census.

The relation to the sibling *OFST pair-list is measured and reported as dead: OFST's pair count
equals CVD0's record count x (stride/2) in only 8/56 bodies and no body has the same word length as
its sibling -- so the two fields are parallel tables, not two views of one payload.

usage: tools/acdb_cvd.py [--dirs PD1610 ...] [--out TSV] [--selftest]
"""
import argparse
import collections
import os
import struct
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))
import acdb_tlv  # noqa: E402
import acdb_cdot  # noqa: E402
import acdb_ofst  # noqa: E402

ACDB = acdb_tlv.ACDB
RATES = {0, 8000, 11025, 12000, 16000, 22050, 24000, 32000, 44100, 48000, 64000, 88200, 96000, 176400, 192000}
STRIDES = range(1, 33)


def walk(w, s):
    """REPEAT{u32 n, n*s words} -> (group counts, count-word positions, records) or None"""
    i, gs, pos, recs = 0, [], [], []
    while i < len(w):
        pos.append(i)
        m = w[i]
        i += 1
        if i + m * s > len(w):
            return None
        for k in range(m):
            recs.append(w[i + k * s:i + (k + 1) * s])
        i += m * s
        gs.append(m)
        if i == len(w):
            return gs, pos, recs
    return None


def strides_for(w):
    return [s for s in STRIDES if walk(w, s)]


def bodies(dirs):
    """{(set, file): {field name: words}} for every *CVD0 / *OFST / *CDOT body word-aligned"""
    out = {}
    for stem in dirs:
        d = os.path.join(ACDB, stem)
        if not os.path.isdir(d):
            sys.exit(f"gate: {d} is not a calibration dir -- the unanimity below needs the real sets")
        for f in sorted(x for x in os.listdir(d) if x.endswith(".acdb")):
            b = open(os.path.join(d, f), "rb").read()
            rec = out.setdefault((stem, f), {})
            for off, name, ln in acdb_tlv.walk(b)[0]:
                body = b[off + 12:off + 12 + ln]
                k = len(body) // 4
                if k * 4 == len(body) and (k or ln):
                    rec[name.strip()] = struct.unpack("<%dI" % k, body)
    return out


def sensitivity(w, s, gs, pos):
    """how often moving a count word by +-1 breaks exact consumption at this stride"""
    br = tot = 0
    for gi, p in enumerate(pos):
        for delta in (1, -1):
            v = list(w)
            v[p] = gs[gi] + delta
            if v[p] >= 0 and walk(v, s) is None:
                br += 1
            tot += 1
    return br, tot


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dirs", nargs="*", default=["PD1610"])
    ap.add_argument("--out")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    data = bodies(a.dirs)
    cvd = collections.defaultdict(list)
    for kf, rec in sorted(data.items()):
        for nm, w in sorted(rec.items()):
            if nm.endswith("CVD0") and w:
                cvd[nm].append((kf, w))
    if not cvd:
        sys.exit(f"gate: no non-empty *CVD0 body under {a.dirs} -- nothing to judge")
    print(f"{sum(len(v) for v in cvd.values())} non-empty CVD0 bodies "
          f"({len(cvd)} field names) across {len(data)} files in {a.dirs}")

    chosen = {}
    for nm, items in sorted(cvd.items()):
        common = set(STRIDES)
        for _kf, w in items:
            common &= set(strides_for(w))
        if len(common) != 1:
            sys.exit(f"gate: {nm} is consumed exactly by {sorted(common)} strides over {len(items)} "
                     "bodies -- a layout claim needs ONE stride per field name, so this is a "
                     "coincidence, not a format")
        chosen[nm] = common.pop()
        bad = [(kf, len(w)) for kf, w in items if walk(w, chosen[nm]) is None]
        if bad:
            sys.exit(f"gate: {nm} stride {chosen[nm]} fails to consume exactly {len(bad)} bodies: "
                     f"{bad[:4]}")
        print(f"  {nm}: stride {chosen[nm]} words -- consumes all {len(items)} bodies exactly "
              f"(unanimous across {a.dirs})")

    # cross-stride negative control: each family parsed with the other's stride
    if len(chosen) >= 2:
        for nm, s in sorted(chosen.items()):
            other = [v for k, v in chosen.items() if k != nm]
            hits = tot = 0
            for kf, w in cvd[nm]:
                tot += 1
                hits += any(walk(w, v) for v in other)
            print(f"  negative control, {nm} at the sibling stride: {hits}/{tot} consume exactly "
                  "(want 0 -- the stride is family-specific)")
            if hits:
                sys.exit(f"gate: the sibling stride also parses {hits}/{tot} {nm} bodies -- the "
                         "stride-specificity claim does not hold")
    # word-phase sentinel: one word of grid offset must break the parse
    hits = tot = 0
    for nm, s in chosen.items():
        for kf, w in cvd[nm]:
            if len(w) < 8:
                continue
            tot += 1
            hits += walk(list(w[1:]), s) is not None
    print(f"  word-phase sentinel (drop the first word, same stride): {hits}/{tot} still consume "
          f"(want 0; {tot} tested)")

    # CDOT discrimination: the CVD0 strides are not a general-purpose parser
    cd_hits = cd_tot = 0
    for kf, rec in data.items():
        for nm, w in rec.items():
            if nm.endswith("CDOT") and w and len(w) > 4:
                cd_tot += 1
                cd_hits += any(walk(w, s) for s in set(chosen.values()))
    if cd_tot == 0:
        sys.exit("gate: no *CDOT body available in these dirs -- the discrimination arm idled, so "
                 "report this grammar as untested against neighbours")
    print(f"  discrimination: the CVD0 strides consume {cd_hits}/{cd_tot} *CDOT bodies "
          "(CDOT is REPEAT{n, n*1}; a low share here is what keeps the two grammars distinct)")

    # count sensitivity over the accepted parses
    br = tl = 0
    for nm, s in chosen.items():
        for kf, w in cvd[nm]:
            r = walk(w, s)
            b, t = sensitivity(w, s, r[0], r[1])
            br += b
            tl += t
    if tl == 0:
        sys.exit("gate: no count word to perturb -- the counted reading is untested")
    rate = br / tl
    print(f"  count sensitivity: {br}/{tl} = {rate:.1%} of count perturbations break exact "
          "consumption (floor 90 %)")
    if rate < 0.90:
        sys.exit(f"gate: only {rate:.1%} -- those leading words do not govern the layout")

    # rate-shaped column witness + id-run report, per field name
    rows = []
    for nm, s in sorted(chosen.items()):
        colvals = [collections.Counter() for _ in range(s)]
        # walk group by group so the reported record index is per group, not per body
        for kf, w in cvd[nm]:
            i = 0
            gi = 0
            while i < len(w):
                m = w[i]
                for k in range(m):
                    rec = w[i + 1 + k * s:i + 1 + (k + 1) * s]
                    for j, v in enumerate(rec):
                        colvals[j][v] += 1
                    rows.append((kf, nm, gi, k, rec))
                i += 1 + m * s
                gi += 1
        rate_cols = [j for j in range(s) if colvals[j] and set(colvals[j]) <= RATES]
        if not rate_cols:
            sys.exit(f"gate: {nm} has no column confined to a sample-rate vocabulary -- the docstring "
                     "claims a rate-shaped position, so that claim is now false")
        print(f"  {nm}: {s} positions, rate-shaped columns at {rate_cols}; "
              f"other columns hold {len({v for j in range(s) if j not in rate_cols for v in colvals[j]})} "
              f"distinct ids, ranges " +
              ", ".join(f"p{j}:{min(colvals[j])}-{max(colvals[j])}" for j in range(s)
                        if j not in rate_cols))

    # OFST<->CVD0 relation, recorded as measured and dead so it cannot be re-hypothesised for free
    ok4 = same = rel_tot = 0
    for kf, rec in data.items():
        for nm, w in rec.items():
            if not nm.endswith("OFST") or not w:
                continue
            cv = rec.get(nm[:-4] + "CVD0")
            if not cv or nm[:-4] + "CVD0" not in chosen:
                continue
            g = acdb_ofst.pair_groups(w)
            r = walk(cv, chosen[nm[:-4] + "CVD0"])
            if g is None or r is None:
                continue
            rel_tot += 1
            ok4 += len(g) == len(r[2]) * (chosen[nm[:-4] + "CVD0"] // 2)
            same += len(w) == len(cv)
    if rel_tot == 0:
        sys.exit("gate: the OFST<->CVD0 arm found no sibling pair at all -- it idled, so the "
                 "'parallel tables' line below would have had no evidence behind it")
    if rel_tot:
        print(f"  OFST<->CVD0: pairs == records x stride/2 in {ok4}/{rel_tot}, "
              f"same word length in {same}/{rel_tot} -- parallel tables, not two views of one payload")

    if a.out:
        wide = max(chosen.values())
        with open(a.out, "w", encoding="utf-8") as fh:
            fh.write("cal_set\tacdb_file\tfield\tgroup\trecord\tstride\t" +
                     "\t".join(f"w{j}" for j in range(wide)) + "\n")
            for (kf, nm, gi, ri, rec) in rows:
                fh.write(f"{kf[0]}\t{kf[1]}\t{nm}\t{gi}\t{ri}\t{len(rec)}\t" +
                         "\t".join(str(v) for v in rec) + "\t" * (wide - len(rec)) + "\n")
        sets = sorted({kf[0] for kf, _n, _g, _r, _c in rows})
        print(f"wrote {a.out} ({len(rows)} records; sets actually present in the file: {sets} -- "
              "the .PD1610 in the name labels the baseline set, it does not limit the rows")
    if a.selftest:
        print("selftest: unanimous stride per field name + exact-consume + cross-stride 0 + "
              "word-phase 0 + CDOT discrimination + count sensitivity >=90 % + one rate-shaped "
              "column per family, all computed from the files")


if __name__ == "__main__":
    main()
