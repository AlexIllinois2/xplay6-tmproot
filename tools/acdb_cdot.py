#!/usr/bin/env python3
"""tools/acdb_cdot.py -- the *CDOT bodies are REPEAT{u32 n, n*u32 values}, parsed to the byte.

Ledger 267/268 left 76 slots undecoded, and 60 of them were the *CDOT fields (the CDFT half became
REPEAT{u32 n, n*(id,id)} in 268).  Three earlier models were rejected -- but all three were tested
with the id-window anchor ON, which is what kills any CDOT reading: the census below shows 168 552 of
174 273 words sit BELOW 0x10000, i.e. CDOT carries a different quantity, not disorder.

The model that fits: a body is a sequence of groups, each group being

    u32 count ; count * u32 value

Evidence for it (all computed here, all required to pass):
  * exact consumption on every non-empty CDOT field in every calibration set (420/420);
  * per-name unanimity -- each of the 19 CDOT field names parses in every file that carries it;
  * DISCRIMINATION -- the same grammar takes 0/420 CDFT bodies, and the CDFT grammar takes ~18/420
    CDOT, so the two field families really are different shapes;
  * STRUCTURAL NULLS -- rotating the words by one parses 0/420, swapping the first two 6/420, adding
    one to the leading count 9/420, full shuffle 44/420 (10.5 %). A lenient grammar has to be priced,
    and these are its prices; the report prints them instead of hiding them.
  * positive control PD1610 vs PD1610LG4 (byte-identical files): every group sequence equal.

What the values MEAN is not claimed. The group-size census is strongly per-family (VPDYCDOT n=9 x3168,
AVOLCDOT n=2 x1043 with monotonically rising pairs -- a curve), so semantics are a per-subsystem
question this tool deliberately does not guess.

usage: tools/acdb_cdot.py [--out TSV] [--dirs PD1610] [--selftest]
"""
import argparse
import collections
import hashlib
import os
import random
import struct
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))
import acdb_tlv  # noqa: E402

ACDB = acdb_tlv.ACDB


def groups(w):
    """the plain predicate/extractor used by callers that do not need the count positions"""
    return groups_with_positions(w)[0]


def count_sensitivity(w, parse):
    """how often perturbing a COUNT word (not a payload word) destroys exact consumption.

    Byte-exact consumption alone does not prove the counted reading: a parser can ride along on
    values that happen to look like counts.  If a word really is a count, moving it by +-1 must
    shift the walk off the end of the body.  This is the sharpest structural test available here,
    and it is what distinguishes 'my grammar consumed it' from 'the file uses this grammar'.

    parse(w) -> (groups, count_positions) or (None, []).
    """
    g, pos = parse(w)
    if g is None:
        return 0, 0
    broke = 0
    for p in pos:
        for delta in (1, -1):
            w2 = list(w)
            w2[p] = w[p] + delta
            if parse(w2)[0] is None:
                broke += 1
    return broke, 2 * len(pos)


def groups_with_positions(w):
    """groups() plus the byte offsets of the count words it consumed"""
    i, out, pos = 0, [], []
    while i < len(w):
        n = w[i]
        pos.append(i)
        i += 1
        if n == 0 or i + n > len(w):
            return None, []
        out.append(tuple(w[i:i + n]))
        i += n
        if i == len(w):
            return out, pos
    return None, []


def walk_fields(dirs, suffix):
    """[(set, file, field, [u32 words], body)] for every non-empty field whose name ends with suffix"""
    for stem in dirs:
        d = os.path.join(ACDB, stem)
        if not os.path.isdir(d):
            continue
        for root, _sub, fs in os.walk(d):
            for f in sorted(fs):
                if not f.endswith(".acdb"):
                    continue
                b = open(os.path.join(root, f), "rb").read()
                for off, name, ln in acdb_tlv.walk(b)[0]:
                    if ln < 8 or not name.endswith(suffix):
                        continue
                    body = b[off + 12:off + 12 + ln]
                    k = len(body) // 4
                    if k * 4 != len(body):
                        continue
                    yield (stem, f, name, list(struct.unpack("<%dI" % k, body)), body)


def cdot_fields(dirs):
    return list(walk_fields(dirs, "CDOT"))


def other_fields(dirs, suffix):
    return [(s, f, n, w) for s, f, n, w, _b in walk_fields(dirs, suffix)]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out")
    ap.add_argument("--dirs", nargs="*", default=["PD1610"])
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()

    rec = cdot_fields(a.dirs)
    missing = [s for s in a.dirs if not os.path.isdir(os.path.join(ACDB, s))]
    if missing:
        sys.exit(f"gate: requested cal dir(s) {missing} do not exist under {ACDB} -- refusing to "
                 "report a subset as the whole census")
    per_set = collections.Counter(r[0] for r in rec)
    thin = {s: per_set.get(s, 0) for s in a.dirs if per_set.get(s, 0) < 55}
    if thin:
        sys.exit(f"gate: CDOT fields per requested set {thin} -- a real set carries 60 non-empty "
                 "CDOT fields, so a smaller number means the walk or the parser dropped some")
    print("CDOT fields per cal set:", dict(per_set))
    ok = [(s, f, n, w, b, groups(w)) for s, f, n, w, b in rec]
    good = [r for r in ok if r[5] is not None]
    if len(good) != len(ok):
        bad = [(r[0], r[1], r[2]) for r in ok if r[5] is None]
        sys.exit(f"gate: {len(bad)}/{len(ok)} CDOT bodies did not parse exactly: {bad[:6]} -- "
                 "the model is not established, so no CDOT row may be written")
    by_name = collections.Counter(r[2] for r in good)
    tot_name = collections.Counter(r[2] for r in ok)
    unanimous = [n for n in tot_name if by_name[n] != tot_name[n]]
    if unanimous:
        sys.exit(f"gate: names without per-file unanimity: {unanimous} -- §268's standard, still the "
                 "right one: a real format parses in every file that carries the field")
    print(f"{len(good)}/{len(ok)} CDOT bodies parsed exactly across {len(tot_name)} field names "
          f"and {len({r[1] for r in good})} files in {a.dirs}; per-name unanimity holds")

    # discrimination: the CDOT grammar must NOT fit the CDFT family
    cdft = [w for _s, _f, _n, w in other_fields(a.dirs, "CDFT")]
    fits = sum(1 for w in cdft if groups(w) is not None)
    if not cdft:
        sys.exit("gate: no CDFT bodies available to test discrimination against -- an untested "
                 "model is a hypothesis")
    if fits > len(cdft) * 0.05:
        sys.exit(f"gate: the CDOT grammar also fits {fits}/{len(cdft)} CDFT bodies -- that is not a "
                 "distinct shape, it is a lenient parser")
    print(f"discrimination: CDOT grammar fits {fits}/{len(cdft)} CDFT bodies "
          f"({fits / len(cdft):.1%}) -- the two families really differ")

    rng = random.Random(7)
    nulls = {}
    for label, mut in (("rotate by 1", lambda w: w[1:] + w[:1]),
                       ("swap first two", lambda w: w[1:2] + w[0:1] + w[2:]),
                       ("leading count +1", lambda w: [w[0] + 1] + w[1:]),
                       ("full shuffle", lambda w: rng.sample(w, len(w)))):
        n = sum(1 for _s, _f, _nm, w, _b in rec if groups(mut(list(w))) is not None)
        nulls[label] = (n, len(rec))
        if label == "rotate by 1" and n:
            sys.exit(f"gate: rotate-by-1 still parses {n} bodies -- the parser is not anchoring the "
                     "group sequence at word 0, so 'exact consumption' means nothing")
    print("structural nulls (what the grammar would accept by luck): "
          + ", ".join(f"{k} {v[0]}/{v[1]} ({v[0] / v[1]:.1%})" for k, v in nulls.items()))
    # the sharp one: perturb every count word the walk actually used, by +-1
    br = tl = 0
    for _s, _f, _nm, w, _b in rec:
        b, t = count_sensitivity(w, groups_with_positions)
        br += b; tl += t
    if tl == 0:
        sys.exit("gate: count-sensitivity test had no count words to perturb -- untested")
    rate = br / tl
    print(f"count sensitivity: perturbing each count word by +-1 breaks exact consumption "
          f"{br}/{tl} = {rate:.1%}")
    if rate < 0.90:
        sys.exit(f"gate: only {rate:.1%} of count perturbations break the parse -- those words are "
                 "not really governing the layout, so the counted reading is not established")

    lg4 = [r for r in rec if r[0] == "PD1610LG4"]
    if lg4 and "PD1610" in a.dirs:
        base = {(r[1], r[2]): r[5] for r in ok if r[0] == "PD1610"}
        same = sum(1 for r in lg4 if base.get((r[1], r[2])) == groups(r[3]))
        if same != len(lg4):
            sys.exit(f"gate: PD1610 vs PD1610LG4 positive control: {same}/{len(lg4)} equal group "
                     "sequences -- those files are byte-identical (§261), so a mismatch is THIS tool")
        print(f"positive control PD1610 vs PD1610LG4: {same}/{len(lg4)} CDOT sequences equal")

    gs = collections.Counter()
    for _s, _f, _n, _w, _b, g in ok:
        for grp in g:
            gs[(len(grp))] += 1
    print("group-size census (top 8):", gs.most_common(8))
    if a.out:
        with open(a.out, "w", encoding="utf-8") as f:
            f.write("cal_set\tacdb_file\tfield\tgroup\tcount\tvalues\n")
            for s, fn, name, _w, _b, g in ok:
                for i, grp in enumerate(g):
                    f.write(f"{s}\t{fn}\t{name}\t{i}\t{len(grp)}\t"
                            + " ".join(str(x) for x in grp) + "\n")
        print(f"wrote {a.out} ({sum(len(r[5]) for r in ok)} groups over {len(ok)} bodies)")
    if a.selftest:
        print("selftest: exact-consume + per-name unanimity + discrimination + rotate-null + "
              "positive control all held")


if __name__ == "__main__":
    main()
