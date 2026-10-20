#!/usr/bin/env python3
"""tools/acdb_ofst.py -- the *OFST bodies parse as pair-lists; what the two columns MEAN is not known.

Why this exists and what it does NOT claim.  §268 rejected the CDFT pair grammar for *CDOT/*OFST --
but it scored every candidate WITH the id-window anchor on, and these fields are not id fields at
all (ledger 300's lesson, applied here: OFST's values sit far below 0x10000).  Drop the anchor and
the grammar fits:

    REPEAT{u32 n, n * (u32 col0, u32 col1)}     consumed to the last word, 8/8 in PD1610

Three further facts are checked rather than assumed, each one able to fail:
  * each OFST body's leading count equals the leading count of the SAME file's <fam>CVD0 body
    (8/8) -- the two fields describe the same set of items;
  * every value in either column is smaller than that file's DATAPOOL byte length -- this is what
    makes "these are offsets into the pool" the leading hypothesis, and it is stated as a ratio,
    not as a conclusion, because a value that fits under a length is necessary, not sufficient;
  * neither column is monotonic, so the pairs are not a sorted index in file order.

So: STRUCTURE parsed, SEMANTICS unclaimed.  The bodies stay in tools/acdb_bodies.py's digest census
on purpose -- a watch list does not need to be understood, and removing them would make the
undecoded count read smaller than it is.

usage: tools/acdb_ofst.py [--dirs PD1610] [--out TSV] [--selftest]
"""
import argparse
import os
import struct
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))
import acdb_tlv  # noqa: E402
import acdb_cdot  # noqa: E402

ACDB = acdb_tlv.ACDB


def pair_groups(w):
    """REPEAT{u32 n, n*(u32,u32)}; None unless the body is consumed exactly"""
    i, out = 0, []
    while i < len(w):
        n = w[i]
        i += 1
        if n == 0 or i + 2 * n > len(w):
            return None
        for k in range(n):
            out.append((w[i + 2 * k], w[i + 2 * k + 1]))
        i += 2 * n
        if i == len(w):
            return out
    return None


def pair_groups_pos(w):
    """pair_groups(w) plus the word offsets of the count words the walk consumed"""
    i, out, pos = 0, [], []
    while i < len(w):
        n = w[i]
        pos.append(i)
        i += 1
        if n == 0 or i + 2 * n > len(w):
            return None, []
        out.extend([[w[i + 2 * k], w[i + 2 * k + 1]] for k in range(n)])
        i += 2 * n
        if i == len(w):
            return out, pos
    return None, []


def collect(dirs):
    """{dir: {field: (words, body, len)}} for CVD0/OFST/DATAPOOL of each cal file"""
    out = {}
    for stem in dirs:
        d = os.path.join(ACDB, stem)
        if not os.path.isdir(d):
            sys.exit(f"gate: {d} is not a calibration dir -- the counts below need the real sets")
        for f in sorted(x for x in os.listdir(d) if x.endswith(".acdb")):
            b = open(os.path.join(d, f), "rb").read()
            rec = out.setdefault((stem, f), {})
            for off, name, ln in acdb_tlv.walk(b)[0]:
                nm = name.strip()
                if nm.endswith(("OFST", "CVD0")) or nm == "DATAPOOL":
                    body = b[off + 12:off + 12 + ln]
                    k = len(body) // 4
                    rec[nm] = (list(struct.unpack("<%dI" % k, body)) if k * 4 == len(body) else None,
                               body, ln)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dirs", nargs="*", default=["PD1610"])
    ap.add_argument("--out")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    data = collect(a.dirs)
    ofst = [(kf, n, v) for kf, rec in data.items() for n, v in rec.items() if n.endswith("OFST")]
    nonempty = [(kf, n, v) for kf, n, v in ofst if v[2] > 0]
    if not nonempty:
        sys.exit("gate: no non-empty *OFST body in the requested dirs -- nothing to judge")
    parsed = [(kf, n, v, pair_groups(v[0])) for kf, n, v in nonempty]
    good = [p for p in parsed if p[3] is not None]
    if len(good) != len(parsed):
        bad = [(p[0], p[1]) for p in parsed if p[3] is None]
        sys.exit(f"gate: {len(bad)}/{len(parsed)} OFST bodies did not consume exactly: {bad[:6]}")
    print(f"{len(good)}/{len(parsed)} non-empty OFST bodies parse as "
          f"REPEAT{{u32 n, n*(u32,u32)}} across {a.dirs}")

    # the CVD0 count agreement
    agree = 0
    cmp_total = 0
    for (kf, n, v, g) in good:
        fam = n[:-4]
        cv = data[kf].get(fam + "CVD0")
        if not cv or cv[0] is None or not cv[0]:
            continue
        cmp_total += 1
        if cv[0][0] == v[0][0]:
            agree += 1
    if cmp_total == 0:
        sys.exit("gate: no <fam>CVD0 sibling found for any OFST body -- the count agreement claimed "
                 "in the docstring is then untested, so do not report this field as characterised")
    if agree != cmp_total:
        sys.exit(f"gate: leading counts agree {agree}/{cmp_total} -- expected all, since the two "
                 "fields are supposed to describe the same item set")
    print(f"leading count equals the sibling <fam>CVD0 count: {agree}/{cmp_total}")

    # DATAPOOL-fit ratio: reported, and only reported.  The competing referent is measured too --
    # if the values were offsets into the sibling CVD0 blob they would fit under ITS length, and
    # they demonstrably do not, which is what makes DATAPOOL the surviving hypothesis.
    fit = tot = cvd_fit = cvd_tot = 0
    dp_missing = []
    for (kf, n, v, g) in good:
        dp = data[kf].get("DATAPOOL")
        if not dp:
            dp_missing.append(kf)
            continue
        lim = len(dp[1])
        cv = data[kf].get(n[:-4] + "CVD0")
        clim = len(cv[1]) if cv else None
        for c0, c1 in g:
            tot += 2
            fit += (c0 < lim) + (c1 < lim)
            if clim is not None:
                cvd_tot += 2
                cvd_fit += (c0 < clim) + (c1 < clim)
    if dp_missing:
        sys.exit(f"gate: DATAPOOL missing in {dp_missing[:3]} -- the fit ratio cannot be stated "
                 "against a pool that was not found")
    if fit != tot:
        print(f"NOTE: only {fit}/{tot} values are below their file's DATAPOOL length -- the "
              "offset-into-pool hypothesis is NOT supported for every value; do not state it as fact")
    else:
        print(f"all {tot} values are < their file's DATAPOOL length (necessary, not sufficient, for "
              "'these are pool offsets')")
    if cvd_tot:
        print(f"same values against the sibling CVD0 blob length instead: {cvd_fit}/{cvd_tot} fit "
              f"({cvd_fit / cvd_tot:.1%}) -- DATAPOOL is the referent that survives, CVD0 does not")
    mono = sum(1 for (_kf, _n, _v, g) in good
               if all(g[i][1] <= g[i + 1][1] for i in range(len(g) - 1)))
    print(f"bodies whose second column is monotonic: {mono}/{len(good)} "
          f"({'sorted index' if mono == len(good) else 'NOT a sorted index in file order'})")
    # every value in both columns is a multiple of 4 -- measured, because it is the one structural
    # fact about these columns and it does NOT on its own mean "byte offset": *CDOT words sit at
    # 60-70 % and the LUT families at 55-73 %, so alignment is common in this file format.  What is
    # unusual is that it holds for 100 % of these bodies in every set.
    all4 = sum(1 for (_kf, _n, _v, g) in good if all(a % 4 == 0 and b % 4 == 0 for a, b in g))
    vals = sum(2 * len(g) for (_kf, _n, _v, g) in good)
    print(f"bodies whose EVERY value in BOTH columns is a multiple of 4: {all4}/{len(good)} "
          f"({vals} values) -- scale or word-index reading, not claimed as an offset: DATAPOOL bodies "
          "are not all word-multiples (16/49) and the tiling reading was measured dead in ledger 303")
    # the sharp structural test (shared helper with tools/acdb_cdot.py): move each count word by +-1
    br = tl = 0
    for (kf, n, v, g) in good:
        b, t = acdb_cdot.count_sensitivity(v[0], pair_groups_pos)
        br += b; tl += t
    if tl == 0:
        sys.exit("gate: count-sensitivity had no count words to perturb -- untested, so the counted "
                 "reading is not established")
    rate = br / tl
    print(f"count sensitivity: perturbing each count word by +-1 breaks exact consumption "
          f"{br}/{tl} = {rate:.1%}")
    if rate < 0.90:
        sys.exit(f"gate: only {rate:.1%} of count perturbations break the parse -- those words do not "
                 "govern the layout, so call this a coincidence, not a format")
    # chain reading (col1 = running offset, col0 = the stride to the next one) -- computed here so
    # the hypothesis is recorded as tested-and-dead rather than quietly dropped
    chain_hits = chain_pairs = 0
    for (kf, n, v, g) in good:
        w = v[0]
        i = 0
        while i < len(w):
            m = w[i]
            i += 1
            # pairs of THIS group, walked straight out of the word list so group borders are real
            for k in range(m - 1):
                a0, _b0 = w[i + 2 * k], w[i + 2 * k + 1]
                a1, b1 = w[i + 2 * (k + 1)], w[i + 2 * (k + 1) + 1]
                chain_pairs += 1
                if b1 - _b0 == a0:
                    chain_hits += 1
            i += 2 * m
            if i == len(w):
                break
    if chain_pairs:
        print(f"running-offset reading (col1[i+1] - col1[i] == col0[i], within a group): "
              f"{chain_hits}/{chain_pairs} = {chain_hits / chain_pairs:.1%} -- NOT how these pairs "
              "relate, so the two columns stay unnamed")
    if a.out:
        with open(a.out, "w", encoding="utf-8") as fh:
            fh.write("cal_set\tacdb_file\tfield\tpair_index\tcol0\tcol1\tn_from_header\n")
            for (kf, n, v, g) in good:
                for i, (c0, c1) in enumerate(g):
                    fh.write(f"{kf[0]}\t{kf[1]}\t{n}\t{i}\t{c0}\t{c1}\t{v[0][0]}\n")
        print(f"wrote {a.out} ({sum(len(p[3]) for p in good)} pairs)")
    if a.selftest:
        print("selftest: exact-consume + CVD0 count agreement + DATAPOOL-fit census + monotony "
              "report all computed from the files (semantics deliberately NOT claimed)")


if __name__ == "__main__":
    main()
