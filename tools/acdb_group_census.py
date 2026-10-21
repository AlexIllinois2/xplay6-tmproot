#!/usr/bin/env python3
"""Does the GROUP INDEX in a pool field name anything, or is it just position?  (task 520)

The coordinate layer of §577 joins two boards by (field, group, slot) and it works -- 37 302 slots
agree -- but "works as a join key" is not "has a referent".  This tool answers the weaker and the
stronger question separately, with a null, because the candidate set was enumerated first:

  H1 positional only        group i is just the i-th REPEAT run in that block; nothing outside the
                            block fixes what i means.  Then matching i->i across boards buys nothing
                            over matching i->j.
  H2 per-block category      run i always points at the same KIND of blob within its own field
                            (e.g. every block's run 0 is the short list).  Then a within-field
                            statistic separates i from j.
  H3 global slot             run i of field F points at the SAME pool blobs in every block of F, and
                            the same set across boards (modulo layout) -- i.e. i indexes a board-level
                            table.  Then both matrices below are diagonal-dominant.

Measurements, each with the matching null:
  A) within-board  : for a field, Jaccard( target-set of run i, block X ; target-set of run i, block Y )
                     over all block pairs, versus the same statistic with one block's run order shuffled.
  B) cross-board   : for a field, overlap of run i's TARGET PAYLOAD SETS between the two boards,
                     as an i-by-j matrix (i on A, j on B).  H1 predicts a flat matrix, H3 a diagonal one.
  Controls: the matrix is reported with its own diagonal-minus-offdiagonal margin, and a random
  relabelling of A's run indices gives the margin's null.  If the observed margin does not beat the
  null, the honest verdict is "the group index carries no referent we can measure" -- 真缺素材, named
  with numbers instead of a guess.

usage: tools/acdb_group_census.py [--da DIR] [--db DIR] [--top N]
"""
import argparse
import collections
import hashlib
import itertools
import os
import random
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))
import acdb_pool as P  # noqa: E402


def ph(b):
    return hashlib.sha1(b).hexdigest()[:12]


def runs_by_group(kf, pool, ids=None):
    """field name -> {group index: [target payload hashes]} accumulated over every block of that field"""
    acc = collections.defaultdict(lambda: collections.defaultdict(list))
    names_acc = collections.defaultdict(lambda: collections.defaultdict(list))
    counts = collections.defaultdict(list)
    for nm, (rngs, _cnt, _m) in P.coords(kf).items():
        fl = P.field_words(*kf)
        pay = {o: p for (o, _L, p) in P.walk(pool)[0]}
        counts[nm].append(len(rngs))
        for gi, rng in enumerate(rngs):
            for wi in rng:
                off = P.u32(fl[nm], wi * 4)
                if off in pay:
                    acc[nm][gi].append(ph(pay[off]))
                    if ids is not None:
                        names_acc[nm][gi].append(module_names(pay[off], ids))
    return (acc, names_acc, counts) if ids is not None else (acc, counts)


def jac(a, b):
    sa, sb = set(a), set(b)
    if not sa or not sb:
        return None
    return len(sa & sb) / float(len(sa | sb))


def module_names(payload, ids):
    """the §306/§307 anchor rule, used here only to ANSWER 'what is this block': any word inside
    the id band that the universe ledger names.  Reported as a set, because a block can carry more
    than one id and §307 already showed the first-word key is not unique."""
    out = set()
    for i in range(0, len(payload) - 3, 4):
        w = int.from_bytes(payload[i:i + 4], "little")
        if P.IDBAND[0] <= w <= P.IDBAND[1] and w in ids:
            out.add(ids[w])
    return out


def main():
    ap = argparse.ArgumentParser()
    # pools() resolves a set name under ACDB, and passes an absolute path straight through, so
    # either board can be named.  Cross-board is the whole point here.
    ap.add_argument("--da", default="PD1610")
    ap.add_argument("--db", default=os.path.join(ROOT, "art/audio-7.1.1/acdbdata/PD1610"))
    ap.add_argument("--top", type=int, default=6)
    a = ap.parse_args()
    import acdb_tlv  # noqa: E402
    for d in (a.da, a.db):
        p2 = d if os.path.isabs(d) else os.path.join(acdb_tlv.ACDB, d)
        if not os.path.isdir(p2):
            sys.exit("ABORT: %s is not a calibration set -- the census has no data to measure, "
                     "which is not the same as a null result" % p2)
    pa, pb = P.pools([a.da]), P.pools([a.db])
    ra = {P.role_of(kf): kf for kf in pa}
    rb = {P.role_of(kf): kf for kf in pb}
    rng = random.Random(20261019)

    print("# files: %d on %s, %d on %s" % (len(pa), os.path.basename(os.path.dirname(a.da)),
                                           len(pb), os.path.basename(os.path.dirname(a.db))))
    print("# A = within-board run-i agreement across blocks (Jaccard); null = one block's run order"
          " shuffled; B = cross-board run-i x run-j payload-set overlap margin")
    summary = []
    for role in sorted(set(ra) & set(rb)):
        A, ca = runs_by_group(ra[role], pa[ra[role]])
        B, cb = runs_by_group(rb[role], pb[rb[role]])
        for fld in sorted(set(A) & set(B)):
            ga = {k: v for k, v in A[fld].items()}
            gb = {k: v for k, v in B[fld].items()}
            nruns_a = max(ga) + 1 if ga else 0
            nruns_b = max(gb) + 1 if gb else 0
            if nruns_a < 2 or nruns_b < 2:
                continue
            # A) within-board: does run i pick the same blobs across blocks of this field?
            same, shuf = [], []
            keys = sorted(ga)
            for i in keys:
                # the accumulated list per run index across blocks is per-block entries; split them
                per = ga[i]
                same.append(len(set(per)) / float(len(per)))
                p2 = list(per)
                rng.shuffle(p2)
                shuf.append(len(set(p2)) / float(len(p2)))
            # B) cross-board matrix by payload set, plus the relabelling null
            mat = {}
            for i in keys:
                for j in sorted(gb):
                    mat[(i, j)] = jac(ga[i], gb[j])
            diag = [v for (i, j), v in mat.items() if i == j and v is not None]
            off = [v for (i, j), v in mat.items() if i != j and v is not None]
            null_diag = []
            for _ in range(20):
                perm = list(range(nruns_a))
                rng.shuffle(perm)
                null_diag += [mat[(perm[i % nruns_a], i % nruns_a)] for i in range(nruns_b)
                              if mat.get((perm[i % nruns_a], i % nruns_a)) is not None]
            md = sum(diag) / len(diag) if diag else 0.0
            mo = sum(off) / len(off) if off else 0.0
            mn = sum(null_diag) / len(null_diag) if null_diag else 0.0
            print("%-26s %-12s runs=%d/%d blocks=%d/%d  A uniq-i=%.2f uniq-shuf=%.2f  "
                  "B diag=%.3f off=%.3f null=%.3f margin=%+.3f"
                  % (role[:26], fld[:12], nruns_a, nruns_b, len(ca[fld]), len(cb[fld]),
                     sum(same) / len(same) if same else -1,
                     sum(shuf) / len(shuf) if shuf else -1, md, mo, mn, md - mo))
            summary.append((role, fld, nruns_a, md - mo, mn, md - mn))
    win = [s for s in summary if s[3] > s[4] and s[4] > 0.02]
    print("\n# verdict")
    print("# fields with a usable group index (observed diagonal-offdiag margin beats its own"
          " relabelling null): %d/%d" % (len(win), len(summary)))
    for s in sorted(summary, key=lambda x: -x[3])[:a.top]:
        print("   %-26s %-12s runs=%d margin=%+.3f null=%+.3f" % (s[0][:26], s[1][:12], s[2], s[3], s[4]))
    # naming pass: can run i say WHICH module its blocks belong to?
    ids = P.load_ids()
    print("\n# naming: share of a run's blocks that agree on one ledger name (null = run labels"
          " shuffled within the field)")
    if not ids:
        print("#   the id ledger art/audio-6.0.1/acdb-ids.ALL.tsv is absent -- naming is UNMEASURED, not empty")
    named = unmeasured = 0
    rows = []
    for role in sorted(set(ra) & set(rb)):
        A = runs_by_group(ra[role], pa[ra[role]], ids)[1]  # names, not payload hashes
        for fld in sorted(A):
            for gi in sorted(A[fld]):
                lst = A[fld][gi]
                if not lst:
                    continue
                withname = [x for x in lst if x]
                if not withname:
                    unmeasured += 1
                    continue
                cnt = collections.Counter(n for st in withname for n in st)
                top, _tn = cnt.most_common(1)[0]
                share = sum(1 for st in withname if top in st) / float(len(withname))
                rows.append((role, fld, gi, len(lst), len(withname), share, top))
                named += 1
    import statistics
    if rows:
        import statistics
        ag = [r[5] for r in rows]
        print("#   %d (field,run) cells nameable, %d carry no id-band word at all; mean agreement"
              " = %.2f (a run whose blocks are one module scores 1.00, an arbitrary mix scores low)"
              % (named, unmeasured, statistics.mean(ag)))
    else:
        print("#   0 nameable cells -> the group index cannot be NAMED from this ledger, only matched")
    if not win:
        print("# => 真缺素材（带测量）：组号在两板之间的配对不比随机重贴更像一个身份，"
              "所以它不能当语义槽引用；能引用的只有 §577 那枚 (field,group,slot) 连接本身")
    else:
        print("# => 组号至少在这些字段上是可引用的身份，下一步是去命名它指向的那批块")


if __name__ == "__main__":
    main()
