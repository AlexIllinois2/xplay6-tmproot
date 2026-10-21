#!/usr/bin/env python3
"""tools/acdb_pairs.py -- the *CDFT / *CDOT bodies are sequences of (id,id) pair-lists.

Found by reading two small bodies, then checked by arithmetic:

    Speaker_cal  AVOLCDFT  len=40  = {n=2 + 2*(0x10bfe,0x10c29),(0x111d2,0x111d5)}
                                     {n=2 + 2*(0x10bfe,0x10c29),(0x111d3,0x111d4)}      20+20
    Bluetooth    ACGICDFT  len=152 = {n=4 + 4 pairs}  {n=14 + 14 pairs}                  36+116

So the model is:  payload = REPEAT { u32 n, n * (u32 a, u32 b) }  and the run must consume the
field body EXACTLY -- that exactness is the gate, same kind of anchor that settled the container
grammar (ledger 263).  This replaces the three equal-size-blob models that §267 rejected.

What this yields is STRUCTURE plus key lists, not values: the pairs look like
(module, param) -- the second element walks up by one while the first repeats -- so a CDFT names
which params a cal type carries.  Whether the numbers themselves live in DATAPOOL stays unjudged.

Usage: tools/acdb_pairs.py [--dirs PD1610] [--verbose-fail]
"""
import argparse
import collections
import csv
import os
import struct
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))
import acdb_tlv  # noqa: E402

ACDB = acdb_tlv.ACDB
ART = os.path.join(ROOT, "art/audio-6.0.1")


# The ACDB id namespace has (at least) two populated bands, both evidenced elsewhere in this
# project: 0x00010000-0x00140000 (module/param ids -- the QACT workspace catalog lives here, and so
# do the LUT keys) and 0x01000000-0x01400000 (graph/topology keys -- 0x1000fff1.. are AUDIO_TX_*_FVSAM
# in acdb-topologies, 0x1000ffff is the "no topology" sentinel in DATAPOOL -- all of these are
# 0x1000_0000 + something, i.e. the 256 M band; my first attempt wrote 0x1000000 (16 M) by
# mis-reading 0x1000b500 as a small number, which left 21 CDFT bodies "weak" for no reason but mine.
# 21 CDFT bodies carry
# pairs in the second band, and excluding them would have been my window being wrong, not the format.
BANDS = ((0x10000, 0x14000), (0x10000000, 0x14000000))


def in_idspace(v):
    return any(lo <= v < hi for lo, hi in BANDS)


def parse_lists(pay, anchor=True):
    """[(n, [(a,b),...])] consuming the payload exactly, or None.

    anchor=True additionally requires every word of every pair to sit in the id window.  That second
    gate is not decoration: on shuffled CDFT payloads the exact-consumption test alone still passes
    67/420 (16%), so structure by itself would be the §251 kind of ruler with no scale.
    """
    out, p = [], 0
    while p + 4 <= len(pay):
        n = struct.unpack_from("<I", pay, p)[0]
        if n == 0 or 4 + 8 * n > len(pay) - p:
            return None
        pairs = struct.unpack_from("<" + "I" * (2 * n), pay, p + 4)
        if anchor and not all(in_idspace(v) for v in pairs):
            return None
        out.append((n, list(zip(pairs[0::2], pairs[1::2]))))
        p += 4 + 8 * n
    return out if p == len(pay) else None


def load_catalog():
    """id -> names from the QACT workspace tables (the same catalog that gave 0 joins while the
    LUT keys were unreadable -- §264).  Absent files just mean no annotations."""
    cat = {}
    for fn, col, lab in (("acdb-blocks.PD1610.tsv", "module_id", "block"),
                         ("acdb-topologies.PD1610.tsv", "id", "topology"),
                         ("acdb-params.PD1610.tsv", "interface_id", "interface")):
        p = os.path.join(ART, fn)
        if not os.path.exists(p):
            continue
        for r in csv.DictReader(open(p), delimiter="\t"):
            v = (r.get(col) or "").strip()
            nm = (r.get(lab) or "").strip()
            if v.lower().startswith("0x") and nm and nm != "?":
                cat.setdefault(int(v, 16), set()).add(nm)
    return cat


def idspace(v):
    if 0x10000 <= v < 0x14000:
        return "module/param"
    if 0x10000000 <= v < 0x14000000:
        return "graph/topology"
    if 1 <= v < 0x1000:
        return "small"
    return f"other({v:#x})"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dirs", default="PD1610")
    ap.add_argument("--all-dirs", action="store_true", help="parse every acdbdata dir")
    ap.add_argument("--verbose-fail", action="store_true")
    args = ap.parse_args()
    dirs = sorted(d for d in os.listdir(ACDB) if os.path.isdir(os.path.join(ACDB, d))) \
        if args.all_dirs or args.dirs == "ALL" else args.dirs.split(",")

    cat = load_catalog()
    rows, ok, bad, weak = [], 0, collections.Counter(), collections.Counter()
    nulls = null_total = 0
    shape = collections.defaultdict(collections.Counter)
    for d in dirs:
        for fn in sorted(f for f in os.listdir(os.path.join(ACDB, d)) if f.endswith(".acdb")):
            b = open(os.path.join(ACDB, d, fn), "rb").read()
            fl, end = acdb_tlv.walk(b)
            if end != len(b):
                sys.exit(f"gate: {d}/{fn} does not walk to EOF")
            for off, raw, ln in fl:
                name = raw.strip()
                if not name.endswith(("CDFT", "CDOT")) or ln < 8:
                    continue
                pay = b[off + 12:off + 12 + ln]
                if len(pay) < 4:
                    continue
                cnt0 = struct.unpack_from("<I", pay, 0)[0]
                if cnt0 == 0:
                    continue
                lists = parse_lists(pay)
                if lists is None:
                    if parse_lists(pay, anchor=False) is not None:
                        weak[name[-4:]] += 1
                    bad[name[-4:]] += 1
                    if args.verbose_fail and len(bad) < 8:
                        print(f"  FAIL {d}/{fn} {name} len={ln} first_count={cnt0}")
                    continue
                ok += 1
                shape[name[-4:]][tuple(n for n, _ in lists)] += 1
                for li, (n, pairs) in enumerate(lists):
                    for pi, (a, bb) in enumerate(pairs):
                        rows.append((d, fn, name, li, n, pi, f"{a:#010x}", f"{bb:#010x}",
                                     idspace(a), idspace(bb),
                                     ";".join(sorted(cat.get(a, []))), ";".join(sorted(cat.get(bb, [])))))
    import random
    for d in dirs:
        for fn in sorted(f for f in os.listdir(os.path.join(ACDB, d)) if f.endswith(".acdb")):
            b = open(os.path.join(ACDB, d, fn), "rb").read()
            for off, raw, ln in acdb_tlv.walk(b)[0]:
                if not raw.strip().endswith("CDFT") or ln < 16:
                    continue
                pay = bytearray(b[off + 12:off + 12 + ln])
                if struct.unpack_from("<I", pay, 0)[0] == 0:
                    continue
                r = random.Random(5)
                r.shuffle(pay)
                null_total += 1
                nulls += parse_lists(bytes(pay)) is not None

    p = os.path.join(ART, f"acdb-pairs.{'PD1610' if dirs == ['PD1610'] else 'ALL'}.tsv")
    with open(p, "w", encoding="utf-8") as fh:
        fh.write("dir\tfile\tfield\tlist\tn_pairs\tpair\tid_a\tid_b\tspace_a\tspace_b\tname_a\tname_b\n")
        for r in rows:
            fh.write("\t".join(str(x) for x in r) + "\n")

    print(f"parsed {ok} CDFT/CDOT bodies exactly; {sum(bad.values())} did not fit the pair-list model")
    if bad:
        print("   failures by class:", dict(bad))
    tot = ok + sum(bad.values())
    print(f"   => {ok}/{tot} = {ok / tot:.1%} of non-empty CDFT/CDOT fields")
    cdft_tot = ok + bad.get("CDFT", 0)
    print(f"   CDFT class: {ok - (tot - ok and 0) and ''}{sum(1 for r in rows if r[2].endswith('CDFT')) > 0} "
          f"-- reported per class below")
    cls_ok = collections.Counter()
    print(f"   weak-pass (structure fits, words are NOT in the id window): {dict(weak) or 'none'}")
    print(f"   shuffle null over CDFT bodies: {nulls}/{null_total} still parse "
          f"({nulls / max(null_total, 1):.1%}) -- with the id-window anchor this is the number to trust")
    for cls, c in shape.items():
        uniq = c.most_common()
        print(f"   {cls} list-length shapes (top 3 of {len(c)}): {[(list(k), v) for k, v in uniq[:3]]}")
    named = sum(1 for r in rows if r[10] or r[11])
    ids = {int(r[6], 16) for r in rows} | {int(r[7], 16) for r in rows}
    print(f"distinct ids in the pair lists: {len(ids)}, of which the workspace catalog names "
          f"{len(ids & set(cat))}; {named}/{len(rows)} pair rows carry at least one name")
    spaces = collections.Counter(r[8] for r in rows)
    print("   id_a spaces seen:", dict(spaces.most_common(5)))
    print(f"wrote {p} ({len(rows)} pairs)")
    cdft_all = sum(1 for r in rows if r[2].endswith("CDFT")) > 0
    if weak:
        print("NOTE: these bodies fit the structure but a word fell outside both id bands -- "
              "left unparsed and named here: " + ", ".join(sorted(weak)))
    n_cdft = null_total
    if n_cdft and ok < tot - sum(weak.values()):
        print(f"NOTE: {tot - ok - sum(weak.values())} bodies fit neither model")
    # hard gate: the CDFT class must be fully explained, or this tool is not reporting a layout
    if bad.get("CDFT", 0) or weak.get("CDFT", 0):
        sys.exit(f"gate: CDFT not fully parsed (hard failures {bad.get('CDFT', 0)}, "
                 f"weak {weak.get('CDFT', 0)}) -- the pair-list model is incomplete")
    print(f"gate: every non-empty CDFT body parsed into pair-lists ({null_total} CDFT bodies walked)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
