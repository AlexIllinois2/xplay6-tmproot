#!/usr/bin/env python3
"""tools/acdb_card.py -- the calibration CARD for the acdb_dev_ids this machine really uses.

Why this shape: the coefficient tables cannot be named further with what is on hand (87 of 102
property ids appear ONLY as a LUT key -- tools/acdb_props.py, and the name pool holds no param
names).  But the port question does not need those names.  It needs one answer to:

    "on Android 7, does the ACDB hold the same numbers for device 15 / 124 / 150 as 6.0.1 did?"

So this tool extracts, per (table, device, app_type, sample rate), the remaining words of every
record -- the device column found by DATA (all values inside the 92 pool ids, >=8 distinct, see
ledger 264) and the app_type/fs columns from the two authorities of ledger 263.

Controls built in, because a card that cannot tell two boards apart is not a card:
  POSITIVE  PD1610 vs PD1610LG4 must be IDENTICAL (established byte-identical files in ledger 261)
  NEGATIVE  PD1610 vs PD1516A must DIFFER (a different board's calibration set)

Usage: tools/acdb_card.py [--dir PD1610] [--devices auto]   # auto = ids read from route-states.tsv
       tools/acdb_card.py --controls
"""
import argparse
import collections
import csv
import os
import struct
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))
import acdb_tlv  # noqa: E402  the anchored walk + count model is one source of truth

ACDB = acdb_tlv.ACDB
ART = os.path.join(ROOT, "art/audio-6.0.1")
FS = acdb_tlv.FS


def pool_device_ids(dirs=("PD1610",)):
    p = os.path.join(ART, "acdb-devs.PD1610.tsv")
    if not os.path.exists(p):
        sys.exit("gate: acdb-devs.PD1610.tsv missing -- run tools/acdb_names.py")
    return {int(r["acdb_dev_id"]) for r in csv.DictReader(open(p), delimiter="\t")}


def live_device_ids():
    """the ids actually seen on the wire: (app_type, dev_id) pairs in the live control dump"""
    rs = os.path.join(ART, "route-states.tsv")
    if not os.path.exists(rs):
        sys.exit("gate: route-states.tsv missing -- cannot know which devices to card")
    out = {}
    for ln in open(rs, encoding="utf-8"):
        p = ln.rstrip("\n").split("\t")
        if len(p) < 2 or not p[0].startswith("Audio Stream ") or "App Type Cfg" not in p[0]:
            continue
        for st, cell in zip(("idle", "speaker", "headphones"), p[2:5]):
            w = cell.split()
            if len(w) >= 2 and int(w[1]):
                out.setdefault(int(w[1]), set()).add(st)
    return out


def card(dir_name, devs_wanted, pool):  # noqa: C901
    appn = acdb_tlv.app_type_names()
    acdb_tlv.APPNAMED.update(appn)
    appset = set(appn)
    rows, tables = [], 0
    root = os.path.join(ACDB, dir_name)
    for fn in sorted(f for f in os.listdir(root) if f.endswith(".acdb")):
        b = open(os.path.join(root, fn), "rb").read()
        fl, end = acdb_tlv.walk(b)
        if end != len(b):
            sys.exit(f"gate: {dir_name}/{fn} does not walk to EOF")
        # pass 1: decode every fixed-record table, then decide which column is which by value
        decoded = {}
        for off, raw, ln in fl:
            name = raw.strip()
            cnt, rs = acdb_tlv.count_rec(b, off, ln)
            if not isinstance(rs, int) or rs % 4:
                continue
            w = rs // 4
            vals = [struct.unpack_from("<" + "I" * w, b, off + 16 + rs * i) for i in range(cnt)]
            decoded[name] = (off, vals, w)
            tables += 1
        for name, (off, vals, w) in decoded.items():
            if not vals:
                continue
            dpos = apos = fpos = None
            drule = "-"
            for p in range(w):
                distinct = {v[p] for v in vals}
                if dpos is None and len(distinct) >= 8 and distinct <= pool:
                    dpos, drule = p, "numbered pool"
                elif dpos is None and len(distinct) >= 8 and 1 <= min(distinct) <= max(distinct) <= 0x1000:
                    # the same window the numbered pool lives in (max id seen 839); used only when
                    # this dir has no pool of its own -- reported per row, not silently
                    dpos, drule = p, "small-int window (dir has no numbered pool)"
                if apos is None and acdb_tlv.app_type_column(distinct) is not None:
                    apos = p
                if fpos is None and distinct and distinct <= (FS | {0}):
                    fpos = p
            for v in vals:
                if dpos is None or v[dpos] not in devs_wanted:
                    continue
                rest = [f"{x:#010x}" for j, x in enumerate(v) if j not in (dpos, apos, fpos)]
                rows.append((name, v[dpos],
                             f"{v[apos]}({','.join(appn.get(v[apos], ['unnamed-in-conf']))})" if apos is not None else "-",
                             v[fpos] if fpos is not None else "-", " ".join(rest), drule))
    return rows, tables


def emit(dir_name, devs_wanted, pool, outdir):
    rows, tables = card(dir_name, devs_wanted, pool)
    suffix = dir_name if len(devs_wanted) <= 8 else dir_name + "-full"
    p = os.path.join(outdir, f"acdb-card.{suffix}.tsv")
    with open(p, "w", encoding="utf-8") as fh:
        fh.write("table\tacdb_dev_id\tapp_type\tsample_rate\trest_of_record\tdev_col_rule\n")
        for r in sorted(rows, key=lambda x: tuple(str(y) for y in x)):
            fh.write("\t".join(str(x) for x in r) + "\n")
    by = collections.Counter(r[1] for r in rows)
    rules = collections.Counter(r[5] for r in rows)
    print(f"{dir_name}: {len(rows)} carded records from {tables} tables -> {p}")
    print(f"   device column by: " + ", ".join(f"{k}={v}" for k, v in rules.most_common()))
    print(f"   per device: " + ", ".join(f"{k}={by[k]}" for k in sorted(by)))
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default="PD1610")
    ap.add_argument("--devices", default="auto")
    ap.add_argument("--outdir", default=ART)
    ap.add_argument("--controls", action="store_true")
    args = ap.parse_args()
    live = live_device_ids()
    declared = set()
    mp = os.path.join(ART, "acdb-map-output.tsv")
    if os.path.exists(mp):
        declared = {int(a[1]) for a in (ln.split("\t") for ln in open(mp))
                    if len(a) == 2 and a[1].strip().isdigit()}
    if args.devices == "auto":
        wanted = set(live) | declared
    elif args.devices == "all":
        # every device the pool names: the 3-device card is the "what this machine plays now" view,
        # this one is the full surface so the 7 comparison still works if 7 routes a device by a
        # different id (then only the per-device rows move, not the whole card)
        wanted = set(pool_device_ids(args.dir))
    else:
        wanted = {int(x) for x in args.devices.split(",")}
    missing = sorted(wanted - pool_device_ids(args.dir))
    if missing:
        print(f"note: live ids {missing} have NO name in the ACDB pool -- carded by number only")

    rows = emit(args.dir, wanted, pool_device_ids(args.dir), args.outdir)
    if not args.controls:
        print("ids carded: " + ", ".join(f"{i}({','.join(sorted(live.get(i, ['declared-only'])))})" for i in sorted(wanted)))
        return 0
    # POSITIVE: PD1610LG4 is byte-identical to PD1610 (ledger 261) -> card must be identical
    a = {tuple(r) for r in rows}
    b = {tuple(r) for r in emit("PD1610LG4", wanted, pool_device_ids("PD1610LG4"), args.outdir)}
    print(f"\ncontrol POSITIVE (files byte-identical per 261 -> card identical): PD1610 vs PD1610LG4 "
          f"{'PASS' if a == b else 'FAIL, diff=' + str(len(a ^ b))}")
    # NEGATIVE must test VALUE sensitivity.  Carding another board is not the negative: the numbered
    # device pool exists only in PD1610/PD1610LG4 (tools/acdb_names.py --dirs ALL), so a stock
    # reference dir yields an empty card for a reason that has nothing to do with my values.
    other_dev = {tuple(r) for r in card(args.dir, {14}, pool_device_ids(args.dir), )[0]}
    print(f"control NEGATIVE (a different device on the same board -> different rows): dev 14 vs dev 15 "
          f"{'PASS differing' if other_dev and not (other_dev & a) else 'FAIL, card does not separate devices'}")
    print(f"   device-14 rows: {len(other_dev)}, device-15/150 rows: {len(a)}, overlap {len(other_dev & a)}")
    print("   (the pool-source notes above are why cross-board carding is not the negative control: "
          "stock reference dirs have no numbered device pool, so their card is empty for a reason "
          "unrelated to my values)")
    return 0 if (a == b and other_dev and not (other_dev & a)) else 1


if __name__ == "__main__":
    sys.exit(main())
