#!/usr/bin/env python3
"""tools/acdb_lut_sense.py -- is my *LUT record parse pinned by the format, or only by my judgement?

The ACDB field stores a name, a length and a record COUNT; the record SIZE is derived from
    length - 4 == count * size
so any divisor of (length-4) is an arithmetically legal layout.  Ledger 322 measured that slack: about 14
alternative counts per field divide cleanly, and ~10% of those also have a word 0 that looks like device
ids -- i.e. division alone proves almost nothing.

What this tool reports instead is the perturbation that matters for the port: if the stored count were
shifted by +/-1 or +/-2 (a different Android 7 build, a re-numbered device, a corrupted word), would the
file still parse AND still look like a device table?  If yes, my parser could mis-read silently.  Measured
on 6.0.1: 6.8%-20.9% of fields still divide, and ZERO of those keep a device-like word 0.

Second finding kept as a gate: joint_keys() takes the FIRST position whose values look like device ids.
That is safe only while at most one position qualifies -- here no field ever showed two, so the row
identity of ledger 308-318 is a reading and not a choice.  The tool re-checks that on whatever sets it is
given, which is how it stays honest on 7.

usage: tools/acdb_lut_sense.py [--dirs PD1610 PD1516A QRD MTP Fluid] [--out TSV] [--selftest]
"""
import argparse
import collections
import csv
import os
import struct
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))
import acdb_row_groups as R  # noqa: E402
import acdb_tlv  # noqa: E402

ACDB = acdb_tlv.ACDB
DELTAS = (-2, -1, 1, 2)


def universe():
    devs = set(acdb_tlv.dev_names())
    p = os.path.join(R.ART, "acdb-devs.ALL.tsv")
    if os.path.exists(p):
        for r in csv.DictReader(open(p, encoding="utf-8"), delimiter="\t"):
            if r["acdb_dev_id"].isdigit():
                devs.add(int(r["acdb_dev_id"]))
    if not devs:
        sys.exit("gate: the device-id universe is empty -- every judgement below needs it, so no "
                 "verdict may be printed (run tools/acdb_names.py first)")
    return devs


def fields(st, devs, floor=8):
    """yield (table, records-as-rows) for every fixed-record table field on one board"""
    d = os.path.join(ACDB, st)
    if not os.path.isdir(d):
        sys.exit(f"gate: {d} is not a calibration dir")
    for f in sorted(x for x in os.listdir(d) if x.endswith(".acdb")):
        b = open(os.path.join(d, f), "rb").read()
        for off, raw, ln in acdb_tlv.walk(b)[0]:
            tab = raw.strip()
            if not acdb_tlv.is_table(tab):
                continue
            cnt, rs = acdb_tlv.count_rec(b, off, ln)
            if cnt == 0 or rs in (None, "empty") or rs % 4:
                continue
            rows = []
            for i in range(cnt):
                at = off + 16 + i * rs
                if at + rs > off + 12 + ln:
                    break
                rows.append(struct.unpack_from("<%dI" % (rs // 4), b, at))
            yield tab, b, off, ln, cnt, rs, rows


def device_like(vals, devs, floor):
    return len(vals) >= floor and (vals <= devs or (vals and 1 <= min(vals) and max(vals) <= 0x1000))


def sense(dirs, devs, floor=8):
    """per table: fields, true-parse failures, and for each delta how many nearby counts still parse and
    how many of those keep a device-like word 0 (the silent-mis-parse class)."""
    agg = collections.defaultdict(collections.Counter)
    ambig = collections.Counter()
    for st in dirs:
        for (tab, b, off, ln, cnt, rs, rows) in fields(st, devs, floor):
            a = agg[tab]
            a["fields"] += 1
            span = ln - 4
            a["true_closes"] += (span == cnt * rs)
            a["device_col"] += bool(rows) and device_like({r[0] for r in rows}, devs, floor)
            quals = [q for q in (range(len(rows[0])) if rows else [])
                     if device_like({r[q] for r in rows}, devs, floor)]
            a[f"cols{min(len(quals), 2)}"] += 1
            if len(quals) >= 2:
                ambig[tab] += 1
            for delta in DELTAS:
                c2 = cnt + delta
                a[f"d{delta:+d}_tot"] += 1
                if c2 < 1 or span % c2:
                    continue
                r2 = span // c2
                if r2 % 4 or r2 < 8:
                    continue
                rr = []
                for i in range(c2):
                    at = off + 16 + i * r2
                    if at + r2 > off + 12 + ln:
                        break
                    rr.append(struct.unpack_from("<%dI" % (r2 // 4), b, at))
                if not rr:
                    continue
                a[f"d{delta:+d}_parse"] += 1
                a[f"d{delta:+d}_devlike"] += device_like({r[0] for r in rr}, devs, floor)
    return agg, ambig


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dirs", nargs="*", default=["PD1610", "PD1516A", "QRD", "MTP", "Fluid"])
    ap.add_argument("--out")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    devs = universe()
    print(f"device-id universe {len(devs)} ids; boards {a.dirs}")
    agg, ambig = sense(a.dirs, devs)
    tabs = sorted(agg)
    tot = collections.Counter()
    print(f"\n{'table':11} {'fields':>6} {'true closes':>11} {'device col':>10} "
          + " ".join(f"{'d' + str(d) + ' parse/dev':>16}" for d in DELTAS))
    for t in tabs:
        g = agg[t]
        tot.update(g)
        print(f"{t:11} {g['fields']:6} {g['true_closes']:11} {g['device_col']:10} "
              + " ".join(f"{str(g[f'd{d:+d}_parse']) + '/' + str(g[f'd{d:+d}_devlike']):>16}"
                         for d in DELTAS))
    if tot["fields"] != tot["true_closes"]:
        sys.exit(f"gate: {tot['fields'] - tot['true_closes']} fields do not close on their own stored "
                 "count -- the record model is wrong somewhere and no sensitivity number means anything")
    silent = sum(tot[f"d{d:+d}_devlike"] for d in DELTAS)
    parses = sum(tot[f"d{d:+d}_parse"] for d in DELTAS)
    print(f"\nfields {tot['fields']}: every one closes on its stored count (that is the positive control).")
    print(f"count perturbed by {list(DELTAS)}: {parses} nearby counts still divide into a word record "
          f"({parses/max(tot['fields']*4,1):.1%} of the tries), and {silent} of those KEEP a device-like "
          f"word 0 -- silent-mis-parse risk = {silent/max(parses,1):.2%} of the surviving parses")
    if silent:
        print(f"  rows to look at: {[(t, tot2) for t, tot2 in ((t, agg[t]) for t in tabs) if any(tot2[f'd{d:+d}_devlike'] for d in DELTAS)]}")
    amb_tot = sum(ambig.values())
    print(f"columns that look like device ids: {tot['cols2']} fields had TWO OR MORE qualifiers "
          f"({tot['cols1']} had exactly one, {tot['cols0']} none) -- tools/acdb_row_groups.py picks the "
          "first, which is only a reading while this stays 0")
    if amb_tot:
        sys.exit(f"gate: {amb_tot} fields have an ambiguous device column (>=2 qualifying positions) -- "
                 "the row identity in acdb_row_groups.py is then a choice, and its verdicts may not be "
                 "published without a rule to decide")
    if a.out:
        with open(a.out, "w", encoding="utf-8") as fh:
            fh.write("\t".join(["table", "fields", "true_closes", "device_col_at_0"]
                               + [f"d{d:+d}_parse_divides" for d in DELTAS]
                               + [f"d{d:+d}_still_device_like" for d in DELTAS]
                               + ["cols_1_qualifier", "cols_2plus_qualifiers"]) + "\n")
            for t in tabs:
                g = agg[t]
                fh.write("\t".join([t, str(g["fields"]), str(g["true_closes"]), str(g["device_col"])]
                                   + [str(g[f"d{d:+d}_parse"]) for d in DELTAS]
                                   + [str(g[f"d{d:+d}_devlike"]) for d in DELTAS]
                                   + [str(g["cols1"]), str(g["cols2"])]) + "\n")
        print(f"wrote {a.out} ({len(tabs)} tables)")
    if a.selftest:
        # the metric must be able to move: with the distinct-value floor dropped to 2, nearby counts
        # start passing the device test -- if it stays 0 there, the arm is inert, not reassuring.
        agg2, _ = sense(a.dirs, devs, floor=2)
        loose = sum(g[f"d{d:+d}_devlike"] for g in agg2.values() for d in DELTAS)
        if loose == 0:
            sys.exit("gate: even with the floor at 2 no perturbed count looked device-like -- the "
                     "measurement cannot move, so the 0 above is not evidence")
        print(f"selftest: every field closes on its stored count; with the >=8 distinct rule the "
              f"perturbed counts that survive are 0/{parses}, and the rule is demonstrably live because "
              f"loosening the floor to 2 yields {loose} -- so the 0 is the format, not an inert test")


if __name__ == "__main__":
    main()
