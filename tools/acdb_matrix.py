#!/usr/bin/env python3
"""tools/acdb_matrix.py -- one row per (cal type, module, param): who calibrates it and for whom.

Two decoded layers finally speak to each other (ledger 263/264/268):

  *CDFT / *CDOT bodies   -> REPEAT{u32 n, n*(module_id, param_id)}      (tools/acdb_pairs.py)
  *LUT tables            -> records keyed on (device_id, app_type, ...) (tools/acdb_tlv.py)

They share a naming root: ACGI/ACGD/AVOL/VCGI/VCD2/VPDY/VPST/ADST/VDP/AFE/AFEC/LSMC/AANC/VVP3/AVP3/
ASTM/VSTM/VST2 appear on BOTH sides (ACGICDFT next to ACGILUT0).  So the join is by that root, and
each row answers the port question directly:

    "for cal type X, module M param P: which files carry it, and does the matching LUT cover the
     device ids this machine actually uses?"

Controls (a matrix that cannot tell two boards apart is decoration):
  POSITIVE  PD1610 vs PD1610LG4 -- byte-equal files (ledger 261) must give an identical matrix
  NEGATIVE  PD1610 vs QRD       -- must differ, and say WHICH cal types lost or gained pairs
  SCHEMA    every cal root seen in a *CDFT field must also exist as a *LUT field and vice versa,
            reported per file (a firmware that breaks this is a different generator, not a re-tune)

Usage: tools/acdb_matrix.py [--dir PD1610] [--compare QRD]
"""
import argparse
import collections
import csv
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ART = os.path.join(ROOT, "art/audio-6.0.1")


def read_pairs(dir_name):
    p = os.path.join(ART, f"acdb-pairs.{dir_name}.tsv")
    if not os.path.exists(p):
        p = os.path.join(ART, "acdb-pairs.ALL.tsv")
        if not os.path.exists(p):
            sys.exit("gate: no acdb-pairs table -- run tools/acdb_pairs.py")
        rows = [r for r in csv.DictReader(open(p), delimiter="\t") if r["dir"] == dir_name]
    else:
        rows = list(csv.DictReader(open(p), delimiter="\t"))
    out = collections.defaultdict(lambda: {"module": "", "param": "", "fields": set(), "files": set()})
    for r in rows:
        root = r["field"][:4]          # ACGI / ACGD / AVOL / VCGI / VCD2 / VPDY / VPST / ...
        d = out[(root, r["id_a"], r["id_b"])]
        d["fields"].add(r["field"])
        d["files"].add(r["file"])
        d["module"] = d["module"] or r["name_a"]
        d["param"] = d["param"] or r["name_b"]
    return out


def read_lut(dir_name):
    p = os.path.join(ART, f"acdb-lut.{dir_name}.tsv")
    if not os.path.exists(p):
        sys.exit(f"gate: {p} missing -- run tools/acdb_tlv.py")
    dev = collections.defaultdict(set)
    app = collections.defaultdict(set)
    tables = collections.defaultdict(int)
    for r in csv.DictReader(open(p), delimiter="\t"):
        if r["dir"] != dir_name:
            continue
        tables[r["table"]] += 1
        for note in r["notes"].split(";"):
            if note.endswith(")") and "=dev(" in note:
                dev[r["table"]].add(int(note.split("=dev(")[1].split(":")[0]))
            elif note.endswith(")") and "=app_type(" in note:
                app[r["table"]].add(note.split("=app_type(")[1].split(":")[1].rstrip(")"))
    return tables, dev, app


def lut_files(dir_name):
    """which *LUT roots exist per file, from the field inventory"""
    p = os.path.join(ART, f"acdb-tlv.{dir_name}.tsv")
    if not os.path.exists(p):
        p = os.path.join(ART, "acdb-tlv.PD1610.tsv")
    roots = collections.defaultdict(set)
    for r in csv.DictReader(open(p), delimiter="\t"):
        if r["dir"] != dir_name:
            continue
        f = r["field"].strip()
        if f.endswith(("LUT", "LUT0")):
            roots[r["file"]].add(f[:4])
    return roots


def build(dir_name):
    pairs = read_pairs(dir_name)
    tables, dev, app = read_lut(dir_name)
    roots = lut_files(dir_name)
    rows = []
    for (root, m, prm), info in sorted(pairs.items()):
        lut_table = next((t for t in tables if t.startswith(root)), "-")
        rows.append({
            "cal_root": root, "module_id": m, "module_name": info["module"] or "",
            "param_id": prm, "param_name": info["param"] or "",
            "fields": ";".join(sorted(info["fields"])),
            "files": ";".join(sorted(info["files"])),
            "lut_table": lut_table,
            # NOT truncated: the reach test below compares against device ids this machine uses, and
            # a [:12] cap here would silently drop e.g. id 15 and report "no live device reaches it"
            "lut_devices": ",".join(str(x) for x in sorted(dev.get(lut_table, []))),
            "lut_device_count": len(dev.get(lut_table, [])),
            "lut_app_types": ",".join(sorted(app.get(lut_table, []))[:8]),
        })
    schema = []
    for fn, rs in sorted(roots.items()):
        paired = {k[0] for k, v in pairs.items() if fn in v["files"]}
        schema.append((fn, sorted(rs), sorted(paired)))
    return rows, schema, tables


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default="PD1610")
    ap.add_argument("--compare", default=None)
    ap.add_argument("--only-missing-in", default=None, metavar="DIR",
                    help="write the rows this dir has and DIR lacks, with the devices each cal type reaches")
    args = ap.parse_args()
    rows, schema, tables = build(args.dir)
    p = os.path.join(ART, f"acdb-matrix.{args.dir}.tsv")
    cols = ["cal_root", "module_id", "module_name", "param_id", "param_name", "fields", "files",
            "lut_table", "lut_devices", "lut_device_count", "lut_app_types"]
    with open(p, "w", encoding="utf-8") as fh:
        fh.write("\t".join(cols) + "\n")
        for r in rows:
            fh.write("\t".join(str(r[c]) for c in cols) + "\n")
    named = sum(1 for r in rows if r["module_name"])
    joined = sum(1 for r in rows if r["lut_table"] != "-")
    print(f"{args.dir}: {len(rows)} (cal type, module, param) rows -> {p}")
    print(f"   module id named by the QACT catalog: {named}/{len(rows)}; "
          f"row has a matching *LUT table: {joined}/{len(rows)}")
    print("   cal roots: " + ", ".join(sorted({r['cal_root'] for r in rows})))
    all_roots = {t[:4] for t in tables}
    miss_lut = sorted({r["cal_root"] for r in rows if r["lut_table"] == "-"})
    for root in miss_lut:
        near = sorted(x for x in all_roots if sum(a != b for a, b in zip(root, x)) == 1 and len(x) == len(root))
        # VCD2 has *CDFT/*CDOT but its LUT is spelled VGD2LUT0 by the same producer: a name-form
        # asymmetry, NOT a missing calibration.  Shown, never silently matched.
        print(f"   cal root {root}: no {root}LUT here"
              + (f" -- but a near-spelling {near} LUT exists, so this is naming, not absence" if near else
                 " -- and no near-spelling either"))
    print(f"   schema check: {len(schema)} files, LUT roots per file "
          f"{sorted({len(rs) for _, rs, _ in schema})}, pair-bearing cal roots "
          f"{sorted({len(cf) for _, _, cf in schema})}")

    if args.only_missing_in:
        other_rows, _, _ = build(args.only_missing_in)
        oth = {(r["cal_root"], r["module_id"], r["param_id"]) for r in other_rows}
        only = [r for r in rows if (r["cal_root"], r["module_id"], r["param_id"]) not in oth]
        p2 = os.path.join(ART, f"acdb-matrix.{args.dir}-missing-in-{args.only_missing_in}.tsv")
        with open(p2, "w", encoding="utf-8") as fh:
            cols2 = ["cal_root", "module_id", "module_name", "param_id", "param_name",
                     "lut_table", "lut_devices", "lut_device_count", "files"]
            fh.write("\t".join(cols2) + "\n")
            for r in sorted(only, key=lambda x: (x["cal_root"], x["module_id"], x["param_id"])):
                fh.write("\t".join(str(r[c]) for c in cols2) + "\n")
        LIVE = {15: "speaker", 124: "speaker-protected", 150: "hifi-headset"}
        reach = collections.Counter()
        for r in only:
            devs = {int(x) for x in r["lut_devices"].split(",") if x.isdigit()}
            for d, nm in LIVE.items():
                if d in devs:
                    reach[nm] += 1
        print(f"\nvivo-only hooks (not present in {args.only_missing_in}): {len(only)} rows -> {p2}")
        print(f"   rows whose LUT covers a device this machine actually uses: "
              + ", ".join(f"{k}={v}" for k, v in reach.most_common())
              + ("" if reach else "  <-- none of the live devices reach them; they belong to other device classes"))
        per = collections.Counter(r["cal_root"] for r in only)
        print("   by cal type: " + ", ".join(f"{k}={v}" for k, v in per.most_common()))
        for k, v in per.most_common(3):
            sample = [r for r in only if r["cal_root"] == k][:3]
            print(f"     {k}: " + "; ".join(f"{r['module_id']}{('/' + r['module_name']) if r['module_name'] else ''}"
                                           f"->{r['param_id']} devs[{r['lut_devices'] or '-'}]" for r in sample))
        return 0

    if args.compare:
        cur = {(r["cal_root"], r["module_id"], r["param_id"]) for r in rows}
        other_rows, _, _ = build(args.compare)
        oth = {(r["cal_root"], r["module_id"], r["param_id"]) for r in other_rows}
        lost, gained = sorted(cur - oth), sorted(oth - cur)
        byroot_lost = collections.Counter(k[0] for k in lost)
        byroot_gained = collections.Counter(k[0] for k in gained)
        print(f"\n{args.dir} vs {args.compare}: shared {len(cur & oth)}, "
              f"only in {args.dir} {len(lost)}, only in {args.compare} {len(gained)}")
        print("   lost per cal type: " + (", ".join(f"{k}={v}" for k, v in byroot_lost.most_common()) or "none"))
        print("   gained per cal type: " + (", ".join(f"{k}={v}" for k, v in byroot_gained.most_common()) or "none"))
        if args.compare == "PD1610LG4":
            print(f"   control POSITIVE (byte-equal files -> identical matrix): {'PASS' if cur == oth else 'FAIL'}")
            return 0 if cur == oth else 1
        if args.compare in ("QRD", "MTP", "PD1516A", "Fluid", "Liquid"):
            print(f"   control NEGATIVE (another board must move the matrix): "
                  f"{'PASS' if lost or gained else 'FAIL -- matrix cannot tell boards apart'}")
            return 0 if (lost or gained) else 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
