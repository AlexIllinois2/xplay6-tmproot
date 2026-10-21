#!/usr/bin/env python3
"""tools/acdb_lut.py -- SUPERSEDED by tools/acdb_tlv.py; kept only as the record of how the
record sizes were first established.

SUPERSEDED because the field locations here came from a regex name scan. tools/acdb_tlv.py walks
the real structure (packed name[8] + u32 len + payload list from offset 0x20) and its walk lands
exactly on end-of-file on 49/49 files, so table offsets, counts and record sizes are now anchored
instead of inferred. Its derived sizes for the 7 tables both tools know agree (DPROPLUT 12,
ACGILUT 20, ACGDLUT 20, VSTMLUT 20, ASTMLUT 12, GLBLLUT 12, GPROPLUT 8) -- that agreement is what
earned acdb_tlv.py the right to overwrite acdb-lut.PD1610.tsv.

This script also wrote the same output file as the new tool, so it now refuses to run.
"""
import argparse
import csv
import os
import re
import struct
import sys

sys.exit("superseded: run tools/acdb_tlv.py (it writes art/audio-6.0.1/acdb-lut.PD1610.tsv)")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ACDB = os.path.join(ROOT, "art/audio-6.0.1/live/extra/files/system/etc/acdbdata")
ART = os.path.join(ROOT, "art/audio-6.0.1")

# record size established by unanimity across files (see docstring)
REC = {"DPROPLUT": 12, "ACGILUT": 20, "ACGDLUT": 20, "VSTMLUT": 20,
       "ASTMLUT": 12, "GLBLLUT": 12, "GPROPLUT": 8}
TAG = re.compile(("(" + "|".join(REC) + ")")[1:-1].encode())
FS = {8000, 11025, 12000, 16000, 22050, 24000, 32000, 44100, 48000, 88200, 96000, 176400, 192000}


def load_catalog():
    names = {}
    for fn, col_id, col_name in (("acdb-blocks.PD1610.tsv", "module_id", "block"),
                                 ("acdb-params.PD1610.tsv", "interface_id", "interface"),
                                 ("acdb-topologies.PD1610.tsv", "id", "topology")):
        p = os.path.join(ART, fn)
        if not os.path.exists(p):
            continue
        for r in csv.DictReader(open(p), delimiter="\t"):
            v = (r.get(col_id) or "").strip()
            if v.lower().startswith("0x"):
                names.setdefault(int(v, 16), []).append(f"{r.get(col_name) or r.get('interface_name') or '?'}[{col_name}]")
    return names


def tables(b):
    """(name, payload_offset, count) only where the header model actually fits, plus a skip count"""
    out, skipped = [], 0
    # names are 7 or 8 chars in the file (ACGILUT is 7 and the tag field is space padded), so
    # search each known name rather than matching a fixed letter count
    hits = sorted([m for name in REC for m in re.finditer(re.escape(name.encode()), b)], key=lambda m: m.start())
    for m in hits:
        name = m.group().decode()
        ln = at = None
        for c in range(m.end(), m.end() + 5):
            if c + 4 > len(b):
                break
            v = struct.unpack_from("<I", b, c)[0]
            if 0 < v <= 0x400000 and c + 4 + v <= len(b):
                ln, at = v, c + 4
                break
        if ln is None:
            skipped += 1
            continue
        cnt = struct.unpack_from("<I", b, at)[0]
        if cnt == 0 or cnt * REC[name] != ln - 4:
            skipped += 1
            continue
        out.append((name, at + 4, cnt))
    return out, skipped


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dirs", default="PD1610", help="comma list of acdbdata subdirs, or ALL")
    ap.add_argument("--out", default=os.path.join(ART, "acdb-lut.PD1610.tsv"))
    args = ap.parse_args()
    if not os.path.isdir(ACDB):
        sys.exit(f"gate: {ACDB} missing")
    cat = load_catalog()
    dirs = sorted(d for d in os.listdir(ACDB) if os.path.isdir(os.path.join(ACDB, d))) if args.dirs == "ALL" \
        else args.dirs.split(",")

    rows, per_table, named, skipped = [], {}, 0, {}
    for d in dirs:
        for fn in sorted(f for f in os.listdir(os.path.join(ACDB, d)) if f.endswith(".acdb")):
            b = open(os.path.join(ACDB, d, fn), "rb").read()
            tl, sk = tables(b)
            skipped[fn] = skipped.get(fn, 0) + sk
            for name, off, cnt in tl:
                per_table[name] = per_table.get(name, 0) + 1
                w = REC[name] // 4
                for i in range(cnt):
                    vals = struct.unpack_from("<" + "I" * w, b, off + REC[name] * i)
                    notes = []
                    for j, v in enumerate(vals):
                        if v in FS:
                            notes.append(f"f{j}=fs({v})")
                        if v in cat:
                            notes.append(f"f{j}={';'.join(cat[v])}")
                    named += bool(notes)
                    rows.append((d, fn.replace(d + "_", ""), f"{off:#x}", name, i,
                                 " ".join(f"{v:#010x}" for v in vals), ";".join(notes)))

    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write("dir\tfile\ttable_off\ttable\trecord\twords\tdecoded\n")
        for r in rows:
            fh.write("\t".join(str(x) for x in r) + "\n")
    print(f"record sizes used (established by unanimity): {REC}")
    print(f"wrote {args.out}: {len(rows)} records from {sum(per_table.values())} tables in dirs {dirs}")
    recs = {}
    for r in rows:
        recs[r[3]] = recs.get(r[3], 0) + 1
    for k in sorted(per_table):
        print(f"   {k:10s} tables={per_table[k]:3d} rec={REC[k]:2d}B records={recs.get(k,0)}")
    print(f"records with at least one catalog/fs cross-reference: {named}/{len(rows)} ({named/max(len(rows),1):.0%})")
    print("NOT parsed (model does not fit): *CDFT, *CDOT, MINFOLUT -- see ledger 251/261 on why we do not guess these")
    return 0


if __name__ == "__main__":
    sys.exit(main())
