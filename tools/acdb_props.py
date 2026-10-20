#!/usr/bin/env python3
"""tools/acdb_props.py -- which ACDB field mentions each raw property id (0x1xxxx space).

The ACDB name pool (tools/acdb_names.py) names 92 device numbers and 14 topologies, and NOTHING in
the 0x00010000-0x00014000 range that the coefficient tables key on (DPROPLUT f1, VSTMLUT f0,
GLBLLUT, GPROPLUT, ACGILUT f1...).  No property names exist in these files, so this tool does not
pretend to name them -- it establishes each id's CLASS, structurally:

    the *CDFT / *CDOT / *LUT fields are named by their prefix (ACGI = analog core gain interpolator,
    VSTM = voice stream, VPST/VPDY = ..., DPROP = device property), and every payload boundary is
    known from the anchored walk (ledger 263).  So: in which fields does this u32 actually appear?

Mentions are counted ONLY inside `*CDFT` / `*CDOT` / DATAPOOL fields -- the ones whose body this
tool cannot parse.  Counting the LUT payloads too would be circular: the id is in DPROPLUT because
it IS a DPROPLUT key, which says nothing about what it means.

An id that shows up only under `VSTM*` fields is a VSTM-domain id -- that is an observation about
where the file stores it, not a claimed human-readable name.  The scan is confined to a payload
whose boundaries are proven, and it reports the alignment that matched plus a same-window shuffle
null, because a 4-byte pattern inside a 70 KB blob is exactly where §251-style coincidences live.

Output: acdb-props.PD1610.tsv  id  uses_in_luts  class_fields  matches(bytes@offset)  shuffle_null

Usage: tools/acdb_props.py [--dirs PD1610] [--lo 0x10000] [--hi 0x14000]
"""
import argparse
import collections
import csv
import os
import random
import struct
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ACDB = os.environ.get("ACDB_DIR") or os.path.join(ROOT, "art/audio-6.0.1/live/extra/files/system/etc/acdbdata")
#  ACDB_DIR lets the whole acdb_* family read another ROM's copies (the official 7.1.1 set lives at
#  art/audio-7.1.1/acdbdata) -- the tools were written against one tree and the port work needs two.
ART = os.path.join(ROOT, "art/audio-6.0.1")
HDR = 32
LO, HI = 0x10000, 0x14000


def walk(b):
    at, out = HDR, []
    while at + 12 <= len(b):
        raw = b[at:at + 8]
        if not all(32 <= c < 127 for c in raw):
            break
        ln = struct.unpack_from("<I", b, at + 8)[0]
        out.append((at, raw.decode("latin-1").strip(), ln))
        at += 12 + ln
        if at > len(b):
            break
    return out, at


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dirs", default="PD1610")
    ap.add_argument("--lo", default=hex(LO))
    ap.add_argument("--hi", default=hex(HI))
    ap.add_argument("--nulls", type=int, default=3, help="shuffle arms per file for the false-hit rate")
    args = ap.parse_args()
    lo, hi = int(args.lo, 16), int(args.hi, 16)
    d = dirs = args.dirs.split(",")[0] if args.dirs != "ALL" else None

    # 1) the ids we want classified: values in the property window used as keys in the LUT records
    lut = os.path.join(ART, f"acdb-lut.{d}.tsv")
    if not os.path.exists(lut):
        sys.exit(f"gate: {lut} missing -- run tools/acdb_tlv.py")
    uses = collections.defaultdict(collections.Counter)
    for r in csv.DictReader(open(lut), delimiter="\t"):
        for pos, w in enumerate(r["words"].split()):
            v = int(w, 16)
            if lo <= v < hi:
                uses[v][f"{r['table']}[f{pos}]"] += 1
    print(f"ids in {lo:#x}..{hi:#x} used as LUT keys: {len(uses)}")

    # 2) which fields mention each id (aligned scan inside proven payload boundaries)
    fields_of = collections.defaultdict(set)
    offsets_of = collections.defaultdict(list)
    null_hits = 0
    null_bytes = 0
    real_bytes = 0
    real_hits = 0
    root = os.path.join(ACDB, d)
    for fn in sorted(f for f in os.listdir(root) if f.endswith(".acdb")):
        b = open(os.path.join(root, fn), "rb").read()
        fl, end = walk(b)
        if end != len(b):
            sys.exit(f"gate: {fn} does not walk to EOF -- run tools/acdb_tlv.py first")
        for off, name, ln in fl:
            if not (name.endswith(("CDFT", "CDOT")) or name == "DATAPOOL"):
                continue
            real_bytes += ln
            pay = b[off + 12:off + 12 + ln]
            for i in range(0, len(pay) - 3, 4):
                v = struct.unpack_from("<I", pay, i)[0]
                if v in uses:
                    fields_of[v].add(name)
                    offsets_of[v].append(f"{name}@{off + 12 + i:#x}")
                    real_hits += 1
        # null arm: same predicate on a shuffled payload window, same id set
        r = random.Random(11)
        for _ in range(args.nulls):
            pay = bytearray(b[:4096])
            r.shuffle(pay)
            null_bytes += len(pay)
            for i in range(0, len(pay) - 3, 4):
                if struct.unpack_from("<I", pay, i)[0] in uses:
                    null_hits += 1
    arms = args.nulls * len([f for f in os.listdir(root) if f.endswith(".acdb")])
    rd = real_hits / max(real_bytes, 1) * 1024
    nd = null_hits / max(null_bytes, 1) * 1024
    print(f"real: {real_hits} hits in {real_bytes} scanned bytes of CDFT/CDOT/DATAPOOL = {rd:.3f}/KB")
    print(f"shuffle null: {null_hits} hits in {null_bytes} shuffled bytes over {arms} arms = {nd:.3f}/KB"
          f"  -> signal/noise {rd / nd if nd else float('inf'):.1f}x")
    if nd and rd / nd < 5:
        sys.exit("gate: the mention signal is not dense enough above its own null to classify ids")

    named = {i: sorted(fl) for i, fl in fields_of.items()}
    covered = sum(1 for i in uses if named.get(i))
    p = os.path.join(ART, f"acdb-props.{d}.tsv")
    with open(p, "w", encoding="utf-8") as fh:
        fh.write("id\tuses_in_luts\tclass_fields\tn_field_hits\tshuffle_null_hits\n")
        for i in sorted(uses):
            fh.write(f"{i:#010x}\t{';'.join(f'{k}x{v}' for k, v in sorted(uses[i].items()))}\t"
                     f"{';'.join(named.get(i, []))}\t{len(offsets_of.get(i, []))}\t{null_hits}\n")
    print(f"{covered}/{len(uses)} ids are mentioned inside at least one field "
          f"({'YES, the class signal exists' if covered else 'NO -- ids appear only as LUT keys'})")
    per_cls = collections.Counter()
    for i, ns in named.items():
        per_cls[",".join(ns) if ns else "(unmentioned)"] += 1
    for k, v in per_cls.most_common(12):
        print(f"   {v:4d} ids -> {k}")
    print(f"wrote {p}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
