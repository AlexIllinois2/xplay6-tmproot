#!/usr/bin/env python3
"""tools/acdb_names.py -- harvest the UTF-16 id/name records that live inside the ACDB files.

Why this and not the DATAPOOL layout: the pool is a heterogeneous block collection -- the
{u32 tag, u32 count, count*rec} chain (with a variable name-record mode) found 0 full-consuming
solutions on it this round, so shipping a pool parser would be shipping a guess (ledger 240/251).
Each individual name record, however, is self-verifying:

    u32 len   +  len bytes of UTF-16LE where every high byte is 0x00 and every low byte is 0x20..0x7e

MIN_LN = 8 bytes (4 characters) is set from that measurement, not from taste: below it the
shuffle null is non-zero (9 two-character hits over 1.1 MB) and the predicate is the file's own
padding bytes, not a name.  For a 4-character name the chance rate is ~(1/256 * 95/256)^7 ~= 1e-21 per position by chance, and the tool
also reports an empirical shuffle null on the same predicate. The u32 immediately before `len` is
carried as `id_candidate` and is only used for the join when the same (id, name) pair is seen in
more than one place -- the record shape proves `len`, not which u32 is the key.

Positive control built in: DEVCATIN (ledger 261) stores one such record whose name must equal the
device category the file is named after (Speaker/Handset/Headset/Bluetooth/Hdmi/General).

Outputs: acdb-names.PD1610.tsv (dir file offset id len name in_field control)
         acdb-ids.PD1610.tsv  (id names sources, joined against the QACT workspace catalog)

Usage: tools/acdb_names.py [--dirs PD1610|ALL] [--outdir art/audio-6.0.1]
"""
import argparse
import collections
import csv
import os
import re
import struct
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ACDB = os.environ.get("ACDB_DIR") or os.path.join(ROOT, "art/audio-6.0.1/live/extra/files/system/etc/acdbdata")
#  ACDB_DIR lets the whole acdb_* family read another ROM's copies (the official 7.1.1 set lives at
#  art/audio-7.1.1/acdbdata) -- the tools were written against one tree and the port work needs two.
CATALOG = {"acdb-blocks.PD1610.tsv": ("module_id", "block"),
           "acdb-topologies.PD1610.tsv": ("id", "topology"),
           "acdb-params.PD1610.tsv": ("interface_id", "interface_name")}
HDR = 32
# a 2-char "name" is what a byte-shuffle of the same files produces (measured: 9 such hits per MB);
# the threshold below is what makes the anchor ours rather than the file's zero bytes
MIN_LN = 8
CATS = {"Speaker", "Handset", "Headset", "Bluetooth", "Hdmi", "General"}


def fields(b):
    """the anchored field list (ledger 263) so every name hit can be attributed to a field"""
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


def name_records(pay):
    """[(offset, id_candidate, byte_len, name)] on the predicate described above"""
    out = []
    i, n = 0, len(pay)
    while i + 8 <= n:
        ln = struct.unpack_from("<I", pay, i)[0]
        if MIN_LN <= ln <= 0x400 and ln % 2 == 0 and i + 4 + ln <= n:
            s = pay[i + 4:i + 4 + ln]
            if all(s[k] == 0 and 0x20 <= s[k - 1] < 0x7f for k in range(1, ln, 2)):
                nm = s.decode("utf-16-le")
                key = struct.unpack_from("<I", pay, i - 4)[0] if i >= 4 else None
                out.append((i - 4 if i >= 4 else i, key, ln, nm))
                i += 4 + ln
                continue
        i += 2
    return out


def shuffle_null(pay, rng_seed=7):
    import random
    r = random.Random(rng_seed)
    b = bytearray(pay)
    r.shuffle(b)
    return len(name_records(bytes(b)))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dirs", default="PD1610")
    ap.add_argument("--outdir", default=os.path.join(ROOT, "art/audio-6.0.1"))
    args = ap.parse_args()
    dirs = sorted(d for d in os.listdir(ACDB) if os.path.isdir(os.path.join(ACDB, d))) \
        if args.dirs == "ALL" else args.dirs.split(",")
    target_dirs = {d for d in dirs if not any(x in d for x in ("Fluid", "Liquid", "MTP", "QRD", "PD1516A"))}

    rows, per_file, nulls = [], 0, 0
    for d in dirs:
        for fn in sorted(f for f in os.listdir(os.path.join(ACDB, d)) if f.endswith(".acdb")):
            b = open(os.path.join(ACDB, d, fn), "rb").read()
            fl, end = fields(b)
            if end != len(b):
                sys.exit(f"gate: {d}/{fn} does not walk to EOF -- run tools/acdb_tlv.py first")
            hits = name_records(b)
            nulls += shuffle_null(b)
            # field attribution by offset
            starts = [(o, nm) for o, nm, ln in fl]
            per_file += 1
            for off, key, ln, nm in hits:
                owner = [f for f in starts if f[0] <= off]
                trunc = nm.endswith("_") or nm.rstrip() != nm
                rows.append((d, fn, f"{off:#x}", f"{key:#x}" if key is not None else "-",
                             ln, nm, owner[-1][1] if owner else "?",
                             "DEVCATIN" if owner and owner[-1][1] == "DEVCATIN" else "",
                             "name runs into a non-printable byte -- treat as truncated, not as the whole name"
                             if trunc else ""))

    # positive control: every per-device file must yield its own category name inside DEVCATIN
    # The gate is asserted on the machine's OWN dir only -- the other acdbdata dirs are reference
    # sets whose filenames do not track their DEVCATIN (measured: Fluid_Speaker carries "Headset"
    # etc.), and asserting that there would test my assumption, not the data. Those mismatches are
    # reported below as an observation.
    seen = {(r[0], r[1], r[5]) for r in rows if r[6] == "DEVCATIN"}
    miss, other = [], []
    for d in dirs:
        for fn in sorted(f for f in os.listdir(os.path.join(ACDB, d)) if f.endswith(".acdb")):
            if "Global" in fn:
                continue
            cat = next((c for c in CATS if c in fn), None)
            if not cat:
                continue
            if (d, fn, cat) not in seen:
                (miss if d in target_dirs else other).append(f"{d}/{fn} -> filename says {cat}, "
                                                             f"DEVCATIN says "
                                                             f"{sorted(n for (dd, ff, n) in seen if dd == d and ff == fn) or 'nothing'}")

    p1 = os.path.join(args.outdir, f"acdb-names.{'PD1610' if dirs == ['PD1610'] else 'ALL'}.tsv")
    with open(p1, "w", encoding="utf-8") as fh:
        fh.write("dir\tfile\toffset\tid_candidate\tbytes\tname\tin_field\tdevcatin_control\tnote\n")
        for r in rows:
            fh.write("\t".join(str(x) for x in r) + "\n")

    # id -> names, only where the same (id, name) pair recurs (the recurrence is the witness)
    pair_src = collections.defaultdict(set)
    pair_name = {}
    for r in rows:
        if r[3] != "-":
            k = (int(r[3], 16), r[5])
            pair_src[k].add(r[0] + "/" + r[1])
            pair_name[k] = r[5]
    ids = collections.defaultdict(set)
    for (i, nm), src in pair_src.items():
        ids[i].add(nm)
    cat = {}
    for f, (col, lab) in CATALOG.items():
        p = os.path.join(ROOT, "art/audio-6.0.1", f)
        if not os.path.exists(p):
            continue
        for r in csv.DictReader(open(p), delimiter="\t"):
            v = (r.get(col) or "").strip()
            if v.lower().startswith("0x"):
                nm = (r.get(lab) or "").strip()
                if nm:
                    cat.setdefault(int(v, 16), set()).add(nm + f" [{lab}]")
    p2 = os.path.join(args.outdir, f"acdb-ids.{'PD1610' if dirs == ['PD1610'] else 'ALL'}.tsv")
    with open(p2, "w", encoding="utf-8") as fh:
        fh.write("id\tn_files\tacdb_names\tworkspace_catalog\tfiles\n")
        njoin = 0
        for i in sorted(set(ids) | set(cat)):
            ac = ";".join(sorted(ids.get(i, [])))
            wc = ";".join(sorted(cat.get(i, [])))
            srcs = ";".join(sorted({f for (j, _), fs in pair_src.items() if j == i for f in fs}))
            if ac and wc:
                njoin += 1
            fh.write(f"{i:#010x}\t{len(srcs.split(';'))}\t{ac}\t{wc}\t{srcs}\n")

    # the device-number table: the ACDB names its devices "<acdb_dev_id>_<NAME>", so the id is
    # inside the string and needs no pool layout to read
    devs = collections.defaultdict(lambda: {"names": set(), "files": set()})
    for r in rows:
        m = re.match(r"^(\d{1,4})_[A-Za-z0-9_]+$", r[5])
        if m and r[6] != "DEVCATIN":
            k = int(m.group(1))
            devs[k]["names"].add(r[5])
            devs[k]["files"].add(r[0] + "/" + r[1])
    p3 = os.path.join(args.outdir, f"acdb-devs.{'PD1610' if dirs == ['PD1610'] else 'ALL'}.tsv")
    with open(p3, "w", encoding="utf-8") as fh:
        fh.write("acdb_dev_id\tnames\tn_files\tfiles\talso_declared_in_platform_info\n")
        decl = {}
        mp = os.path.join(ROOT, "art/audio-6.0.1/acdb-map-output.tsv")
        if os.path.exists(mp):
            for line in open(mp):
                a = line.rstrip("\n").split("\t")
                if len(a) == 2 and a[1].isdigit():
                    decl[int(a[1])] = a[0]
        for k in sorted(devs):
            d = devs[k]
            fh.write(f"{k}\t{';'.join(sorted(d['names']))}\t{len(d['files'])}\t"
                     f"{';'.join(sorted(d['files']))}\t{decl.get(k, '')}\n")

    ctl = [k for k in decl if k in devs]
    print(f"device-number control: platform_info declares {sorted(decl)}, "
          f"the ACDB name pool has {len(ctl)}/{len(decl)} of them -> "
          f"{'PASS' if ctl == sorted(decl) else 'PARTIAL ' + str(sorted(set(decl) - set(ctl)))}")
    print(f"devs -> {p3}  ({len(devs)} device numbers named in the pool)")
    for k in sorted(set(decl) | {150}):
        if k in devs:
            print(f"     {k:4d}  {sorted(devs[k]['names'])}  {decl.get(k, '(not declared in platform_info)')}")

    trunc = [r[5] for r in rows if r[8]]
    print(f"scanned {per_file} files, {len(rows)} name records, "
          f"{len(trunc)} flagged truncated ({';'.join(sorted(set(trunc))[:4]) or 'none'}) -- kept in the table, marked, not dropped")
    print(f"shuffle null on the same predicate: {nulls} hits in {per_file} shuffled payloads "
          f"(if this is not 0 the anchor is weaker than the docstring claims)")
    print(f"DEVCATIN positive control on {sorted(target_dirs) or 'the target dirs'}: "
          f"{'PASS' if not miss else 'FAIL ' + '; '.join(miss[:4])} ({len(seen)} files carry their own category name)")
    if other:
        print(f"   reference dirs differ from their filenames in {len(other)} of {len(other) + len(seen)} files "
              f"(e.g. {other[0]}) -- reported, not gated: those dirs are stock reference sets, not this machine")
    numbered = collections.Counter(r[0] for r in rows if re.match(r"^\d{1,4}_", r[5]) and r[6] == "DATAPOOL")
    print(f"   numbered device-pool present in: " +
          ", ".join(f"{d}={numbered.get(d, 0)}" for d in dirs) +
          "  <-- stock reference dirs have NO such pool; it is this board's own addition")
    print(f"names -> {p1}")
    multi = sum(1 for i in ids if len({f for (j, _), fs in pair_src.items() if j == i for f in fs}) > 1)
    print(f"ids  -> {p2}  ({njoin} named by BOTH the .acdb and the QACT workspace, "
          f"{multi} of {len(ids)} ids recur in more than one file)")
    return 0 if not miss else 1


if __name__ == "__main__":
    sys.exit(main())
