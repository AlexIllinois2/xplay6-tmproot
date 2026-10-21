#!/usr/bin/env python3
"""tools/acdb_tlv.py -- anchored field walk of the ACDB (.acdb) container.

The grammar (this is what §261's blind sub-block search could not find, and what it replaces):

    header          32 B: 'QCMSNDDB' + u32 + u32 + subdb tag + version + size + size   (ledger 261)
    field list      starts at 0x20, packed, no index, no padding between fields:
                    name[8]  +  u32 len  +  payload[len]
    name[8]         printable ASCII, 7-char names padded (mix of '0' and ' ' -- both kept raw)
    payload of a table   u32 count + count * rec, rec = (len-4)/count

Gate: the walk must land EXACTLY on end-of-file. It does on 49/49 files (7 dirs x 7), which is
what makes this an anchor rather than a guess -- a wrong field length desynchronises the walk and
the remaining names stop being ASCII. tools/acdb_workspace.py and the regex version of
tools/acdb_lut.py scanned names and are superseded for anything actionable.

Two outputs: the field inventory, and the decoded records of every table whose record size comes
out integral. `*CDFT`/`*CDOT`/DATAPOOL are variable-size by construction here -- reported, not
guessed (ledger 251: a scan without a scale is worse than no scan).

Cross-references used to NAME raw u32s, both independent of this file's own payload:
  - app_type ids 0x11130..0x11135 come from vendor/etc/audio_output_policy.conf ("app_type <n>")
    AND from the DATAPOOL pair lists in 3+ files; where the two agree the id gets a name.

Usage: tools/acdb_tlv.py [--dirs PD1610|ALL] [--outdir art/audio-6.0.1] [--selftest]
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
OUT_CONF = os.path.join(ROOT, "art/audio-6.0.1/live/extra/files/vendor/etc/audio_output_policy.conf")
HDR = 32
APPNAMED = {}
FS = {8000, 11025, 12000, 16000, 22050, 24000, 32000, 44100, 48000, 88200, 96000, 176400, 192000}
# not tables -- a u32 read at their +12 is string data, so the record model must not be applied
STRING_FIELDS = {"MODIFIED", "SWPNAME", "SWPVERS", "OEMINFO", "ACSWVERS", "ADSPVERS", "CDCNAME",
                 "DEVCATIN"}
# DATAPOOL sat in STRING_FIELDS until ledger 303, which made tools/acdb_bodies.py's digest census
# skip it -- so the project's "what is still unreadable" list silently left out its largest unreadable
# region.  It is not a header field: measured over all seven sets the largest header field is 28 B
# (SWPNAME) while pool bodies run 194 B..109262 B, and 16/49 of them are not even a whole number of
# words.  Note the header bucket legitimately holds *binary* names too (SWPVERS/ACSWVERS are 0 %
# printable version words), so the separation scan() asserts is size, not printability.
BLOB_FIELDS = {"DATAPOOL"}
# The record model {u32 count, count*rec} is asserted only for *LUT* fields. The *CDFT / *CDOT
# ("cal default" / "cal other") fields start with a count too but then carry an id list plus a
# blob, and their fitted "rec" differs from file to file (8 vs 100 B) -- that disagreement is the
# evidence they are not fixed-record tables, so this tool inventories them and says so.
def is_table(name):
    return name.strip().endswith("LUT") or name.strip().endswith("LUT0")


def walk(b, at=HDR):
    """[(off, raw_name, len)] walking the packed field list; stops when the name is not ASCII."""
    out = []
    while at + 12 <= len(b):
        raw = b[at:at + 8]
        if not all(32 <= c < 127 for c in raw):
            break
        ln = struct.unpack_from("<I", b, at + 8)[0]
        out.append((at, raw.decode("latin-1"), ln))
        at += 12 + ln
        if ln > len(b) or at > len(b):
            break
    return out, at


def count_rec(b, off, ln):
    """(count, rec_size) when the table model actually fits, else (count, None)."""
    if ln < 4:
        return None, None
    cnt = struct.unpack_from("<I", b, off + 12)[0]
    if cnt == 0:
        return cnt, "empty"
    if (ln - 4) % cnt:
        return cnt, None
    return cnt, (ln - 4) // cnt


def dev_names():
    """acdb_dev_id -> name from the ACDB's own '<n>_<NAME>' pool (tools/acdb_names.py).
    Absent is fine -- the records then simply carry no device annotation."""
    p = os.path.join(ROOT, "art/audio-6.0.1/acdb-devs.PD1610.tsv")
    if not os.path.exists(p):
        return {}
    out = {}
    for r in csv.DictReader(open(p), delimiter="\t"):
        nm = r["names"].split(";")[0]
        out[int(r["acdb_dev_id"])] = nm.split("_", 1)[1] if "_" in nm else nm
    return out


def dev_column(table, rows_, devs):
    """the position that IS the device id, decided by the data: every distinct value in the dev-id
    set, and at least 8 of them (a 1-2 value column is not evidence of anything)"""
    if not devs:
        return None
    for pos in range(len(rows_[0][5].split())):
        vals = {int(r[5].split()[pos], 16) for r in rows_}
        if len(vals) >= 8 and vals <= set(devs):
            return pos
    return None


def app_type_column(vals):
    """the column that IS app_type, as a structural rule rather than a lookup list: a contiguous
    run of ids that contains at least one id the vendor conf names.  The conf names only
    0x11130/0x11131/0x11134, but DATAPOOL enumerates 0x11130..0x11135 as the set (ledger 263/264),
    so matching by conf membership alone silently missed 3 of the 6."""
    distinct = set(vals)
    if not any(v in APPNAMED for v in distinct):
        return None
    lo, hi = min(distinct), max(distinct)
    # arithmetic, never set(range(lo, hi+1)): a sparse column such as {0, 0x1000ffff} would build a
    # 16-million-element set -- that is what hung the QRD card run until it was killed by PID
    if hi - lo > 63 or len(distinct) != hi - lo + 1:
        return None
    return lo


def app_type_names():
    """id -> [profile names] from the vendor's own output policy conf (never hard-coded here)."""
    if not os.path.exists(OUT_CONF):
        return {}
    txt = open(OUT_CONF, encoding="utf-8", errors="replace").read()
    names = collections.defaultdict(list)
    # two-space-indented profile blocks only; the outer "outputs {" nests them all
    for prof, body in re.findall(r"^  ([A-Za-z0-9_]+) \{\n(.*?)^  \}", txt, re.S | re.M):
        m = re.search(r"app_type\s+(\d+)", body)
        if m:
            names[int(m.group(1))].append(prof)
    return names


def selftest(dirs):
    """POSITIVE: real files land on EOF.  NEGATIVE: one corrupted u32 len must break the walk."""
    p = None
    for d in dirs:
        for fn in sorted(os.listdir(os.path.join(ACDB, d))):
            if fn.startswith("Speaker") and fn.endswith(".acdb"):
                p = os.path.join(ACDB, d, fn)
                break
        if p:
            break
    if not p:
        sys.exit("selftest: no Speaker*_cal.acdb found to corrupt -- nothing was proven")
    b = open(p, "rb").read()
    fl, end = walk(b)
    if end != len(b):
        sys.exit(f"selftest POSITIVE failed: clean file does not land on EOF ({end:#x} vs {len(b):#x})")
    print(f"  POSITIVE clean walk: {len(fl)} fields, ends {end:#x} == filesize {len(b):#x}")
    tgt = next(f for f in fl if f[1].strip() == "DPROPLUT")
    bad = bytearray(b)
    struct.pack_into("<I", bad, tgt[0] + 8, tgt[2] + 1)
    fl2, end2 = walk(bytes(bad))
    if end2 == len(bad):
        sys.exit("selftest NEGATIVE failed: a corrupted field length still lands on EOF -- gate is blind")
    print(f"  NEGATIVE len+1 on {tgt[1]}: walk dies at {end2:#x} after {len(fl2)} of {len(fl)} fields "
          f"(EOF {len(bad):#x}) -- gate is live")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dirs", default="PD1610")
    ap.add_argument("--outdir", default=os.path.join(ROOT, "art/audio-6.0.1"))
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if not os.path.isdir(ACDB):
        sys.exit(f"gate: {ACDB} missing")
    all_dirs = sorted(d for d in os.listdir(ACDB) if os.path.isdir(os.path.join(ACDB, d)))
    if args.selftest:
        selftest(all_dirs)
        return 0
    dirs = all_dirs if args.dirs == "ALL" else [d for d in args.dirs.split(",")]

    appn = app_type_names()
    APPNAMED.update(appn)
    devs = dev_names()
    inv, recs, variable, strf, empty = [], [], collections.Counter(), collections.Counter(), \
        collections.Counter()
    blob = collections.Counter()
    hdr_max = 0
    blob_min = 1 << 62
    short = {}
    rec_size_seen = collections.defaultdict(set)
    tight = nfiles = 0
    for d in dirs:
        for fn in sorted(f for f in os.listdir(os.path.join(ACDB, d)) if f.endswith(".acdb")):
            b = open(os.path.join(ACDB, d, fn), "rb").read()
            fl, end = walk(b)
            if end != len(b):
                short[d + "/" + fn] = end
                continue
            tight += 1
            nfiles += 1
            for off, raw, ln in fl:
                name = raw.strip()
                if name in STRING_FIELDS:
                    hdr_max = max(hdr_max, ln)
                elif name in BLOB_FIELDS and ln:
                    blob_min = min(blob_min, ln)
                cnt, rs = (None, None) if (name in STRING_FIELDS or name in BLOB_FIELDS
                                           or not is_table(name)) \
                    else count_rec(b, off, ln)
                if rs in (None, "empty"):
                    note = ("string/header field" if name in STRING_FIELDS else
                            "binary payload pool: block chain {u32 L, L bytes} parsed by tools/acdb_pool.py "
                            "(ledger 304), block meaning unnamed -- kept in the digest census by "
                            "tools/acdb_bodies.py" if name in BLOB_FIELDS else
                            "not a fixed-record table (CDFT/CDOT/CVD/OFST)" if rs is None else
                            "declared table, count=0 -> nothing stored in this file")
                    (strf if name in STRING_FIELDS else
                     blob if name in BLOB_FIELDS else
                     empty if rs == "empty" else variable)[name] += 1
                    inv.append((d, fn, raw, off, ln, "" if cnt is None else cnt, "", note))
                    continue
                rec_size_seen[name].add(rs)
                inv.append((d, fn, raw, off, ln, cnt, rs, ""))
                words = rs // 4
                if words * 4 != rs:
                    variable[name] += 1
                    continue
                base = off + 16
                for i in range(cnt):
                    vals = struct.unpack_from("<" + "I" * words, b, base + rs * i)
                    notes = []
                    for j, v in enumerate(vals):
                        if v in FS:
                            notes.append(f"f{j}=fs({v})")
                        # the app_type note is added by the column rule below, not per value -- per
                        # value it silently misses the 3 ids the vendor conf does not name

                    recs.append((d, fn, f"{base:#x}", name, i,
                                 " ".join(f"{v:#010x}" for v in vals), ";".join(notes)))

    if short:
        sys.exit(f"gate: {len(short)} of {tight + len(short)} file(s) did not walk to EOF: " +
                 ", ".join(f"{k} -> {v:#x}" for k, v in list(short.items())[:6]))
    per_tab = collections.defaultdict(list)
    for idx, r in enumerate(recs):
        per_tab[r[3]].append(idx)
    appcol = {}
    for t, idxs in per_tab.items():
        words = [recs[i][5].split() for i in idxs]
        for p in range(len(words[0])):
            if app_type_column({int(w[p], 16) for w in words}) is not None:
                appcol[t] = p
                for i, w in zip(idxs, words):
                    v = int(w[p], 16)
                    row = list(recs[i])
                    row[6] = (row[6] + ";" if row[6] else "") + \
                        f"f{p}=app_type({v}:{','.join(appn.get(v, ['unnamed-in-conf']))})"
                    recs[i] = tuple(row)
                break
    devcol = {}
    for t, idxs in per_tab.items():
        words = [recs[i][5].split() for i in idxs]
        pos = None
        for p in range(len(words[0])):
            vals = {int(w[p], 16) for w in words}
            if len(vals) >= 8 and vals <= set(devs):
                pos = p
                break
        devcol[t] = pos if devs else None
        if devcol[t] is None:
            continue
        for i, w in zip(idxs, words):
            v = int(w[pos], 16)
            if v in devs:
                row = list(recs[i])
                row[6] = (row[6] + ";" if row[6] else "") + f"f{pos}=dev({v}:{devs[v]})"
                recs[i] = tuple(row)
    if blob and hdr_max >= blob_min:
        sys.exit(f"gate: the header/pool split is not separable by size -- the largest STRING_FIELDS "
                 f"body is {hdr_max} B while the smallest BLOB_FIELDS body is {blob_min} B, so one of "
                 "the two labels is a guess (ledger 303: DATAPOOL sat in STRING_FIELDS and dropped out "
                 "of the undecoded-body census that way)")
    if blob:
        print(f"header/pool size separation: max header {hdr_max} B < min pool body {blob_min} B "
              f"-- the buckets are separated by measured size, not by printability "
              f"(SWPVERS/ACSWVERS are 0 % printable header words, so printability would be a false "
              "ruler here)")
    stem = "_".join(dirs) if len(dirs) == 1 else "ALL"
    p1 = os.path.join(args.outdir, f"acdb-tlv.{stem}.tsv")
    with open(p1, "w", encoding="utf-8") as fh:
        fh.write("dir\tfile\tfield\toffset\tlen\tcount\trec_bytes\tnote\n")
        for r in inv:
            fh.write("\t".join(str(x) for x in r) + "\n")
    p2 = os.path.join(args.outdir, f"acdb-lut.{stem}.tsv")
    with open(p2, "w", encoding="utf-8") as fh:
        fh.write("dir\tfile\ttable_off\ttable\trecord\twords\tnotes\n")
        for r in recs:
            fh.write("\t".join(str(x) for x in r) + "\n")

    nonuni = {k: sorted(v) for k, v in rec_size_seen.items() if len(v) > 1}
    print(f"walked to EOF: {tight} files, all of them (dirs {dirs})")
    print(f"fields: {len(inv)} ({len(rec_size_seen)} tables with an integral record size, "
          f"{len(variable)} variable-size, {len(strf)} string/header, {len(blob)} binary pool)")
    print(f"records: {len(recs)} -> {p2}")
    print(f"inventory -> {p1}")
    for name in sorted(rec_size_seen):
        files = sum(1 for r in inv if r[2].strip() == name)
        print(f"   {name:10s} rec={sorted(rec_size_seen[name])[0]:5d} B  in {files:3d} files")
    print("record size NOT unanimous across files:", nonuni if nonuni else "none")
    print(f"device-id column found by data (not typed), naming from {len(devs)} pool ids: "
          + ", ".join(f"{t}=f{c}" for t, c in sorted(devcol.items()) if c is not None))
    print(f"app_type column by the contiguous-run rule (conf names only {sorted(appn)}): "
          + (", ".join(f"{t}=f{c}" for t, c in sorted(appcol.items())) or "none found"))
    print(f"empty tables (count=0 in this file): {sum(empty.values())} rows over "
          f"{len(empty)} names")
    print("variable-size fields (inventory only, bodies not parsed):", ", ".join(sorted(variable)))
    print(f"app_type authority: {OUT_CONF} -> " +
          ", ".join(f"{i:#x}={n[0]}" for i, n in sorted(appn.items())))
    named = sum(1 for r in recs if r[6])
    print(f"records carrying an app_type or sample-rate cross-reference: {named}/{len(recs)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
