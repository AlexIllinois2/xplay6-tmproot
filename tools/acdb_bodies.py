#!/usr/bin/env python3
"""tools/acdb_bodies.py -- digest every field body this project has NOT put a meaning on.

What is on the list and why: the *CVD0*/*OFST* families (each has a proven grammar now -- acdb_cvd
and acdb_ofst -- but no named column, so the values are still not understood) and DATAPOOL, whose counted-array reading
failed (0/49 bodies consume exactly under any stride) because it is not an array of equal records but
a chain of variable blocks; their byte lengths are not always word multiples (16/49) and they open on app_type ids in the same numbering as the LUT
cross-references (69936/69937/69940 = deep_buffer/default/compress_offload_24).  Ledger 304 then
found the grammar -- a chain of byte-length-prefixed blocks {u32 L, L bytes}, 49/49 pools consumed to
the last byte -- and the blocks still have no named type, which is why the bodies are on this list.

For history: *CDFT* and *CDOT* used to be here too, and three models were tested against all 49 files
and rejected by per-name unanimity (a real model gives the same record shape in every file that
carries the field):

    M1 {u32 count, count*u32 id, count*blob}   -- ACGICDFT fits in 8 files and fails in 34
    M4 {u32 count, count*(id,id), count*blob}   -- same spread; also implies blobs of 33 B
    M6 sequential {u32 id, u32 len, blob}       -- dies at once: ACGICDFT's 2nd word 0x10717 as a
                                                   length exceeds the whole field (1404 B)

Those two families left the list when the anchor that blocked them was removed (ledger 268/300);
DATAPOOL should have been here all along and was not, because acdb_tlv labelled it a string/header
field and this tool trusted the label (ledger 303).

Unresolved is not the same as unwatchable. Per (file, field) we store sha16 of the exact body bytes,
so "the part we cannot read" becomes diffable on Android 7, and the port diff can name WHICH fields
moved instead of only saying the file hash changed.

Controls: POSITIVE PD1610 vs PD1610LG4 (byte-equal files, ledger 261) -> every body digest equal.
          NEGATIVE PD1610 vs QRD -> differing bodies in a counted number of fields (not zero).

Usage: tools/acdb_bodies.py [--dirs PD1610]        # write acdb-bodies.<stem>.tsv
       tools/acdb_bodies.py --compare PD1610 PD1610LG4
"""
import argparse
import collections
import hashlib
import os
import struct
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))
import acdb_tlv  # noqa: E402

ACDB = acdb_tlv.ACDB
ART = os.path.join(ROOT, "art/audio-6.0.1")
def is_decoded(name):
    """fields another tool already turns into rows: the *LUT* tables (acdb_tlv/acdb_card), the header
    strings (acdb_meta), the *CDFT* bodies (acdb_pairs, ledger 268), the *CDOT* bodies (acdb_cdot:
    REPEAT{u32 n, n*u32}, 360/360 across the six distinct sets with the CDFT grammar taking 0 of
    them, ledger 300), the *OFST* pair-lists and -- since ledger 303 -- the *CVD0* record arrays
    (acdb_cvd: REPEAT{u32 n, n*s} with s=8 for VPDY and 7 for VPST, 56/56 bodies).  None of those
    grammars names its columns, so structure is not the reason a field leaves this list; a field
    leaves it when its VALUES are understood.  DATAPOOL is here because no grammar fits it at all
    (0/49 bodies consume exactly under any counted-array stride) -- and until ledger 303 it was NOT
    here, because acdb_tlv classed it as a string/header field and this predicate trusted that label."""
    return (name.endswith(("LUT", "LUT0")) or name in acdb_tlv.STRING_FIELDS
            or name.endswith(("CDFT", "CDOT")))


def cdot_still_parses(d):
    """marking CDOT decoded is a claim about acdb_cdot.py, so re-check it here rather than trust the
    name predicate: every CDOT body in this dir must still parse exactly.  A model that silently
    stopped fitting would otherwise be reported as 'decoded' by the census."""
    import acdb_cdot
    bad = []
    for stem, f, name, w, _b in acdb_cdot.walk_fields([os.path.basename(d)], "CDOT"):
        if acdb_cdot.groups(w) is None:
            bad.append((f, name))
    return bad


def bodies(d):
    """[(dir, file, field, offset, len, sha16)] for every field body the project cannot interpret"""
    if not os.path.isdir(os.path.join(ACDB, d)):
        sys.exit(f"gate: {ACDB}/{d} is not an acdbdata directory")
    rows = []
    for fn in sorted(f for f in os.listdir(os.path.join(ACDB, d)) if f.endswith(".acdb")):
        b = open(os.path.join(ACDB, d, fn), "rb").read()
        fl, end = acdb_tlv.walk(b)
        if end != len(b):
            sys.exit(f"gate: {d}/{fn} does not walk to EOF -- run tools/acdb_tlv.py first")
        for off, raw, ln in fl:
            name = raw.strip()
            if is_decoded(name) or ln == 0:
                continue
            body = b[off + 12:off + 12 + ln]
            rows.append((d, fn, name, off, ln, hashlib.sha256(body).hexdigest()[:16]))
    return rows


def keymap(d):
    out = {}
    for r in bodies(d):
        k = (r[1].replace(d + "_", "", 1), r[2])
        if k in out and out[k] != r[5]:
            sys.exit(f"gate: key collision {k} in {d}")
        out[k] = r[5]
    if len(out) != len(bodies(d)):
        sys.exit(f"gate: {d} keyed {len(out)} slots from {len(bodies(d))} bodies -- collisions")
    return out


def compare_pair(a, b):
    """(baseline slots, candidate slots, differing keys) -- the arm acdb_port_diff calls"""
    ka, kb = keymap(a), keymap(b)
    shared = set(ka) & set(kb)
    return ka, kb, sorted(k for k in shared if ka[k] != kb[k])


def compare(a, b):
    # key by (file name minus its own dir prefix, field) so QRD_Foo_cal.acdb lines up with Foo_cal.acdb.
    # The first attempt used fn.split("_")[-1], which maps every *_cal.acdb to "cal.acdb" and silently
    # collapsed 136 bodies into 42 comparisons -- hence the collision gate right below.
    def keymap(d):
        out = {}
        for r in bodies(d):
            k = (r[1].replace(d + "_", "", 1), r[2])
            if k in out and out[k] != r[5]:
                sys.exit(f"gate: key collision {k} in {d} -- two bodies share one slot, comparison "
                         "would silently drop rows")
            out[k] = r[5]
        rows = len(bodies(d))
        if len(out) != rows:
            sys.exit(f"gate: {d} keyed {len(out)} slots from {rows} bodies -- collisions")
        return out
    ka, kb = keymap(a), keymap(b)
    shared = set(ka) & set(kb)
    diff = sorted(k for k in shared if ka[k] != kb[k])
    print(f"{a} vs {b}: {len(shared)} of {len(ka)}/{len(kb)} body slots compared, {len(diff)} differ, "
          f"{len(set(ka) - set(kb))} only in {a}, {len(set(kb) - set(ka))} only in {b}")
    cls = collections.Counter()
    for f, _ in [(k[1], k[0]) for k in diff]:
        cls["CDFT (cal default)" if f.endswith("CDFT") else
             "CDOT (cal other)" if f.endswith("CDOT") else
             "CVD/OFST" if f.endswith(("CVD0", "OFST")) else
             "DATAPOOL" if f == "DATAPOOL" else "other"] += 1
    print("   by class: " + ", ".join(f"{k}={v}" for k, v in cls.most_common()))
    per_field = collections.Counter(k[1] for k in diff)
    for f, n in per_field.most_common(10):
        print(f"      {f:10s} differs in {n} file(s)")
    return ka, kb, diff


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dirs", default="PD1610")
    ap.add_argument("--compare", nargs=2, metavar=("A", "B"))
    args = ap.parse_args()
    # is_decoded() claims CDOT is readable; that claim belongs to acdb_cdot.py, so verify it here
    # before the census quietly shrinks the undecoded list on the strength of a name suffix.
    for stem in sorted(d for d in os.listdir(ACDB) if os.path.isdir(os.path.join(ACDB, d))):
        bad = cdot_still_parses(os.path.join(ACDB, stem))
        if bad:
            sys.exit(f"gate: {stem}: {len(bad)} CDOT bodies no longer parse under acdb_cdot's model "
                     f"({bad[:4]}) -- is_decoded() may not call them decoded while that is true")
    if args.compare:
        ka, kb, diff = compare(*args.compare)
        if args.compare[1] == "PD1610LG4":
            print("   control POSITIVE (files byte-equal per 261): "
                  f"{'PASS' if not diff else 'FAIL ' + str(len(diff)) + ' bodies differ'}")
            return 0 if not diff else 1
        if args.compare[1] in ("QRD", "PD1516A"):
            print("   control NEGATIVE (another board must move some bodies): "
                  f"{'PASS' if diff else 'FAIL -- the digest arm sees nothing'}")
            return 0 if diff else 1
        return 0
    dirs = sorted(d for d in os.listdir(ACDB) if os.path.isdir(os.path.join(ACDB, d))) \
        if args.dirs == "ALL" else args.dirs.split(",")
    for d in dirs:
        if not os.path.isdir(os.path.join(ACDB, d)):
            sys.exit(f"gate: no such acdbdata dir: {d} (use ALL for every dir)")
    allrows = []
    for d in dirs:
        allrows += bodies(d)
    stem = dirs[0] if len(dirs) == 1 else "ALL"
    p = os.path.join(ART, f"acdb-bodies.{stem}.tsv")
    with open(p, "w", encoding="utf-8") as fh:
        fh.write("dir\tfile\tfield\toffset\tlen\tbody_sha16\n")
        for r in allrows:
            fh.write("\t".join(str(x) for x in r) + "\n")
    per = collections.Counter(r[2] for r in allrows)
    tot = sum(r[4] for r in allrows)
    print(f"{len(allrows)} undecoded field bodies over {len(dirs)} dir(s), {tot} bytes total -> {p}")
    print(f"   {len(per)} distinct field names; largest groups: "
          + ", ".join(f"{k}={v}" for k, v in per.most_common(6)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
