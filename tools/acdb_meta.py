#!/usr/bin/env python3
"""tools/acdb_meta.py -- read the ACDB headers of every stashed .acdb and answer the 6->7 questions
that do NOT need the (still unparsed) coefficient payloads.

What the bytes prove (all verified here, not assumed):
  * file = 'QCMSNDDB'(8) + u32@8 + u32@12 + sub-db tag@16 + version@20 + size@24 + size@28,
    and the declared size equals len(file)-32 in every file -- a hard invariant, so this tool
    aborts rather than tabulating a header model that stopped matching.
  * then a list of NAME + u32 len + payload fields. Names are NOT fixed width ('MODIFIED' is 8,
    'SPNAME ' is 7 -- the trailing space is part of the name, which is exactly what broke my first
    read and made the platform string come out as None).
  * the platform identity ('SWPNAME ' -- SouthWest's field, not 'SPNAME': the name really is
    8 chars ending in a space, and looking for 'SPNAME' silently returned nothing) is the field a QC ACDB loader compares at open time, so it is
    the concrete material for ledger 211's open item "ACDB 的 6->7 兼容性只做了实物留底".

Output: art/audio-6.0.1/acdb-meta.PD1610.tsv + a same-bytes report across board directories.

Usage: tools/acdb_meta.py [--base art/audio-6.0.1/live/extra/files/system/etc/acdbdata]
"""
import argparse
import hashlib
import os
import re
import struct
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NAME_RE = re.compile(rb"[A-Z][A-Z ]{2,9}")


def utf16(b):
    if len(b) % 2 or not b:
        return None
    try:
        s = b.decode("utf-16-le")
    except UnicodeDecodeError:
        return None
    s = s.split("\0")[0]
    return s if s and all(32 <= ord(c) < 127 for c in s) else None


def fields_after_header(b, cap=24):
    """walk NAME/len/payload triples; accept both 7- and 8-byte names by testing each end offset"""
    out = []
    o = 32
    while o + 12 <= len(b) and len(out) < cap:
        m = NAME_RE.match(b, o)
        if not m:
            break
        name = m.group().decode("latin-1")
        end = m.end()
        ln = None
        for cand in range(end, end + 5):
            if cand + 4 <= len(b):
                v = struct.unpack_from("<I", b, cand)[0]
                if 0 < v <= 512 and cand + 4 + v <= len(b):
                    ln, payload_at = v, cand + 4
                    break
        if ln is None:
            break
        raw = b[payload_at:payload_at + ln]
        txt = utf16(raw) or raw.split(b"\0")[0].decode("latin-1", "replace")
        if any(ord(c) < 32 for c in txt):      # version fields are raw bytes, not text
            txt = "0x" + raw.rstrip(b"\0").hex() + (f" (= {int.from_bytes(raw.rstrip(chr(0).encode()), 'little')})"
                                                     if raw.rstrip(b"\0") and len(raw.rstrip(b"\0")) <= 4 else "")
        out.append((name.strip(), ln, txt, m.start()))
        o = payload_at + ln
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default=os.path.join(ROOT, "art/audio-6.0.1/live/extra/files/system/etc/acdbdata"))
    args = ap.parse_args()
    if not os.path.isdir(args.base):
        sys.exit(f"gate: {args.base} missing")

    dirs = sorted(d for d in os.listdir(args.base) if os.path.isdir(os.path.join(args.base, d)))
    rows, bad, seen_fields, inv = [], [], set(), []
    for d in dirs:
        for fn in sorted(f for f in os.listdir(os.path.join(args.base, d)) if f.endswith(".acdb")):
            p = os.path.join(args.base, d, fn)
            b = open(p, "rb").read()
            if b[:8] != b"QCMSNDDB":
                bad.append(f"{d}/{fn}: no QCMSNDDB magic")
                continue
            tag = b[16:20].decode("latin-1")
            ver, sz1, sz2 = struct.unpack_from("<III", b, 20)
            if sz1 != len(b) - 32 or sz2 != sz1:
                bad.append(f"{d}/{fn}: declared size {sz1}/{sz2} != len-32 ({len(b)-32})")
                continue
            if tag not in ("AVDB", "GCDB", "ASMB"):
                bad.append(f"{d}/{fn}: unexpected sub-db tag {tag!r}")
            flds_raw = fields_after_header(b)
            flds = {n: (l, v, off) for n, l, v, off in flds_raw}
            plat = (flds.get("SWPNAME") or (0, "", 0))[1]
            def fv(n):
                return (flds.get(n) or (0, "", 0))[1]
            rows.append((d, fn, tag, ver, len(b), sz1, fv("MODIFIED"), plat,
                         fv("SWPVERS"), fv("ACSWVERS"), fv("ADSPVERS"), fv("OEMINFO"), fv("CDCNAME"),
                         hashlib.sha256(b).hexdigest()[:16], hashlib.md5(b).hexdigest()))
            seen_fields.update(flds)
            for n, (l, v, off) in flds.items():
                inv.append((d, fn, n, off, l, v))

    if bad:
        print("header model stopped matching -- not writing a table:")
        for x in bad[:10]:
            print("  ", x)
        return 1
    out = os.path.join(ROOT, "art/audio-6.0.1/acdb-meta.PD1610.tsv")
    with open(out, "w", encoding="utf-8") as fh:
        fh.write("dir\tfile\tsubdb\tversion\tbytes\tdeclared_size\tmodified\tSWPNAME\tSWPVERS\tACSWVERS\tADSPVERS\tOEMINFO\tCDCNAME\tsha16\tmd5\n")
        for r in rows:
            fh.write("\t".join(str(x) for x in r) + "\n")
    invout = os.path.join(ROOT, "art/audio-6.0.1/acdb-fields.PD1610.tsv")
    with open(invout, "w", encoding="utf-8") as fh:
        fh.write("dir\tfile\tfield\toffset\tdeclared_len\tvalue\n")
        for r in inv:
            fh.write("\t".join(str(x) for x in r) + "\n")
    print(f"wrote {out}: {len(rows)} files, header invariant held on all of them")
    print(f"wrote {invout}: {len(inv)} header fields ({len(seen_fields)} distinct names)")
    print("sub-db tags:", sorted({r[2] for r in rows}), " versions:", sorted({r[3] for r in rows}))
    for col, lbl in ((7, "SWPNAME"), (8, "SWPVERS"), (9, "ACSWVERS"), (10, "ADSPVERS"), (12, "CDCNAME")):
        vals = sorted({r[col] for r in rows if r[col]})
        print(f"  {lbl}: {vals if vals else 'field absent from these headers'}")
    print("MODIFIED stamps:", sorted({r[6] for r in rows})[:6])
    print("header field vocabulary:", sorted(seen_fields))

    # do the two PD1610 board variants actually share one calibration set?
    bys = {}
    for d, fn, _t, _v, _b, _s, _m, _p, sha in rows:
        bys.setdefault(fn.replace(d + "_", "").replace("Fluid_", "").replace("Liquid_", "")
                        .replace("QRD_", "").replace("MTP_", ""), {})[d] = sha
    shared = [f for f, m in bys.items() if "PD1610" in m and "PD1610LG4" in m and m["PD1610"] == m["PD1610LG4"]]
    print(f"PD1610 vs PD1610LG4 identical bytes: {len(shared)}/{len([f for f, m in bys.items() if 'PD1610' in m and 'PD1610LG4' in m])} files")
    return 0


if __name__ == "__main__":
    sys.exit(main())
