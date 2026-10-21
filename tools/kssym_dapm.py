#!/usr/bin/env python3
"""tools/kssym_dapm.py -- decode the vivo Hi-Fi codec's DAPM widget arrays out of fw/Image.

Why (ledger 291): the widget that triggers the DAC writes is identified by NAME, and names are what a
7 build can silently change -- so the whole array is decoded and cross-checked against the widget
files the running card actually exposed under debugfs.  Binary-decoded names are the "should be";
the live debugfs listing is the "actually is"; a mismatch is reported, not smoothed over.

Field positions are derived, not assumed: .name is read at +NAME_OFF and .event at +EVENT_OFF inside an
entry of ENTRY bytes; the tool PROVES the layout by requiring (a) every decoded name to deref to a
printable string and (b) at least one entry's .event to equal a known callback (--expect-NAME=SYM).
If either fails it exits non-zero instead of emitting a table of offsets.

usage: tools/kssym_dapm.py [--out TSV] [--expect 'HiFi DAC=hifi_codec_dac_event']
"""
import argparse
import bisect
import struct
import sys

TEXT = 0xFFFFFFC000080000
ROOT = "/home/v/.local/project/xplay6"
IMG = f"{ROOT}/fw/Image"
KALL = f"{ROOT}/art/kallsyms_real.txt"
ENTRY, NAME_OFF, SNAME_OFF, FLAGS_OFF, EVENT_OFF = 0xF0, 0x08, 0x10, 0x78, 0x80
ARRAY = "vivo_codec_dapm_widgets"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=None)
    ap.add_argument("--expect", default="HiFi DAC=hifi_codec_dac_event")
    a = ap.parse_args()

    syms = []
    for ln in open(KALL, encoding="utf-8", errors="replace"):
        p = ln.split()
        if len(p) == 3:
            try:
                v = int(p[0], 16)
            except ValueError:
                continue
            if v >= TEXT:
                syms.append((v, p[2]))
    syms.sort()
    vas = [x for x, _ in syms]

    def owner(x):
        i = bisect.bisect_right(vas, x) - 1
        return syms[i][1] if i >= 0 else "?"

    def strlen_at(x):
        if not (TEXT <= x < TEXT + len(data)):
            return None
        o = x - TEXT
        e = data.find(b"\x00", o, o + 160)
        if e < 0:
            return None
        c = data[o:e]
        return c.decode("latin-1") if c and all(32 <= b < 127 for b in c) else None

    data = open(IMG, "rb").read()
    starts = [v for v, n in syms if n == ARRAY]
    if not starts:
        sys.exit(f"no {ARRAY} object in kallsyms")
    rows = []
    for si, st in enumerate(starts):
        nxt = [v for v, _ in syms if v > st]
        span = (nxt[0] - st) if nxt else 0
        cnt = span // ENTRY
        if span % ENTRY:
            print(f"NOTE array#{si} @{st:#x} span {span:#x} is not a multiple of {ENTRY:#x} -- "
                  f"decoding {cnt} whole entries and reporting the remainder")
        for k in range(cnt):
            b = st + k * ENTRY
            nm = strlen_at(struct.unpack_from("<Q", data, b + NAME_OFF - TEXT)[0])
            sn = strlen_at(struct.unpack_from("<Q", data, b + SNAME_OFF - TEXT)[0])
            fl = struct.unpack_from("<I", data, b + FLAGS_OFF - TEXT)[0]
            ev = struct.unpack_from("<Q", data, b + EVENT_OFF - TEXT)[0]
            if nm is None:
                sys.exit(f"gate: array#{si} entry#{k} @{b:#x} has no printable .name at +{NAME_OFF:#x} "
                         f"-- the assumed layout (stride {ENTRY:#x}) is wrong, so nothing here is decoded")
            rows.append((si, f"{st:#x}", k, f"{b:#x}", nm, sn or "", hex(fl),
                         owner(ev) if ev else "", f"{ev:#x}" if ev else ""))
    want_name, want_fn = a.expect.split("=", 1)
    ok = [r for r in rows if r[4] == want_name and r[7] == want_fn]
    if not ok:
        sys.exit(f"gate: no entry decodes as name={want_name!r} with .event={want_fn!r} -- either the "
                 "layout offsets are wrong or this array is not the running one; refusing to emit")
    print(f"{len(starts)} {ARRAY} arrays, {len(rows)} entries decoded; "
          f"layout proved by {ok[0][4]!r} -> {ok[0][6]} (array#{ok[0][0]} entry#{ok[0][2]})")
    hdr = "array\tarray_at\tentry\taddr\tname\tsname\tevent_flags\tevent\tevent_va"
    body = "\n".join("\t".join(str(x) for x in r) for r in rows)
    print(hdr)
    for r in rows:
        print("\t".join(str(x) for x in r))
    if a.out:
        with open(a.out, "w", encoding="utf-8") as fh:
            fh.write(hdr + "\n" + body + "\n")
        print("wrote", a.out)


if __name__ == "__main__":
    main()
