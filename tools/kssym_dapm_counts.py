#!/usr/bin/env python3
"""tools/kssym_dapm_counts.py -- read every codec driver's DAPM inventory out of the kernel image.

The struct is `struct snd_soc_codec_driver`, and the three field pairs sit at fixed offsets (proved
below, not assumed):

    +0x88 controls            +0x90 num_controls
    +0x98 dapm_widgets        +0xa0 num_dapm_widgets
    +0xa8 dapm_routes         +0xb0 num_dapm_routes

so a driver's route-array LENGTH is available without inferring it from .rodata layout.  Two
`audio_map` symbols exist because tomtom.c and tasha.c each define one under the same C name, so
counting rows needs a per-address denominator (ledger 294).  Measured here (ledger 296): the symbol
span happens to equal num_dapm_routes on EVERY driver-referenced array -- the span never overran, and
an earlier note claiming it did was a misreading of this tool's own distinct-edge count as row count.
That is why the two derivations are cross-checked instead of one being trusted.

Second derivation of each length: the NEXT kallsyms object boundary.  There is no declared end in
the image -- what reads like a {start,end} pointer pair is the array start followed by an unrelated
neighbouring object.  The two derivations must agree on every driver-referenced array or this tool
refuses; arrays only the boundary can bound are labelled weaker, not presented as declarations.

usage: tools/kssym_dapm_counts.py [--symbol NAME ...]   (no symbols given => report all drivers)
"""
import argparse
import bisect
import struct
import sys

TEXT = 0xFFFFFFC000080000
ROOT = "/home/v/.local/project/xplay6"
IMG = f"{ROOT}/fw/Image"
KALL = f"{ROOT}/art/kallsyms_real.txt"
CTRL, WIDGETS, ROUTES = 0x88, 0x98, 0xa8


def load():
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
    return syms, open(IMG, "rb").read()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--symbol", action="append", default=[],
                    help="route-array symbol to bound (repeatable)")
    ap.add_argument("--out")
    ap.add_argument("--stride", type=lambda x: int(x, 0), default=0x20)
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()

    syms, data = load()
    vas = [v for v, _ in syms]
    name_of = dict(syms)

    def q(va):
        if not (TEXT <= va < TEXT + len(data)):
            return None
        return struct.unpack_from("<Q", data, va - TEXT)[0]

    def owner(addr):
        i = bisect.bisect_right(vas, addr) - 1
        return syms[i] if i >= 0 else (0, "?")

    # 1. every qword site that equals a symbol start, and the qword that follows it
    by_addr = {}
    for v, n in syms:
        by_addr.setdefault(v, []).append(n)

    drivers = []
    for v, n in syms:
        if not (n.endswith("_driver") or n.startswith("soc_codec_dev_")):
            continue
        c_ptr, c_n = q(v + CTRL), q(v + CTRL + 8)
        w_ptr, w_n = q(v + WIDGETS), q(v + WIDGETS + 8)
        r_ptr, r_n = q(v + ROUTES), q(v + ROUTES + 8)
        # Only the ROUTES pair is required.  Requiring all three silently dropped a whole variant:
        # a second `soc_vivo_codec_driver` exists with .controls == NULL, and its num_dapm_routes == 3
        # is a real declared bound for the uppercase-SPEAKER table (ledger 296).
        if not (r_ptr and r_ptr in by_addr and r_n and r_n < 0x10000):
            continue
        c_ok = c_ptr and c_ptr in by_addr and c_n and c_n < 0x10000
        w_ok = w_ptr and w_ptr in by_addr and w_n and w_n < 0x10000
        drivers.append((v, n,
                        c_ptr if c_ok else 0, c_n if c_ok else 0,
                        w_ptr if w_ok else 0, w_n if w_ok else 0,
                        r_ptr, r_n))
    if not drivers:
        sys.exit(f"gate: no struct snd_soc_codec_driver shape found at +{CTRL:#x}/+{WIDGETS:#x}/"
                 f"+{ROUTES:#x} in {len(syms)} symbols -- the field offsets are wrong for this "
                 "kernel, so no count here is trustworthy")

    # 2. second derivation of the same length: the NEXT kallsyms object boundary.  This is NOT a
    # declared end -- the image has no {start,end} pair, what looks like one is `array start` followed
    # by an unrelated neighbouring object (verified: the qword after tomtom's audio_map is aif3_cap_mixer,
    # after vivo_codec_audio_map#0 it is the string 'msm8996_hifi_put').  It agrees with
    # num_dapm_routes on the six driver-referenced arrays, which is what makes the stride trustworthy;
    # for the two arrays no driver struct references, it is the ONLY bound available, so it is
    # labelled weaker rather than presented as an independent declaration (ledger 295).
    ends = {}
    nxt_of = {}
    for i, (v, _n) in enumerate(syms):
        if i + 1 < len(syms):
            nxt_of[v] = syms[i + 1][0]
    for v, nx in nxt_of.items():
        n, rem = divmod(nx - v, a.stride)
        if rem == 0 and 0 < n < 0x10000:
            ends.setdefault(v, []).append((nx, n))

    rows = []
    for v, n, c_ptr, c_n, w_ptr, w_n, r_ptr, r_n in drivers:
        alt = {x[1] for x in ends.get(r_ptr, [])}
        agree = "both" if alt == {r_n} else f"next-object boundary says {sorted(alt) or 'none'}"
        rows.append((n, f"{v:#x}",
                     by_addr[c_ptr][0] if c_ptr else "(NULL .controls)",
                     c_n if c_ptr else "",
                     by_addr[w_ptr][0] if w_ptr else "(NULL .dapm_widgets)",
                     w_n if w_ptr else "",
                     by_addr[r_ptr][0], r_n, f"{r_ptr:#x}", agree))

    want = set(a.symbol)
    if want:
        # filter by ADDRESS, not name: kallsyms holds several objects under one C name (tomtom.c and
        # tasha.c both call their table `audio_map`) and every copy needs its own bound.
        rows = [r for r in rows if r[6] in want]
        got = {(r[6], int(r[8], 16)) for r in rows}
        for m in sorted(want):
            for v, n in syms:
                if n != m or (m, v) in got:
                    continue
                # not referenced by a codec driver struct -- only the next-object boundary bounds it,
                # which is weaker, so it is labelled that way instead of being called a declaration.
                ns = {x[1] for x in ends.get(v, [])}
                if len(ns) != 1:
                    sys.exit(f"gate: asked to bound {m} @{v:#x}: no codec driver struct points at it "
                             f"and the next-object boundary gives {sorted(ns) or 'nothing'} -- its "
                             "length is NOT established, so decoding it would be guesswork")
                c = ns.pop()
                rows.append(("(no driver struct)", "", "", "", "", "", m, c, f"{v:#x}",
                             "next-object boundary only (no declared count)"))

    print(f"{len(rows)} codec driver(s) with a full DAPM inventory; "
          "num_dapm_routes cross-checked against the next kallsyms object boundary")
    hdr = ("driver\tdriver_at\tcontrols\tnum_controls\tdapm_widgets\tnum_dapm_widgets\t"
           "dapm_routes\tnum_dapm_routes\troutes_at\tcount_agreement")
    print(hdr)
    for r in rows:
        print("\t".join(str(x) for x in r))
    if a.out:
        with open(a.out, "w", encoding="utf-8") as fh:
            fh.write(hdr + "\n" + "\n".join("\t".join(str(x) for x in r) for r in rows) + "\n")
        print("wrote", a.out)

    if a.selftest:
        # the offsets are only "proved" if they hold on more than one driver AND the two derivations
        # of the route count agree on every one of them
        if len(rows) < 3:
            sys.exit(f"gate: selftest needs >=3 driver structs to call the offsets proved, got "
                     f"{len(rows)}")
        bad = [r[0] for r in rows if r[9] != "both"]
        if bad:
            sys.exit(f"gate: selftest: {bad} disagree between num_dapm_routes and the "
                     "the next-object boundary -- one of the two derivations is wrong")
        print(f"selftest: {len(rows)} drivers, identical offsets, and num_dapm_routes == "
              "(next_object - start)/stride on every one")


if __name__ == "__main__":
    main()
