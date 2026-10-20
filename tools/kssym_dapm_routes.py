#!/usr/bin/env python3
"""tools/kssym_dapm_routes.py -- decode the DAPM route arrays (the widget-to-widget connections).

Pairs with tools/kssym_dapm.py (§291, widget names).  Layout was derived, not assumed: entries are
32 bytes -- {sink @+0x00, control @+0x08, source @+0x10, unused @+0x18} -- proved by the fact that
one entry carries a NON-NULL control ('I2S_RX', a route through a DAPM mixer switch) while the rest
carry NULL there, and by the whole array ending exactly at the next kallsyms object.

The tool refuses to emit unless (a) the span is an exact multiple of the stride, (b) every decoded
sink/source derefs to a printable name, and (c) --expect passes: an edge like 'HiFi DAC->HiFi AMP'
must be present, which is the same edge the running card reported through debugfs (§290/291).

usage: tools/kssym_dapm_routes.py [--out TSV] [--expect 'HiFi DAC->HiFi AMP'] [--symbol NAME]
"""
import argparse
import bisect
import glob
import os
import struct
import sys

TEXT = 0xFFFFFFC000080000
ROOT = "/home/v/.local/project/xplay6"
IMG = f"{ROOT}/fw/Image"
KALL = f"{ROOT}/art/kallsyms_real.txt"
STRIDE, SINK, CTRL, SRC = 0x20, 0x00, 0x08, 0x10


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out")
    ap.add_argument("--expect", default="HiFi DAC->HiFi AMP")
    ap.add_argument("--symbol", default="vivo_codec_audio_map")
    ap.add_argument("--at", help="only this array address, when one C name has several objects "
                                 "(kallsyms holds two `audio_map`: tomtom's and tasha's)")
    ap.add_argument("--min-directed", type=int, default=0)
    ap.add_argument("--bounds", help="TSV from tools/kssym_dapm_counts.py; gives each array's exact "
                                     "entry count from num_dapm_routes, replacing the symbol span")
    ap.add_argument("--require-known-names", action="store_true",
                    help="stop at an entry whose endpoint is not a known widget/pin name")
    a = ap.parse_args()
    ws, _, gs = a.expect.partition("->")

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
    data = open(IMG, "rb").read()

    def str_at(x):
        if not isinstance(x, int) or not (TEXT <= x < TEXT + len(data)):
            return None
        o = x - TEXT
        e = data.find(b"\x00", o, o + 200)
        if e < 0:
            return None
        c = data[o:e]
        return c.decode("latin-1") if c and all(32 <= b < 127 for b in c) else None

    def qword(va):
        return struct.unpack_from("<Q", data, va - TEXT)[0]

    names_known = set()
    wt = f"{ROOT}/art/audio-6.0.1/dapm-widgets.PD1610.tsv"
    if os.path.exists(wt):
        import csv as _csv
        for r in _csv.DictReader(open(wt, encoding="utf-8"), delimiter="\t"):
            names_known.add(r["name"])
            if r["sname"]:
                names_known.add(r["sname"])
    for f in sorted(glob.glob(f"{ROOT}/art/audio-6.0.1/live/dapm-edges-*.txt")):
        for ln in open(f, encoding="utf-8", errors="replace"):
            if ln.startswith("#") or not ln.strip():
                continue
            p_ = ln.rstrip("\n").split("\t")
            names_known |= {p_[0], p_[1]}
    if not names_known:
        print("NOTE: no widget/live name universe available -- falling back to the NULL terminator "
              "alone, so an unbounded array will overrun")
    bounds = {}
    if a.bounds:
        import csv as _csv2
        with open(a.bounds, encoding="utf-8") as fh:
            for r in _csv2.DictReader(fh, delimiter="\t"):
                bounds[int(r["routes_at"], 16)] = int(r["num_dapm_routes"])
        if not bounds:
            sys.exit(f"gate: {a.bounds} has no rows -- run tools/kssym_dapm_counts.py first, the "
                     "entry count has to come from num_dapm_routes and not from the symbol span")
    starts = [v for v, n in syms if n == a.symbol]
    if a.at:
        starts = [v for v in starts if v == int(a.at, 16)]
    if not starts:
        sys.exit(f"no {a.symbol} object in kallsyms -- the route array has another name there, "
                 "so decoding would be guesswork")
    if bounds and not any(s in bounds for s in starts):
        sys.exit(f"gate: none of the {len(starts)} {a.symbol} arrays appear in {a.bounds} -- that "
                 "file bounds different objects, so it is not this array's denominator")
    rows, ends = [], []
    for si, st in enumerate(starts):
        nxt = [v for v, _ in syms if v > st]
        span = (nxt[0] - st) if nxt else 0
        if span <= 0 or span % STRIDE:
            sys.exit(f"gate: {a.symbol}#{si} @{st:#x} spans {span:#x} bytes, not a multiple of the "
                     f"{STRIDE:#x} stride -- the layout is wrong for this array")
        # Three possible bounds, best first (ledger 294):
        #   (0) --bounds: num_dapm_routes read out of the codec driver struct.  Exact, and the only
        #       one that works on the codec arrays -- their symbol span runs into the next .rodata
        #       string, so rows past the real end still deref to printable names.
        #   (1) the C terminator -- an entry with both pointers NULL.  The vivo arrays honour it,
        #       the codec ones do not (they are fixed-size arrays with no sentinel).
        #   (2) --require-known-names -- stop at an endpoint that is not a widget/pin name anywhere.
        #       Opt-in only: it truncates a correct decode when the live name universe is partial.
        n_exp = bounds.get(st)
        limit = n_exp if n_exp is not None else span // STRIDE
        if n_exp is not None and n_exp * STRIDE > span:
            sys.exit(f"gate: {a.symbol}#{si} @{st:#x}: num_dapm_routes={n_exp} needs "
                     f"{n_exp * STRIDE:#x} bytes but the object only spans {span:#x} -- the count "
                     "and the layout cannot both be right")
        stopped = None
        before = len(rows)
        for k in range(limit):
            b = st + k * STRIDE
            sq, qq = qword(b + SINK), qword(b + SRC)
            if not sq and not qq:
                stopped = (k, b, "empty")
                break
            if a.require_known_names and names_known:
                bad = [(w, str_at(w)) for w in (sq, qq) if w and str_at(w) not in names_known]
                if bad:
                    stopped = (k, b, f"unknown-name {bad[0][1]!r} (qword {bad[0][0]:#x})")
                    break
            sink = str_at(sq)
            ctrl = str_at(qword(b + CTRL))
            src = str_at(qq)
            if sink is None or src is None:
                sys.exit(f"gate: {a.symbol}#{si} entry#{k} @{b:#x} has no printable sink/source "
                         f"(sink={sink!r} src={src!r}) -- stride/offset assumption broke here")
            rows.append((si, f"{st:#x}", k, f"{b:#x}", sink, ctrl or "", src))
        ends.append((a.symbol, si, st, len(rows) - before, stopped, n_exp))
        if n_exp is not None and stopped is not None:
            sys.exit(f"gate: {a.symbol}#{si} @{st:#x}: num_dapm_routes={n_exp} but entry "
                     f"{stopped[0]} is {stopped[2]} -- the array stops short of its declared length, "
                     "so either the stride is wrong or this is not the array that count describes")
    # direction: ASoC's .sink is DOWNSTREAM, so the live edge "HiFi DAC out -> HiFi AMP" decodes as
    # source='HiFi DAC', sink='HiFi AMP' -- checked that way round, and the tool says so in its output
    for sym, si, st, n, stopped, n_exp in ends:
        tag = f"(num_dapm_routes={n_exp})" if n_exp is not None else "(bounded by symbol span)"
        print(f"  {sym}#{si} @{st:#x}: {n} routes {tag}"
              + (f", stopped at entry {stopped[0]} ({stopped[2]}) @{stopped[1]:#x}" if stopped else
                 ", ran to the bound with no NULL entry"))
    # Cross-check every decode against the device-side DAPM edge listings (live/dapm-edges-*.txt),
    # which come from debugfs and are independent of this decoder.  A reversed hit means sink/source
    # are swapped; it is never negotiable, with or without --expect.
    files = sorted(glob.glob(f"{ROOT}/art/audio-6.0.1/live/dapm-edges-*.txt"))
    live = set()
    for f in files:
        for ln in open(f, encoding="utf-8", errors="replace"):
            if ln.startswith("#") or not ln.strip():
                continue
            p_ = ln.rstrip("\n").split("\t")
            live.add((p_[0], p_[1]))
    mine = {(r[6], r[4]) for r in rows}
    directed = sum(1 for e in mine if e in live)
    reversed_ = sum(1 for e in mine if (e[1], e[0]) in live and e not in live)
    if live:
        # every number here gets its denominator named: `rows decoded` and `distinct edges` differ
        # (several arrays hold the same entry), and reading one as the other is how a correct decode
        # got rejected as an overrun (ledger 296)
        print(f"live-edge coverage: {directed} directed, {reversed_} reversed; rows decoded "
              f"{len(rows)}, distinct edges {len(mine)} ({len(rows) - len(mine)} duplicate entries), "
              f"live edges {len(live)} from {len(files)} listing(s)")
        if reversed_:
            sys.exit(f"gate: {reversed_} decoded edge(s) match a live edge backwards -- sink/source "
                     "are swapped, refusing to emit")
    if ws:
        if not any(r[6] == ws and r[4] == gs for r in rows):
            sys.exit(f"gate: no entry decodes as source={ws!r} -> sink={gs!r} -- either the layout is "
                     "wrong or this array is not the running card's; refusing to emit")
    else:
        if not files:
            sys.exit("gate: --expect '' needs live/dapm-edges-*.txt to prove the layout against and "
                     "none exists -- derive them from the debugfs dapm capture first")
        if directed < a.min_directed:
            sys.exit(f"gate: {a.symbol} decoded {len(mine)} edges but only {directed} are directed "
                     f"live matches (need >= --min-directed={a.min_directed}). A low count means the "
                     "stride or the array bound is wrong. Refusing to emit.")
    ctrl_named = [r for r in rows if r[5]]
    proof = f"edge source='{ws}' -> sink='{gs}'" if ws else "live-edge coverage above"
    print(f"{len(starts)} {a.symbol} arrays, {len(rows)} routes decoded; layout proved by {proof}; "
          f"{len(ctrl_named)} entries carry a non-NULL control "
          f"({sorted({r[5] for r in ctrl_named})[:6]})")
    hdr = "array\tarray_at\tentry\taddr\tsink\tcontrol\tsource"   # sink is DOWNSTREAM
    if a.out:
        with open(a.out, "w", encoding="utf-8") as fh:
            fh.write(hdr + "\n" + "\n".join("\t".join(str(x) for x in r) for r in rows) + "\n")
        print("wrote", a.out)
    print(hdr)
    for r in rows:
        print("\t".join(str(x) for x in r))


if __name__ == "__main__":
    main()
