#!/usr/bin/env python3
"""tools/dapm_route_selectors.py -- name the knob each declared route is waiting on.

dapm-coverage says a route is UNCONNECTED (both widgets exist, no path published).  For a port that
is only half an answer: what actually turns the path on?  In ASoC a route row is

    { .sink = <widget>, .control = <kcontrol's enum item text OR kcontrol name>, .source = <widget> }

so the knob is found by looking the control string up in the live control universe:
  - if .control is an item of the ENUM kcontrol whose name == .sink  -> the sink itself is the mux
    (this is the common QC shape: 'ADC MUX0' widget, 'ADC MUX0' kcontrol, item 'AMIC')
  - else if .control is an item of some other ENUM kcontrol          -> reachable, via that kcontrol
  - else if .control is itself a live kcontrol name (BOOL)            -> a plain switch
  - else                                                              -> no live knob by that name

Inputs are all live-side artifacts (controls-live.tsv, enum-items.tsv from tools/audio_index.py) plus
the decoded route/coverage TSVs, so 7-side comparison is the same join over a fresh capture.

usage: tools/dapm_route_selectors.py [--out TSV] [--top 12]
"""
import argparse
import csv
import glob
import os
import sys
from collections import Counter, defaultdict

ROOT = "/home/v/.local/project/xplay6"
BASE = f"{ROOT}/art/audio-6.0.1"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out")
    ap.add_argument("--top", type=int, default=12)
    ap.add_argument("--controls", default=f"{BASE}/controls-live.tsv")
    ap.add_argument("--enums", default=f"{BASE}/live/enum-items.tsv")
    a = ap.parse_args()

    if not os.path.exists(a.controls) or not os.path.exists(a.enums):
        sys.exit(f"gate: need both {a.controls} and {a.enums} (tools/audio_index.py writes them) -- "
                 "without the live control universe every 'no knob' verdict is a guess")
    kctl = {}
    for ln in open(a.controls, encoding="utf-8", errors="replace"):
        p = ln.rstrip("\n").split("\t")
        if len(p) < 2:
            continue
        kctl[p[0]] = p[1]
    item_owner = defaultdict(list)
    n_enum = 0
    for ln in open(a.enums, encoding="utf-8", errors="replace"):
        p = ln.rstrip("\n").split("\t")
        if len(p) < 3:
            continue
        n_enum += 1
        for it in p[2:]:
            it = it.lstrip(">").strip()
            if it:
                item_owner[it].append(p[0])
    if not kctl or not item_owner:
        sys.exit(f"gate: parsed {len(kctl)} kcontrols and {n_enum} enum lines -- an empty universe "
                 "means the capture or the parser broke, not that the card has no knobs")

    covs = sorted(glob.glob(f"{BASE}/dapm-coverage-0x*.tsv"))
    if len(covs) != 7:
        sys.exit(f"gate: {len(covs)} coverage files, expected 7")

    cls = Counter()
    per_arr = {}
    rows = []
    for cv in covs:
        at = os.path.basename(cv)[len("dapm-coverage-"):-len(".tsv")]
        crows = list(csv.DictReader(open(cv, encoding="utf-8"), delimiter="\t"))
        if not crows:
            sys.exit(f"gate: {cv} empty")
        for r in crows:
            ctl, sink = r["control"], r["sink"]
            composed = f"{sink} {ctl}"
            if not ctl:
                k = "NO-CONTROL (plain connection)"
                via = ""
            elif ctl in item_owner and sink in item_owner[ctl]:
                k = "SINK-MUX"
                via = sink
            elif composed in kctl:
                # DAPM names a widget's switch '<widget name> Switch', and QC route rows store just the
                # suffix -- 'SmartPA Switch' is live BOOL and Off, which IS why that path is unpublished
                k = "SINK-SWITCH"
                via = composed
            elif ctl in item_owner:
                k = "OTHER-ENUM"
                via = ",".join(sorted(set(item_owner[ctl]))[:3])
            elif ctl in kctl:
                k = "BOOL-SWITCH"
                via = ctl
            else:
                k = "NO-LIVE-KNOB"
                via = ""
            cls[(r["class"], k)] += 1
            rows.append((at, r["class"], sink, ctl, k, via))
    tot = len(rows)
    unc = [x for x in rows if x[1] == "UNCONNECTED"]
    print(f"{tot} routes joined against {len(kctl)} live kcontrols / "
          f"{len(item_owner)} distinct enum item texts")
    print(f"\nclass of route x kind of knob (UNCONNECTED rows only, {len(unc)} of them):")
    for k, v in sorted(((kk, vv) for kk, vv in cls.items() if kk[0] == "UNCONNECTED"),
                       key=lambda kv: -kv[1]):
        print(f"  {k[1]:28} {v:5}")
    print("\nevery route, by class:")
    for c in ("LIVE", "UNCONNECTED", "SOURCE-ABSENT", "SINK-ABSENT", "BOTH-ABSENT"):
        n = sum(v for (cc, _k), v in cls.items() if cc == c)
        if n:
            print(f"  {c:14} {n:5}")
    # a join with no positive hit is a broken join, not a finding
    pos = sum(v for (cc, k), v in cls.items()
              if k in ("SINK-MUX", "SINK-SWITCH", "OTHER-ENUM", "BOOL-SWITCH"))
    if not pos:
        sys.exit(f"gate: 0 routes resolved to a live knob -- the join cannot be trusted "
                 f"(control strings like {sorted({x[3] for x in rows if x[3]})[:4]} should hit enum "
                 "items if the universes line up)")
    nolive = sum(v for (cc, k), v in cls.items() if k == "NO-LIVE-KNOB")
    print(f"resolved to a live knob: {pos}/{tot}; unresolved: {nolive}")
    top = Counter(x[3] for x in unc if x[4] == "NO-LIVE-KNOB")
    print(f"top UNCONNECTED controls with no live knob of that name: {top.most_common(a.top)}")
    if a.out:
        with open(a.out, "w", encoding="utf-8") as f:
            f.write("array\tclass\tsink\tcontrol\tknob_kind\tknob\n")
            for t in rows:
                f.write("\t".join(t) + "\n")
        print("wrote", a.out)


if __name__ == "__main__":
    main()
