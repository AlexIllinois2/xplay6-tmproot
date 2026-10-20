#!/usr/bin/env python3
"""tools/kssym_dapm_coverage.py -- account for every declared route: live, unconnected, or phantom.

The route arrays declare far more edges than debugfs published (tasha: 1167 declared, 213 in-edges
seen on the running card).  "178 match" says nothing about the other 989, and a port needs that:
a route whose widgets are absent from the card is a different failure than one whose selector switch
simply is not connected.

So each decoded route is resolved against the live widget universe BY CONTEXT.  That matters more
than it looks: widget names are effectively global on this card (only 1 name appears in two
contexts), and paths DO cross contexts -- hifi-codec's `HP` widget lists `HPHL`/`HPHR` as sources
while those two widget files live under codec:tasha_codec.  A bare-name lookup would happily "find"
a widget in the wrong codec and call a phantom route real.

Classes, per route (sink is the DOWNSTREAM end, ASoC's .sink):
    LIVE            (source, sink) appears in the published in-edges
    UNCONNECTED     both endpoints exist as live widgets, but no such path is published -- i.e. the
                    control/selector on that route is not set right now
    SINK-ABSENT     the sink name has no widget file anywhere on the card
    SOURCE-ABSENT   the source name has no widget file anywhere on the card
    BOTH-ABSENT     neither exists

Every route must land in exactly one class and the counts must sum to the array length, or the tool
refuses -- a silent drop is how a 0 or a small number gets read as an answer.

usage: tools/kssym_dapm_coverage.py ROUTES_TSV [--context codec:tasha_codec] [--top 15]
"""
import argparse
import csv
import glob
import os
import sys
from collections import Counter, defaultdict

ROOT = "/home/v/.local/project/xplay6"
LIVE = f"{ROOT}/art/audio-6.0.1/live"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("routes")
    ap.add_argument("--context", default="",
                    help="only routes of this codec context, e.g. codec:tasha_codec")
    ap.add_argument("--owner-context", default="",
                    help="the DAPM context this array belongs to, e.g. codec:tasha_codec.  Without "
                         "it an endpoint that shares its name with a live codec's widget reads as "
                         "'present', which would call a never-instantiated codec's table merely "
                         "unconnected.  Machine arrays pass 'machine'.")
    ap.add_argument("--top", type=int, default=15)
    ap.add_argument("--out", help="TSV: one row per route with its class")
    a = ap.parse_args()

    wuni = f"{LIVE}/dapm-widgets-all.txt"
    if not os.path.exists(wuni):
        sys.exit(f"gate: {wuni} missing -- run tools/dapmsnap.py <capture> --emit-all {wuni}; "
                 "without a per-context widget universe every 'absent' verdict is a guess")
    where = defaultdict(set)
    n_pairs = 0
    for ln in open(wuni, encoding="utf-8", errors="replace"):
        if ln.startswith("#") or not ln.strip():
            continue
        ctx, w = ln.rstrip("\n").split("\t")
        where[w].add(ctx)
        n_pairs += 1
    if n_pairs < 100:
        sys.exit(f"gate: widget universe has only {n_pairs} pairs -- a real card exposes hundreds")

    edges = set()
    efiles = sorted(glob.glob(f"{LIVE}/dapm-edges-*.txt"))
    if not efiles:
        sys.exit(f"gate: no {LIVE}/dapm-edges-*.txt -- the live side of the comparison is missing")
    for f in efiles:
        for ln in open(f, encoding="utf-8", errors="replace"):
            if ln.startswith("#") or not ln.strip():
                continue
            p_ = ln.rstrip("\n").split("\t")
            edges.add((p_[0], p_[1]))

    rows = list(csv.DictReader(open(a.routes, encoding="utf-8"), delimiter="\t"))
    if not rows:
        sys.exit(f"gate: {a.routes} has no rows")
    if a.context:
        key = a.context.split(":")[-1]
        rows = [r for r in rows if f"codec:{key}" == a.context] or rows
        if not rows:
            sys.exit(f"gate: --context {a.context} filtered the array down to 0 routes -- the array "
                     "was named for another codec, so this would report nothing as 'everything'")

    if a.owner_context == "machine":
        owner_live = True      # machine routes legitimately reach into every codec's widgets
    elif not a.owner_context:
        owner_live = True      # no owner declared: judge against the whole card, and the refusal
                               # below is what stops that from being read as a coverage verdict
    else:
        owner_live = any(a.owner_context == c for ws in where.values() for c in ws)
        if not owner_live:
            print(f"NOTE: no widget in the live capture belongs to {a.owner_context!r} -- that "
                  "context was never instantiated, so EVERY route of this array is reported as "
                  "ABSENT-family rather than 'unconnected' (the tomtom/wsa881x shape)")
    cls, ctl_absent, ctl_unc = Counter(), Counter(), Counter()
    out = []
    for r in rows:
        sink, src, ctl = r["sink"], r["source"], r["control"]
        live = (src, sink) in edges
        if owner_live:
            s_ok, k_ok = src in where, sink in where
        else:
            s_ok = k_ok = False
        if live:
            c = "LIVE"
        elif not s_ok and not k_ok:
            c = "BOTH-ABSENT"
            ctl_absent[ctl] += 1
        elif not k_ok:
            c = "SINK-ABSENT"
            ctl_absent[ctl] += 1
        elif not s_ok:
            c = "SOURCE-ABSENT"
            ctl_absent[ctl] += 1
        else:
            c = "UNCONNECTED"
            ctl_unc[ctl] += 1
        cls[c] += 1
        out.append((c, src, ctl, sink, ",".join(sorted(where.get(src, ()))),
                    ",".join(sorted(where.get(sink, ())))))
    if a.out:
        with open(a.out, "w", encoding="utf-8") as f:
            f.write("class\tsource\tcontrol\tsink\tsource_contexts\tsink_contexts\towner_context\n")
            for t in out:
                f.write("\t".join(str(x) for x in t) + f"\t{a.owner_context}\n")
    if sum(cls.values()) != len(rows):
        sys.exit(f"gate: classified {sum(cls.values())} of {len(rows)} routes -- some route fell "
                 "through the class ladder, so these numbers are not an accounting")
    phant = cls["SINK-ABSENT"] + cls["SOURCE-ABSENT"] + cls["BOTH-ABSENT"]
    print(f"{len(rows)} routes classified (array {os.path.basename(a.routes)}"
          + (f", context {a.context}" if a.context else "") + ")")
    for k in ("LIVE", "UNCONNECTED", "SOURCE-ABSENT", "SINK-ABSENT", "BOTH-ABSENT"):
        print(f"  {k:14} {cls[k]:5}   {100.0*cls[k]/len(rows):5.1f}%")
    print(f"  widget universe: {n_pairs} context/widget pairs, {len(where)} distinct names; "
          f"{len(edges)} published in-edges from {len(efiles)} listings")
    if not a.owner_context and phant and cls["LIVE"] == 0:
        sys.exit(f"gate: {phant} phantom and 0 live, and no --owner-context was declared -- this "
                 "array is probably a never-instantiated codec's table, which is a finding about "
                 "instantiation, not about coverage. Pass --owner-context to say so explicitly.")
    print(f"\ntop controls among UNCONNECTED (widgets exist, selector not set): "
          f"{ctl_unc.most_common(a.top)}")
    print(f"top controls among ABSENT-widget routes (name has no widget file on this card): "
          f"{ctl_absent.most_common(a.top)}")
    absent_names = sorted({r[1] for r in out if r[0].startswith(("SOURCE", "BOTH"))})
    print(f"\ndistinct ABSENT source names: {len(absent_names)} -- sample {absent_names[:12]}")
    print(f"distinct endpoint names that live in a DIFFERENT context than each other: "
          f"{len({(r[1], r[3]) for r in out if r[4] and r[5] and r[4] != r[5]})} "
          "(paths cross codec contexts, so per-codec edge files are indexed by the SINK's context)")
    if a.owner_context and a.owner_context != "machine":
        collide = [r for r in out if r[0].endswith("ABSENT") and (r[4] or r[5])]
        print(f"name-collision guard: {len(collide)} ABSENT route(s) whose endpoint name IS live but "
              f"only under a context other than {a.owner_context} -- a bare-name lookup would call "
              "these 'unconnected' and hide that this codec was never instantiated")
    if a.out:
        print("wrote", a.out)


if __name__ == "__main__":
    main()
