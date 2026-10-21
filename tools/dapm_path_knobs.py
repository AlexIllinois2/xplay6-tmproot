#!/usr/bin/env python3
"""tools/dapm_path_knobs.py -- for each audible endpoint, which route state feeds it.

The port question is concrete: to get sound out of the headphone jack or the speaker, which DAPM
selectors have to be where.  §297 established that every unpublished route resolves to a live knob;
this walks the graph and says WHICH knobs are on the way to WHICH endpoint.

Method (all inputs are artifacts, nothing hand-typed):
  1. edges come from the route arrays whose own context is live -- decided by the coverage file's
     verdict (INSTANTIATED), not by a hardcoded list, so tomtom's and the uppercase-SPEAKER variant
     are excluded by evidence;
  2. nodes are widget names. That is safe only because the live capture has ~unique names, and the
     tool checks it instead of assuming it (see the name-collision gate below);
  3. roots = widgets with no incoming edge (streams/pins), terminals = no outgoing edge (HP, Speaker);
  4. per terminal: reverse BFS gives the ancestor set, and a shortest reverse path gives ONE concrete
     knob chain that is actionable.

Positive control (this is what makes the traversal trustworthy): the Hi-Fi path already proven from
the debugfs capture -- HiFi DAC -> HiFi AMP -> HiFi HPOUT -> HP -- must come out of the traversal.

usage: tools/dapm_path_knobs.py [--terminal HP] [--top 12] [--out TSV]
"""
import argparse
import csv
import glob
import os
import sys
from collections import Counter, defaultdict, deque

ROOT = "/home/v/.local/project/xplay6"
BASE = f"{ROOT}/art/audio-6.0.1"
HIFI_PATH = ["HiFi DAC", "HiFi AMP", "HiFi HPOUT", "HP"]   # §290, read off the running card


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--terminal", action="append", default=[],
                    help="only these endpoints (repeatable); default = all terminals")
    ap.add_argument("--top", type=int, default=12)
    ap.add_argument("--out")
    ap.add_argument("--emit-matrix",
                    help="also write a terminal x ancestor-edge matrix: one row per (terminal, edge) "
                         "that lies on some route into that terminal, so the port gets the FULL knob "
                         "checklist and not only the shortest chain")
    ap.add_argument("--no-selftest", action="store_true",
                    help="skip the Hi-Fi path control (NOT recommended: a traversal without a known "
                         "answer in it is unmeasured)")
    a = ap.parse_args()

    covs = sorted(glob.glob(f"{BASE}/dapm-coverage-0x*.tsv"))
    if len(covs) != 7:
        sys.exit(f"gate: {len(covs)} coverage files, expected 7")
    sel = f"{BASE}/dapm-route-selectors.PD1610.tsv"
    if not os.path.exists(sel):
        sys.exit(f"gate: {sel} missing -- run tools/dapm_route_selectors.py first; without the knob "
                 "join a path is a list of edges, not a setting")
    knob = {(r["array"], r["sink"], r["control"]): r
            for r in csv.DictReader(open(sel, encoding="utf-8"), delimiter="\t")}
    if not knob:
        sys.exit(f"gate: {sel} parsed to 0 rows")

    wuni = f"{BASE}/live/dapm-widgets-all.txt"
    share = Counter()
    for ln in open(wuni, encoding="utf-8", errors="replace"):
        if ln.startswith("#") or not ln.strip():
            continue
        _c, w = ln.rstrip("\n").split("\t")
        share[w] += 1
    dupes = {w: n for w, n in share.items() if n > 1}
    if len(dupes) > 3:
        sys.exit(f"gate: {len(dupes)} widget names appear in more than one context "
                 f"({list(dupes.items())[:5]}) -- keying nodes by bare name would merge distinct "
                 "widgets, so this traversal needs (context,name) keys instead")

    edges = []          # (source, sink, control, class, kind, knob)
    used_arr, skipped_arr = set(), set()
    for cv in covs:
        at = os.path.basename(cv)[len("dapm-coverage-"):-len(".tsv")]
        rows = list(csv.DictReader(open(cv, encoding="utf-8"), delimiter="\t"))
        phant = sum(1 for r in rows if r["class"].endswith("ABSENT"))
        if phant * 2 >= len(rows):
            skipped_arr.add(at)
            continue
        used_arr.add(at)
        for r in rows:
            # an ABSENT-class route is not an edge of the live graph at all: one of its endpoints has
            # no widget file on this card, so traversing it would let a phantom node (e.g. the machine
            # array's 'HEADPHONE') become the shortest chain to HP
            if r["class"].endswith("ABSENT"):
                continue
            k = knob.get((at, r["sink"], r["control"]))
            edges.append((r["source"], r["sink"], r["control"], r["class"],
                          k["knob_kind"] if k else "?", k["knob"] if k else ""))
    if not edges:
        sys.exit("gate: no edges survived the instantiation filter -- nothing to traverse")
    out_by = defaultdict(list)
    in_by = defaultdict(list)
    nodes = set()
    for s, k, c, cl, kind, kn in edges:
        out_by[s].append((k, c, cl, kind, kn))
        in_by[k].append((s, c, cl, kind, kn))
        nodes.add(s); nodes.add(k)
    roots = sorted(n for n in nodes if not in_by[n])
    terminals = sorted(n for n in nodes if not out_by[n])
    print(f"{len(edges)} edges from {len(used_arr)} instantiated arrays "
          f"(skipped {len(skipped_arr)} not bound to this card: {sorted(skipped_arr)}); "
          f"{len(nodes)} nodes, {len(roots)} roots, {len(terminals)} terminals")

    def reverse_bfs(t):
        """prev[x] = the node x was reached through (one hop closer to t); depth[x] = hops to t"""
        seen, prev, depth = {t}, {}, {t: 0}
        q = deque([t])
        while q:
            n = q.popleft()
            for s, c, cl, kind, kn in in_by[n]:
                if s not in seen:
                    seen.add(s); prev[s] = (n, c, cl, kind, kn); depth[s] = depth[n] + 1
                    q.append(s)
        return seen, prev, depth

    def chain_to(t, prev, depth, roots):
        """shortest root->t route: take the nearest root in reverse-BFS terms, follow prev-links"""
        near = [r for r in roots if r in depth]
        if not near:
            return []
        x = min(near, key=lambda r: depth[r])
        hops = []
        for _ in range(60):
            if x == t:
                break
            p = prev.get(x)
            if not p:
                return []
            hops.append((x, p[0], p[1], p[2], p[3], p[4]))
            x = p[0]
        return hops if hops and hops[-1][1] == t else []

    wanted = a.terminal or terminals
    missing = [t for t in wanted if t not in terminals]
    if missing:
        sys.exit(f"gate: asked for terminal(s) {missing} which are NOT terminals in this graph "
                 "(they have outgoing routes) -- pick from the reported terminal list")
    rows = []
    for t in terminals:
        if t not in wanted:
            continue
        anc, prev, depth = reverse_bfs(t)
        reach_roots = sorted(n for n in anc if n in roots)
        chain = chain_to(t, prev, depth, reach_roots)
        inc = Counter()
        for x in anc:
            for s, c, cl, kind, kn in in_by[x]:
                inc[cl] += 1
        rows.append((t, len(anc), len(reach_roots), ", ".join(reach_roots[:3]),
                     " / ".join(f"{s}->{d}" + (f" [{kn}={kind}]" if kn else "")
                                for s, d, _c, _cl, kind, kn in chain) or "(no chain)",
                     dict(inc)))
    for t, na, nr, rr, chain, inc in rows:
        print(f"\n== terminal {t}: {na} ancestors, {nr} roots reach it (e.g. {rr})")
        print(f"   shortest chain: {chain}")
        print(f"   incoming edges by class: {inc}")
    if not rows:
        sys.exit("gate: no terminal rows produced -- the traversal answered nothing")

    if not a.no_selftest:
        hp = next((r for r in rows if r[0] == "HP"), None)
        if not hp:
            sys.exit("gate: selftest: HP is not in the terminal set -- the graph lost the headphone "
                     "endpoint that the live capture publishes, so no chain here can be trusted")
        anc, prev, depth = reverse_bfs("HP")
        pairs = {(s, d) for s, d, _c, _cl, _k, _n in edges}
        need_nodes = set(HIFI_PATH)
        need_edges = {(HIFI_PATH[i], HIFI_PATH[i + 1]) for i in range(len(HIFI_PATH) - 1)}
        miss_n = sorted(need_nodes - anc)
        miss_e = sorted(need_edges - pairs)
        if miss_n or miss_e:
            sys.exit(f"gate: selftest FAILED: the card-proven chain {' -> '.join(HIFI_PATH)} (§290) "
                     f"is not reproduced: nodes missing from HP's ancestors {miss_n}, edges missing "
                     f"from the graph {miss_e}. Either the edge direction is swapped or an array "
                     "dropped out, so the other terminals' chains are not evidence either")
        print(f"\nselftest: all of {' -> '.join(HIFI_PATH)} is inside HP's ancestor set and its three "
              "edges exist with the direction ASoC reports")

    if a.emit_matrix:
        # Full checklist, not just one route: edge (s->x) is on SOME path into t exactly when x is an
        # ancestor of t, because the reverse BFS marks s as an ancestor the moment it sees s->x.
        mx, knob_by_term = [], {}
        for t in wanted:
            anc, prev, depth = reverse_bfs(t)
            knobs = set()
            for x in anc:
                for s, c, cl, kind, kn in in_by[x]:
                    knobs.add((kn or c, kind))
                    mx.append((t, x, s, c, cl, kind, kn, depth[x]))
            knob_by_term[t] = knobs
        if not mx:
            sys.exit(f"gate: --emit-matrix produced 0 rows -- the ancestor sets are empty, so the "
                     "traversal found no path into any terminal, which contradicts the LIVE counts")
        with open(a.emit_matrix, "w", encoding="utf-8") as f:
            f.write("terminal\tsink\tsource\tcontrol\tclass\tknob_kind\tknob\thops_to_terminal\n")
            for r in mx:
                f.write("\t".join(str(x) for x in r) + "\n")
        sizes = {t: len(v) for t, v in knob_by_term.items()}
        print(f"\nwrote {a.emit_matrix}: {len(mx)} (terminal, edge) rows; distinct knobs per terminal: "
              + ", ".join(f"{t}={n}" for t, n in sorted(sizes.items(), key=lambda kv: -kv[1])))
        need = {t: {k for k in v if k[1] != "NO-CONTROL (plain connection)"}
                for t, v in knob_by_term.items()}
        print("knobs that must be SET (non-plain-connection) per terminal: "
              + ", ".join(f"{t}={len(need[t])}" for t in sorted(need)))
        # 'knobs in the cone' is not the checklist. But a KNOB-level live/unlive split is not a
        # partition either: one mux knob appears on many routes and can sit in only one place, so the
        # same knob legitimately shows up on both sides. The honest partition is over ROUTES.
        by_state = {}
        for t in wanted:
            live_k, un_k = set(), set()
            live_r = un_r = 0
            for term, _x, _s, _c, cl, kind, kn, _d in mx:
                if term != t or kind == "NO-CONTROL (plain connection)":
                    continue
                if cl == "LIVE":
                    live_k.add((kn, kind)); live_r += 1
                else:
                    un_k.add((kn, kind)); un_r += 1
            by_state[t] = (live_k, un_k, live_r, un_r)
        print("routes in the cone (connected / not) and the distinct knobs they touch, per terminal:")
        for t, (lk, uk, lr, ur) in sorted(by_state.items()):
            both = sorted(lk & uk)
            print(f"   {t:14} routes {lr:3} live / {ur:4} unconnected   knobs "
                  f"{len(lk | uk):3} total ({len(lk)} touched by a live route, {len(uk)} by an "
                  f"unconnected one, {len(both)} by both -- a mux sits in one place so its other "
                  "positions stay unconnected)")
        # Is there a knob every output depends on?  Intersect the SET-able knobs only -- including the
        # plain-connection sentinel would make this look non-empty while answering nothing.
        common = (set.intersection(*(v for v in need.values())) if need else set())
        if common:
            print(f"knobs required by EVERY terminal asked for ({len(common)}): "
                  f"{sorted(common)[:a.top]} -- these must not differ for any output to work")
        else:
            print("no named knob is required by every terminal: each output has its own selector "
                  "cone, so a 7-side check has to go endpoint by endpoint (there is no single "
                  "'master gate' to compare)")
    if a.out:
        with open(a.out, "w", encoding="utf-8") as f:
            f.write("terminal\tancestors\troots_reaching\texample_roots\tshortest_chain\tedges_by_class\n")
            for r in rows:
                f.write("\t".join(str(x) for x in r) + "\n")
        print("wrote", a.out)


if __name__ == "__main__":
    main()
