#!/usr/bin/env python3
"""tools/acdb_order.py -- does the ORDER in which the loader reads a dir's *.acdb files matter?

libacdbloader.so's acdb_loader_init_v2 globs the chosen directory (strstr(name, ".acdb")), appends
each hit into one list capped at 20, and hands the list to the ADSP. readdir order is filesystem
hash order, not alphabetical, so if two files of the same dir define the same key with a different
payload, the listening result depends on an order nobody controls. This measures whether that can
happen at all: for every table and every key-prefix length, it counts keys that two different files
claim with different records.

Usage: tools/acdb_order.py [art/audio-6.0.1/acdb-lut.PD1610.tsv ...]
Exit != 0 when any collision is found (order matters -> the load order becomes an artifact to capture).
"""
import collections
import os
import sys


def load(path):
    rows = []
    with open(path, newline="") as f:
        hdr = f.readline().rstrip("\n").split("\t")
        ix = {n: i for i, n in enumerate(hdr)}
        for need in ("dir", "file", "table", "words"):
            if need not in ix:
                sys.exit(f"gate: {path} has no {need!r} column (columns: {hdr})")
        for ln in f:
            p = ln.rstrip("\n").split("\t")
            if len(p) < len(hdr):
                sys.exit(f"gate: {path} short row: {ln[:60]!r}")
            rows.append((p[ix["dir"]], p[ix["file"]], p[ix["table"]], p[ix["words"]]))
    return rows


def collisions(rows, injected=None):
    """returns {(table, prefix_len): {key: {file: set(words)}}} with >=2 files claiming a key differently"""
    bytab = collections.defaultdict(list)
    for _dir, fn, tab, words in rows:
        bytab[tab].append((fn, words))
    out = {}
    for tab, lst in bytab.items():
        widths = {len(w.split()) for _f, w in lst}
        if len(widths) != 1:
            sys.exit(f"gate: table {tab} mixes record widths {sorted(widths)} -- key prefix is undefined")
        w = widths.pop()
        for p in range(1, w):
            seen = collections.defaultdict(lambda: collections.defaultdict(set))
            for fn, words in lst:
                toks = words.split()
                seen[" ".join(toks[:p])][fn].add(words)
            for key, per in seen.items():
                if len(per) < 2:
                    continue
                allsets = [s for s in per.values()]
                if any(a != b for a in allsets[1:]):       # same key, different payload
                    out.setdefault((tab, p), {})[key] = {fn: sorted(s) for fn, s in per.items()}
    if injected:                                          # positive control: a known collision
        tab, key, files = injected
        out.setdefault((tab, 1), {})[key] = {f: ["<synthetic>"] for f in files}
    return out


def main():
    paths = [a for a in sys.argv[1:] if not a.startswith("-")]
    if not paths:
        paths = ["art/audio-6.0.1/acdb-lut.PD1610.tsv"]
    for path in paths:
        if not os.path.exists(path):
            sys.exit(f"gate: {path} missing -- run tools/acdb_tlv.py first")
        rows = load(path)
        files = sorted({r[1] for r in rows})
        tabs = sorted({r[2] for r in rows})
        if not files or not tabs:
            sys.exit(f"gate: {path} yielded no files/tables")
        col = collisions(rows)
        # the ruler must be able to see a collision: inject one and require it to show up
        probe = collisions(rows, injected=("<probe-table>", "<probe-key>", files[:2]))
        if ("<probe-table>", 1) not in probe:
            sys.exit(f"gate: {path}: positive control did not register -- this ruler is blind")
        print(f"{os.path.basename(path)}: {len(rows)} records, {len(files)} files, {len(tabs)} tables, "
              f"control=PASS (injected collision detected)")
        if not col:
            print("   NO cross-file key collision at any prefix length: the load order cannot change "
                  "what the ADSP ends up with -- the port needs the FILE SET, not the order")
            continue
        worst = min(col, key=lambda k: k[1])
        print(f"   {sum(len(v) for v in col.values())} cross-file collision key(s) over "
              f"{len(col)} (table, prefix_len) classes; shortest key width = {worst[1]} words in {worst[0]}")
        for (tab, p), keys in sorted(col.items())[:8]:
            ex = next(iter(keys.items()))
            print(f"     {tab} prefix={p}w: {len(keys)} key(s) e.g. {ex[0]} <- "
                  + ", ".join(f"{fn}({len(v)})" for fn, v in sorted(ex[1].items())))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
