#!/usr/bin/env python3
"""tools/cnt_compare.py -- say whether a .cnt on another firmware carries the SAME tuning blocks.

This is the port-side acceptance arm for the DSP layer. §257 established that the kernel forwards
each embedded block whole to ADSP (param 6 etc.) without parsing it, so byte equality of the blocks
is the right thing to check -- decoding the CoolFlux payload is not needed to prove the tuning is the
same, and would not be portable anyway.

Reference = the 6.0.1 inventory produced by tools/cnt_embed.py (--write), i.e. cnt-embed.PD1610.tsv.
The walk is imported from cnt_embed so the two can never disagree about offsets.

Exit 0 only if every expected block is present with the same id, size and body hash.

Usage: tools/cnt_compare.py <file.cnt> [--cnt-name tfa98xx_PD1610.cnt] [--ref PATH]
"""
import argparse
import csv
import hashlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cnt_embed import container_crc_ok, iter_blocks  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cnt")
    ap.add_argument("--cnt-name", help="reference row filter; default = basename of the file")
    ap.add_argument("--ref", default=os.path.join(ROOT, "art/audio-6.0.1/live/tfa98xx/embedded/cnt-embed.PD1610.tsv"))
    args = ap.parse_args()

    if not os.path.exists(args.ref):
        sys.exit(f"gate: reference inventory missing ({args.ref}) -- run tools/cnt_embed.py --write first")
    name = args.cnt_name or os.path.basename(args.cnt)
    blob = open(args.cnt, "rb").read()

    head_ok = container_crc_ok(blob)
    print(f"{name}: container header (magic 'PM' + size@6 + CRC@10 recomputed) = {'OK' if head_ok else 'DIFFERS from 6.0.1'}")
    expect = [r for r in csv.DictReader(open(args.ref), delimiter="\t") if r["cnt"] == name]
    if not expect:
        sys.exit(f"gate: no reference rows for {name!r} in {args.ref} -- refusing to pass an unanchored file")
    found = iter_blocks(blob)
    got = {(b["name"], b["id"]): b for b in found}

    bad = 0
    for r in expect:
        key = (r["name"], r["id"])
        b = got.get(key)
        if b is None:
            print(f"  MISSING  {key[1]}/{key[0]}")
            bad += 1
            continue
        body_sha = hashlib.sha256(b["body"]).hexdigest()[:16] if b["body"] else "-"
        if b["dsc_size"] != int(r["dsc_size"]):
            print(f"  SIZE     {key[1]}/{key[0]}: {b['dsc_size']} vs {r['dsc_size']}")
            bad += 1
        elif body_sha != r["body_sha"]:
            print(f"  BYTES    {key[1]}/{key[0]}: sha {body_sha} vs {r['body_sha']}")
            bad += 1
        else:
            print(f"  OK       {key[1]}/{key[0]} {b['dsc_size']}B sha={body_sha} -> {b['route']}")
    extra = [k for k in got if k[0] not in {e["name"] for e in expect}]
    for k in extra:
        print(f"  EXTRA    {k[1]}/{k[0]} (not in the 6.0.1 reference)")
    print(f"\nverdict: expected={len(expect)} found={len(found)} mismatched={bad} header_ok={head_ok}")
    return 0 if (bad == 0 and not extra and head_ok) else 1


if __name__ == "__main__":
    sys.exit(main())
