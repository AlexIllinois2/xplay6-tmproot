#!/usr/bin/env python3
"""tools/acdb_patch7_from6.py -- build the AB-test artifact for the ACDB layer: a copy of the 7.1.1
calibration files whose addressed cal blobs carry 6.0.1's bytes, without moving a single pointer.

Why this shape and not "copy the files over": §577/§578 measured that between PD1610 (6.0.1) and
PD1610_7 (7.1.1) the DATAPOOL differs in 23 blocks / 1220 bytes, seen through 37 302 addressing
coordinates -- 275 of them point at a same-LENGTH block with different bytes, 286 at a block whose
length differs.  Only the same-length ones can be written in place: the pool offsets stay valid, so
every `*CDOT`/DPROPLUT pointer in the file keeps pointing where it did.

Gates -- each one is what would make the output wrong rather than merely different:
  * the patched file must still land EXACTLY on end-of-file in the TLV walk (§261's anchor);
  * the patched file's DATAPOOL chain must still close to the last byte (§304);
  * the pool offsets of the coordinates we touched must be UNCHANGED (no pointer may move), and the
    bytes at the *other* side's offsets must be byte-equal after the write;
  * every coordinate NOT in the patch set must still read exactly what 7 read before, so a stray
    write cannot hide inside "it patched fine".
  * a coordinate whose two sides have different lengths is SKIPPED and counted, never truncated.

Nothing here touches the device.  The output goes to a directory you can push and point the loader
at (§378's calfile cascade); restoring is restoring the property, not reflashing.

usage: tools/acdb_patch7_from6.py [--role Headset_cal.acdb ...] [--out /tmp/acdb-patched] [--list]
"""
import argparse
import collections
import os
import struct
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))
import acdb_tlv  # noqa: E402
import acdb_pool as P  # noqa: E402


CMP = os.environ.get("ACDB_DIR") or os.path.join(ROOT, "art/audio-7.1.1/acdbdata-cmp")
P.ACDB = CMP  # coord_map/coords read through acdb_pool's own dir variable
SET6 = "PD1610"
SET7 = "PD1610_7"


def datapool_file_range(stem, f):
    """(path, absolute byte range of the DATAPOOL payload inside the file) -- the pool offsets the
    coordinates speak are relative to this range's start."""
    path = os.path.join(CMP, stem, f)
    b = open(path, "rb").read()
    for off, name, ln in acdb_tlv.walk(b)[0]:
        if name.strip() == "DATAPOOL" and ln:
            return path, b, off + 12, ln
    sys.exit(f"gate: {path} has no non-empty DATAPOOL field")


def patch(role, out_dir, dry=False):
    p6, b6, base6, len6 = datapool_file_range(SET6, role_file(SET6, role))
    p7, b7, base7, len7 = datapool_file_range(SET7, role_file(SET7, role))
    pool6, pool7 = b6[base6:base6 + len6], b7[base7:base7 + len7]
    cm6 = P.coord_map((SET6, role_file(SET6, role)), pool6, {o for o, _L, _p in P.walk(pool6)[0]})
    cm7 = P.coord_map((SET7, role_file(SET7, role)), pool7, {o for o, _L, _p in P.walk(pool7)[0]})
    both = set(cm6) & set(cm7)
    same, differ_len, equal = [], [], 0
    for c in sorted(both):
        o6, x6 = cm6[c]
        o7, x7 = cm7[c]
        if x6 == x7:
            equal += 1
        elif len(x6) == len(x7):
            same.append((c, o6, o7, x6))
        else:
            differ_len.append((c, o6, o7, len(x6), len(x7)))
    # FAN-OUT RULE, and it is the whole ballgame here.  A 7-side block is usually addressed by many
    # coordinates (mean ~28), so writing one offset rewrites every coordinate that shares it.  The
    # first version of this tool asked only "do these two coordinates want the same bytes?" and wrote
    # 63 of them -- measured afterwards, that BREAKS 4 884 coordinates that used to read equal
    # (Handset 11 649 -> 9 545, Headset 7 011 -> 4 493, Speaker 14 391 -> 14 129), because an offset
    # written for coordinate X is also the address of coordinate Z, whose 6.0.1 counterpart already
    # matched 7 byte for byte.  So the admissible write is: EVERY coordinate on the 7 side that shares
    # this offset must want the SAME 6.0.1 payload, and that payload must not already be there.
    fan7 = collections.defaultdict(list)
    for c, (o7, x7) in cm7.items():
        fan7[o7].append(c)
    by7 = collections.defaultdict(list)
    for c, o6, o7, x6 in same:
        by7[o7].append((c, x6))
    conflict, regressed = {}, {}
    for o7, v in by7.items():
        if len({x[1] for x in v}) > 1:
            conflict[o7] = v
            continue
        want = v[0][1]
        others = [c for c in fan7[o7] if c not in {x[0] for x in v}]
        bad = [c for c in others if c in cm6 and cm6[c][1] != want]
        if bad:
            regressed[o7] = (len(bad), v[0][0])
    same = [(c, o6, o7, x6) for c, o6, o7, x6 in same if o7 not in conflict and o7 not in regressed]
    tot_regress = sum(v[0] for v in regressed.values())
    if not same:
        return {"role": role, "patched": 0, "skipped length": len(differ_len), "equal": equal,
                "bytes": 0, "file": None, "conflicts": len(conflict), "protected": tot_regress}
    if tot_regress:
        print(f"  {role}: {len(regressed)} offsets refused because they would break {tot_regress} "
              "currently-equal coordinates")

    nb = bytearray(b7)
    # a coordinate's offset is the block's HEADER word (walk() reports `(p, L, payload)` with p at the
    # u32 that counts the bytes after it), so the payload starts at +4 -- writing at +0 overwrites the
    # length word and the chain dies two blocks later.  That is what §304's close-gate caught here.
    for c, o6, o7, x6 in same:
        nb[base7 + o7 + 4: base7 + o7 + 4 + len(x6)] = x6
    # ---- gates on the produced bytes, not on intention ----
    fl, at_end = acdb_tlv.walk(bytes(nb))
    if not at_end:
        sys.exit(f"GATE {role}: the patched file no longer lands on end-of-file -- the write moved "
                 "something it should not have touched")
    dpos = [o for o, n, l in fl if n.strip() == "DATAPOOL"]
    if len(dpos) != 1:
        sys.exit(f"GATE {role}: DATAPOOL field moved ({len(dpos)} of them)")
    base7c = dpos[0] + 12
    poolc = bytes(nb[base7c:base7c + len7])
    blocks, closed = P.walk(poolc)
    if not closed:
        sys.exit(f"GATE {role}: the patched pool chain does not close -- §304's grammar is broken")
    if [(o, L) for o, L, _p in blocks] != [(o, L) for o, L, _p in P.walk(pool7)[0]]:
        sys.exit(f"GATE {role}: block offsets or lengths moved -- a same-length write must not "
                 "relayout the pool (this is the tell that a header word was touched)")
    payc = {o: p for o, _L, p in blocks}
    moved = [c for c, o6, o7, x6 in same if payc[o7] != x6]
    if moved:
        sys.exit(f"GATE {role}: {len(moved)} patched coordinates do not read 6.0.1's bytes (e.g. {moved[:3]})")
    # fan-out is expected: MANY coordinates point at the same block (the 23 one-sided blocks show up
    # as 275+286 coordinates), so a coordinate outside the patch set may legitimately change -- but
    # only if its block offset is one of the offsets that was written.  Anything else is a stray write.
    written = {o7 for _c, _o6, o7, _x in same}
    patched_set = {x[0] for x in same}
    # gate 5 -- the aggregate read-out, not the per-write one: the whole point of the fan-out rule is
    # that a write can make its own coordinate agree while breaking the neighbours that share the
    # block, so count equal-reading coordinates before and after and refuse any net loss.
    eq_before = sum(1 for c in both if cm6[c][1] == cm7[c][1])
    eq_after = sum(1 for c in both if cm6[c][1] == payc.get(cm7[c][0], cm7[c][1]))
    if eq_after < eq_before:
        sys.exit(f"GATE {role}: equal-reading coordinates went {eq_before} -> {eq_after}; the patch "
                 "traded agreements -- refuse the offsets that cause it")
    stray = [c for c in both
             if c not in patched_set and cm7[c][0] not in written
             and cm7[c][1] != payc.get(cm7[c][0], cm7[c][1])]
    if stray:
        sys.exit(f"GATE {role}: {len(stray)} coordinates changed whose block offset was never written "
                 f"(e.g. {stray[:3]})")
    out = None
    if not dry:
        os.makedirs(out_dir, exist_ok=True)
        out = os.path.join(out_dir, role_file(SET7, role))
        open(out, "wb").write(bytes(nb))
    return {"role": role, "patched": len(same), "skipped length": len(differ_len),
            "equal gain": eq_after - eq_before, "equal": equal,
            "bytes": sum(len(x[3]) for x in same), "file": out, "conflicts": len(conflict),
            "protected": tot_regress,
            "coords": [f"{c[0]} g{c[1]}/w{c[2]}" for c, _o, _o7, _x in same]}


def role_file(stem, role):
    """the cal files inside a set dir carry the board prefix on some trees and not on others --
    resolve by the role suffix instead of assuming either spelling."""
    d = os.path.join(CMP, stem)
    c = [f for f in sorted(os.listdir(d)) if f == role or f.endswith("_" + role)]
    if len(c) != 1:
        sys.exit(f"gate: {role} resolves to {c} in {d} -- exactly one file was expected")
    return c[0]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--role", action="append", help="cal file, repeatable (default: the three that differ)")
    ap.add_argument("--out", default="/tmp/acdb-patched-7")
    ap.add_argument("--list", action="store_true", help="list the patched coordinates")
    a = ap.parse_args()
    roles = a.role or ["Handset_cal.acdb", "Headset_cal.acdb", "Speaker_cal.acdb"]
    tot = collections.Counter()
    for r in roles:
        res = patch(r, a.out)
        tot["patched coordinates"] += res["patched"]
        tot["skipped (length differs)"] += res["skipped length"]
        tot["already equal"] += res["equal"]
        tot["bytes written"] += res["bytes"]
        tot["conflicting target blocks"] += res["conflicts"]
        tot["coordinates protected by the refusal"] += res.get("protected", 0)
        print(f"{r:20} patched {res['patched']:3}  skipped-for-length {res['skipped length']:3}  "
              f"conflicts {res['conflicts']:3}  already equal {res['equal']:6}  "
              f"gain {res.get('equal gain', 0):+4}  bytes {res['bytes']:6}  -> {res['file']}")
        if a.list and res.get("coords"):
            for c in res["coords"]:
                print("      ", c)
    print("totals:", ", ".join(f"{k} {v}" for k, v in tot.items()))
    print("  NOTE: this writes NOTHING to the device; it produces files.  Loading them is the "
          "calfile property (§378) and restoring that property is the undo.")


if __name__ == "__main__":
    main()
