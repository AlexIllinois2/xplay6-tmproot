#!/usr/bin/env python3
"""tools/acdb_port_diff.py -- the executable 6.0.1 -> 7 ACDB comparison, testable right now.

The end goal is "after switching to Android 7, the same listening result". For the ACDB layer that
means one question, answerable without listening and without a device:

    is the candidate .acdb set the same calibration object as the 6.0.1 PD1610 set?

This tool compares, in that order (cheapest and most decisive first), and says WHY it differs:

  1. container schema   -- the packed field-name sequence of every file (tools/acdb_tlv.py walk)
  2. version triple     -- SWPNAME / ADSPVERS / CDCNAME (ledger 261; the loader's own compatibility keys)
  3. numbered device pool present? (ledger 265 -- it is vivo's own section, 0 rows in stock dirs)
  4. card overlap       -- the (table, device, app_type, values) rows for the live device ids
  5. bytes              -- sha16 per file

Self-tested on the local reference dirs, which stand in for "another firmware's acdbdata":
  PD1610 vs PD1610LG4  -> must read IDENTICAL (proven byte-equal in ledger 261)   = POSITIVE arm
  PD1610 vs PD1516A    -> must read DIFFERENT, with a named reason                 = NEGATIVE arm

Exit code: 0 only when the candidate is byte-identical to the baseline; 1 otherwise (with reasons).
Usage: tools/acdb_port_diff.py [--base PD1610] [--other ALL] [--json]
"""
import argparse
import collections
import hashlib
import os
import re
import struct
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))
import acdb_bodies  # noqa: E402  the undecoded-body digest arm
import acdb_tlv  # noqa: E402  one source of truth for the walk

ACDB = acdb_tlv.ACDB
ART = os.path.join(ROOT, "art/audio-6.0.1")


def sha16(p):
    return hashlib.sha256(open(p, "rb").read()).hexdigest()[:16]


def schema(b):
    fl, end = acdb_tlv.walk(b)
    return [n.strip() for _, n, _ in fl], end == len(b)


def strings_of(b, want):
    fl, _ = acdb_tlv.walk(b)
    for off, name, ln in fl:
        if name.strip() == want:
            return b[off + 12:off + 12 + ln].decode("latin-1").strip("\x00 ")
    return ""


def header_triple(root, d):
    """the three compatibility keys, read from whichever file in the dir carries them"""
    for fn in sorted(os.listdir(os.path.join(root, d))):
        if not fn.endswith(".acdb"):
            continue
        b = open(os.path.join(root, d, fn), "rb").read()
        # the '0' padding belongs to the FIELD NAME, not to the value: strip("0") here would turn
        # 'MSM8996.LA.1.0' into 'MSM8996.LA.1.' and compare two equally mangled strings
        swp = re.sub(r"\s+", "", strings_of(b, "SWPNAME"))
        adsp = re.sub(r"\s+", "", strings_of(b, "ADSPVERS"))
        cdc = re.sub(r"\s+", "", strings_of(b, "CDCNAME"))
        if swp or adsp or cdc:
            return swp, adsp, cdc
    return "", "", ""


def numbered_pool(d):
    """count of numbered device ids, read from the ANCHORED harvest (tools/acdb_names.py) rather
    than re-scanning bytes here -- two implementations of the same predicate drift, and the loose
    one here counted 54 against the anchored 92"""
    import csv
    # ★0 must be a MEASUREMENT, not the shape of an absent input.  The old code returned 0 when it
    # fell through to `acdb-names.ALL.tsv` (6.0.1's harvest) and filtered it for a dir that file was
    # never built from -- which this tool then printed as "candidate has NO vivo device pool ->
    # stock QCOM set" for the official 7.1.1 files, while tools/acdb_card.py counted a numbered pool
    # of 11995 records in that very same directory.  If the chosen file has no rows for `d`, the
    # honest answer is None: "not harvested for this dir -- run tools/acdb_names.py --dirs <d>".
    for p in (os.path.join(ART, f"acdb-names.{d}.tsv"), os.path.join(ART, "acdb-names.ALL.tsv")):
        if not os.path.exists(p):
            continue
        rows = [r for r in csv.DictReader(open(p), delimiter="\t") if r["dir"] == d]
        if not rows:
            continue
        ids = {int(r["name"].split("_")[0]) for r in rows
               if r["in_field"] == "DATAPOOL" and re.match(r"^\d{1,4}_", r["name"])}
        return len(ids)
    return None


def card_rows(d):
    p = os.path.join(ART, f"acdb-card.{d}.tsv")
    if not os.path.exists(p):
        return None
    import csv
    return {tuple(r.values()) for r in csv.DictReader(open(p), delimiter="\t")}


def full_card(d):
    """device -> set of carded rows, from tools/acdb_card.py --devices all (86 devices on PD1610)"""
    import csv
    p = os.path.join(ART, f"acdb-card.{d}-full.tsv")
    if not os.path.exists(p):
        return None
    by = collections.defaultdict(set)
    for r in csv.DictReader(open(p), delimiter="\t"):
        by[int(r["acdb_dev_id"])].add((r["table"], r["app_type"], r["sample_rate"], r["rest_of_record"]))
    return by


def compare(base, other):
    root = ACDB
    out = {"base": base, "other": other, "reasons": [], "identical": True}
    fb = sorted(f for f in os.listdir(os.path.join(root, base)) if f.endswith(".acdb"))
    fo = sorted(f for f in os.listdir(os.path.join(root, other)) if f.endswith(".acdb"))
    stem = lambda f: f.replace(other + "_", "").replace(base + "_", "")
    if {stem(f) for f in fb} != {stem(f) for f in fo}:
        out["reasons"].append(f"file sets differ: {sorted({stem(f) for f in fb} ^ {stem(f) for f in fo})}")
        out["identical"] = False
    for f, g in zip(sorted(fb, key=stem), sorted(fo, key=stem)):
        if stem(f) != stem(g):
            continue
        bb = open(os.path.join(root, base, f), "rb").read()
        bo = open(os.path.join(root, other, g), "rb").read()
        sb, okb = schema(bb)
        so, oko = schema(bo)
        if not oko:
            out["reasons"].append(f"{stem(g)}: candidate does not walk to EOF -- not a file this reader can interpret")
            out["identical"] = False
        elif sb != so:
            out["reasons"].append(f"{stem(g)}: field schema differs ({len(sb)} vs {len(so)} fields, first diff "
                                  f"{next((i for i, (x, y) in enumerate(zip(sb, so)) if x != y), None)})")
            out["identical"] = False
        if sha16(os.path.join(root, base, f)) != sha16(os.path.join(root, other, g)):
            out["identical"] = False
    tb, to = header_triple(root, base), header_triple(root, other)
    if not any(tb):
        # an empty triple on BOTH sides would make this arm pass without testing anything (§260)
        sys.exit(f"gate: baseline {base} version triple unreadable -- the strings_of reader is broken")
    if tb != to:
        out["reasons"].append(f"version triple differs: {tb} -> {to}")
        out["identical"] = False
    pb, po = numbered_pool(base), numbered_pool(other)
    out["pool"] = (pb, po)
    if po is None:
        out["reasons"].append(f"candidate pool unknown -- run tools/acdb_names.py --dirs {other}")
    if pb != po:
        out["reasons"].append(f"numbered device pool: baseline {pb} ids, candidate {po} ids"
                              + ("  (candidate has NO vivo device pool -> stock QCOM set)" if po == 0 else ""))
        out["identical"] = False
    kb, ko, kdiff = acdb_bodies.compare_pair(base, other)
    out["bodies"] = (len(kb), len(kdiff))
    if kb and not ko:
        out["reasons"].append(f"candidate has no body rows -- dir {other} unreadable?")
        out["identical"] = False
    elif kdiff:
        out["reasons"].append(f"undecoded bodies differ in {len(kdiff)}/{len(kb)} field slots "
                              f"(the part no tool parses yet -- see tools/acdb_bodies.py)")
        out["identical"] = False
    fb, fo = full_card(base), full_card(other)
    if fb is None or fo is None:
        out["reasons"].append(f"per-device card arm skipped: {'baseline' if fb is None else 'candidate'} "
                              f"has no acdb-card.*-full.tsv -- run tools/acdb_card.py --dir {base if fb is None else other} --devices all")
        if fb is not None:
            out["identical"] = False
    else:
        both = sorted(set(fb) & set(fo))
        ident = [d for d in both if fb[d] == fo[d]]
        onlyb = sorted(set(fb) - set(fo))
        out["devices"] = (len(both), len(ident), onlyb)
        # the live devices by name, checked one by one: a device can be PRESENT yet carry other numbers
        for dev, label in ((15, "speaker"), (124, "speaker-protected"), (150, "Hi-Fi headset")):
            if dev in fb and not fo.get(dev):
                out["reasons"].append(f"device {dev} ({label}): baseline has {len(fb[dev])} cal rows, "
                                      f"candidate has NONE -- that path cannot sound the same on this cal set")
                out["identical"] = False
            elif dev in fb and dev in fo and fb[dev] != fo[dev]:
                out["reasons"].append(f"device {dev} ({label}): present in both but "
                                      f"{len(fb[dev] - fo[dev])}/{len(fb[dev])} rows differ")
        if onlyb:
            out["reasons"].append(f"{len(onlyb)} device ids calibrated only in the baseline: {onlyb[:12]}"
                                  + ("…" if len(onlyb) > 12 else ""))
            out["identical"] = False
        if len(ident) != len(both):
            out["reasons"].append(f"per-device cards differ: {len(ident)}/{len(both)} device row-sets identical")
    ab, ao = card_rows(base), card_rows(other)
    if ab is None:
        out["reasons"].append(f"baseline card acdb-card.{base}.tsv missing -- run tools/acdb_card.py")
    elif ao is None:
        out["reasons"].append(f"candidate card acdb-card.{other}.tsv missing -- run tools/acdb_card.py --dir {other}")
        out["identical"] = False
    else:
        out["card"] = (len(ab), len(ao), len(ab & ao))
        if ab != ao:
            out["reasons"].append(f"cal card differs: {len(ab)} vs {len(ao)} rows, {len(ab & ao)} shared")
            out["identical"] = False
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="PD1610")
    ap.add_argument("--other", default="ALL", help="dir name, or ALL for every other dir")
    args = ap.parse_args()
    if not os.path.isdir(os.path.join(ACDB, args.base)):
        sys.exit(f"gate: baseline dir {args.base} not in {ACDB}")
    others = sorted(d for d in os.listdir(ACDB) if d != args.base and os.path.isdir(os.path.join(ACDB, d))) \
        if args.other == "ALL" else [args.other]
    rc = 0
    for o in others:
        r = compare(args.base, o)
        v = "IDENTICAL" if r["identical"] else "DIFFERENT"
        card = f" card shared {r['card'][2]}/{r['card'][0]}" if "card" in r else ""
        bod = f" bodies differ {r['bodies'][1]}/{r['bodies'][0]}" if "bodies" in r else ""
        dv = r.get("devices")
        dev = ""
        if dv:
            dev = f" devices {dv[1]}/{dv[0]} identical"
            if dv[2]:
                dev += f", {len(dv[2])} baseline-only"
        print(f"{args.base} vs {o:10s}: {v}  pool {r['pool'][0]}->{r['pool'][1]}{bod}{dev}{card}")
        for reason in r["reasons"]:
            print(f"      - {reason}")
        if o == "PD1610LG4":
            print(f"   control POSITIVE (byte-equal per 261): {'PASS' if r['identical'] else 'FAIL'}")
            if not r["identical"]:
                rc = 1
        elif o == "PD1516A":
            print(f"   control NEGATIVE (a different board must not read identical): "
                  f"{'PASS' if not r['identical'] else 'FAIL -- the ruler cannot tell two boards apart'}")
            if r["identical"]:
                rc = 1
    return rc


if __name__ == "__main__":
    sys.exit(main())
