#!/usr/bin/env python3
"""tools/cnt_bf_hits.py -- which bitfield enum family do the device's .cnt files speak?

Why this is now answerable: earlier blind scans used a *modelled* legality rule (address/pos/len
any combination that fits 16 bits) and that accepted ~59% of arbitrary u16 values -- no scale, so
the self-consistency it found proved nothing. Here the legal set is the 220 concrete enum values
read out of the running driver's TfaBfNames (tools/tfa_bf_table.py), which is a ~0.3% target.

The null is empirical, not assumed: each .cnt is byte-shuffled (fixed seed, several permutations)
and rescanned with the same ruler. Chance density and observed density are printed side by side.
Enum values cluster in low addresses, so a uniform 1/65536 estimate would be wrong -- that is
exactly why the shuffle control is here.

Family split comes from the reference headers: names defined as TFA1_BF_* vs TFA2_BF_*
(fw/tfa-ref/inc/tfa1_tfafieldnames.h, tfa2_tfafieldnames_N1C.h). A name with a 90/91/87 suffix or
no reference macro at all is reported as its own class instead of being folded in.

Usage: tools/cnt_bf_hits.py [--dir art/audio-6.0.1/live/tfa98xx] [--perms 5]
"""
import argparse
import csv
import os
import random
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REF = os.path.join(ROOT, "fw/tfa-ref/inc")


def ref_families():
    fam = {}
    for fn, tag in (("tfa1_tfafieldnames.h", "TFA1"), ("tfa2_tfafieldnames_N1C.h", "TFA2")):
        p = os.path.join(REF, fn)
        if not os.path.exists(p):
            sys.exit(f"gate: reference header missing: {p}")
        for m in re.finditer(rf"\b{tag}_BF_([A-Z0-9_]+)\s*=\s*(0x[0-9a-fA-F]+)", open(p).read()):
            name, val = m.group(1), int(m.group(2), 16)
            fam.setdefault(name, set()).add((tag, val))
    return fam


def runs(buf, enums, phase, fpos=2, stride=4):
    """consecutive records whose field-u16 is a real enum -- nxpTfaBitfield_t is
    {u16 value; u16 field}, so a profile's bitfield list must appear as a run, not as scatter.
    fpos says where inside the 4-byte record the field sits (2 = value-first, 0 = field-first)."""
    out, cur = [], []
    for off in range(phase, len(buf) - 3, stride):
        field = buf[off + fpos] | (buf[off + fpos + 1] << 8)
        if field in enums and field != 0x0000:
            cur.append((off, field))
        else:
            if len(cur) >= 2:
                out.append(cur)
            cur = []
    if len(cur) >= 2:
        out.append(cur)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default=os.path.join(ROOT, "art/audio-6.0.1/live/tfa98xx"))
    ap.add_argument("--tsv", default=os.path.join(ROOT, "art/audio-6.0.1/tfa-bf.TfaBfNames.tsv"))
    ap.add_argument("--perms", type=int, default=5)
    args = ap.parse_args()

    rows = list(csv.DictReader(open(args.tsv), delimiter="\t"))
    if len(rows) < 100:
        sys.exit(f"gate: only {len(rows)} enums in {args.tsv} -- rerun tfa_bf_table.py")
    # keyed by enum, but keep every (enum,name) row: two rows may share an encoding, and a plain
    # dict would silently drop 21 of the 220 fields
    pairs = [(int(r["bf_enum"], 16), r["name"]) for r in rows]
    enums = {e for e, _ in pairs}
    name_of = {}
    for e, n in pairs:
        name_of.setdefault(e, []).append(n)
    fam = ref_families()

    def classify(name, enum):
        ent = fam.get(name)
        if not ent:
            return "device-only" if re.search(r"(90|91|87)\s*$", name) else "no-ref"
        for tag, val in ent:
            if val == enum:
                return tag
        # name known in both/one family but this exact encoding is not in the reference
        return "/".join(sorted({t for t, _ in ent})) + "+delta"

    cls = {}
    for e, n in pairs:
        cls.setdefault(e, set()).add(classify(n, e))
    print(f"rows={len(pairs)} distinct enums={len(enums)} zero-encoding in set={0x0000 in enums}")
    flat = {}
    for s in cls.values():
        flat["|".join(sorted(s))] = flat.get("|".join(sorted(s)), 0) + 1
    print("classes: " + ", ".join(f"{k}:{v}" for k, v in sorted(flat.items(), key=lambda x: -x[1])))

    def scan(buf, drop):
        hits = {}
        for off in range(len(buf) - 1):
            e = buf[off] | (buf[off + 1] << 8)
            if e in enums and e != 0xFFFF and e not in drop:
                hits.setdefault(e, []).append(off)
        return hits

    cnts = sorted(f for f in os.listdir(args.dir) if f.endswith(".cnt"))
    if not cnts:
        sys.exit(f"gate: no .cnt under {args.dir}")
    rng = random.Random(20261015)
    for fn in cnts:
        buf = open(os.path.join(args.dir, fn), "rb").read()
        print(f"\n{fn}  size={len(buf)}  u16-slots={len(buf) - 1}")
        for label, drop in (("all enums", frozenset()), ("minus 0x0000", frozenset({0x0000}))):
            h = scan(buf, drop)
            tot = sum(len(v) for v in h.values())
            bytewise = {}
            for e, offs in h.items():
                key = "|".join(sorted(cls[e]))
                bytewise[key] = bytewise.get(key, 0) + len(offs)
            null = []
            for _ in range(args.perms):
                b = bytearray(buf)
                rng.shuffle(b)
                null.append(sum(len(v) for v in scan(bytes(b), drop).values()))
            nm = sum(null) / len(null)
            print(f"  [{label}] observed={tot} ({tot/(len(buf)-1):.2%})  "
                  f"shuffled null={nm:.1f} ({nm/(len(buf)-1):.2%})  ratio={tot/nm if nm else float('inf'):.2f}x")
            print("      by family: " + ", ".join(f"{k}={v}" for k, v in sorted(bytewise.items(), key=lambda x: -x[1])))
            top = sorted(((len(v), e) for e, v in h.items()), reverse=True)[:6]
            print("      concentration: " + ", ".join(
                f"{name_of[e][0]}({e:#06x})x{n}" for n, e in top))
        # structural anchor: runs of records, both field positions and both alignments.
        # restricted to the "sharp" subset -- enums whose pos>0 and len>=2. Round encodings
        # (0x0080, 0x1000, 0x8000, 0x0f00) are just addr<<8 with pos=len-1=0, and those numbers are
        # common as sizes/offsets/masks in ANY binary, so they made even the run test under-powered.
        sharp = {e for e in enums if ((e >> 4) & 0xF) > 0 and (e & 0xF) >= 2}
        print(f"  sharp subset (pos>0 and len>=2): {len(sharp)} of {len(enums)}")
        for fpos in (2, 0):
            for phase in (0,):
                for label, eset in (("all", enums), ("sharp", sharp)):
                    rr = runs(buf, eset, phase, fpos)
                    obs = sum(len(r) for r in rr)
                    null = []
                    for _ in range(args.perms):
                        b = bytearray(buf)
                        rng.shuffle(b)
                        null.append(sum(len(r) for r in runs(bytes(b), eset, phase, fpos)))
                    nm = sum(null) / len(null)
                    best = max((len(r) for r in rr), default=0)
                    print(f"  [runs {label} field-at+{fpos} phase={phase}] runs>=2:{len(rr)} records:{obs}"
                          f" longest:{best} null:{nm:.1f} ratio:{obs/nm if nm else float('inf'):.1f}x")
                    for r in sorted(rr, key=len, reverse=True)[:2]:
                        fam = "|".join(sorted({c for _, f in r for c in cls[f]}))
                        print(f"      run@{r[0][0]:#05x} len={len(r)} [{fam}] " +
                              ", ".join(f"{name_of[f][0]}({f:#06x})" for _, f in r[:10]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
