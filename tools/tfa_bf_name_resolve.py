#!/usr/bin/env python3
"""tools/tfa_bf_name_resolve.py -- name the residue: §320 matched 167/220 driver bit-fields exactly and
called the other 53 residue.  This tool asks WHY, with a second, independent parser.

The driver's own table (220 rows decoded out of fw/Image in §250) spells a field as `BSSCR87 ` while
fw/tfa-ref/inc/tfa9887_tfafieldnames.h spells the same thing `{ 0x511, "BSSCR"}`.  Decoding 0x511 with
§250's grammar (addr = e>>8, pos = (e>>4)&0xf, len = (e&0xf)+1) gives addr 5 / pos 1 / len 2 -- exactly
the driver row.  So the residue is a NAMING convention (the driver appends the chip number and a space),
not an unknown bit field.

Categories, decided by (name, bfEnum) agreement -- never by name alone:
  EXACT          raw name (as in the driver) equals a header name AND the enum matches
  RESOLVED       name matches after stripping the trailing chip digits + whitespace, enum matches,
                 and the header belongs to the chip the suffix names
  RENAMED        name matches (stripped) in the suffix's chip but the ENUM differs -- same spelling,
                 different bit position, so the driver row is NOT that field
  ABSENT         no header in the reference tree declares the stripped name at all

Controls that must fire before anything is published:
  * a re-derivation of §320's TFA1 count: this parser's EXACT-vs-TFA1 total must equal the number the
    family artifact recorded (167) -- two implementations agreeing, one reading the binary table, one
    reading headers;
  * a base rate: how many rows would "match" if the enum were ignored (the §251 lesson: a legal set
    without a structural anchor gets fooled);
  * --selftest removes the enum equality from the RESOLVED rule and requires the count to change
    (a control that cannot fail is not a control).

usage: tools/tfa_bf_name_resolve.py [--out TSV] [--selftest] [--ref-dir DIR]
"""
import argparse
import collections
import csv
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
ART = os.path.join(ROOT, "art", "audio-6.0.1")
DRIVER = os.path.join(ART, "tfa-bf.TfaBfNames.tsv")
FAMILY = os.path.join(ART, "tfa-bf-family.TfaBfNames.tsv")
ROW_RE = re.compile(r"\{\s*(0x[0-9a-fA-F]+)\s*,\s*\"([^\"]+)\"\s*\}")
ENUM_RE = re.compile(r"\b[A-Za-z0-9]+_BF_([A-Za-z0-9_]+)\s*=\s*(0x[0-9a-fA-F]+)")
FIELD_RE = re.compile(r"_TFA_FIELD_\s*\(\s*([A-Za-z0-9_]+)\s*,\s*(0x[0-9a-fA-F]+|\d+)\s*,\s*"
                      r"(0x[0-9a-fA-F]+|\d+)\s*,\s*(0x[0-9a-fA-F]+|\d+)", re.S)
CHIP_RE = re.compile(r"tfa(\d+)_tfafieldnames")


def chip_of(fname):
    m = CHIP_RE.search(os.path.basename(fname))
    return m.group(1) if m else None


def load_headers(ref_dir):
    """each reference header spells its fields up to three ways; collect all of them and, crucially,
    check that the spellings agree with each other before any of them is allowed to name a driver row"""
    per_chip, info, conflicts = collections.defaultdict(list), {}, []
    for f in sorted(os.listdir(ref_dir)):
        if not f.endswith(".h"):
            continue
        text = open(os.path.join(ref_dir, f), encoding="utf-8", errors="replace").read()
        forms = collections.defaultdict(dict)          # name -> {form: enum}
        for e, n in ROW_RE.findall(text):
            forms[n].setdefault("table", int(e, 16))
        for n, e in ENUM_RE.findall(text):
            forms[n].setdefault("enum", int(e, 16))
        for n, a, p, l in FIELD_RE.findall(text):
            forms[n].setdefault("macro",
                                (int(a, 0) << 8) | (int(p, 0) << 4) | (int(l, 0) - 1))
        for n, fm in forms.items():
            if len(set(fm.values())) > 1:
                conflicts.append((f, n, dict(fm)))
            for form, e in fm.items():
                entry = (e, n, f, form)
                info.setdefault(f, []).append(entry)
                c = chip_of(f)
                if c:
                    per_chip[c].append(entry)
    return info, per_chip, conflicts


def chip_of(fname):
    m = CHIP_RE.search(os.path.basename(fname))
    return m.group(1) if m else None


def strip_suffix(name):
    m = re.fullmatch(r"([A-Za-z0-9_]+?)\s*(\d{2,3})\s*", name)
    return (m.group(1), m.group(2)) if m else (name.strip(), None)


def decode(e):
    return e >> 8, (e >> 4) & 0xF, (e & 0xF) + 1


def classify(driver, per_chip, strict_enum=True):
    out = []
    for r in driver:
        enum = int(r["bf_enum"], 16)
        raw = r["name"]
        base, suffix = strip_suffix(raw)
        raw_hits = [(e, f, fm) for c, rows in per_chip.items() for e, n, f, fm in rows if n == raw]
        if raw_hits and (not strict_enum or any(e == enum for e, _f, _m in raw_hits)):
            cat, hits = "EXACT", [h for h in raw_hits if h[0] == enum] or raw_hits
        else:
            # the driver suffix is the tail of a chip number ('87' -> tfa9887), so match it as a suffix,
            # not as a whole key -- otherwise RESOLVED (the chip the name itself claims) can never fire
            own = [c for c in per_chip if suffix and c.endswith(suffix)]
            named = [(e, f, fm) for c in own for e, n, f, fm in per_chip[c] if n == base]
            if named and strict_enum and any(e == enum for e, _f, _m in named):
                cat, hits = "RESOLVED", [x for x in named if x[0] == enum]
            elif named:
                cat, hits = "RENAMED", named
            else:
                anywhere = [(e, f, fm) for c, rows in per_chip.items()
                            for e, n, f, fm in rows if n == base]
                if anywhere and strict_enum and any(e == enum for e, _f, _m in anywhere):
                    cat, hits = "RESOLVED_OTHER_CHIP", [x for x in anywhere if x[0] == enum]
                elif anywhere:
                    cat, hits = "ABSENT_SAME_NAME_OTHER_ENUM", anywhere[:3]
                else:
                    cat, hits = "ABSENT", []
        out.append({"raw": raw, "base": base, "suffix": suffix or "-", "addr": r["addr"],
                    "pos": r["pos"], "len": r["len"], "enum": f"{enum:#x}", "cat": cat,
                    "fam": {os.path.basename(f).split("_tfafield")[0] for e, f, _m in hits},
                    "form": ",".join(sorted({m for e, f, m in hits})) or "-",
                    "where": ", ".join(f"{os.path.basename(f)}:{m}@{e:#x}" for e, f, m in hits[:3])
                    or "-"})
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--ref-dir", default=os.path.join(ROOT, "fw", "tfa-ref", "inc"))
    ap.add_argument("--driver-tsv", default=DRIVER,
                    help="the 220-row driver bit-field table decoded from the Image in "
                    "§250 (tools/tfa_bf_table.py); on 7 point this at 7's own decode")
    a = ap.parse_args()
    if not os.path.isdir(a.ref_dir):
        sys.exit(f"gate: reference header dir {a.ref_dir} does not exist -- nothing to resolve against")
    driver = list(csv.DictReader(open(DRIVER, encoding="utf-8"), delimiter="\t"))
    if len(driver) != 220:
        sys.exit(f"gate: the driver table read from {a.driver_tsv} has {len(driver)} rows, not 220 -- §320's "
                 "counts are stated over 220 rows, so this comparison would be meaningless")
    info, per_chip, conflicts = load_headers(a.ref_dir)
    if not per_chip:
        sys.exit(f"gate: no field spellings found under {a.ref_dir} -- the parser does not know this "
                 "header dialect, so 'ABSENT' would be a claim about this tool")
    if conflicts:
        sys.exit(f"gate: {len(conflicts)} header field(s) are spelled with DIFFERENT bit positions by "
                 f"the same reference file (first: {conflicts[0]}) -- the reference tree contradicts "
                 "itself, so it may not be used to name anything")
    rows = classify(driver, per_chip)
    cats = collections.Counter(r["cat"] for r in rows)

    # control 1: reproduce §320's per-family exact count with this independent parser
    fam = list(csv.DictReader(open(FAMILY, encoding="utf-8"), delimiter="\t"))
    exp = {}
    for r in fam:
        if r["row_name"] == "-":
            exp[r["family"]] = exp.get(r["family"], 0) + int(r["exact"])
    tfa1_expected = exp.get("tfa1_tfafieldnames.h:TFA1")
    tfa1_got = sum(1 for r in rows if r["cat"] == "EXACT" and any(f.startswith("tfa1") for f in r["fam"]))
    if tfa1_expected is None or tfa1_got != tfa1_expected:
        sys.exit(f"gate: this parser counts {tfa1_got} TFA1 exact rows but §320's artifact says "
                 f"{tfa1_expected} -- the two readings disagree, so the residue categories below are "
                 "not comparable to them")

    # control 2: the base rate -- what would "match" if the enum were ignored at all
    loose = classify(driver, per_chip, strict_enum=False)
    loose_cats = collections.Counter(r["cat"] for r in loose)

    print(f"headers       {len(info)} files with field spellings, "
          f"{sum(len(v) for v in info.values())} entries; chips with a table: {sorted(per_chip)}")
    print(f"driver        {len(driver)} rows; §320 TFA1 exact reproduced here = {tfa1_got} (matches "
          f"the artifact's {tfa1_expected})")
    print(f"categories    " + ", ".join(f"{k}={v}" for k, v in sorted(cats.items())))
    print(f"loose (no     " + ", ".join(f"{k}={v}" for k, v in sorted(loose_cats.items())) +
          " <- base rate if the bit position is ignored)")
    print("              enum enforced)")
    for r in rows:
        if r["cat"] != "EXACT":
            print(f"   {r['cat']:26} {r['raw']:14} enum {r['addr']}/{r['pos']}/{r['len']} "
                  f"-> {r['where']}")
    if a.selftest:
        if loose_cats == cats:
            sys.exit("gate: --selftest: dropping the enum requirement changed no category at all -- "
                     "the classification does not depend on the bit position, so a RESOLVED row is "
                     "just a name match wearing a structural costume")
        moved = {k: (cats.get(k, 0), loose_cats.get(k, 0)) for k in set(cats) | set(loose_cats)
                 if cats.get(k, 0) != loose_cats.get(k, 0)}
        print(f"selftest: the enum check is load-bearing -- without it the categories move: "
              + ", ".join(f"{k} {s}->{l}" for k, (s, l) in sorted(moved.items())))
    if a.out:
        cols = [("cat", "cat"), ("raw_name", "raw"), ("stripped", "base"), ("chip_suffix", "suffix"),
                ("addr", "addr"), ("pos", "pos"), ("len", "len"), ("enum", "enum"),
                ("spelling", "form"), ("header_match", "where")]
        widths = set()
        lines = []
        for r in rows:
            if not r["raw"].strip():
                sys.exit(f"gate: a driver row has no name to publish -- the row would be silent")
            if r["cat"] != "ABSENT" and r["where"] == "-":
                sys.exit(f"gate: {r['cat']} row {r['raw']} carries no header citation -- a category "
                         "without evidence of WHERE it matched is just a label")
            line = [str(r.get(k, "-")).replace("\n", "\\n") for _h, k in cols]
            widths.add(len(line))
            lines.append("\t".join(line))
        for cat, n in sorted(cats.items()):
            lines.append("\t".join([cat, "COUNT", "-", "-", "-", "-", "-", str(n), "-", "-"]))
            widths.add(len(cols))
        with open(a.out, "w", encoding="utf-8") as fh:
            fh.write("\t".join(h for h, _k in cols) + "\n")
            fh.write("\n".join(lines) + "\n")
        if len(widths) != 1:
            sys.exit(f"gate: {a.out} rows disagree on column count {sorted(widths)}")
        print(f"wrote {a.out} ({len(lines) + 1} lines x {next(iter(widths))} columns)")


if __name__ == "__main__":
    main()
