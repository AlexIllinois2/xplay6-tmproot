#!/usr/bin/env python3
"""tools/tfa_field_family_docs.py -- what do NXP's own field tables say the bits we watch MEAN?

The 6.0.1 driver names the fields (tfa9890_tfafieldnames.h copies them verbatim) but its comments are the
bare name for most of them, so §346/§348 could classify a field as a setting without ever saying what it
sets.  The reference tree holds the generated tables for ELEVEN sibling chips, and those comments DO carry
formulas and units for some of the same names -- ktemp for example is documented as
"(1 - VALUE*TEMP)*signal" by tfa2/tfa9872 while tfa9890 only says "temperature compensation trimming".

This is deliberately NOT merged into one number: a comment is quoted WITH ITS CHIP, because the 9890's own
datasheet is what would prove the same formula applies here, and that document is not on this machine
(§350 tried twice to fetch it and failed).  A row therefore says: what the 9890 table states, what the
family states, and whether anything with a unit or a formula was found at all.

usage: tools/tfa_field_family_docs.py [--out TSV] [--selftest]
"""
import argparse
import csv
import glob
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ART = os.path.join(ROOT, "art", "audio-6.0.1")
HDRS = sorted(glob.glob(os.path.join(ART, "..", "..", "fw", "tfa-ref", "inc", "*tfafieldnames*.h")))
ENTRY = re.compile(r'\{\s*(0x[0-9a-fA-F]+)\s*,\s*"([^"]+)"\}[^/]*?/\*(.*?)\*/')
UNITISH = re.compile(r"\[?[dD]%|\bmA\b|\bV\b|dB|\(C\)|°C|step of|VALUE|Hz|sample rate|%")
OUR_CHIP = "tfa9890"


def harvest(path):
    out = {}
    for line in open(path, encoding="utf-8", errors="replace"):
        m = ENTRY.search(line)
        if not m:
            continue
        chip = os.path.basename(path).split("_")[0]
        name = m.group(2).strip()
        com = m.group(3).strip().rstrip(",").strip()
        leaf = name.split("/")[0].split("[")[0].strip()
        if not com:
            continue
        out.setdefault(leaf.lower(), set()).add((chip, name, com))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if not HDRS:
        sys.exit("gate: no *tfafieldnames*.h under fw/tfa-ref/inc -- the reference tree is not here, so "
                 "no family comment can be quoted and this tool has nothing to say")
    fam = [harvest(h) for h in HDRS]
    merged = {}
    for d in fam:
        for k, v in d.items():
            merged.setdefault(k, set()).update(v)
    fh = os.path.join(ART, "tfa-field-history.PD1610.tsv")
    if not os.path.exists(fh):
        sys.exit(f"gate: {fh} missing -- the field list (and which of them are settings) comes from that "
                 "artifact, this tool invents none")
    rows = [r for r in csv.DictReader(open(fh, encoding="utf-8"), delimiter="\t")
            if r["kind"] == "field-history"]
    if not rows:
        sys.exit("gate: no field-history rows to describe")
    out_rows = []
    n_info = n_unit = 0
    for r in rows:
        leaf = r["field"].split("/")[-1].split("[")[0].strip().lower()
        # the same control is spelled differently across generations (the 9890 table says ktemp,
        # tfa2/tfa9894 say cs_ktemp), so look the sibling tables up by the bare name AND by the
        # cs_-prefixed one, and quote the name the chip itself used so the reader sees it is not a 9890 entry
        aliases = {leaf, "cs_" + leaf}
        ents = set()
        for kk, vv in merged.items():
            if kk in aliases or kk.endswith("_" + leaf):
                ents.update(vv)
        ours = sorted(c for chip, n, c in ents if chip == OUR_CHIP)
        other = sorted(f"{chip}[{n}]: {c}" for chip, n, c in ents if chip != OUR_CHIP)
        carries = [c for c in ours + other if UNITISH.search(c) or "VALUE" in c]
        if ours or other:
            n_info += 1
        if carries:
            n_unit += 1
        out_rows.append({
            "field": r["field"], "reg": r["reg"], "span": r["span"], "source": r["source"],
            "distinct": r["distinct"], "values": r["values"], "class": r["class"],
            "own_comment": " | ".join(ours) or "(the 9890 table gives no comment beyond the name)",
            "family_comments": " || ".join(other) or "none",
            "unit_or_formula": "yes" if carries else "no",
            "verdict": ("9890 names it and the family states a formula/unit -- read it as: "
                        + (carries[0] if carries else "-")) if carries else (
                "named by the 9890 table only -- the scale is NOT established locally (needs the 9890 "
                "datasheet)" if ours else
                "comment found only in sibling-chip tables -- same field name, different silicon, so this "
                "is a hypothesis for the 9890, never a value")})
    cols = ["field", "reg", "span", "source", "distinct", "values", "class", "own_comment",
            "family_comments", "unit_or_formula", "verdict"]
    if not rows or n_info < len(rows) * 0.5:
        sys.exit(f"gate: comments found for only {n_info} of {len(rows)} fields -- the harvest is not "
                 "reading the tables it claims to (a wrong regex looks exactly like an empty comment)")
    kt = [r for r in out_rows if r["field"].endswith("ktemp") or "/ktemp" in r["field"]]
    if not kt or not any("VALUE" in r["family_comments"] for r in kt):
        sys.exit(f"gate: ktemp rows {kt[:1]} carry no (1 - VALUE*TEMP) family comment -- §350's claim "
                 "that the trimming coefficient is documented by sibling tables would be unsupported")
    print(f"headers         {len(HDRS)} sibling tables read; distinct field names with any comment: "
          f"{len(merged)}")
    print(f"fields          {len(out_rows)} named fields: {n_info} have a comment somewhere in the family, "
          f"{n_unit} of them state a formula or a unit")
    for r in kt + [x for x in out_rows if x["field"].endswith("cs_neghyst")][:1]:
        print(f"  {r['reg']} {r['field']}{r['span']} class={r['class']} value={r['values']} :: "
              f"own=[{r['own_comment'][:60]}] family=[{r['family_comments'][:110]}]")
    if a.selftest:
        rev = [r for r in out_rows if r["unit_or_formula"] == "yes"]
        if not rev:
            sys.exit("gate: --selftest: no row claims a formula or unit -- the UNITISH filter never fires "
                     "and the column would be decoration")
        blank = [r for r in out_rows if r["own_comment"] == "" or r["verdict"] == ""]
        if blank:
            sys.exit(f"gate: --selftest: {len(blank)} rows with an empty comment/verdict cell")
        print(f"selftest: {len(rev)} rows do carry a formula or unit; no row leaves the verdict cell empty")
    if a.out:
        with open(a.out, "w", encoding="utf-8") as fh2:
            fh2.write("\t".join(cols) + "\n")
            for r in out_rows:
                line = "\t".join(str(r[c]) for c in cols)
                if len(line.split("\t")) != len(cols):
                    sys.exit("gate: a row does not have the declared column count")
                fh2.write(line + "\n")
        print(f"wrote {a.out} ({len(out_rows)} rows x {len(cols)} columns)")


if __name__ == "__main__":
    main()
