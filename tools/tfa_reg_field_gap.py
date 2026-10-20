#!/usr/bin/env python3
"""tools/tfa_reg_field_gap.py -- why do the live PA registers 0x40 / 0x46 / 0x47 / 0x4c decode to ZERO
bit fields (§250's residue)?  Two possible answers and this tool separates them:

  A  the driver's TfaBfNames table is TRIMMED relative to the reference family -- the bits exist and are
     named in tfa1_tfafieldnames.h but the device's table does not carry them;
  B  nobody names those bits -- the register is a whole-register status/interrupt port and the bit
     meanings live in a DIFFERENT table (the headers carry an IRQ-name table, `tfaIrqName_t`).

For every register in the binary-supplied 26-register denominator (tfa-regs.PD1610.tsv, §249) the tool
reports: driver fields, reference fields (per candidate family), the gap, and the names in the gap.

Controls, all aborts:
  * per-register driver field counts must reproduce tfa-reg-fields.PD1610.tsv's `nfields` column for
    all 26 registers -- two tools, one from the machine code (§250), one here;
  * the 220-row total and the family vote from §320 must be re-derived from the inputs, not typed;
  * N1C/TFA2 (the family that matches 0 driver rows) must give a DIFFERENT gap profile than TFA1, or
    the family choice is not doing any work here.

usage: tools/tfa_reg_field_gap.py [--out TSV] [--selftest]
"""
import argparse
import collections
import csv
import hashlib
import importlib.util
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
ART = os.path.join(ROOT, "art", "audio-6.0.1")
DRIVER = os.environ.get("TFA_DRIVER", os.path.join(ART, "tfa-bf.TfaBfNames.tsv"))
REGS = os.path.join(ART, "tfa-regs.PD1610.tsv")
FIELDS = os.path.join(ART, "tfa-reg-fields.PD1610.tsv")
REF = os.environ.get("TFA_REF", os.path.join(ROOT, "fw", "tfa-ref", "inc"))


def sha16(p):
    return hashlib.sha256(open(p, "rb").read()).hexdigest()[:16]


def load_resolver():
    spec = importlib.util.spec_from_file_location("tfa_bf_name_resolve",
                                                  os.path.join(HERE, "tfa_bf_name_resolve.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def ref_names_for(reg, info, header):
    return {n for e, n, f, form in info.get(header, []) if e >> 8 == reg}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    rsv = load_resolver()
    if not os.path.isdir(REF):
        sys.exit(f"gate: reference dir {REF} missing")
    info, per_chip, conflicts = rsv.load_headers(REF)
    if conflicts:
        sys.exit(f"gate: {len(conflicts)} reference fields contradict themselves on bit position -- "
                 "the reference tree may not be used as a witness")
    print(f"input           driver {DRIVER} [{sha16(DRIVER)}]; reference {REF} "
          f"({len(info)} headers, {sum(len(v) for v in info.values())} spellings)")
    driver = list(csv.DictReader(open(DRIVER, encoding="utf-8"), delimiter="\t"))
    if len(driver) != 220:
        sys.exit(f"gate: driver table has {len(driver)} rows, not 220")
    drv_by_reg = collections.defaultdict(list)
    for r in driver:
        drv_by_reg[int(r["bf_enum"], 16) >> 8].append(r["name"])

    # which family does the driver's numbering belong to?  re-derive §320's vote from these inputs
    fam_rows = collections.defaultdict(set)
    for e, n, f, form in [x for c in per_chip.values() for x in c]:
        fam_rows[f].add((n, e))
    def vote(fname):
        s = fam_rows.get(fname, set())
        return sum(1 for r in driver if (r["name"].strip(), int(r["bf_enum"], 16)) in s)
    tfa1 = "tfa1_tfafieldnames.h"
    n1c = "tfa2_tfafieldnames_N1C.h"
    v1, v2 = vote(tfa1), vote(n1c)
    print(f"family vote     exact (name,enum) rows: {tfa1}={v1}, {n1c}={v2}")

    reg_denom = [r for r in csv.DictReader(open(REGS, encoding="utf-8"), delimiter="\t")
                 if re.fullmatch(r"0x[0-9a-f]{2}", r.get("reg", "").strip())]
    if len(reg_denom) != 26:
        sys.exit(f"gate: {REGS} exposes {len(reg_denom)} registers, not the 26 the PA layer is counted "
                 "over -- the denominator has to come from the artifact, not from my memory")
    exp_fields = {int(r["reg"], 16): int(r["nfields"]) for r in
                  csv.DictReader(open(FIELDS, encoding="utf-8"), delimiter="\t")}
    if len(exp_fields) != 26:
        sys.exit(f"gate: {FIELDS} has {len(exp_fields)} registers, expected 26")
    mismatch = [(f"{k:#x}", len(drv_by_reg.get(k, [])), v) for k, v in sorted(exp_fields.items())
                if len(drv_by_reg.get(k, [])) != v]
    if mismatch:
        sys.exit(f"gate: this tool and §250's artifact disagree on driver field counts for "
                 f"{mismatch[:4]} -- two readings of the same table must match before either is quoted")

    rows, gaps, syn_total, miss_total = [], [], 0, 0
    for r in sorted(exp_fields):
        drv = sorted(drv_by_reg.get(r, []))
        drv_enums = {e for e in (int(x["bf_enum"], 16) for x in driver) if e >> 8 == r}
        # one bit range is spelled several ways inside a single header (DatasheetNames vs BitNames),
        # so the comparison unit is the ENUM, never the name
        ref = collections.defaultdict(set)               # enum -> spellings, in the voted family
        for e, n, f, form in info.get(tfa1, []):
            if e >> 8 == r:
                ref[e].add(n)
        missing = sorted(e for e in ref if e not in drv_enums)
        covered = sorted(e for e in ref if e in drv_enums)
        synonyms = sorted({n for e in covered for n in ref[e]} - {x.strip() for x in drv})
        miss_total += len(missing)
        syn_total += len(synonyms)
        rows.append({"reg": f"{r:#04x}", "n_drv": len(drv), "n_ref_tfa1": len(ref),
                     "missing_bits": len(missing), "synonym_names": len(synonyms),
                     "missing_names": ", ".join(sorted({n for e in missing for n in ref[e]})) or "-",
                     "drv_names": ", ".join(drv) or "-"})
        if not drv:
            gaps.append((f"{r:#04x}", len(missing), len(ref)))
    print(f"name systems      the headers spell one bit range several ways (DatasheetNames vs BitNames); "
          f"comparing by NAME would have called {syn_total} of these synonyms missing -- this table "
          f"counts bit positions ({miss_total} genuinely unnamed by the driver)")
    print(f"registers       {len(rows)} (26-register denominator; driver counts reproduce §250 exactly)")
    for x in rows:
        print(f"   {x['reg']}  driver {x['n_drv']:2}  tfa1 {x['n_ref_tfa1']:2}  missing {x['missing_bits']:2}"
              f"  synonym-names {x['synonym_names']:2}  {x['missing_names'][:70]}")
    print("registers the driver names NOTHING for: " + ", ".join(
        f"{reg} ({miss} bit positions named only by the reference, of {tot} known there)"
        for reg, miss, tot in gaps) or "none")
    if v1 == v2:
        sys.exit("gate: TFA1 and N1C/TFA2 vote the same here -- the family choice is not doing work, "
                 "so the gap column would not depend on §320's verdict")
    if a.selftest:
        naive = sum(max(0, len(ref_names_for(r, info, tfa1))
                        - len({x.strip() for x in drv_by_reg.get(r, [])})) for r in exp_fields)
        if syn_total == 0:
            sys.exit("gate: --selftest: no register has a synonym-only name, so the enum-vs-name "
                     "distinction is not exercised -- this tool's numbers would be indistinguishable "
                     "from the naive name comparison")
        print(f"selftest: name-based comparison would report {naive} gaps vs {miss_total} bit "
              f"positions actually unnamed ({syn_total} synonym names are the difference) -- the enum "
              "rule is load-bearing")
    if a.out:
        cols = ["reg", "n_drv", "n_ref_tfa1", "missing_bits", "synonym_names", "missing_names",
                "drv_names"]
        lines, widths = [], set()
        for x in rows:
            line = [str(x[c]).replace("\n", "\\n") for c in cols]
            if not x["reg"].startswith("0x"):
                sys.exit("gate: a register row lost its address -- shape is not the point, content is")
            widths.add(len(line))
            lines.append("\t".join(line))
        with open(a.out, "w", encoding="utf-8") as fh:
            fh.write("\t".join(cols) + "\n")
            fh.write("\n".join(lines) + "\n")
        if len(widths) != 1:
            sys.exit(f"gate: {a.out} rows disagree on column count {sorted(widths)}")
        print(f"wrote {a.out} ({len(lines) + 1} lines x {next(iter(widths))} columns)")


if __name__ == "__main__":
    main()
