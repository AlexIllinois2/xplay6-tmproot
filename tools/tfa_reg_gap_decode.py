#!/usr/bin/env python3
"""tools/tfa_reg_gap_decode.py -- read the live value of the registers §250 could not name anything for.

§329 established that the driver's TfaBfNames table is TRIMMED: the reference tree names 60 bit
positions the driver's table omits.  Four registers get nothing from the driver at all, and the one
that matters is 0x47: the live dump prints a value for it (0x7be1, identical across every idle and
playing sample), the register-name table calls it NO-NAME, and the genregs macro header names no
field for it either -- so the ONLY names available for those 16 bits come from the per-chip field
tables (tfa1_tfafieldnames.h and tfa9890_tfafieldnames.h, which agree bit for bit).

What has to be true before a decoded field is worth printing:
  * the number being decoded is read twice -- from the 26-register artifact AND from the raw debugfs
    capture this session's port_check.sh left behind -- and the two must agree per register;
  * at least two reference headers must place the field at the same (pos,len); a single header's
    opinion is a hypothesis, not a reading;
  * the fields must TILE bits 0..15 without overlap: if they do, the register has no unnamed remainder
    left, which is what turns "we guess these are the fields" into "these 16 bits are fully described";
  * the genregs header is queried too, because its absence is the reason the driver printed NO-NAME --
    the tool reports that as the cause rather than leaving it as an unexplained blank.

usage: tools/tfa_reg_gap_decode.py [--out TSV] [--selftest] [--capture PATH]
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
FIELDS = os.path.join(ART, "tfa-reg-fields.PD1610.tsv")
REGS = os.path.join(ART, "tfa-regs.PD1610.tsv")
REF = os.environ.get("TFA_REF", os.path.join(ROOT, "fw", "tfa-ref", "inc"))
GENREGS = os.path.join(REF, "tfa98xx_genregs_N1C.h")
CAP = os.environ.get("TFA_CAP", max(
    (os.path.join(ART, "live", f) for f in os.listdir(os.path.join(ART, "live"))
     if f.startswith("portcheck-") and f.endswith(".txt")), key=os.path.getmtime))
WITNESS_HEADERS = ("tfa1_tfafieldnames.h", "tfa9890_tfafieldnames.h")


def sha16(p):
    return hashlib.sha256(open(p, "rb").read()).hexdigest()[:16]


def load_resolver():
    spec = importlib.util.spec_from_file_location("tfa_bf_name_resolve",
                                                  os.path.join(HERE, "tfa_bf_name_resolve.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def genregs_fields(reg):
    """TFA98XX_<REGNAME>_<FIELD>_POS / _LEN macro pairs from the genregs header -- the table the
    driver's register-name path reads.  Returns the field names it declares for a register ADDRESS
    (the macros key on the register's NAME, so the name->address map from the same header is used;
    field-mask defines carry short hex values too and must be excluded from that map)."""
    if not os.path.exists(GENREGS):
        return []
    text = open(GENREGS, encoding="utf-8", errors="replace").read()
    addr_of = {}
    for name, val in re.findall(r"^#define\s+(TFA98XX_\w+)\s+(0x[0-9a-fA-F]{1,2})\s*$", text, re.M):
        base = name[len("TFA98XX_"):]
        if re.search(r"_(MSK|POS|LEN|MAX)$", base):
            continue
        addr_of[base] = int(val, 16)
    pos, ln = collections.defaultdict(dict), collections.defaultdict(dict)
    for name, val in re.findall(r"^#define\s+(\w+)\s+([^\s/].*?)\s*$", text, re.M):
        m = re.fullmatch(r"TFA98XX_(\w+?)_([A-Z0-9]+)_(POS|LEN)", name)
        if not m or m.group(1) not in addr_of:
            continue
        (pos if m.group(3) == "POS" else ln)[m.group(1)][m.group(2)] = int(val, 0)
    out = []
    for base, a in addr_of.items():
        if a == reg:
            out += sorted(f for f in pos[base] if f in ln[base])
    return sorted(set(out))


def capture_values(path):
    txt = open(path, encoding="utf-8", errors="replace").read()
    sec = txt.split("## tfa98xx/codec_reg")[1].split("##")[0]
    out = {}
    for reg, val in re.findall(r"reg\{([0-9a-f]{4})\}:([0-9a-f]+)", sec):
        out[int(reg, 16) & 0xff] = int(val, 16)
    if len(out) < 20:
        sys.exit(f"gate: the capture {path} yielded {len(out)} codec_reg lines -- a PA reading has to be "
                 "complete before its bits may be decoded from it")
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--capture", default=CAP)
    a = ap.parse_args()
    rsv = load_resolver()
    info, per_chip, conflicts = rsv.load_headers(REF)
    if conflicts:
        sys.exit(f"gate: {len(conflicts)} reference fields disagree with themselves on bit position")
    drv_fields = {int(r["reg"], 16): int(r["nfields"]) for r in
                  csv.DictReader(open(FIELDS, encoding="utf-8"), delimiter="\t")}
    unnamed = sorted(r for r, n in drv_fields.items() if n == 0)
    if not unnamed:
        sys.exit(f"gate: {FIELDS} names a field for every register -- nothing to decode, so this run "
                 "would publish an empty answer")
    live = {int(r["reg"], 16): (int(r["idle"], 16), int(r["play"], 16), r["class"], r["name"])
            for r in csv.DictReader(open(REGS, encoding="utf-8"), delimiter="\t")
            if re.fullmatch(r"[0-9a-f]{4}", r["idle"] or "")}
    cap = capture_values(a.capture)
    print(f"inputs          live values {REGS} [{sha16(REGS)}]; raw capture {a.capture} "
          f"[{sha16(a.capture)}]; reference {REF}; genregs {GENREGS} [{sha16(GENREGS)}]")
    rows = []
    for reg in unnamed:
        if reg not in live:
            sys.exit(f"gate: register {reg:#04x} has no driver fields but no live value either -- the "
                     "26-register denominator and the field table do not cover the same set")
        idle, play, cls, rname = live[reg]
        if cap.get(reg) not in (idle, play):
            sys.exit(f"gate: register {reg:#04x}: the artifact says idle/play {idle:#04x}/{play:#04x} "
                     f"but the raw capture says {cap.get(reg):#04x} -- the number to decode is not "
                     "agreed between the two readings")
        # group by bit range, not by name: the newer headers spell the SAME bit twice (ISTADCCR and
        # int_out_flag_adc10_ready are both bit 14 of INTERRUPT_OUT_REG1), so a "field" is a (pos,len)
        # with a set of synonyms.  Overlapping DIFFERENT ranges is the case that must not happen.
        groups = collections.defaultdict(collections.Counter)   # (pos,len) -> header -> names
        names = collections.defaultdict(set)                    # (pos,len) -> synonyms
        for h, entries in info.items():
            for e, n, f, form in entries:
                if e >> 8 != reg:
                    continue
                pl = ((e >> 4) & 0xF, (e & 0xF) + 1)
                groups[pl][h] += 1
                names[pl].add(n)
        if not groups:
            sys.exit(f"gate: no reference header names a single field at {reg:#04x}, yet §329 counted "
                     "gaps there -- the two tools read the reference tree differently, stop")
        # a whole-register alias (tfa1's hid_code spans 0..15 while N1C names each bit) legitimately
        # CONTAINS other groups; only a PARTIAL overlap between two groups is ambiguous
        def contains(a, b):
            return a[0] <= b[0] and a[0] + a[1] >= b[0] + b[1]
        narrow = [pl for pl in groups
                  if not any(pl != other and contains(pl, other) for other in groups)]
        aliases = sorted(set(groups) - set(narrow))
        for i, (p, w) in enumerate(sorted(narrow)):
            for q, v in sorted(narrow)[i + 1:]:
                if set(range(p, p + w)) & set(range(q, q + v)):
                    sys.exit(f"gate: {reg:#04x} has partially overlapping bit groups {[p, p + w - 1]} "
                             f"and {[q, q + v - 1]} -- the reference tables conflict and a decode would "
                             "be a coin flip")
        covered = set()
        tiles = []
        for (p, w) in sorted(narrow):
            covered |= set(range(p, p + w))
            tiles.append((p, w, "/".join(sorted(names[(p, w)])),
                          (idle >> p) & ((1 << w) - 1), (play >> p) & ((1 << w) - 1),
                          len(groups[(p, w)])))
        alias_txt = ", ".join(f"{n}[{p + w - 1}:{p}]" for p, w in sorted(aliases)
                              for n in sorted(names[(p, w)])) or "-"
        two = sum(1 for t in tiles if t[5] >= 2)
        witness = (f"{two}/{len(tiles)} bit groups placed identically by >=2 of the {len(info)} headers"
                   if two else "single-header only -- a hypothesis, not a reading")
        rows.append({"reg": f"{reg:#04x}", "value": f"{idle:#04x}", "class": cls, "reg_name": rname,
                     "n_named": len(tiles),
                     "fields": ", ".join(f"{n}[{q + w - 1}:{q}]" for q, w, n, _i, _p, _h in tiles),
                     "coverage": len(covered), "witness": witness, "two_witness": two, "aliases": alias_txt,
                     "genregs": ", ".join(genregs_fields(reg)) or "no entry (the reason for NO-NAME)",
                     "decode": "; ".join(f"{n}={v}" for _q, _w, n, v, _p, _h in tiles),
                     "same": "idle==playing on every bit group"
                     if all(v == q for _i2, _w2, _n2, v, q, _h2 in tiles) else "idle and playing differ"})
        print(f"   {rows[-1]['reg']}  value {rows[-1]['value']}  class {cls}  name {rname}")
        print(f"      tiling: {rows[-1]['fields']}  covers {len(covered)}/16 bits  "
              f"[{rows[-1]['witness']}]")
        print(f"      decode: {rows[-1]['decode']}")
        print(f"      genregs macro table: {rows[-1]['genregs']}")
    full = [r for r in rows if r["coverage"] == 16]
    two = [r for r in rows if r["two_witness"] == r["n_named"] and r["coverage"] == 16]
    print(f"summary         {len(rows)} registers with no driver field names; "
          f"{len(full)} tiled across all 16 bits; {len(two)} of those with EVERY field placed by a second header")
    if a.selftest:
        one = [r for r in rows if r["two_witness"] and r["coverage"] == 16]
        if not one:
            sys.exit("gate: --selftest: no register is witnessed by two headers, so the agreement "
                     "requirement was never exercised and 'agree' means nothing here")
        print(f"selftest: {len(one)} register(s) rest on two headers placing every field identically; "
              "dropping the second header would leave the decode with one witness and the gate above "
              "would stop the run")
    if a.out:
        cols = ["reg", "value", "class", "reg_name", "fields", "coverage", "two_witness",
                "witness", "aliases", "genregs", "decode", "same"]
        lines, widths = [], set()
        for x in rows:
            line = [str(x[c]).replace("\n", "\\n") for c in cols]
            if x["reg"] == "-" or x["value"] == "-":
                sys.exit("gate: a decode row lost its address or value")
            widths.add(len(line))
            lines.append("\t".join(line))
        cap_row = ["CAPTURE", a.capture, sha16(a.capture), "-", "-", str(len(rows)), "-", "-", "-",
                   f"{len(full)} registers fully tiled", "-", "-"]
        if len(cap_row) != len(cols):
            sys.exit(f"gate: the CAPTURE row has {len(cap_row)} fields but the table has {len(cols)}")
        lines.append("\t".join(cap_row))
        widths.add(len(cap_row))
        with open(a.out, "w", encoding="utf-8") as fh:
            fh.write("\t".join(cols) + "\n")
            fh.write("\n".join(lines) + "\n")
        if len(widths) != 1:
            sys.exit(f"gate: {a.out} rows disagree on column count {sorted(widths)}")
        print(f"wrote {a.out} ({len(lines) + 1} lines x {next(iter(widths))} columns)")


if __name__ == "__main__":
    main()
