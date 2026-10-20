#!/usr/bin/env python3
"""tools/tfa_field_history.py -- does each NAMED bit field of the SmartPA hold the same value in every
capture we hold, and what does that say about comparing it on Android 7?

§330 named the bits inside the four registers the driver cannot decode (0x46 cs_neghyst, 0x47
switch_fb/se_hyst/se_level/ktemp) and §328/§329 named the rest, but the carry list only ever compared
WHOLE REGISTER bytes.  A whole-byte comparison cannot say which of those bits are a setting the port
must reproduce and which are the chip telling you something -- requiring 7 to reproduce a measurement is
as wrong as ignoring a setting.  This tool answers it from the captures themselves: every field is read
out of every PA session snapshot, and the count of distinct values across sessions is the evidence.

Sections matter (§285): the same file carries the ES9038 block whose addresses 0x00-0x2e are a SUBSET of
the TFA9890's 26, so a parser that reads the whole file silently mixes the two chips.  Only the
`## tfa98xx/codec_reg` section is read here, and --selftest proves the split is load-bearing.

usage: tools/tfa_field_history.py [--out TSV] [--selftest] [--live DIR]
"""
import argparse
import csv
import glob
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ART = os.path.join(ROOT, "art", "audio-6.0.1")
FIELDS_P = os.path.join(ART, "tfa-reg-fields.PD1610.tsv")
GAP_P = os.path.join(ART, "tfa-reg-gap-decode.PD1610.tsv")
REGS_P = os.path.join(ART, "tfa-regs.PD1610.tsv")
PA_HEAD = "## tfa98xx/codec_reg"
ROW = re.compile(r"^reg\{([0-9a-f]{1,6})\}:([0-9a-f]+)\s*$")
SPAN = re.compile(r"^([A-Za-z0-9_/]+)\[(\d+):(\d+)\]$")


def read_fields(path, kind):
    """field groups per register, as (name, msb, lsb) -- spans are written [msb:lsb]"""
    out = {}
    if not os.path.exists(path):
        sys.exit(f"gate: {path} missing -- the field names come from that artifact, they cannot be typed in")
    for r in csv.DictReader(open(path, encoding="utf-8"), delimiter="\t"):
        reg = r["reg"]
        raw = r["bitfields_addr_pos_len"].split() if kind == "driver" else [
            t.strip() for t in r["fields"].split(",")]
        fs = []
        for tok in raw:
            if not tok:
                continue
            m = SPAN.match(tok)
            if not m:
                continue
            name, hi, lo = m.group(1), int(m.group(2)), int(m.group(3))
            fs.append((name, hi, lo))
        if fs:
            out.setdefault(reg, [])
            out[reg].extend(fs)
    return out


def check_spans(fields, src):
    """geometry as a gate: [msb:lsb] must be msb>=lsb and every field must fit in 16 bits.  Overlapping
    spans are NOT rejected: the driver's own table names a wide field and a narrow one over the same
    bits (the alias shape of §330), so they are counted and reported instead.  Reversed spans are what
    this catches, and --selftest proves it by swapping every pair."""
    overlaps = []
    for reg, fs in fields.items():
        seen = {}
        for name, hi, lo in fs:
            if hi < lo:
                sys.exit(f"gate: {src} {reg} field {name}[{hi}:{lo}] has msb below lsb -- the span order "
                         "this tool assumes is [msb:lsb]; a reversed reading would extract different bits")
            if hi > 15:
                sys.exit(f"gate: {src} {reg} field {name} reaches bit {hi} which a 16-bit register lacks")
            for b in range(lo, hi + 1):
                if b in seen:
                    overlaps.append(f"{reg} bit {b}: {seen[b]} / {name}")
                seen[b] = name
    return overlaps


def pa_sections(path):
    """the PA register map of ONE capture, PA section only"""
    txt = open(path, encoding="utf-8", errors="replace").read()
    i = txt.find(PA_HEAD)
    if i < 0:
        return {}
    tail = txt[i + len(PA_HEAD):]
    nxt = re.search(r"^## ", tail, re.M)
    tail = tail[:nxt.start()] if nxt else tail
    out = {}
    for line in tail.splitlines():
        m = ROW.match(line.strip())
        if m:
            out["0x" + m.group(1).lstrip("0").rjust(2, "0") if m.group(1).strip("0") else "0x00"] = \
                int(m.group(2), 16)
    return out


def all_sections(path):
    """the NAIVE whole-file parse: every reg{} line, sections ignored, LATER lines overwrite earlier
    ones.  This is the shape of the §285 bug (the ES9038 block is dumped after the PA block and its
    addresses 0x00-0x2e are a subset of the PA's), so it is used only by the control that shows the
    section split is load-bearing"""
    out = {}
    for line in open(path, encoding="utf-8", errors="replace"):
        m = ROW.match(line.strip())
        if m:
            key = "0x" + (m.group(1).lstrip("0").rjust(2, "0") if m.group(1).strip("0") else "00")
            out[key] = int(m.group(2), 16)
    return out


def field_value(raw, hi, lo):
    return (raw >> lo) & ((1 << (hi - lo + 1)) - 1)


def against(baseline_path, rows):
    """§349: compare this corpus against a baseline field-history artifact (the 6.0.1 table) at FIELD
    level.  Only fields the baseline itself calls stable are judged -- a field that varies in 6.0.1 has no
    expected value, and asking 7 for one would be a false red.  `absent` (a baseline-stable field this
    corpus cannot even decode) is kept separate from `match` so the answer cannot read greener than it is."""
    base = [r for r in csv.DictReader(open(baseline_path, encoding="utf-8"), delimiter="\t")
            if r["kind"] == "field-history"]
    mine = {(r["reg"], r["field"], r["span"], r["source"]): r for r in rows}
    c = {"stable": 0, "match": 0, "differ": [], "varies_here": [], "absent": [], "not_judged": 0}
    for b in base:
        if str(b["distinct"]) != "1":
            c["not_judged"] += 1
            continue
        c["stable"] += 1
        k = (b["reg"], b["field"], b["span"], b["source"])
        if k not in mine:
            c["absent"].append(f"{b['reg']} {b['field']}{b['span']}")
            continue
        m = mine[k]
        if str(m["distinct"]) != "1":
            c["varies_here"].append(f"{b['reg']} {b['field']}{b['span']} reads {m['values']} here, "
                                    f"baseline {b['values']}")
            continue
        if m["values"] == b["values"]:
            c["match"] += 1
        else:
            c["differ"].append(f"{b['reg']} {b['field']}{b['span']} here={m['values']} "
                               f"baseline={b['values']}")
    c["baseline_fields"] = len(base)
    return c


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out")
    ap.add_argument("--live", default=os.path.join(ART, "live"))
    ap.add_argument("--against", help="baseline field-history .tsv to compare this corpus against (art/audio-6.0.1/tfa-field-history.PD1610.tsv is the 6.0.1 one)")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    drv = read_fields(FIELDS_P, "driver")
    ref = read_fields(GAP_P, "ref")
    ov_drv = check_spans(drv, FIELDS_P)
    ov_ref = check_spans(ref, GAP_P)
    if not os.path.exists(REGS_P):
        sys.exit(f"gate: {REGS_P} missing -- the register denominator (26) comes from that table")
    want = [r["reg"] for r in csv.DictReader(open(REGS_P, encoding="utf-8"), delimiter="\t")]
    cls = {r["reg"]: r["class"] for r in csv.DictReader(open(REGS_P, encoding="utf-8"), delimiter="\t")}
    caps = sorted(glob.glob(os.path.join(a.live, "portcheck-*.txt")), key=os.path.getmtime)
    snaps = []
    for c in caps:
        s = pa_sections(c)
        if s and len(s) == len(want):
            snaps.append((os.path.basename(c), c, s))
    if len(snaps) < 2:
        sys.exit(f"gate: only {len(snaps)} of {len(caps)} captures hold a full PA section ({len(want)} "
                 "registers) -- distinct-value counts need at least two sessions")
    overlap = set(drv) & set(ref)
    print(f"alias spans     driver table: {len(ov_drv)} overlapping bit claims over "
          f"{len({o.split()[0] for o in ov_drv})} register(s); reference table: {len(ov_ref)} over "
          f"{len({o.split()[0] for o in ov_ref})} -- the driver names a wide field and a narrow one on "
          "the same bits (§330's alias shape), so these are extracted separately and NOT merged")
    print(f"fields          driver-named {sum(len(v) for v in drv.values())} over {len(drv)} registers; "
          f"reference-named {sum(len(v) for v in ref.values())} over {len(ref)}; registers named by "
          f"BOTH: {sorted(overlap) or 'none'}")
    print(f"captures        {len(snaps)} of {len(caps)} portcheck files carry exactly the {len(want)} PA "
          f"registers (section-split parse; whole-file parsing would mix the ES9038 block)")
    rows = []
    for src, fields in (("driver", drv), ("reference", ref)):
        for reg in sorted(fields, key=lambda x: int(x, 16)):
            for name, hi, lo in fields[reg]:
                vals = {}
                for cap, _path, snap in snaps:
                    v = field_value(snap[reg], hi, lo) if reg in snap else None
                    vals.setdefault(v, []).append(cap)
                distinct = sorted({v for v in vals if v is not None})
                stable = len(distinct) == 1
                rows.append({
                    "kind": "field-history", "reg": reg, "field": name, "span": f"[{hi}:{lo}]",
                    "source": src, "sessions": len(snaps), "distinct": len(distinct),
                    "values": ",".join(str(v) for v in distinct) or "-",
                    "class": cls.get(reg, "?"),
                    "verdict": (f"same value in all {len(snaps)} sessions -> a value 7 must reproduce "
                                "(setting-shaped)" if stable else
                                f"takes {len(distinct)} values across sessions -> chip-side/state, "
                                "comparing it on 7 as a setting would be wrong")})
    for r in rows:
        if r["field"].split("/")[-1] in ("ktemp", "se_level", "switch_fb", "ctrl_cs_neghyst"):
            print(f"  {r['reg']} {r['field']}{r['span']} ({r['source']}) sessions={r['sessions']} "
                  f"distinct={r['distinct']} values=[{r['values']}] class={r['class']}")
    n_stable = sum(1 for r in rows if r["distinct"] == 1)
    # §348: collide this field-level view with §283's register-level classes (a DIFFERENT
    # instrument: whole-byte comparison across sessions).  Agreement is a cross-witness; a
    # disagreement is published as such, never smoothed.
    varying_regs = {r["reg"] for r in rows if r["distinct"] != 1}
    covered = {r["reg"] for r in rows}
    cross = []
    for reg in sorted(covered, key=lambda x: int(x, 16)):
        field_says = "state" if reg in varying_regs else "setting"
        reg_says = cls.get(reg, "?")
        ok = (field_says == "setting") == (reg_says == "STABLE")
        cross.append({"kind": "class-cross", "reg": reg, "field": f"{len([r for r in rows if r['reg'] == reg])} fields",
                      "span": "-", "source": "cross-check", "sessions": len(snaps),
                      "distinct": "-", "values": "-", "class": reg_says,
                      "verdict": (("AGREES: " if ok else "DISAGREES: ")
                                  + f"register class {reg_says} vs fields say {field_says}"
                                  + ("" if ok else " -- two instruments disagree, name it, do not pick one"))})
    n_agree = sum(1 for c in cross if c["verdict"].startswith("AGREES"))
    print(f"class cross      {len(cross)} registers carry named fields: {n_agree} AGREE with §283's "
          f"register-level class, {len(cross) - n_agree} DISAGREE "
          f"(cross = {', '.join(c['reg'] for c in cross if c['verdict'].startswith('DISAGREE')) or 'none'}); "
          f"{len([r for r in want if r not in covered])} of {len(want)} registers carry NO named field and "
          "are not comparable here")
    if len(cross) < 15:
        sys.exit(f"gate: only {len(cross)} of {len(want)} PA registers carry a named field -- the "
                 "cross-check would be comparing a minority of the register set, so its agreement means "
                 "nothing")
    rows += cross
    n_field_rows = len([r for r in rows if r["kind"] == "field-history"])
    print(f"summary         {n_field_rows} named fields over {len(snaps)} sessions: {n_stable} reproduce the "
          f"same value every session, {n_field_rows - n_stable} do not")
    if a.against:
        c = against(a.against, [r for r in rows if r["kind"] == "field-history"])
        print(f"against         {a.against}: baseline names {c['baseline_fields']} fields, {c['stable']} "
              f"stable there and therefore judged, {c['not_judged']} vary in the baseline and are NOT "
              f"compared; this corpus: {c['match']} match, {len(c['differ'])} differ, "
              f"{len(c['varies_here'])} stable-there-but-varying-here, {len(c['absent'])} not decodable")
        for line in (c["differ"] + c["varies_here"])[:40]:
            print(f"  RED            {line}")
        for line in c["absent"][:40]:
            print(f"  NO-ANSWER      {line}")
        if c["absent"]:
            print(f"NO-ANSWER: {len(c['absent'])} baseline-stable field(s) cannot be read from this corpus "
                  "(register absent or bit-field not named) -- rc=2, never a pass")
            raise SystemExit(2)
        if c["differ"] or c["varies_here"]:
            sys.exit(f"gate: {len(c['differ'])} field(s) differ from the baseline and "
                     f"{len(c['varies_here'])} are stable in the baseline yet vary here -- a settings-level "
                     "difference on the audible path, name each one")
        print(f"against         {c['match']} of {c['stable']} baseline-stable fields hold the same value")
    if a.selftest:
        bad = [r for r in rows if r["distinct"] == 1 and r["sessions"] < 2]
        if bad:
            sys.exit(f"gate: --selftest: {len(bad)} fields called stable on fewer than two sessions")
        two = None
        for cand in sorted(glob.glob(os.path.join(a.live, "*.txt"))):
            t = open(cand, encoding="utf-8", errors="replace").read()
            if PA_HEAD in t and "## es9038/reg" in t and len(all_sections(cand)) > len(want) + 20:
                two = cand
                break
        if two is None:
            sys.exit("gate: --selftest: no capture under " + a.live + " holds BOTH a full PA section and "
                     "the ES9038 block -- the §285 cross-section control cannot run, so the PA-only "
                     "parse is unproven here (the portcheck files carry an empty DAC section)")
        pas = pa_sections(two)
        whole = all_sections(two)
        mixed = sum(1 for reg in want if reg in whole and reg in drv
                    and any(field_value(whole[reg], hi, lo) != field_value(pas[reg], hi, lo)
                            for name, hi, lo in drv[reg]))
        if mixed == 0:
            sys.exit(f"gate: --selftest: the naive whole-file (last-wins) parse moves no field value in "
                     f"{os.path.basename(two)} -- then the §285 section split is not load-bearing here and "
                     "this control proves nothing")
        print(f"selftest: in {os.path.basename(two)} the naive whole-file parse moves {mixed} of "
              f"{len(want)} registers to a different field value -- the PA-only parse is load-bearing "
              "(ledger 285)")
        rev = {reg: [(n, lo, hi) for n, hi, lo in fs] for reg, fs in drv.items()}
        try:
            check_spans(rev, "reversed-span control")
        except SystemExit as e:
            print(f"selftest: reversing the span order aborts -> {str(e)[:110]}")
        else:
            sys.exit("gate: --selftest: the span-geometry gate accepts a reversed [lsb:msb] reading -- "
                     "it cannot certify the extraction")
        frows = [r for r in rows if r["kind"] == "field-history"]
        base = os.path.join(ART, "tfa-field-history.PD1610.tsv")
        if not os.path.exists(base):
            sys.exit(f"gate: --selftest: no baseline artifact at {base} -- the field-level comparison arm "
                     "IS the 7-side judgement, so it has to be provable red here")
        c0 = against(base, frows)
        if c0["differ"] or c0["varies_here"] or c0["absent"]:
            sys.exit(f"gate: --selftest: the shipped 6.0.1 baseline compared against 6.0.1 captures is not "
                     f"clean (differ={len(c0['differ'])} varies={len(c0['varies_here'])} "
                     f"absent={len(c0['absent'])}) -- the comparison arm itself is wrong")
        if not c0["stable"] or c0["match"] != c0["stable"]:
            sys.exit(f"gate: --selftest: {c0['match']} of {c0['stable']} judged fields matched -- the "
                     "positive control has to be total or it certifies nothing")
        pick = next((i for i, r in enumerate(frows)
                     if str(r["distinct"]) == "1" and r["values"] not in ("-", "")), None)
        if pick is None:
            sys.exit("gate: --selftest: no stable field carries a readable value -- the red fixture "
                     "cannot be built")
        moved = [dict(r) for r in frows]
        moved[pick]["values"] = str(int(moved[pick]["values"]) + 1)
        c1 = against(base, moved)
        if len(c1["differ"]) != 1 or frows[pick]["reg"] not in c1["differ"][0]:
            sys.exit(f"gate: --selftest: bumping one stable field value gives differ="
                     f"{len(c1['differ'])} {c1['differ'][:1]} -- a real tuning change would pass unseen")
        dropped = [dict(r) for i, r in enumerate(frows) if i != pick]
        c2 = against(base, dropped)
        if len(c2["absent"]) != 1 or c2["match"] != c0["match"] - 1:
            sys.exit(f"gate: --selftest: dropping one corpus field gives absent={len(c2['absent'])} "
                     f"match={c2['match']} (expected 1 / {c0['match'] - 1}) -- a field that could not be "
                     "read would still be counted as agreement")
        print(f"selftest: --against compares {c0['stable']} baseline-stable fields and refuses the "
              f"{c0['baseline_fields'] - c0['stable']} that vary in the baseline; clean corpus matches "
              f"{c0['match']}/{c0['stable']}, one bumped value -> 1 DIFFER at {frows[pick]['reg']}, one "
              f"unread field -> 1 NO-ANSWER")
    if a.out:
        cols = ["kind", "reg", "field", "span", "source", "sessions", "distinct", "values", "class",
                "verdict"]
        widths = {len(cols)}
        with open(a.out, "w", encoding="utf-8") as fh:
            fh.write("\t".join(cols) + "\n")
            for r in rows:
                line = "\t".join(str(r[c]) for c in cols)
                if len(line.split("\t")) != len(cols):
                    sys.exit("gate: a row does not have the declared column count")
                fh.write(line + "\n")
        print(f"wrote {a.out} ({len(rows)} rows x {len(cols)} columns)")


if __name__ == "__main__":
    main()
