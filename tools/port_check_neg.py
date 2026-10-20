#!/usr/bin/env python3
"""tools/port_check_neg.py -- regression controls for the register layers of port_check.sh check.

Why this exists (ledger 285): the gate used to parse reg{...} lines out of the WHOLE capture, and the
ES9038's addresses (0x00-0x2e) are a subset of the TFA9890's, so 47 DAC bytes silently overwrote 12
PA registers.  That reading was then explained as a route precondition instead of traced to the parse,
and the explanation cost a precondition that excused rows it should never have excused.  A fix like
that is only worth anything if the broken shape still fails, so the controls are asserted here.

Base is always a REAL capture (default: newest live/portcheck-*.txt the judge can use), and every
control asserts that it flipped the dimension its verdict depends on.  A–E take the both-chips-powered
capture because D needs the two address spaces to really overlap; K–M take the amp-off capture because
that is the shape 7's speaker route presents (ledger 361).

  A clean capture, both chips powered            -> rc=0 (nothing is excused; PA judged in every route)
  B witness control flipped to its other value   -> rc=0 (no route can switch PA judging off)
  C one STABLE PA register doctored              -> rc=1, names the PA row
  D one DAC register doctored                    -> rc=1 names the DAC row AND NO PA row
                                                   (this is the 285 regression: the old parse made PA
                                                    0x08 read the DAC byte and go red)
  E a section header removed                     -> refuses to judge at all (NO-ANSWER), never a green

  F the §341 derivation on the real artifacts    -> rc=0 and states "predicted == captured"
  G the arm-binding artifact doctored            -> rc=1 quoting "the binding is not a 2x2"
  H the impedance column moved                   -> rc=1 quoting a DIFFERENT predicted byte, so the
                                                   equality gate is what reddens it (not a crash)
  (F/G/H run tools/dac_integration_params.py --derive against doctored copies in /tmp; each fixture
  first asserts that its edit changed bytes, because an inert doctoring and a blind gate look identical)

  I tools/tfa_field_history.py --against, on the REAL 6.0.1 captures -> rc=0, every baseline-stable
    field matching (the plumbing and its denominators are what this certifies)
  J the same ruler against a fixture where every capture pins reg{0046} bits 15:13 to 3 -> rc=1 and the
    line names cs_neghyst here=3 baseline=2, so a setting-bit change on 7 cannot hide behind "some
    registers differ, that is expected" -- the comparison judges 128 fields, not 26 bytes
  (the fixture asserts it moved >= 2 captures, and the NO-ANSWER branch -- a baseline-stable field that
  cannot be read at all -- exits rc=2; tools/tfa_field_history.py --selftest proves that one in-process)

  K the amp-off capture (PA complete, DAC section holds only the driver's own power-off message)
    -> rc=0, DAC prints UNAVAILABLE and PA is still judged: the runbook's step-4 green on 7 must not
      be an excusal
  L one STABLE PA register doctored IN THAT SAME CAPTURE -> rc=1 naming the PA row -- this is the
    permanent regression for §282, where the DAC being off made me invent a route precondition that
    excused 8 PA rows; §285 measured it away and nothing may re-earn it
  M delete only the power-off message line -> rc=1, DAC reads SHORT and never UNAVAILABLE: the excusal
    is earned by that one text line, so a 7 build that words it differently is reported as a truncated
    capture rather than silently excused

Fixtures go to /tmp; nothing under art/ is written, so a fake can never be indexed as a baseline.
Only the table's own verdict is asserted (the "exit codes: table=.." line) and SKIP_DT=1 keeps the
device-tree half out -- a ruler for a ruler should not need a working phone.

usage: python3 tools/port_check_neg.py [capture-file]
"""
import csv
import glob
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TABLE = os.path.join(ROOT, "art/audio-6.0.1/port-target.PD1610.tsv")
GATE = os.path.join(ROOT, "tools/port_check.sh")
PA_REG = "0x08"          # PA register, table value 0x3800
DAC_REG = "0x08"         # same address on the other chip -- deliberately the colliding one


def base_capture():
    fs = sorted(glob.glob(os.path.join(ROOT, "art/audio-6.0.1/live/portcheck-*.txt")),
                key=os.path.getmtime)
    for f in reversed(fs):
        t = open(f, encoding="utf-8", errors="replace").read()
        if "## es9038/reg" in t and "reg{" in t.split("## es9038/reg")[1].split("## controls")[0]:
            return f
    sys.exit("no live/portcheck-*.txt holds BOTH a PA and a DAC section -- control D/E are pointless "
             "without a capture where the two address spaces really do overlap")


def _split(t):
    return (t.split("## tfa98xx/codec_reg")[1].split("## es9038/reg")[0],
            t.split("## es9038/reg")[1].split("## controls")[0],
            t.split("## controls")[1])


def off_capture(want_pa, wit_item=None, wit_on=None):
    """newest REAL capture in the shape 7's speaker route has: the PA dump complete, the DAC dump
    holding nothing but the driver's own power-off message (§235 -- the ES9038 is powered down unless
    the headphone path is up, so most captures and the first one a 7 speaker check produces look like
    this).  64 of the 140 live files have it; picking by mtime alone is what made step 4 unusable
    (ledger 360), hence the same three-section + PA-count test as base_capture."""
    fs = sorted(glob.glob(os.path.join(ROOT, "art/audio-6.0.1/live/portcheck-*.txt")),
                key=os.path.getmtime)
    for f in reversed(fs):
        t = open(f, encoding="utf-8", errors="replace").read()
        if not all(k in t for k in ("## tfa98xx/codec_reg", "## es9038/reg", "## controls")):
            continue
        pa, dac, ctl = _split(t)
        if re.search(r"reg\{", dac) or "is off" not in dac:
            continue
        if len(re.findall(r"^reg\{", pa, re.M)) < want_pa:
            continue
        if wit_item:
            # the shape K/L/M test is amp-OFF as well as DAC-off: a capture taken while the speaker path
            # was live matches the DAC pattern too (the newest 07:36 and 08:36 sessions are exactly that),
            # and doctoring one on it would test a different route than the two cells claim
            m = re.search(re.escape(wit_item) + r"\s+(\S+)", ctl)
            if not m or m.group(1) == wit_on:
                continue
        return f
    sys.exit(f"no live/portcheck-*.txt has the amp-off shape ({want_pa} PA registers plus a DAC section "
             "carrying only the power-off message) -- controls K/L/M are the 7-side speaker route and "
             "cannot be built out of a capture that never had that route")


def run(path, table=TABLE):
    p = subprocess.run(["bash", GATE, "check", "/tmp/portcheck-neg-out.txt"],
                       cwd=ROOT, env={**os.environ, "SKIP_DT": "1", "CAPTURE": path, "TABLE": table},
                       capture_output=True, text=True)
    out = p.stdout + p.stderr
    m = re.search(r"exit codes: table=(-?\d+)", out)
    if m:
        return int(m.group(1)), out
    if "NO-ANSWER" in out or "CAPTURE lacks" in out:
        # refusing to judge is itself the verdict control E asks about; the process code is the answer
        return p.returncode, out
    sys.exit("fixture gate: no 'exit codes: table=' line and no refusal (the run died mid-judgment):\n"
             + out[-400:])


def write(path, text):
    open(path, "w", encoding="utf-8").write(text)
    return path


def main():
    cap = sys.argv[1] if len(sys.argv) > 1 else base_capture()
    txt = open(cap, encoding="utf-8", errors="replace").read()
    rows = list(csv.DictReader(open(TABLE, encoding="utf-8"), delimiter="\t"))
    pa_sec = txt.split("## tfa98xx/codec_reg")[1].split("## es9038/reg")[0]
    dac_sec = txt.split("## es9038/reg")[1].split("## controls")[0]

    # each doctored line must be one the table actually enforces, or the control tests nothing
    def table_val(layer, item):
        r = [x for x in rows if x["layer"] == layer and x["item"] == item]
        if not r:
            sys.exit(f"fixture gate: table has no {item}")
        return r[0]

    pa_row = table_val("PA/TFA9890", f"codec_reg {PA_REG}")
    if pa_row["use_case"] != "STABLE":
        sys.exit(f"fixture gate: {PA_REG} is no longer STABLE ({pa_row['use_case']}) -- pick another")
    dac_row = table_val("DAC/ES9038", f"reg {DAC_REG}")
    pa_live = re.search(r"reg\{0008\}:([0-9a-f]+)", pa_sec)
    dac_live = re.search(r"reg\{8\}:([0-9a-f]+)", dac_sec)
    if not pa_live or not dac_live:
        sys.exit(f"fixture gate: reg 8 not found in both sections of {cap} (PA {pa_live}, DAC {dac_live})")
    pa_new = "0" if pa_live.group(1) != "0" else "1"
    dac_new = "ff" if dac_live.group(1) != "ff" else "fe"

    wit = [r for r in rows if r["layer"] == "ALSA control" and r["use_case"].startswith("WITNESS")]
    if len(wit) != 1:
        sys.exit(f"fixture gate: table holds {len(wit)} WITNESS rows, expected exactly 1")
    item = wit[0]["item"]
    live_w = re.search(re.escape(item) + r"\s+(\S+)", txt.split("## controls")[1])
    if not live_w:
        sys.exit(f"fixture gate: capture has no {item} line")
    others = [v for _, v in re.findall(r"(idle|play|speaker)=(\S+)", wit[0]["value"]) if v != live_w.group(1)]
    if not others:
        sys.exit(f"fixture gate: the table never observed {item} at another value -- control B is empty")
    flip = re.compile(rf"({re.escape(item)})\s+{re.escape(live_w.group(1))}\b")

    pa_bad = write("/tmp/portcheck-neg-pabad.txt",
                   txt.replace(pa_live.group(0),
                               pa_live.group(0).replace(pa_live.group(1), pa_new)))
    if re.search(r"reg\{0008\}:" + pa_new, open(pa_bad, encoding="utf-8").read()) is None:
        sys.exit("fixture gate: control C never moved the PA register")
    dac_bad = write("/tmp/portcheck-neg-dacbad.txt",
                    txt.replace(dac_live.group(0), dac_live.group(0).replace(dac_live.group(1), dac_new)))
    if dac_live.group(0) in open(dac_bad, encoding="utf-8").read():
        sys.exit("fixture gate: control D never moved the DAC register")
    wit_flip = write("/tmp/portcheck-neg-witness.txt", flip.sub(rf"\1 {others[0]}", txt))
    if flip.search(open(wit_flip, encoding="utf-8").read()):
        sys.exit(f"fixture gate: control B never flipped {item}")
    no_head = write("/tmp/portcheck-neg-nohead.txt", txt.replace("## es9038/reg", "## es9038-torn"))
    if "## es9038/reg" in open(no_head, encoding="utf-8").read():
        sys.exit("fixture gate: control E never removed the section header")

    # cells K/L/M: the capture shape ANDROID 7 WILL PRESENT when the speaker route is checked.  Two of
    # step 4's verdicts hinge on text lines a different build may print differently -- the DAC
    # power-off message (it is the ONLY thing that earns DAC/ES9038 = UNAVAILABLE) and the route
    # witness (an earlier version of this gate let the amp-off route excuse PA rows; §285 measured
    # that away).  All three doctorings assert they moved the line the judgement reads.
    exp_pa = sum(1 for r in rows if r["layer"] == "PA/TFA9890")
    wit_cols = dict(re.findall(r"(idle|play|speaker)=(\S+)", wit[0]["value"]))
    off = off_capture(exp_pa, wit_item=item, wit_on=wit_cols["speaker"])
    odt = open(off, encoding="utf-8", errors="replace").read()
    opa, odac, octl = _split(odt)
    oma = re.search(r"^[^\n]*is off[^\n]*\n?", odac, re.M)
    if not oma:
        sys.exit(f"fixture gate: {off} excuses the DAC layer on something off_capture accepted but the "
                 "line regex cannot find -- the excusal and the fixture would disagree about the marker")
    if odt.count(oma.group(0)) != 1:
        sys.exit(f"fixture gate: the power-off message occurs {odt.count(oma.group(0))} times in {off}; "
                 "removing one of them would leave the judge still excused")
    live_off_w = re.search(re.escape(item) + r"\s+(\S+)", octl)
    if not live_off_w:
        sys.exit(f"fixture gate: the amp-off capture has no {item} line")
    if live_off_w.group(1) == wit_cols["speaker"]:
        sys.exit(f"fixture gate: {off} records {item}={wit_cols['speaker']} -- that is the speaker-path "
                 "route; K/L/M exist to test the amp-OFF route §282 mis-read, so pick the other shape")
    opa_live = re.search(r"reg\{0008\}:([0-9a-f]+)", opa)
    if not opa_live:
        sys.exit(f"fixture gate: {off} has no reg{{0008}} in its PA section -- control L has nothing to doctor")
    opa_new = "0" if opa_live.group(1) != "0" else "1"
    off_pa_bad = write("/tmp/portcheck-neg-offpa.txt",
                       odt.replace(opa_live.group(0), opa_live.group(0).replace(opa_live.group(1), opa_new)))
    if re.search(r"reg\{0008\}:" + opa_new, open(off_pa_bad, encoding="utf-8").read()) is None:
        sys.exit("fixture gate: control L never moved the PA register in the amp-off capture")
    off_no_mark = write("/tmp/portcheck-neg-offnomark.txt", odt.replace(oma.group(0), "", 1))
    omt = open(off_no_mark, encoding="utf-8").read()
    if "is off" in _split(omt)[1]:
        sys.exit("fixture gate: control M never removed the power-off message from the DAC section")
    if len(omt) != len(odt) - len(oma.group(0)):
        sys.exit(f"fixture gate: control M deleted {len(odt) - len(omt)} bytes, not the {len(oma.group(0))}"
                 "-byte message line -- it broke the capture elsewhere and SHORT would prove nothing")

    # cells F/G/H: the §341 derivation (--derive) -- its inputs are the arm binding artifact and the
    # impedance column, so doctoring either one must reach the equality gate.  Every fixture first
    # proves it actually moved bytes, otherwise rc=0 would look like "the gate does not bite".
    art = os.path.join(ROOT, "art/audio-6.0.1")
    dip = os.path.join(art, "dac-integration-params.PD1610.tsv")
    di = list(csv.DictReader(open(dip, encoding="utf-8"), delimiter="\t"))
    rows_at = ",".join(sorted({r["name"].split("@")[-1] for r in di if r["kind"] == "alt-table"}))
    bound = [r for r in di if "bound arm:" in (r["verdict"] or "")]
    if len(bound) != 1:
        sys.exit(f"gate: {dip} has {len(bound)} bound-arm rows -- F/G/H need exactly one prediction "
                 "to compare against")
    cands = bound[0]["candidates"].split()
    live_byte, cold_byte = bound[0]["live"], cands[3]
    arms_p = os.path.join(art, "arm64-cfg-arms.PD1610.tsv")
    arms_txt = open(arms_p, encoding="utf-8").read()
    arms_doc = arms_txt.replace("\tintegration_params_normal\t", "\tintegration_params_headphone\t")
    if arms_doc == arms_txt:
        sys.exit("fixture gate: control G's doctoring changed NOT ONE byte of the binding artifact -- "
                 "an inert fixture cannot certify anything")
    arms_bad = write("/tmp/portcheck-neg-arms.tsv", arms_doc)
    imp_p = os.path.join(art, "dac-impedance-chain.PD1610.tsv")
    imp_rows = list(csv.DictReader(open(imp_p, encoding="utf-8"), delimiter="\t"))
    fields = list(imp_rows[0].keys())
    moved = 0
    for r in imp_rows:
        if r["stage"] == "2b" and (r["text"] or "").startswith("live playing-headphones"):
            r["value"] = "3"
            moved += 1
    if moved < 2:
        sys.exit(f"fixture gate: control H found {moved} live impedance rows to move (want 2: both ears)")
    imp_bad = "/tmp/portcheck-neg-imp.tsv"
    with open(imp_bad, "w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=fields, delimiter="\t")
        w.writeheader()
        w.writerows(imp_rows)

    def run_derive(arms_at=None, imp_at=None):
        e = {**os.environ, "SKIP_DT": "1"}
        if arms_at:
            e["DIP_ARMS"] = arms_at
        if imp_at:
            e["DIP_IMP"] = imp_at
        p = subprocess.run([sys.executable, os.path.join(ROOT, "tools", "dac_integration_params.py"),
                            "--derive", "--rows-at", rows_at,
                            "--out", "/tmp/portcheck-neg-derive.tsv"],
                           capture_output=True, text=True, cwd=ROOT, env=e)
        return p.returncode, p.stdout + p.stderr

    FH_BASE = os.path.join(ROOT, "art", "audio-6.0.1", "tfa-field-history.PD1610.tsv")
    LIVE = os.path.join(ROOT, "art", "audio-6.0.1", "live")
    FH_REG, FH_MASK, FH_SET = "0046", 0x7 << 13, 3 << 13

    def run_fh(live_dir):
        q = subprocess.run([sys.executable, os.path.join(ROOT, "tools", "tfa_field_history.py"),
                           "--live", live_dir, "--against", FH_BASE,
                           "--out", "/tmp/portcheck-neg-fields.tsv"],
                           capture_output=True, text=True, cwd=ROOT,
                           env={**os.environ, "SKIP_DT": "1"})
        return q.returncode, q.stdout + q.stderr

    def field_fixture():
        """a '7' that differs by ONE setting bit: every PA capture gets reg{0046} bits 15:13 pinned to 3
        (the baseline reads 2 there, and §330 named that field ctrl_cs_neghyst).  Asserts the mutation
        really moved the line, or the control would be vacuous."""
        d = "/tmp/portcheck-neg-live"
        os.makedirs(d, exist_ok=True)
        n = 0
        for c in sorted(glob.glob(os.path.join(LIVE, "portcheck-*.txt"))):
            t = open(c, encoding="utf-8", errors="replace").read()
            m = re.search(r"^reg\{%s\}:([0-9a-f]+)\s*$" % FH_REG, t, re.M)
            if not m:
                continue
            v = int(m.group(1), 16)
            nv = (v & ~FH_MASK) | FH_SET
            if nv == v:
                continue
            d2 = t[:m.start(1)] + f"{nv:0{len(m.group(1))}x}" + t[m.end(1):]
            with open(os.path.join(d, os.path.basename(c)), "w", encoding="utf-8") as fh:
                fh.write(d2)
            n += 1
        if n < 2:
            sys.exit(f"fixture gate: the field control moved {n} capture(s) (want >= 2) -- cs_neghyst is "
                     "not pinned to the value the baseline records, so control J would prove nothing")
        return d, n

    fails = []

    def check(name, cond, detail):
        print(("  ok    " if cond else "  FAIL  ") + name + " -- " + detail)
        if not cond:
            fails.append(name)

    print(f"base capture: {cap}\n   PA reg{PA_REG} live={pa_live.group(1)} -> doctored {pa_new}; "
          f"DAC reg{DAC_REG} live={dac_live.group(1)} -> doctored {dac_new}; "
          f"witness {item} {live_w.group(1)} -> {others[0]}")

    rc, out = run(cap)
    check("A clean capture judges every layer (no excusal path exists)",
          rc == 0 and "mismatches vs the 6.0.1 table: 0" in out, f"table rc={rc}")
    rc, out = run(wit_flip)
    check("B flipping the route witness does NOT change what is judged",
          rc == 0 and "PA rows not equality-enforced" in out and "NOT enforced" not in out,
          f"table rc={rc}")
    rc, out = run(pa_bad)
    check("C a doctored STABLE PA register goes red",
          rc == 1 and f"PA codec_reg {PA_REG}" in out and f"DAC reg {DAC_REG}" not in out,
          f"table rc={rc}")
    rc, out = run(dac_bad)
    check("D a doctored DAC register reddens ONLY the DAC row (ledger 285 regression)",
          rc == 1 and f"DAC reg {DAC_REG}" in out and f"PA codec_reg {PA_REG}" not in out,
          f"table rc={rc}")
    rc, out = run(no_head)
    check("E a capture with a torn section header refuses to answer",
          rc != 0 and ("NO-ANSWER" in out or "CAPTURE lacks" in out),
          f"table rc={rc}, refused at the " + ("python judge" if "NO-ANSWER" in out else "bash pre-check"))
    rc, out = run_derive()
    check("F the derivation predicts the in-play byte from its four inputs on the real artifacts",
          rc == 0 and "AGREE" in out and f"predicted {live_byte}" in out,
          f"derive rc={rc}; predicts {live_byte} for reg {bound[0]['reg']}")
    rc, out = run_derive(arms_at=arms_bad)
    check("G doctoring the arm binding reddens the derivation",
          rc == 1 and "the binding is not a 2x2" in out,
          f"derive rc={rc}, reason quoted: " + (out.strip().splitlines()[-1][:80] if out.strip() else "-"))
    rc, out = run_derive(imp_at=imp_bad)
    check("H moving the impedance column changes the prediction and the equality gate catches it",
          rc == 1 and f"derived byte {cold_byte}" in out and live_byte in out,
          f"derive rc={rc} (expected column 3 -> {cold_byte} against the captured {live_byte})")

    rc, out = run_fh(LIVE)
    check("I the field-level comparison passes on the real 6.0.1 captures (positive control)",
          rc == 0 and "hold the same value" in out and "RED" not in out,
          "fields rc=%d, " % rc + next((l.strip()[:120] for l in out.splitlines()
                                       if "hold the same value" in l), "-"))
    fixdir, nMoved = field_fixture()
    rc, out = run_fh(fixdir)
    check("J one pinned setting bit on 7 reddens the field comparison and names the field",
          rc == 1 and "cs_neghyst" in out and "here=3 baseline=2" in out,
          f"fields rc={rc}; fixture moved {nMoved} capture(s); "
          + (out.strip().splitlines()[-1][:90] if out.strip() else "-"))

    rc, out = run(off)
    check("K the amp-off capture (7's speaker shape) is judged, not excused",
          rc == 0 and "UNAVAILABLE" in out and "mismatches vs the 6.0.1 table: 0" in out
          and "PA rows not equality-enforced" in out,
          f"table rc={rc}; base {os.path.basename(off)} reads {item}={live_off_w.group(1)}, "
          f"DAC section holds only {oma.group(0).strip()!r}")
    rc, out = run(off_pa_bad)
    check("L a doctored STABLE PA register goes red with the DAC powered off (no route precondition)",
          rc == 1 and f"PA codec_reg {PA_REG}" in out and f"DAC reg {DAC_REG}" not in out
          and "UNAVAILABLE" in out,
          f"table rc={rc}; this is the shape ledger 282 invented a precondition for")
    rc, out = run(off_no_mark)
    dl = next((l.strip() for l in out.splitlines() if l.strip().startswith("DAC/ES9038")), "-")
    check("M delete only the power-off message and the DAC layer reads SHORT, never UNAVAILABLE",
          rc == 1 and "SHORT" in out and "UNAVAILABLE" not in out
          and "mismatches vs the 6.0.1 table: 0" in out
          and re.search(r"PA/TFA9890\s+%d\s+%d\s+OK" % (exp_pa, exp_pa), out),
          f"table rc={rc}; PA is still judged in the same run and the red is only the DAC excusal "
          f"losing its one witness: [{dl}]")

    if fails:
        sys.exit(f"FAIL: {len(fails)} of 13 controls misbehaved: {fails}")
    print("all thirteen controls reproduce (fixtures in /tmp, art/ untouched)")


if __name__ == "__main__":
    main()
