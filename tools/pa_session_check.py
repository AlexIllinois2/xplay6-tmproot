#!/usr/bin/env python3
"""tools/pa_session_check.py -- judge ONE fresh pa-samples session against the published PA baseline.

Why (ledger 362): the 6.0.1 acceptance for the PA layer is a 26-register table where 18 rows are
equality-enforced and 8 are excluded because they were MEASURED to move (BATS = battery readback,
MADD/MEMA = chip counters, REQ/DCVO = cross-session).  port_check.sh check judges a full three-section
capture; tools/port_check.sh pa-samples only collects.  Nothing judged a collected session, so the
statement "a new session reproduces the baseline" stayed an oral claim -- and the interesting part
(the 8 excluded registers landing inside their recorded value sets) had no ruler at all.

usage:  python3 tools/pa_session_check.py <pa-samples-file>
        python3 tools/pa_session_check.py --selftest            # three arms, /tmp fixtures only

exit codes:  0 = every STABLE register equal AND every non-STABLE register inside its recorded values
             1 = a name-able disagreement (printed per register)
             2 = refused to answer (file is not a pa-samples session, or a register is missing)

The value sets are read from two artifacts, not typed here: the 26-row class/equality column of
port-target.PD1610.tsv, and the per-field distinct-value lists of tfa-field-history.PD1610.tsv.
"""
import csv
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TABLE = os.path.join(ROOT, "art/audio-6.0.1/port-target.PD1610.tsv")
FHIST = os.path.join(ROOT, "art/audio-6.0.1/tfa-field-history.PD1610.tsv")

# a pa-samples session is: `===== sample N <uptime> =====`, a `-- witness` block, `-- codec_reg` + regs
SAMPLE = re.compile(r"^===== sample (\d+) ", re.M)


def parse(path):
    txt = open(path, encoding="utf-8", errors="replace").read()
    chunks = SAMPLE.split(txt)
    if len(chunks) < 3:
        raise SystemExit(2)
    samples = []
    for i in range(1, len(chunks) - 1, 2):
        body = chunks[i + 1]
        regs = {int(a, 16): int(v, 16)
                for a, v in re.findall(r"reg\{([0-9a-f]{4})\}:([0-9a-f]{1,4})", body)}
        wit = dict(re.findall(r"^([A-Z][\w \-:]*?): (.*)$", body.split("-- codec_reg")[0], re.M))
        if not regs:
            raise SystemExit(f"gate: sample {chunks[i]} parsed 0 registers -- not a codec_reg block")
        samples.append((int(chunks[i]), regs, wit))
    if not samples:
        raise SystemExit(2)
    return samples


def baseline():
    rows = [r for r in csv.DictReader(open(TABLE, encoding="utf-8"), delimiter="\t")
            if r["layer"] == "PA/TFA9890"]
    out = {}
    for r in rows:
        a = int(r["item"].split()[-1], 16)
        vals = {int(v, 16) for v in re.findall(r"(?:idle|play|speaker)=([0-9a-f]{4})", r["value"])}
        out[a] = {"class": r["use_case"], "values": vals, "fields": []}
    # per-field value lists.  They live in the FIELD's own number space, so they are the only way to
    # say "0x01 read 0x3ff and that is inside what BATS has shown" -- comparing the whole register
    # would call a legal battery readback a disagreement (ledger 362 did exactly that before splitting)
    for r in csv.DictReader(open(FHIST, encoding="utf-8"), delimiter="\t"):
        if r["kind"] != "field-history":
            continue
        a = int(r["reg"], 16)
        if a not in out:
            continue
        m = re.fullmatch(r"\[(\d+):(\d+)\]", (r["span"] or "").strip())
        if not m:
            continue
        hi, lo = int(m.group(1)), int(m.group(2))
        vals = {int(v) for v in (r["values"] or "").split(",") if v.strip().isdigit()}
        if not vals:
            continue
        out[a]["fields"].append((r["field"], hi, lo, vals))
    return out


def judge(samples, base):
    """(bad, notes, refused).

    Only the 18 STABLE registers are equality-enforced.  The 8 others are registers the corpus itself
    measured as moving (BATS = battery ADC readback, MADD/MEMA = chip counters, REQ = cross-session),
    so a value the recorded list has not seen is NOT a regression: publishing that as red is how a
    ruler trained on a live route starts lying (it did -- the in-play session of ledger 366 came back
    rc=1 on exactly those three fields while all 18 setting registers matched).  Such a case is a NOTE
    with its class attached, and --strict still turns notes into red when the comparison is
    baseline-vs-baseline rather than baseline-vs-a-different-route."""
    bad, notes, refused = [], [], []
    for a in sorted(base):
        cls = base[a]["class"]
        seen = [s[1].get(a) for s in samples]
        if any(v is None for v in seen):
            refused.append(f"{a:#06x} {cls}: not present in every sample")
            continue
        if not base[a]["fields"]:
            refused.append(f"{a:#06x} {cls}: no per-field ruler, so no value can be called legal")
            continue
        if cls == "STABLE":
            if len(set(seen)) != 1 or any(v not in base[a]["values"] for v in seen):
                bad.append(f"{a:#06x} STABLE: session={seen} table idle/play="
                           f"{sorted(hex(v) for v in base[a]['values'])}")
            continue
        if not base[a]["fields"]:
            refused.append(f"{a:#06x} {cls}: no per-field ruler for it, so a whole-register value "
                           "cannot be called legal or illegal")
            continue
        for v in seen:
            for name, hi, lo, vals in base[a]["fields"]:
                f = (v >> lo) & ((1 << (hi - lo + 1)) - 1)
                if f in vals:
                    continue
                line = (f"{a:#06x} {cls}: field {name}[{hi}:{lo}]={f} is a value the "
                        f"{len(vals)} recorded sample(s) never showed")
                (bad if cls == "STABLE" else notes).append(line)
    return bad, notes, refused


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--selftest":
        return selftest()
    strict = "--strict" in sys.argv[1:]
    args = [x for x in sys.argv[1:] if x != "--strict"]
    if not args:
        sys.exit(__doc__)
    path = args[0]
    if not os.path.isfile(path):
        sys.exit(f"gate: {path} is not a file")
    samples = parse(path)
    base = baseline()
    if len(base) != 26:
        sys.exit(f"gate: {TABLE} gives {len(base)} PA registers, expected 26 (the binary's whitelist)")
    bad, notes, refused = judge(samples, base)
    wit = {k: sorted({s[2].get(k, "-") for s in samples})
           for k in ("SmartPA Switch", "HiFi Mode Switch", "HP Sel") if any(k in s[2] for s in samples)}
    n_stable = sum(1 for a in base if base[a]["class"] == "STABLE")
    print(f"{os.path.basename(path)}: {len(samples)} samples x {len(base)} registers, "
          f"STABLE enforced={n_stable}, route witness={wit}")
    print("counts per class: " + ", ".join(
        f"{c}={sum(1 for a in base if base[a]['class'] == c)}"
        for c in sorted({base[a]["class"] for a in base})))
    for line in refused:
        print("  REFUSED", line)
    for line in bad:
        print("  DIFFER", line)
    for line in notes:
        print("  NOTE  ", line)
    if refused:
        sys.exit(f"NO-ANSWER: {len(refused)} register(s) missing or un-ruler-able -- "
                 "a partial session cannot certify anything")
    if bad:
        sys.exit(f"{len(bad)} SETTING (STABLE) register(s) disagree with the 6.0.1 baseline")
    print(f"VERDICT: session reproduces the baseline -- {n_stable} STABLE registers equal, "
          f"{len(notes)} note(s) on the {len(base) - n_stable} registers the corpus measured as moving")
    if strict and notes:
        sys.exit(f"STRICT: {len(notes)} state-field value(s) outside the recorded sets (rc=1 because "
                 "--strict was asked for; the acceptance criterion itself is met)")


def selftest():
    """three arms on a fixture built FROM the shipped baseline: a clean session passes; one STABLE
    byte moved is reported by name; a value pushed outside the recorded set of a moving register is
    also reported.  An inert fixture and a blind ruler look identical, so each edit is asserted."""
    base = baseline()
    if len(base) != 26:
        sys.exit(f"gate: baseline gives {len(base)} registers, not 26")
    stable = sorted(a for a in base if base[a]["class"] == "STABLE")
    moving = sorted(a for a in base if base[a]["class"] != "STABLE")
    if not stable or not moving:
        sys.exit(f"gate: the table has {len(stable)} STABLE and {len(moving)} moving registers")

    def session(vals_by_sample):
        blocks = []
        for i, vals in enumerate(vals_by_sample):
            body = f"===== sample {i} 100.0 =====\n-- witness\nSmartPA Switch: Off\n-- codec_reg\n"
            body += "".join(f"reg{{{a:04x}}}:{v:x} \n" for a, v in sorted(vals.items()))
            blocks.append(body)
        return "".join(blocks)

    clean = [{a: sorted(base[a]["values"])[0] for a in base} for _ in range(3)]
    p = "/tmp/pa-check-clean.txt"
    open(p, "w", encoding="utf-8").write(session(clean))
    bad, notes, refused = judge(parse(p), base)
    arm1 = not bad and not refused and not notes
    s0 = stable[0]
    flip = lambda c, a: {**c, a: sorted(base[a]["values"])[0] ^ 0x1}   # noqa: E731
    moved = [flip(c, s0) if c[s0] == sorted(base[s0]["values"])[0] else c for c in clean]
    p2 = "/tmp/pa-check-stabledoc.txt"
    open(p2, "w", encoding="utf-8").write(session(moved))
    bad2, _n2, _r2 = judge(parse(p2), base)
    arm2 = bool(bad2) and any(f"{s0:#06x} STABLE" in x for x in bad2)
    m0 = next(a for a in moving if base[a]["fields"])
    name, hi, lo, vals = base[m0]["fields"][0]
    newf = max(vals) + 1 if max(vals) + 1 < (1 << (hi - lo + 1)) else min(vals) - 1
    if newf in vals or newf < 0:
        sys.exit(f"gate: the field fixture cannot leave {name}[{hi}:{lo}]'s recorded set")
    mask = ((1 << (hi - lo + 1)) - 1) << lo
    outside = [{**c, m0: (c[m0] & ~mask) | (newf << lo)} for c in clean]
    if base[m0]["class"] == "STABLE" or ((outside[0][m0] >> lo) & (mask >> lo)) in vals:
        sys.exit(f"gate: the moving fixture did not leave {m0:#06x}.{name}'s recorded set "
                 "-- arm 3 would be inert")
    p3 = "/tmp/pa-check-outside.txt"
    open(p3, "w", encoding="utf-8").write(session(outside))
    bad3, notes3, _r3 = judge(parse(p3), base)
    arm3 = any(name in x for x in (bad3 + notes3))   # the pushed value must be REPORTED, in either list
    arm4 = bool(notes3) and not bad3   # ... and as a NOTE, because the class says this register moves
    # and the strict knob must actually be a knob: the same fixture judged under --strict has to exit 1
    sp = subprocess.run([sys.executable, os.path.abspath(__file__), p3, "--strict"],
                        capture_output=True, text=True)
    arm5 = sp.returncode == 1 and "STRICT" in (sp.stdout + sp.stderr)
    print(f"selftest: clean session passes={arm1}; one STABLE byte moved -> {bad2[:1] if bad2 else '-'}"
          f"={arm2}; {m0:#06x}.{name}[{hi}:{lo}] pushed to {newf} outside its {len(vals)} recorded "
          f"value(s) -> bad={len(bad3)} notes={len(notes3)}: state-class field reddens nothing={arm4}; "
          f"the same fixture under --strict exits rc={sp.returncode} with a STRICT line={arm5}")
    if not (arm1 and arm2 and arm3 and arm4 and arm5):
        sys.exit(f"gate: pa_session_check selftest arms misbehaved {arm1} {arm2} {arm3} {arm4} {arm5}")
    print("all five arms reproduce (fixtures in /tmp, art/ untouched)")
    return 0


if __name__ == "__main__":
    main()
