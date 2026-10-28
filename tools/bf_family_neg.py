import importlib.util
import os
import shutil
import subprocess
import sys

ROOT = "/home/v/.local/project/xplay6"
ART = f"{ROOT}/art/audio-6.0.1"
NAME = "tfa-bf-family.TfaBfNames.tsv"
spec = importlib.util.spec_from_file_location("pm", "/home/v/.local/project/xplay6/xplay6-tmproot/tools/port_manifest.py")
pm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pm)

tspec = importlib.util.spec_from_file_location("tb", f"{ROOT}/tools/tfa_bf_family.py")
tb = importlib.util.module_from_spec(tspec)
tspec.loader.exec_module(tb)
fam = tb.families()


def call(tmp):
    pm.BASE = ART if tmp is None else tmp
    try:
        return ("string", pm.bf_family_sentence())
    except SystemExit as e:
        return ("abort", str(e))


def mut_drop(lines):
    keep = [l for l in lines if "\tN1C/TFA2-no-addr-ballot\t" not in l]
    assert len(keep) < len(lines), "the row I tried to drop was not there -- control did not move the arm"
    lines[:] = keep


def mut_denom(lines):
    n = 0
    for i, l in enumerate(lines):
        if l.startswith("0x10-0x3f\t"):
            f = l.split("\t")
            f[3] = "101"
            lines[i] = "\t".join(f)
            n += 1
    assert n >= 2, f"expected several rows in that bucket, moved {n}"


def mut_empty(lines):
    lines[:] = lines[:1]


def mut_zero_tfa1(lines):
    n = 0
    for i, l in enumerate(lines):
        if "\tTFA1-total\t" in l:
            f = l.split("\t")
            f[2] = "0"
            lines[i] = "\t".join(f)
            n += 1
    assert n == 1


shutil.rmtree("/tmp/bfneg", ignore_errors=True)
muts = {"no-loosened-row": mut_drop, "bucket-denominator": mut_denom, "header-only": mut_empty,
        "tfa1-total-zero": mut_zero_tfa1}
for label, mut in muts.items():
    d = f"/tmp/bfneg/{label}"
    os.makedirs(d)
    lines = open(f"{ART}/{NAME}", encoding="utf-8").read().splitlines()
    mut(lines)
    open(f"{d}/{NAME}", "w", encoding="utf-8").write("\n".join(lines) + "\n")

kind, clean = call(None)
print("[clean] ->", kind)
print("   ", clean)
pm.BASE = "/tmp/bfneg/absent"
kind, miss = call("/tmp/bfneg/absent")
print("[file-absent] ->", kind, "|", miss[:90])

fails = []
for need in ("167/220", "lifts N1C to 39", "45/102", "43 of them", "TFA1-numbered"):
    if need not in clean:
        fails.append(f"positive sentence lost {need!r}")
if "MISSING" not in miss:
    fails.append("file-absent arm did not report MISSING")
for label, _m in muts.items():
    k, o = call(f"/tmp/bfneg/{label}")
    print(f"[{label}] -> {k} | {o[:150]}")
    if k != "abort":
        fails.append(f"{label} did not abort")

# the tool's own padded-name gate, driven from this script so the claim in the table row is executable:
# doctor one STRICTLY-matching driver row by adding a trailing space to its name -- the vote must refuse
# rather than silently move that row into the residue.
drv = open(f"{ART}/tfa-bf.TfaBfNames.tsv", encoding="utf-8").read().splitlines()
pick = None
for i, line in enumerate(drv[1:], start=1):
    ad, p, ln, en, nm = line.split("\t")
    if any((nm, int(ad, 16), int(p), int(ln)) in v for v in fam.values()):
        drv[i] = "\t".join([ad, p, ln, en, nm + " "])
        pick = (i, nm)
        break
if pick is None:
    fails.append("no strictly-matching row available to doctor -- the padded arm had nothing to test")
else:
    d = "/tmp/bfneg/padded-driver"
    os.makedirs(d, exist_ok=True)
    open(f"{d}/tfa-bf-doctored.tsv", "w", encoding="utf-8").write("\n".join(drv) + "\n")
    open(f"{d}/tfa-bf-copy.tsv", "w", encoding="utf-8").write("\n".join(
        open(f"{ART}/tfa-bf.TfaBfNames.tsv", encoding="utf-8").read().splitlines()) + "\n")

    def vote(path):
        r = subprocess.run([sys.executable, f"{ROOT}/tools/tfa_bf_family.py", "--tsv", path],
                           capture_output=True, text=True)
        out = (r.stdout + r.stderr).strip().splitlines()
        return r.returncode, (out[-1] if out else "")

    rc0, t0 = vote(f"{d}/tfa-bf-copy.tsv")
    print(f"[padded-arm positive: the same file UNDOCTORED] -> rc={rc0} | {t0[:110]}")
    if rc0 != 0:
        fails.append(f"the un-doctored copy itself failed (rc={rc0}) -- padded-arm rc=1 would prove nothing")
    rc, t = vote(f"{d}/tfa-bf-doctored.tsv")
    print(f"[padded-driver-name on row {pick[1]!r}] -> rc={rc} | {t[:130]}")
    if rc == 0:
        fails.append("the padded-name arm passed -- the whitespace gate is not firing")

print("\nverdict:", "ALL ARMS BEHAVE" if not fails else "SOME ARM WRONG -> " + "; ".join(fails))
sys.exit(0 if not fails else 1)
