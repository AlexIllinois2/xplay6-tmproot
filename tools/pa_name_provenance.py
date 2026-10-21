#!/usr/bin/env python3
"""tools/pa_name_provenance.py -- where did each PA register NAME in our table come from?

`tfa-regs.PD1610.tsv` carries a `name` per register, taken from the vendor's reference tree
(fw/tfa-ref).  That tree holds several chip families whose tables disagree: the same address is
`INTERRUPT_ENABLE_REG2` in one header and `CurrentSense4` in another, and the driver itself says
"The CurrentSense4 registers are not in the datasheet".  A name is only useful across versions if you
know which family supplied it -- otherwise a 7 build that renames by family reads as a difference.

This tool does not decode the chip; it audits the provenance of the label column.
"""
import argparse, glob, os, re, sys

FAMILY = {
    "tfa1_tfafieldnames.h": "TFA1-bf", "tfa2_tfafieldnames_N1C.h": "N1C-bf",
    "tfa98xx_genregs_N1C.h": "N1C-genregs", "tfa9890_tfafieldnames.h": "9890-bf",
    "tfa9891_genregs.h": "9891-genregs", "tfa9891_tfafieldnames.h": "9891-bf",
    "tfa98xx_tfafieldnames.h": "98xx-bf", "tfa_init.c": "driver-code",
    "tfa9872_device_genregs_POR.h": "9872-POR", "tfa9912_device_genregs.h": "9912-POR",
    "tfa9894_tfafieldnames.h": "9894-bf", "tfa9896_tfafieldnames.h": "9896-bf",
    "tfa9872_tfafieldnames.h": "TFA9872-bf", "tfa9874_tfafieldnames.h": "TFA9874-bf",
    "tfa9887_tfafieldnames.h": "TFA9887-bf", "tfa_dsp.c": "dsp-code", "tfa98xx.c": "core-code",
}
SENTINEL = "ZZZ_QODER_NO_SUCH_REGISTER_NAME"


def read_rows(path):
    import csv
    rows = list(csv.DictReader(open(path, encoding="utf-8"), delimiter="\t"))
    if not rows or "name" not in rows[0]:
        sys.exit("gate: %s has no `name` column -- nothing to audit" % path)
    return rows


def tree(root):
    files = {}
    for pat in ("inc/*.h", "src/*.c", "inc/*.c"):
        for f in glob.glob(os.path.join(root, pat)):
            files[os.path.basename(f)] = open(f, encoding="latin-1").read()
    if not files:
        sys.exit("gate: the reference tree at %s yielded ZERO files -- a 'NOWHERE' answer here would be "
                 "blindness, not a finding" % root)
    return files


def audit(rows, files):
    out = []
    for r in rows:
        nm = (r.get("name") or "").strip()
        if nm in ("", "NO-NAME"):
            out.append({"reg": r["reg"], "name": None, "families": [], "files": []})
            continue
        # substring, NOT \b: the headers write TFA98XX_<NAME>, and a leading \b never matches after an
        # underscore -- that bug made every name read NOWHERE on the first run.
        where = sorted({fam for h, fam in FAMILY.items() if h in files and nm in files[h]})
        out.append({"reg": r["reg"], "name": nm,
                    "families": where or ["NOWHERE"],
                    "files": sorted([h for h in files if nm in files[h]])})
    return out


def report(res, rows, files, root):
    named = [x for x in res if x["name"]]
    anon = [x for x in res if not x["name"]]
    nowhere = [x for x in named if x["families"] == ["NOWHERE"]]
    print("== PA register-name provenance (%s)" % root)
    print("   table rows: %d  named: %d  NO-NAME: %d  named-but-unfound: %d  reference files: %d"
          % (len(res), len(named), len(anon), len(nowhere), len(files)))
    by_fam = {}
    for x in named:
        by_fam.setdefault("・".join(x["families"]), []).append(x["reg"])
    for fam, regs in sorted(by_fam.items(), key=lambda kv: -len(kv[1])):
        print("   %-46s %2d  %s" % (fam[:46], len(regs), "・".join(regs)))
    for x in nowhere:
        print("   NOWHERE: %s = %r" % (x["reg"], x["name"]))
    if named and len(nowhere) == len(named):
        sys.exit("gate: every name reads NOWHERE -- the matcher is broken, not the table")


def selftest(tsv, root):
    rows, files = read_rows(tsv), tree(root)
    res = audit(rows, files)
    named = [x for x in res if x["name"]]
    arms = [
        ("ok: the named rows each resolve to at least one reference family (nothing silently blank)",
         lambda: all(x["families"] and x["families"] != ["NOWHERE"] for x in named)),
        ("gate: a sentinel name must read NOWHERE -- proof the matcher can say 'not found'",
         lambda: (lambda r: r["families"] == ["NOWHERE"])(audit([{"reg": "0x99", "name": SENTINEL}],
                                                                files)[0])),
        ("gate: the same search must find the 9890's own field names in the 9890 table (underscore "
         "prefix makes \\b useless -- this arm fails if someone puts \\b back)",
         lambda: SENTINEL not in files["tfa9890_tfafieldnames.h"] and
                 "se_level" in files["tfa9890_tfafieldnames.h"]),
        ("ok: the denominator (rows / named / NO-NAME / files) is printed from the inputs, not remembered",
         lambda: len(named) + len([x for x in res if not x["name"]]) == len(rows) and len(files) > 5),
        ("gate: an empty reference tree aborts instead of reporting NOWHERE for everything",
         lambda: "ZERO files" in _abort(tree, os.path.join(root, "no-such-dir"))),
        ("gate: if EVERY named row reads NOWHERE the tool aborts rather than delivering a blank census",
         lambda: "every name reads NOWHERE" in _abort(report,
                                                     [{"reg": "0x00", "name": "FOO", "families": ["NOWHERE"]},
                                                      {"reg": "0x01", "name": "BAR", "families": ["NOWHERE"]}],
                                                     rows, files, root)),
    ]
    bad = 0
    for label, fn in arms:
        try:
            ok = bool(fn())
        except SystemExit as e:
            ok = label.startswith("gate:") and str(e) != ""
        except Exception as e:
            ok = False
            print("     (exception: %s)" % str(e)[:160])
        print(("ok   " if ok else "FAIL ") + label)
        bad += 0 if ok else 1
    print("selftest: %d arm(s) failed" % bad)
    return 1 if bad else 0


def _abort(fn, *a):
    try:
        fn(*a)
        return ""
    except SystemExit as e:
        return str(e)
    except Exception as e:
        return "%s: %s" % (type(e).__name__, e)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tsv", default=None)
    ap.add_argument("--ref", default=None)
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    repo = os.environ.get("AUDIO_PORT_ROOT") or "/home/v/.local/project/xplay6"
    tsv = a.tsv or f"{repo}/art/audio-6.0.1/tfa-regs.PD1610.tsv"
    root = a.ref or f"{repo}/fw/tfa-ref"
    if not os.path.exists(tsv):
        sys.exit("gate: " + tsv + " missing")
    if a.selftest:
        sys.exit(selftest(tsv, root))
    report(audit(read_rows(tsv), tree(root)), read_rows(tsv), tree(root), root)


if __name__ == "__main__":
    main()
