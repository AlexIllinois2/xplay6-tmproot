#!/usr/bin/env python3
"""Citation integrity for the acceptance procedure: every path the runbook tells someone to open,
read or write has to be either present, a device-side path, or an explicitly allowed scratch path.

Why: a rotted path in `PORT-RUNBOOK-7.md` is invisible on 6.0.1 (nobody executes the document line by
line here) and fatal on 7 -- the one moment iteration is expensive.  First use of this gate found
`live/fres-play-spk-20261017-0837*.txt`, a name this project never wrote: the real artifact is
`live/tfa98xx/fres-detect-spk-20261017-0837.txt`.

Classes, decided by the token itself and always counted (an unclassified token is an error, so the
denominator cannot quietly shrink):
  repo      art/... tools/... fw/... pocs/...          -> must exist
  pattern   a repo path containing * or <...>          -> must glob to >=1 real file
  device    /sys /dev /proc /data                      -> cannot be checked from this host; counted
  scratch   /tmp/...                                   -> output paths, expected absent
Selftest proves the gate can fire, including the trap this tool itself fell into while being written:
matching a pattern by stripping it down to a prefix silently turns live files into "missing" ones, so
patterns are handed to glob and an arm asserts a known-good pattern resolves.
"""
import csv, glob, os, re, subprocess, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RUNBOOK = os.path.join(ROOT, "art/PORT-RUNBOOK-7.md")
BASE_REL = "art/audio-6.0.1"
TOKEN = re.compile(r"(?<![\w/])((?:art|tools|fw|pocs|live|kernel)/[\w./<>+*\-]*|/tmp/[\w./<>+*\-]+|"
                   r"/(?:sys|dev|proc|data)/[\w./<>*\-]+)")
REPO_FIRST = ("art", "tools", "fw", "pocs", "kernel")


def normalize(tok):
    """The runbook writes `live/...` as shorthand for the baseline directory's live/ -- resolution
    has to see the real path, and the classifier must not rewrite a token that the caller then
    hands to resolve() (the first draft did exactly that and reported 13 live files as dangling)."""
    return f"{BASE_REL}/{tok}" if tok.startswith("live/") else tok


def classify(tok):
    if tok.startswith("/tmp"):
        return "scratch"
    if tok.startswith(("/sys", "/dev", "/proc", "/data")):
        return "device"
    head = tok.split("/")[0]
    if head in REPO_FIRST or head == "live":
        pass
    else:
        return "unknown"
    return "pattern" if ("*" in tok or "<" in tok or tok.endswith("-")) else "repo"


def resolve(kind, tok):
    """repo: exact existence.  pattern: glob, with <time>/<addr> style placeholders turned into *."""
    if kind == "repo":
        return [tok] if os.path.exists(os.path.join(ROOT, tok)) else []
    if kind == "pattern":
        pat = re.sub(r"<[^>]*>", "*", tok)
        pat = os.path.join(ROOT, pat)
        return sorted(glob.glob(pat))
    return []


def scan_table(path):
    """The carry list's own `source` column: a row whose provenance path does not resolve cannot be
    re-derived on 7, which is the only reason the column exists."""
    dead, n = [], 0
    with open(path, encoding="utf-8") as f:
        for i, row in enumerate(csv.DictReader(f, delimiter="\t")):
            for t in set(TOKEN.findall(row.get("source", "") or "")):
                n += 1
                k = classify(normalize(t))
                if k in ("device", "scratch"):
                    continue
                if k == "unknown":
                    dead.append((i, row.get("layer", "?"), t, "unclassified"))
                elif not resolve("pattern" if ("*" in t or "<" in t) else "repo", normalize(t)):
                    dead.append((i, row.get("layer", "?"), t, "no such source"))
    return dead, n, i + 1


def scan(text):
    toks = sorted(set(TOKEN.findall(text)))
    out = {"repo": [], "pattern": [], "device": [], "scratch": [], "unknown": []}
    for t in toks:
        out[classify(normalize(t))].append(normalize(t))
    return out


def report(text, quiet=False):
    buckets = scan(text)
    total = sum(len(v) for v in buckets.values())
    dead = []
    for t in buckets["repo"]:
        if not resolve("repo", t):
            dead.append(("repo", t))
    for t in buckets["pattern"]:
        if not resolve("pattern", t):
            dead.append(("pattern", t))
    if buckets["unknown"]:
        dead += [("unclassified", t) for t in buckets["unknown"]]
    if not quiet:
        print(f"citations: {total} unique -- repo {len(buckets['repo'])}, pattern {len(buckets['pattern'])}, "
              f"device {len(buckets['device'])}, scratch {len(buckets['scratch'])}, "
              f"unclassified {len(buckets['unknown'])}")
        print(f"           repo/pattern resolved: "
              f"{len(buckets['repo']) + len(buckets['pattern']) - len(dead)}/"
              f"{len(buckets['repo']) + len(buckets['pattern'])}")
    for k, t in dead:
        print(f"   DANGLING[{k}] {t}")
    return dead, total


def selftest():
    src = open(RUNBOOK, encoding="utf-8").read()
    dead, _ = report(src, quiet=True)
    bad = 0
    if dead:
        print(f"  FAIL baseline: the shipped runbook has {len(dead)} dangling citations")
        bad += 1
    else:
        print("  ok   baseline runbook resolves every repo/pattern citation")
    # control: a pattern that MUST resolve, proving glob handling is not the blind prefix trick
    ctl = [t for t in scan(src)["pattern"] if "tfafieldnames" in t or "es9038-reg-hpplay" in t]
    if not ctl or any(not resolve("pattern", t) for t in ctl):
        print(f"  FAIL pattern control {ctl} did not resolve -- the pattern matcher is blind")
        bad += 1
    else:
        print(f"  ok   {len(ctl)} known-good pattern(s) resolve via glob "
              f"(the first draft called four live files missing by stripping patterns to prefixes)")
    arms = [
        ("dangling tools/ path is refused", "tools/port_manifest.py", "tools/no_such_tool.py"),
        ("dangling live/ artifact is refused", "live/asound-", "live/asound-nonexistent-"),
        ("a rotted repo directory is refused", "fw/Image", "fw/Image-typo-here"),
    ]
    for label, old, new in arms:
        if old not in src:
            print(f"  FAIL {label}: anchor absent -- vacuous arm")
            bad += 1
            continue
        d, _ = report(src.replace(old, new, 1), quiet=True)
        if any(new in t for _, t in d):
            print(f"  ok   {label}")
        else:
            print(f"  FAIL {label}: the gate did not flag it")
            bad += 1
    # an allowed class must not fire: rewriting a real path into /tmp must stay silent
    d, _ = report(src.replace("tools/port_manifest.py", "/tmp/some/other/tool.py", 1), quiet=True)
    if any("/tmp/some/other" in t for _, t in d):
        print("  FAIL scratch paths are required to exist -- classification is wrong")
        bad += 1
    else:
        print("  ok   /tmp output paths are accepted as absent (they are written by the run)")
    tdead, tn, trows = scan_table(os.path.join(ROOT, BASE_REL, "port-target.PD1610.tsv"))
    if tdead:
        print(f"  FAIL table provenance: {len(tdead)} of {tn} source tokens do not resolve")
        bad += 1
    else:
        print(f"  ok   table provenance: all {tn} source tokens across {trows} rows resolve")
    # and the table mode must be able to fire: break one source path in a temp copy
    import tempfile, shutil
    src_t = os.path.join(ROOT, BASE_REL, "port-target.PD1610.tsv")
    tmp = os.path.join(tempfile.mkdtemp(), "port-target.tsv")
    shutil.copy(src_t, tmp)
    rows = open(tmp, encoding="utf-8").read().splitlines()
    for i, ln in enumerate(rows):
        if "\t" in ln and len(ln.split("\t")) > 5 and "art/" in ln or "live/" in ln:
            cells = ln.split("\t")
            j = [k for k, c in enumerate(cells) if "live/" in c or "art/audio" in c]
            if not j:
                continue
            cells[j[0]] = cells[j[0]].replace("live/", "live/rotted-", 1)
            rows[i] = "\t".join(cells)
            break
    open(tmp, "w", encoding="utf-8").write("\n".join(rows) + "\n")
    d2, _, _ = scan_table(tmp)
    if d2:
        print(f"  ok   a rotted source path in the table is flagged ({len(d2)})")
    else:
        print("  FAIL the table scan did not notice a path I just broke -- it is blind")
        bad += 1
    print(f"selftest: {bad} arm(s) failed")
    return 1 if bad else 0


def main():
    if "--table" in sys.argv:
        tpath = sys.argv[sys.argv.index("--table") + 1] if len(sys.argv) > sys.argv.index("--table") + 1 else os.path.join(ROOT, BASE_REL, "port-target.PD1610.tsv")
        dead, n, rows = scan_table(tpath)
        print(f"table provenance: {rows} rows, {n} source path tokens -- unresolvable {len(dead)}")
        for i, layer, t, why in dead[:10]:
            print(f"   row {i} [{layer}] {t}  <- {why}")
        if dead:
            print(f"gate: {len(dead)} provenance path(s) in {tpath} do not resolve")
            return 1
        print("every source path in the carry list resolves (or is an allowed device/scratch path)")
        return 0
    if "--selftest" in sys.argv:
        return selftest()
    path = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith("-") else RUNBOOK
    dead, total = report(open(path, encoding="utf-8").read())
    if dead:
        print(f"gate: {len(dead)} dangling citation(s) in {path} of {total} checked")
        return 1
    print(f"runbook citations: all {total} tokens classified and every repo/pattern path resolves")
    return 0


if __name__ == "__main__":
    sys.exit(main())
