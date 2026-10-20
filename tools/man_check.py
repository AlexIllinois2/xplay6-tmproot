#!/usr/bin/env python3
"""tools/man_check.py -- verify art/audio-6.0.1/MANIFEST.txt row by row (hash + size + existence).

Written because the whole-file check caught a real defect the first time it ran: three rows I had
just registered were hashed with sha1[:16] while the manifest convention is sha256[:16]
(tools/port_manifest.py:sha16). A registration step and a verification step must use the same ruler.

The hash recipe is read out of port_manifest.py rather than duplicated here, so the two cannot drift.

Both directions are checked: every row must match the file (MISSING/DRIFT), and every file on disk
must have a row (UNLISTED).  The second arm is what ledger 303 was missing -- a newly emitted
artifact was invisible to this tool, so "rows=N problems=0" only ever meant "everything I remembered
to list is intact".  Docs (*.md) and MANIFEST.txt itself stay out of the denominator by design.

Usage: tools/man_check.py [--dir art/audio-6.0.1] [--fix]
"""
import argparse
import hashlib
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ALGO = {"sha256": hashlib.sha256, "sha1": hashlib.sha1, "md5": hashlib.md5}


def recipe():
    src = open(os.path.join(ROOT, "tools/port_manifest.py"), encoding="utf-8").read()
    # the recipe moved behind sha16_bytes() when volatile counters started being masked; read whichever
    # exists, and refuse if neither is there (the old regex silently aborting is the correct outcome --
    # a guessed algorithm would make every row look drifted or clean depending on the guess)
    m = (re.search(r"def sha16_bytes\(b\):\s*\n\s*return hashlib\.(\w+)\(.*?hexdigest\(\)\[:(\d+)\]", src)
         or re.search(r"def sha16\(p\):\s*\n\s*return hashlib\.(\w+)\(.*?hexdigest\(\)\[:(\d+)\]", src))
    if not m:
        sys.exit("gate: cannot read the sha16 recipe out of tools/port_manifest.py -- refusing to guess an algorithm")
    name, width = m.group(1), int(m.group(2))
    if name not in ALGO:
        sys.exit(f"gate: unexpected digest {name} in port_manifest.py")
    return ALGO[name], width, name


ERR_ONLY = re.compile(
    r"syntax error|unmatched|No such file or directory|not found|Permission denied"
    r"|Segmentation fault|Inappropriate ioctl|Read-only file system|Is a directory"
    r"|Operation not permitted|Transport is dead|error:|failed",
    re.I)

NOISE = re.compile(r"^(?:#|##|\s*$|WARNING:|\s*\* )")


def evidence_is_only_failure(data):
    """True when *every* content line of an artifact is a tool-failure message.

    A capture whose only readable line is `sh: syntax error: 'for' unmatched` records that the
    command did not run -- not that the target had no value.  Excluding comment/blank lines keeps
    multi-node logs (which legitimately contain one absent path among real readings) out of the
    net; only files with nothing but errors trip it.
    """
    body = [l for l in data.decode("utf-8", "replace").splitlines() if not NOISE.match(l)]
    return bool(body) and all(ERR_ONLY.search(l) for l in body)


def selftest():
    """The volatile mask must hide the counter and must NOT hide content."""
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    import port_manifest as pmm
    a = b"REACH uptime=23147.79\nREACH fd pid=775 link=/dev/diag\n"
    b = b"REACH uptime=99999.01\nREACH fd pid=775 link=/dev/diag\n"
    c = b"REACH uptime=23147.79\nREACH fd pid=999 link=/dev/diag\n"
    bad = 0
    if not hasattr(pmm, "mask_volatile"):
        print("  FAIL port_manifest has no mask_volatile -- the manifest rows are hashing raw bytes")
        bad += 1
    elif pmm.sha16_bytes(a) != pmm.sha16_bytes(b):
        print("  FAIL a re-taken uptime still moves the digest -- the mask does not reach it")
        bad += 1
    else:
        print("  ok   uptime alone does not move the digest")
    if hasattr(pmm, "sha16_bytes") and pmm.sha16_bytes(a) == pmm.sha16_bytes(c):
        print("  FAIL a real content change is invisible -- the mask is too broad")
        bad += 1
    else:
        print("  ok   a changed pid line still moves the digest")
    # --- evidence-content ruler: an artifact must not be nothing but a tool error ---
    bad_this_round = (b"# device 17 \xe2\x80\x94 \xe5\x8f\x96\xe8\xaf\x81\n"
                      b"# \xe6\x97\xb6\xe9\x97\xb4 2026-10-18\n"
                      b"sh: syntax error: 'for' unmatched\n")
    good_reading = (b"## /proc/asound/card0/pcm0p/sub0/status\nclosed\n"
                    b"## /proc/asound/card0/pcm16c/sub0/status\nclosed\n")
    mixed = (b"ls: /proc/asound/card0/pcm17p: No such file or directory\n"
             b"## still got this one\nState: new\n")
    empty = b""
    tool_missing = b"sh: toybox: not found\nsh: find: not found\n"
    adb_dead = b"error: no devices/emulators found\n"
    for label, blob, want in (("all-failure artifact", bad_this_round, True),
                              ("normal reading", good_reading, False),
                              ("one absent path among readings", mixed, False),
                              ("empty file (no content line)", empty, False),
                              ("every line a missing-tool error", tool_missing, True),
                              ("transport dead, no reading", adb_dead, True)):
        got = evidence_is_only_failure(blob)
        if got is not want:
            print(f"  FAIL evidence ruler on {label}: got {got}, want {want}")
            bad += 1
        else:
            print(f"  ok   evidence ruler {label}: {'flagged' if got else 'left alone'}")
    # --- prune ruler: fires on a dead row, refuses to touch a live-but-drifted row ---
    import subprocess, tempfile, shutil
    def fixture(with_drifted):
        d = tempfile.mkdtemp(prefix="mcprune")
        os.makedirs(os.path.join(d, "live/x"))
        keep = os.path.join(d, "live/x/keep.txt")
        open(keep, "w").write("## h\nclosed\n")
        b = open(keep, "rb").read()
        h = pmm.sha16_bytes(b)
        rows = ["\t".join([h, str(len(b)), "live/x/keep.txt"])]
        rows.append("\t".join([pmm.sha16_bytes(b"gone"), "4", "live/x/dead.txt"]))
        if with_drifted:
            other = os.path.join(d, "live/x/drift.txt")
            open(other, "w").write("old\n")
            rows.append("\t".join(["0" * 16, "999", "live/x/drift.txt"]))
        open(os.path.join(d, "MANIFEST.txt"), "w").write("\n".join(rows) + "\n")
        return d
    def run_mc(d, extra):
        q = subprocess.run([sys.executable, os.path.join(ROOT, "tools/man_check.py"), "--dir", d] + extra,
                           capture_output=True, text=True)
        return q.returncode, q.stdout, q.stderr
    d = fixture(False)
    rc, so, se = run_mc(d, ["--fix", "--prune"])
    if "Traceback" in se or rc != 0 or "PRUNED live/x/dead.txt" not in so or "PRUNED live/x/keep.txt" in so:
        print(f"  FAIL prune did not behave on a dead row (rc={rc}): {se[:120] or so[:120]}")
        bad += 1
    else:
        left = open(os.path.join(d, "MANIFEST.txt"), encoding="utf-8").read().splitlines()
        if len(left) != 1 or "keep.txt" not in left[0]:
            print(f"  FAIL prune left the wrong rows: {left}")
            bad += 1
        else:
            print("  ok   prune drops the absent row and keeps the live one")
    shutil.rmtree(d)
    d = fixture(True)
    rc, so, se = run_mc(d, ["--fix", "--prune"])
    q = subprocess.run([sys.executable, os.path.join(ROOT, "tools/man_check.py"), "--dir", d],
                       capture_output=True, text=True)
    after = open(os.path.join(d, "MANIFEST.txt"), encoding="utf-8").read()
    if "Traceback" in se or "live/x/drift.txt" not in after or q.returncode != 0:
        print("  FAIL a drifted-but-present row got pruned (or the re-check went red after a clean fix)")
        bad += 1
    else:
        print("  ok   a present row survives --fix --prune and re-verifies green")
    shutil.rmtree(d)
    d = fixture(False)
    rc, so, se = run_mc(d, ["--prune"])
    if rc == 0 or "gate: --prune needs --fix" not in so + se:
        print("  FAIL --prune without --fix rewrote the manifest anyway")
        bad += 1
    else:
        print("  ok   --prune alone is refused (rows are only dropped by an explicit rewrite)")
    shutil.rmtree(d)
    print(f"selftest: {bad} arm(s) failed")
    return 1 if bad else 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default=os.path.join(ROOT, "art/audio-6.0.1"))
    ap.add_argument("--fix", action="store_true", help="rewrite hash/size for rows that drifted")
    ap.add_argument("--prune", action="store_true", help="with --fix: drop rows whose file is gone "
                                        "(a renamed/deleted artifact).  Never drops a row for a file "
                                        "that still exists, however drifted")
    ap.add_argument("--selftest", action="store_true", help="prove the volatile mask hides the "
                                        "counter but not the content")
    if "--selftest" in sys.argv:
        sys.exit(selftest())
    args = ap.parse_args()

    fn, width, dname = recipe()
    # Use the WRITER's own digest function rather than re-deriving one from the parsed recipe: the
    # recipe regex only proves the algorithm and width, so a mask added on the writer side (volatile
    # uptime counters) would be silently bypassed here and reappear as a permanent fake DRIFT.
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    import port_manifest as _pmm
    digest = _pmm.sha16_bytes
    _probe = b"digest-recipe probe"
    if digest(_probe) != fn(_probe).hexdigest()[:width]:
        sys.exit("gate: man_check and port_manifest disagree on the digest recipe "
                 f"({digest(_probe)} vs {fn(_probe).hexdigest()[:width]}) -- fix the reader, do not "
                 "pick one and hope")
    man = os.path.join(args.dir, "MANIFEST.txt")
    lines, problems, out = 0, [], []
    swept, eligible, hard, dropped, absent = 0, 0, [], [], 0
    named = set()
    for ln in open(man, encoding="utf-8"):
        p = ln.rstrip("\n").split("\t")
        if len(p) != 3 or not p[0]:
            if ln.strip():
                problems.append(f"malformed row: {ln!r}")
            continue
        lines += 1
        named.add(p[2])
        f = os.path.join(args.dir, p[2])
        if not os.path.exists(f):
            absent += 1
            if args.prune:
                problems.append(f"MISSING {p[2]} -- pruned by this run")
            else:
                problems.append(f"MISSING {p[2]} -- --fix cannot invent a file; the row stays "
                                "unresolved and this run is red")
            if args.prune:
                dropped.append(p[2])          # deliberately not re-emitted into `out`
            else:
                out.append("\t".join(p))
            continue
        blob = open(f, "rb").read()
        swept += 1
        if p[2].startswith("live/"):
            eligible += 1
            if evidence_is_only_failure(blob):
                hard.append(f"EMPTY-EVIDENCE {p[2]} -- every content line is a tool failure; a "
                            "command that did not run is not a reading (fix the capture, "
                            "do not re-hash it)")
        h = digest(blob)
        size = str(os.path.getsize(f))
        if h != p[0] or size != p[1]:
            problems.append(f"DRIFT {p[2]} (hash {p[0]}->{h}, size {p[1]}->{size})")
            out.append("\t".join([h, size, p[2]]))
        else:
            out.append("\t".join(p))
    # the other direction: a file on disk that no MANIFEST row covers.  Without this arm a brand new
    # artifact simply is not in the denominator, so "MANIFEST clean" used to mean "everything I
    # remembered to list is intact" (ledger 303 found acdb-cvd.PD1610.tsv invisible that way)
    unlisted = []
    for dirpath, _dirs, fs in os.walk(args.dir):
        for x in sorted(fs):
            full = os.path.join(dirpath, x)
            rel = os.path.relpath(full, args.dir)
            if rel == "MANIFEST.txt" or rel.endswith((".md", ".pyc")):
                continue
            if rel not in named:
                unlisted.append(rel)
    for rel in sorted(unlisted):
        full = os.path.join(args.dir, rel)
        h = digest(open(full, "rb").read())
        problems.append(f"UNLISTED {rel} -- on disk, no MANIFEST row (run with --fix to append it)")
        out.append("\t".join([h, str(os.path.getsize(full)), rel]))
    if args.prune and not args.fix:
        sys.exit("gate: --prune needs --fix (pruning is a rewrite; refusing to drop rows silently)")
    if problems and args.fix:
        open(man, "w", encoding="utf-8").write("\n".join(out) + "\n")
        print(f"fixed {len(problems)} rows")
    if dropped:
        print(f"pruned {len(dropped)} row(s) whose file is absent -- names:")
        for r in sorted(dropped):
            print("  PRUNED " + r)
    elif args.prune:
        print("pruned 0 rows")
    for pr in problems[:20]:
        print("  " + pr)
    if eligible == 0:
        hard.append("EMPTY-EVIDENCE sweep has no live/ rows in its bucket -- the ruler measured "
                    "nothing, so a clean count here means nothing")
    if swept != lines - absent:
        hard.append(f"SWEEP-INCOMPLETE: read {swept} of {lines - absent} rows that have a file on "
                    f"disk ({lines} rows listed, {absent} absent) -- the content ruler did not see "
                    "every artifact")
    print(f"evidence-content sweep: {swept}/{lines - absent} files read ({lines} rows, {absent} "
          f"absent{', ' + str(len(dropped)) + ' pruned' if dropped else ''}), "
          f"bucket live/ = {eligible}, {len(hard)} refused")
    for pr in hard[:20]:
        print("  " + pr)
    problems += hard
    # what a --fix run could NOT repair: rows pointing at absent files that were not pruned, plus
    # any EMPTY-EVIDENCE refusal.  Before this, `--fix` returned 0 while MISSING rows stayed dead --
    # a green rc that hid an unresolvable row (the §448 gap in its rc form).
    unresolved = len(hard) + sum(1 for x in problems if x.startswith("MISSING") and not args.prune)
    print(f"rows={lines} problems={len(problems)} unresolved_after_fix={unresolved} "
          f"digest={dname}[:{width}]")
    return 1 if unresolved or (problems and not args.fix) else 0


if __name__ == "__main__":
    sys.exit(main())
