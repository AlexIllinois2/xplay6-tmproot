#!/usr/bin/env python3
"""Invariant check: the daemon and every client must agree on the socket layout.

Why this exists (measured 2026-10-19, ledger 588/590/596): the reverse channel's drop directory
moved from `/data/local/tmp/.sud` to `/data/local/tmp/.sud/req` so that `.sud` itself could become
search-only while clients still get a place to publish `req-<pid>`.  Three files implement that
protocol -- tools/sud.c (sweeps it), tools/suc.c and tools/apk/jni/jni_esc.c (write into it) -- and
fixing only the first two left the APK's own JNI probe publishing where nothing looks, in a
directory it can no longer write to.  A protocol split across files has to be checked by a tool,
not by remembering.

usage:
  tools/sud_layout.py            # check the working tree
  tools/sud_layout.py --selftest # prove the checker can see the split (doctored copies)
"""
import argparse
import os
import re
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DAEMON = "tools/sud.c"
CLIENTS = ["tools/suc.c", "tools/apk/jni/jni_esc.c"]
DAEMON_SYMBOLS = {
    "SOCKDIR2": "the daemon's private directory",
    "REQDIR": "where clients publish req-<pid>",
    "SU_LOG": "the audit log",
    "SESSDIR": "the session dir",
}


def defs(path):
    out = {}
    for m in re.finditer(r'#define\s+(\w+)\s+("(?:[^"\\]|\\.)*"|SOCKDIR2\s+"(?:[^"\\]|\\.)*")',
                         open(os.path.join(ROOT, path), encoding="utf-8").read()):
        name, raw = m.group(1), m.group(2)
        parts = re.findall(r'"([^"]*)"', raw)
        out[name] = "".join(parts) if not raw.startswith('"') else raw.strip('"')
    return out


def layout(base=None):
    """(drop dir, private dir, per-client drop dirs) resolved from the sources."""
    base = base or ROOT
    old_root = globals()["ROOT"]
    try:
        globals()["ROOT"] = base
        d = defs(DAEMON)
        missing = [k for k in DAEMON_SYMBOLS if k not in d]
        if missing:
            sys.exit("gate: %s does not define %s -- the parser is not reading this file, so no "
                     "answer below is admissible" % (DAEMON, ",".join(missing)))
        sock = d["SOCKDIR2"]
        drop = sock + d["REQDIR"]
        clients = {}
        for c in CLIENTS:
            cd = defs(c)
            if "REQ_DIR" not in cd:
                sys.exit("gate: %s has no REQ_DIR -- either the client changed shape or this tool "
                         "is looking at the wrong symbol" % c)
            clients[c] = cd["REQ_DIR"]
        return sock, drop, clients, d
    finally:
        globals()["ROOT"] = old_root


MODE_RULES = (
    # (how to find it, what must hold, why)
    ("chmod", "SOCKDIR2", lambda m: not (m & 0o002), "the daemon's private dir must not be "
     "world-writable (ledger 586: any app could then unlink/replace sud.sock)"),
    ("chmod", "REQDIR", lambda m: (m & 0o1000) and (m & 0o002), "the client drop dir must be "
     "world-writable AND sticky (ledger 588/590: without it no caller can publish; without S_ISVTX "
     "a caller can delete another's drop)"),
    ("chmod", "SESSDIR", lambda m: not (m & 0o077), "the session dir must be root-only"),
    ("open", "SU_LOG", lambda m: not (m & 0o004), "the audit log must not be world-readable"),
)


def modes(base=None):
    """Read the octal mode the source actually asks for at each chmod()/open() of a layout macro."""
    base = base or ROOT
    txt = open(os.path.join(base, DAEMON), encoding="utf-8").read()
    found = {}
    for kind, sym, _ok, _why in MODE_RULES:
        m = re.search(r'\b%s\(\s*%s\s*,[^;]*?\b(0o?[0-7]{3,4})\s*\)' % (kind, sym), txt)
        if not m:
            m = re.search(r'\b%s\(\s*%s\b[^;]*?,\s*(0[0-7]{3,4})\s*,' % (kind, sym), txt)
        if not m:
            sys.exit("gate: cannot read the %s(%s, mode) call from %s -- the permission shape is "
                     "unverified, so this run must not certify anything" % (kind, sym, DAEMON))
        found[(kind, sym)] = int(m.group(1), 8)
    return found


def check(base=None):
    sock, drop, clients, d = layout(base)
    bad = []
    for c, where in sorted(clients.items()):
        if where != drop:
            bad.append("%s publishes into %r but the daemon sweeps %r" % (c, where, drop))
    for sym in ("SU_LOG", "SESSDIR"):
        p = sock + d[sym]
        if p.startswith(drop + "/"):
            bad.append("daemon state %s (%s) sits inside the client-writable drop dir %s"
                       % (sym, p, drop))
    mm = modes(base)
    for kind, sym, ok, why in MODE_RULES:
        val = mm[(kind, sym)]
        if not ok(val):
            bad.append("%s(%s) mode %s violates the permission shape: %s"
                       % (kind, sym, oct(val)[2:], why))
    print("daemon private dir : %s" % sock)
    print("client drop dir    : %s" % drop)
    for c, where in sorted(clients.items()):
        print("  client %-28s -> %s %s" % (c, where, "OK" if where == drop else "MISMATCH"))
    for (kind, sym), val in sorted(mm.items()):
        print("  mode  %-10s %-10s %s" % (kind, sym, oct(val)[2:]))
    print("# checked %d file(s), %d daemon symbols, %d client constants, %d mode rules"
          % (1 + len(clients), len(DAEMON_SYMBOLS), len(clients), len(MODE_RULES)))
    return bad


def selftest():
    """The checker must be able to SEE the drift it guards against."""
    bad = check()
    if bad:
        print("FAIL: the working tree itself is inconsistent:\n  " + "\n  ".join(bad))
        return 1
    ok = 0
    with tempfile.TemporaryDirectory() as tmp:
        for rel in [DAEMON] + CLIENTS:
            os.makedirs(os.path.join(tmp, os.path.dirname(rel)), exist_ok=True)
            open(os.path.join(tmp, rel), "w", encoding="utf-8").write(
                open(os.path.join(ROOT, rel), encoding="utf-8").read())
        # arm 1: doctor one client back to the pre-588 layout -- the checker must call it a split
        j = os.path.join(tmp, "tools/apk/jni/jni_esc.c")
        t = open(j, encoding="utf-8").read().replace('REQ_DIR "/data/local/tmp/.sud/req"',
                                                    'REQ_DIR "/data/local/tmp/.sud"')
        open(j, "w", encoding="utf-8").write(t)
        old_root = globals()["ROOT"]
        try:
            globals()["ROOT"] = tmp
            got = check(tmp)
        finally:
            globals()["ROOT"] = old_root
        if got:
            print("  ok   arm: a client pointing at the old drop dir is reported (%d)" % len(got))
            ok += 1
        else:
            print("  FAIL arm: the checker did not notice the doctored client -- it is blind")
        # arm 2: delete a required define -> the parser must refuse instead of answering
        dead = os.path.join(tmp, "dead")
        os.makedirs(os.path.join(dead, "tools/apk/jni"), exist_ok=True)
        open(os.path.join(dead, "tools/sud.c"), "w", encoding="utf-8").write("#define TCP_PORT 1\n")
        for c in CLIENTS:
            os.makedirs(os.path.join(dead, os.path.dirname(c)), exist_ok=True)
            open(os.path.join(dead, c), "w", encoding="utf-8").write('#define REQ_DIR "x"\n')
        try:
            r = subprocess.run([sys.executable, os.path.join(ROOT, "tools/sud_layout.py")],
                               capture_output=True, text=True, env=dict(os.environ,
                                                                        SUD_LAYOUT_ROOT=dead))
        except Exception:
            r = None
        print("  note  arm 2 (missing symbols -> refuse) is exercised inline below, not by env")
        try:
            layout(dead)
            print("  FAIL arm: a tree without REQDIR parsed without complaint")
        except SystemExit as e:
            print("  ok   arm: an unparseable daemon is refused (%s)" % str(e)[:60])
            ok += 1
    # arms 3..6: each permission-shape rule must be violated-ABLE and reported
    VIOLATION = {("chmod", "SOCKDIR2"): "0777", ("chmod", "REQDIR"): "0777",
                 ("chmod", "SESSDIR"): "0777", ("open", "SU_LOG"): "0644"}
    for (kind, sym), bad_mode in VIOLATION.items():
        with tempfile.TemporaryDirectory() as tmp:
            for rel in [DAEMON] + CLIENTS:
                os.makedirs(os.path.join(tmp, os.path.dirname(rel)), exist_ok=True)
                open(os.path.join(tmp, rel), "w", encoding="utf-8").write(
                    open(os.path.join(ROOT, rel), encoding="utf-8").read())
            p = os.path.join(tmp, DAEMON)
            t = open(p, encoding="utf-8").read()
            pat = re.compile(r'(\b%s\(\s*%s\b[^;]*?,\s*)0[0-7]{3,4}(\s*[,)])' % (kind, sym))
            if not pat.search(t):
                print("  FAIL arm: %s(%s) mode literal not found -- the rule cannot be tested"
                      % (kind, sym))
                continue
            open(p, "w", encoding="utf-8").write(pat.sub(r"\g<1>%s\g<2>" % bad_mode, t, count=1))
            old_root = globals()["ROOT"]
            try:
                globals()["ROOT"] = tmp
                got = check(tmp)
                # the doctored copy alone must be what trips it, so the drop-dir split must not
                # also fire (the client constants were copied verbatim)
                split = [g for g in got if "publishes into" in g]
            finally:
                globals()["ROOT"] = old_root
            hits = [g for g in got if "permission shape" in g]
            if hits and not split:
                print("  ok   arm: %s(%s)=%s is reported (%s)"
                      % (kind, sym, bad_mode, hits[0][:70]))
                ok += 1
            else:
                print("  FAIL arm: %s(%s)=%s produced no permission-shape complaint"
                      % (kind, sym, bad_mode))
    print("sud_layout selftest: %d/6 arms passed" % ok)
    return 0 if ok == 6 else 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        sys.exit(selftest())
    bad = check()
    if bad:
        sys.exit("GATE: the socket layout is split across files:\n  " + "\n  ".join(bad))
    print("layout: all clients and the daemon agree")


if __name__ == "__main__":
    main()
