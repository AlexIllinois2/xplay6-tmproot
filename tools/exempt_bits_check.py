#!/usr/bin/env python3
"""Gate: the per-domain-permissive bit list must be the SAME set in every surface that ships it, and
every number in it must be resolved from the policy the device actually loaded.

Why this exists (ledger 2026-10-21 §707): third-party apps could get uid=0 but nothing they ran over
binder worked, because a MAC denial on the REPLY side (peer -> us) is decided by the PEER's type, and
nothing in the tree said which peer types the exemption set has to carry.  Two lists had already drifted:
broot7.c plants from argv_init while run_credread7.sh still names the old init_uts_ns host, and the
"kernel/init/shell" numbers were hand-copied 6.0.1 values in one place and live-measured values in another.

Authority = art/policy-types-7-live.tsv, parsed out of /sys/fs/selinux/policy on the phone.  A number
that is not what its own name says is a refusal, not a warning.

usage:
    python3 tools/exempt_bits_check.py            # check the tree
    python3 tools/exempt_bits_check.py --selftest  # prove the gate can fail
"""
import json
import os
import re
import struct
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TSV = os.path.join(ROOT, "art", "policy-types-7-live.tsv")
BROOT7 = os.path.join(ROOT, "tools", "broot7.c")
CREDREAD = os.path.join(ROOT, "tools", "run_credread7.sh")

# What must be exempt for "an app that was granted root can actually use it" (ledger 707):
#   kernel/qti_init_shell/init  -- what the borrow lands in, and the daemon's holder
#   untrusted_app/shell         -- the delivered app and the adb-side harness
#   servicemanager              -- every binder REPLY from the service registry (get/add service)
#   system_server               -- every binder reply from IPackageManager/IActivityManager/...
REQUIRED_NAMES = ["kernel", "qti_init_shell", "init", "untrusted_app", "shell",
                  "servicemanager", "system_server"]


def live_types():
    if not os.path.exists(TSV):
        raise SystemExit("no %s -- the live type index table has to be dumped from the phone first "
                         "(cat /sys/fs/selinux/policy, then re-run the parser that wrote it)" % TSV)
    t = {}
    for line in open(TSV, errors="ignore"):
        m = re.match(r"^(\d+)\t(\S+)\s*$", line)
        if m:
            t.setdefault(m.group(2), int(m.group(1)))
    if len(t) < 500:
        raise SystemExit("%s parses to only %d types -- that is not a loaded policy" % (TSV, len(t)))
    return t


def numbers_in(text, pattern, where):
    m = re.search(pattern, text, re.S)
    if not m:
        raise SystemExit("%s: no %s match -- refusing to call an absent list 'agreeing'"
                         % (where, pattern))
    return [int(x) for x in re.findall(r"\d+", m.group(1))]


def shipped_lists():
    b = numbers_in(open(BROOT7).read(),
                   r"c7_want\[\]\s*=\s*\{([^}]*)\}", "tools/broot7.c")
    s = numbers_in(open(CREDREAD).read(),
                   r"EXEMPT_BITS=([0-9,]+)", "tools/run_credread7.sh")
    return {"tools/broot7.c": b, "tools/run_credread7.sh": s}


def node_base_from_source():
    """The node host is read out of broot7.c, never retyped: the plant I test on-device and the plant
    the APK writes have to be the same address or the on-device reading certifies nothing."""
    m = re.search(r"#define\s+C7_NODE_BASE\s+(0x[0-9a-fA-F]+)UL", open(BROOT7).read())
    if not m:
        raise SystemExit("tools/broot7.c: no `#define C7_NODE_BASE` -- cannot check where the "
                         "exemption nodes will be planted")
    return int(m.group(1), 16)


def cc_build_mapcheck():
    """Compile the host mirror of the SHIPPED builder (tools/mapcheck.c uses tools/ebitmap_map.h, the
    same header broot7.c compiles).  No compiler is a refusal, not a skip: without it the bytes the
    device will write are unverified."""
    exe = "/tmp/mapcheck-exempt-gate"
    r = subprocess.run(["cc", "-O2", "-o", exe, os.path.join(ROOT, "tools", "mapcheck.c")],
                       capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit("cc failed to build tools/mapcheck.c -- the C-vs-python byte equality cannot "
                         "be checked:\n%s" % (r.stdout + r.stderr)[-600:])
    return exe


def c_bytes(exe, bits, base):
    r = subprocess.run([exe, "--bits", ",".join(str(x) for x in sorted(bits)),
                        "--base", hex(base)], capture_output=True, text=True)
    if r.returncode != 0:
        return None, r.stdout + r.stderr
    nodes = dict((int(i), h) for i, h in re.findall(r"NODE_HEX_(\d+)=([0-9a-f]+)", r.stdout))
    head = re.search(r"HEAD_HEX=([0-9a-f]+)", r.stdout)
    return [nodes[k] for k in sorted(nodes)], (head.group(1) if head else None)


def py_bytes(bits, base):
    r = subprocess.run([sys.executable, os.path.join(ROOT, "tools", "permmap7.py"), "build",
                        "--bits", ",".join(str(x) for x in sorted(bits)),
                        "--base", hex(base)], capture_output=True, text=True)
    if r.returncode != 0:
        return None, r.stdout + r.stderr
    try:
        j = json.loads(r.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        return None, r.stdout
    return j["nodes"], j["head"]


def node_capacity(bits, base):
    """Ask the SAME builder the device runs (tools/permmap7.py) whether the bits fit the node host."""
    nodes, head = py_bytes(bits, base)
    if nodes is None:
        return None, head
    return len(nodes), head


def check(verbose=True):
    t = live_types()
    want = []
    for n in REQUIRED_NAMES:
        if n not in t:
            raise SystemExit("%s is not in the loaded policy -- the required list names a type this "
                             "firmware does not have" % n)
        want.append(t[n])
    want.sort()
    bad = []
    for where, got in sorted(shipped_lists().items()):
        if sorted(got) != want:
            missing = [n for n, v in t.items() if v in set(want) - set(got)]
            extra = [n for n, v in t.items() if v in set(got) - set(want)]
            bad.append("%s: %s (missing=%s extra=%s)" % (
                where, sorted(got), ",".join(sorted(missing)) or "-", ",".join(sorted(extra)) or "-"))
    base = node_base_from_source()
    nw, out = node_capacity(want, base)
    if nw is None:
        raise SystemExit("permmap7.py cannot build this bit set -- the node host is too small:\n%s" % out)
    if nw > 4:
        bad.append("bit set needs %d nodes at %#x, the host holds 4 -- pick a different host" % (nw, base))
    # The bytes the device will be fed come out of tools/ebitmap_map.h (compiled into broot7), while the
    # payloads I measured on-device came from permmap7.py.  Those two must be identical, or an on-device
    # plant certifies the python bytes and not the shipped binary.
    exe = cc_build_mapcheck()
    cn, ch = c_bytes(exe, want, base)
    pn, ph = py_bytes(want, base)
    if cn is None or pn is None:
        raise SystemExit("a builder refused the required set -- C:%s python:%s" % (cn and "ok", pn and "ok"))
    if cn != pn or ch != ph:
        bad.append("the SHIPPED C builder and permmap7.py disagree on the exemption bytes "
                    "(C nodes=%d python=%d, head %s vs %s) -- the device reading does not certify what "
                    "broot7 will write" % (len(cn), len(pn), ch, ph))
    if verbose:
        names = {v: k for k, v in t.items()}
        print("authority: %s (%d types)" % (os.path.relpath(TSV, ROOT), len(t)))
        print("required:  %s" % ", ".join("%d=%s" % (v, names[v]) for v in want))
        print("geometry:  %d node(s) at %#x (C bytes == python bytes, head %s)" % (nw, base, ch))
        for where, got in sorted(shipped_lists().items()):
            print("%-26s %s" % (where, sorted(got)))
    if bad:
        for line in bad:
            sys.stderr.write("MISMATCH %s\n" % line)
        return 1
    print("OK: every shipped exemption list equals the live policy's answer for the required names, "
          "and the shipped builder emits the bytes that were verified on-device")
    return 0


def selftest():
    """Every arm runs on a COPY of the tree in a temp dir -- a self-test that edits the files it gates
    can leave the tree damaged by its own failure (ledger 2026-10-21: I wrote it that way first)."""
    import shutil
    import tempfile
    t = live_types()
    want = sorted(t[n] for n in REQUIRED_NAMES)
    tmp = tempfile.mkdtemp(prefix="exempt-arms-")
    real_b, real_s, real_n = BROOT7, CREDREAD, list(REQUIRED_NAMES)
    arms = []
    try:
        b = os.path.join(tmp, "broot7.c")
        s = os.path.join(tmp, "run_credread7.sh")
        shutil.copy(real_b, b)
        shutil.copy(real_s, s)
        globals()["BROOT7"] = b
        globals()["CREDREAD"] = s

        def put_broot(bits):
            txt = open(b).read()
            open(b, "w").write(re.sub(r"c7_want\[\]\s*=\s*\{[^}]*\}",
                                      "c7_want[] = { %s }" % ", ".join(str(x) for x in bits),
                                      txt, count=1))

        def put_harness(bits):
            txt = open(s).read()
            open(s, "w").write(re.sub(r"EXEMPT_BITS=[0-9,]+",
                                      "EXEMPT_BITS=" + ",".join(str(x) for x in bits), txt, count=1))

        # 0: positive control -- the gate CAN go green, so every red below is a real catch
        put_broot(want); put_harness(want)
        arms.append(("correct set in both surfaces passes", check(False) == 0))

        alt = list(want); alt[0] = alt[0] + 1
        put_broot(alt)
        arms.append(("one digit moved must abort", check(False) != 0))
        put_broot(want)

        put_broot([v for v in want if v not in (t["servicemanager"], t["system_server"])])
        arms.append(("peer types dropped must abort", check(False) != 0))
        put_broot(want)

        put_harness([1, 2, 3, 4, 5, 6, 7])
        arms.append(("harness list made to disagree must abort", check(False) != 0))
        put_harness(want)

        # a set the node host cannot hold must be refused by the geometry side, not silently built.
        # This is asked of the SAME builder the device runs, directly -- editing the shipped lists here
        # would only ever be caught by the equality arm above, which is a different question.
        spread = sorted(set(want) | {1, 500, 900, 1300, 1700})
        base = node_base_from_source()
        nw_spread, _ = node_capacity(spread, base)
        tight_nw, _ = node_capacity(want, base)
        arms.append(("bit set needing more nodes than the host must be refused (nodes=%s)" % nw_spread,
                     nw_spread is None or nw_spread > 4))
        arms.append(("the required set itself fits the host (nodes=%s)" % tight_nw,
                     tight_nw is not None and tight_nw <= 4))
        # the byte comparison must have teeth: one bit more has to change what gets written
        c0 = c_bytes(os.path.join(tempfile.gettempdir(), "mapcheck-exempt-gate"), want, base)
        c1 = c_bytes(os.path.join(tempfile.gettempdir(), "mapcheck-exempt-gate"),
                     sorted(set(want) | {want[-1] + 1}), base)
        arms.append(("one bit more must change the shipped bytes", c0 != c1))
        put_broot(want); put_harness(want)

        REQUIRED_NAMES.append("no_such_domain_here")
        rc = 0
        try:
            check(False)
        except SystemExit:
            rc = 1
        finally:
            REQUIRED_NAMES[:] = real_n
        arms.append(("unknown required name must refuse", rc == 1))
    finally:
        globals()["BROOT7"] = real_b
        globals()["CREDREAD"] = real_s
        shutil.rmtree(tmp, ignore_errors=True)

    bad = [n for n, ok in arms if not ok]
    for n, ok in arms:
        print("  arm %-48s %s" % (n, "ok" if ok else "FAILED"))
    if bad:
        sys.stderr.write("SELFTEST FAIL: %d of %d arms misbehaved (nothing in the tree was touched "
                         "by these arms -- they ran on temp copies)\n" % (len(bad), len(arms)))
        return 1
    print("SELFTEST OK: %d arms" % len(arms))
    return 0


def apk_bits(apk):
    """Look inside the SHIPPED ladder for the exemption array.  Source lists agreeing is not enough:
    the 2026-10-21 build packaged a stale assets/broot7 whose array still held the old five types."""
    r = subprocess.run(["unzip", "-p", apk, "assets/broot7"], capture_output=True)
    if r.returncode != 0 or not r.stdout:
        raise SystemExit("cannot read assets/broot7 out of %s -- the artifact cannot be certified" % apk)
    return r.stdout


def verify_apk(apk):
    t = live_types()
    want = sorted(t[n] for n in REQUIRED_NAMES)
    blob = apk_bits(apk)
    pat = b"".join(struct.pack("<I", x) for x in want)
    hits = blob.count(pat)
    if hits != 1:
        sys.stderr.write("ARTIFACT REFUSES: the shipped exemption array %s appears %d time(s) in "
                         "%s (%d bytes) -- expected exactly 1. Bits wanted: %s\n"
                         % (want, hits, apk, len(blob), ",".join(map(str, want))))
        return 1
    print("artifact: %s carries the live-policy array %s exactly once (assets/broot7, %d B)"
          % (os.path.basename(apk), want, len(blob)))
    return 0


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        raise SystemExit(selftest())
    if "--verify-apk" in sys.argv:
        i = sys.argv.index("--verify-apk")
        if i + 1 >= len(sys.argv):
            raise SystemExit("--verify-apk needs the APK path")
        raise SystemExit(verify_apk(sys.argv[i + 1]))
    raise SystemExit(check())
