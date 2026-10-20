#!/usr/bin/env python3
"""Gate the su-name-gate constants across EVERY surface that carries them.

The adb route takes its numbers from `pgdalias.py --shell` at run time, so it can never ship a stale
address.  The APK route cannot: tools/clobber.c holds the same values as C #defines, compiled in.
Before this script, nothing compared the two -- so a kernel image change would have left the app
writing an address that only pgdalias knows is wrong (and pgdalias would have said so, loudly, to
nobody, because the app never calls it).

The authority is pgdalias' derivation from fw/<profile>/Image (it asserts the site word, the branch
target, the EPERM producer and the fall-through instruction against the image before emitting).
This script compares that authority with the constants the shipped binary carries, and refuses.

    python3 tools/gate_constants.py            # check both profiles
    python3 tools/gate_constants.py --selftest # + the arms that prove the checker can fail
"""
import os
import re
import subprocess
import sys
import tempfile

T = os.path.dirname(os.path.abspath(__file__))
CLOBBER = os.path.join(T, "clobber.c")

# profile -> list of (pgdalias key, clobber.c define, how to read the define)
#   "va"   : compare integers directly
#   "word" : GATE_*_HEX is MEMORY ORDER ("a023f837"); the C constant is the instruction WORD
#   "desc" : ALIAS_DESC_HEX is the 8-byte little-endian payload; the C literal is the u64
MAP = {
    "6.0.1": [
        ("ALIAS_ENTRY_VA", "SUGATE_PGD_ENTRY", "va"),
        ("ALIAS_BASE", "SUGATE_ALIAS_BASE", "va"),
        ("GATE_PRIMARY_VA", "SUGATE_GATE_VA", "va"),
        ("GATE_ORIG_HEX", "SUGATE_GATE_ORIG", "word"),
        ("GATE_PATCH_HEX", "SUGATE_GATE_PATCH", "word"),
        ("WITNESS_PRIMARY", "ENFORCE_ADDR", "va"),
    ],
    "7": [
        ("ALIAS_ENTRY_VA", "SUGATE7_PGD_ENTRY", "va"),
        ("ALIAS_BASE", "SUGATE_ALIAS_BASE", "va"),
        ("GATE_PRIMARY_VA", "SUGATE7_GATE_VA", "va"),
        ("GATE_ORIG_HEX", "SUGATE7_GATE_ORIG", "word"),
        ("GATE_PATCH_HEX", "SUGATE7_GATE_PATCH", "word"),
        ("WITNESS_PRIMARY", "SUGATE7_MODPROBE_VA", "va"),
    ],
}
DESC_LIT = "0x0040000040000711ULL"        # the same descriptor literal, in both routes' C code


def derive(profile):
    """pgdalias' own answer for this profile, or SystemExit -- never a partial set."""
    r = subprocess.run([sys.executable, os.path.join(T, "pgdalias.py"),
                        "--profile", profile, "--shell"],
                       capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit("pgdalias.py --profile %s refused (rc=%d):\n%s\n"
                         "=> the shipped constants are NOT re-derived; do not build on them"
                         % (profile, r.returncode, r.stderr[-800:]))
    kv = {}
    for line in r.stdout.splitlines():
        m = re.match(r"^([A-Z0-9_]+)=(.*)$", line.strip())
        if m:
            kv[m.group(1)] = m.group(2).strip("'")
    return kv


def define(src, name):
    m = re.search(r"^#define\s+%s\s+(0x[0-9a-fA-F]+)" % re.escape(name), src, re.M)
    if not m:
        raise SystemExit("gate: %s is no longer a #define in clobber.c -- this script's list is "
                         "stale, update MAP rather than trusting a pass" % name)
    return int(m.group(1), 16)


def authority(kv, key, how):
    if key not in kv:
        raise SystemExit("gate: pgdalias emitted no %s; refusing to compare a partial set" % key)
    v = kv[key]
    if how == "va":
        return int(v, 16)
    if how == "word":
        return int.from_bytes(bytes.fromhex(v), "little")
    if how == "desc":
        return int.from_bytes(bytes.fromhex(v), "little")
    raise SystemExit("gate: unknown reading %r" % how)


def check(src, label):
    """Every expected pair is compared, and the count is reported (silence is not a verdict)."""
    bad = []
    n = 0
    for profile, pairs in MAP.items():
        kv = derive(profile)
        for key, name, how in pairs:
            a, c = authority(kv, key, how), define(src, name)
            n += 1
            tag = "clobber.c[%s]" % label
            if a != c:
                bad.append("%-3s %-16s %s=%#x  authority=%#x" % (profile, name, tag, c, a))
                print("  BAD profile %s  %-18s %#018x  != pgdalias %s=%#x" % (profile, name, c, key, a))
            else:
                print("  ok  profile %s  %-18s %#018x  (= pgdalias %s)" % (profile, name, c, key))
        # the descriptor literal, which appears in the C code rather than as a #define
        d = int.from_bytes(bytes.fromhex(kv["ALIAS_DESC_HEX"]), "little")
        n += 1                                  # the denominator counts attempted pairs, not passed ones
        if DESC_LIT not in src:
            bad.append("%-3s %-18s descriptor literal %s absent from clobber.c" % (profile, "ALIAS_DESC", DESC_LIT))
            print("  BAD profile %s  %-18s literal %s not in clobber.c" % (profile, "ALIAS_DESC", DESC_LIT))
        elif define_desc(src) != d:
            bad.append("%-3s %-18s clobber.c=%#x authority=%#x" % (profile, "ALIAS_DESC", define_desc(src), d))
            print("  BAD profile %s  %-18s %#018x  != pgdalias ALIAS_DESC_HEX=%#x" % (profile, "ALIAS_DESC", define_desc(src), d))
        else:
            print("  ok  profile %s  %-18s %#018x  (= pgdalias ALIAS_DESC_HEX)" % (profile, "ALIAS_DESC", d))
    return n, bad


def define_desc(src):
    m = re.search(r"put_le\(desc,\s*(0x[0-9a-fA-F]+)ULL", src)
    if not m:
        raise SystemExit("gate: no put_le(desc, 0x...ULL) in clobber.c -- the alias descriptor moved")
    return int(m.group(1), 16)


def selftest(src):
    """The checker must be able to fail, on the two shapes that were actually broken before.
    Values are rewritten by regex because the file's hex case is not the point of the arm."""
    def poke(name, new):
        return lambda s, n=name, v=new: re.sub(r"(#define\s+%s\s+)0x[0-9a-fA-F]+" % re.escape(n),
                                               r"\g<1>0x" + v, s, count=1)

    def drop(name):
        return lambda s, n=name: re.sub(r"^#define\s+%s.*$" % re.escape(n), "/* gone */", s, flags=re.M)

    arms = [
        ("one hex digit off the gate site", poke("SUGATE7_GATE_VA", "ffffffc000323404"), True),
        ("the original word in the wrong byte order", poke("SUGATE7_GATE_ORIG", "a023f837"), True),
        ("a witness VA moved by one page", poke("SUGATE7_MODPROBE_VA", "ffffffc001a4a9b8"), True),
        ("the descriptor's page frame changed",
         lambda s: s.replace(DESC_LIT, "0x0080000040000711ULL"), True),
        ("a define removed (the list would go un-checked)", drop("SUGATE7_MODPROBE_VA"), True),
        ("the untouched file", lambda s: s, False),
    ]
    for name, mutate, must_fail in arms:
        mutated = mutate(src)
        if mutated == src and must_fail:
            raise SystemExit("SELFTEST FAIL: arm %r changed nothing -- the arm is blind" % name)
        fd, path = tempfile.mkstemp(suffix=".c", prefix="gate_clobber_")
        with os.fdopen(fd, "w") as f:
            f.write(mutated)
        try:
            n, bad = check(open(path).read(), "arm:" + name)
            failed = bool(bad)
        except SystemExit as e:
            print("  arm %-45s aborted by the checker: %s" % (name, str(e)[:70]))
            failed = True
        finally:
            os.unlink(path)
        if failed != must_fail:
            raise SystemExit("SELFTEST FAIL: arm %r expected must_fail=%s, got failure=%s"
                             % (name, must_fail, failed))
        print("  arm %-45s %s as required" % (name, "rejected" if failed else "passed"))


def main():
    src = open(CLOBBER).read()
    n, bad = check(src, "shipped")
    if "--selftest" in sys.argv:
        print("--- arms (the checker must be able to fail) ---")
        selftest(src)
    print("--- %d constant pairs compared against fw/*/Image derivations ---" % n)
    if bad:
        print("MISMATCH (the APK route would ship these while pgdalias disagrees):")
        for b in bad:
            print("  " + b)
        return 1
    print("GATE CONSTANTS AGREE (clobber.c == pgdalias, both profiles)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
