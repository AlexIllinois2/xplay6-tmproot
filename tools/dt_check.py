#!/usr/bin/env python3
"""tools/dt_check.py -- verify the board-level TFA acceptance windows, and say what the driver would
fall back to if a property is missing.

Why the fallback matters (ledger 258/259): tfa98xx_i2c_probe reads five vivo,tfa98xx-* limits with
of_property_read_u32_array and, on failure, stores a COMPILED-IN default into the same struct fields
(+0xb8..+0xc8) that fRes_Detect later uses as the f0 window. So an Android-7 device tree that simply
drops one property does not error out -- it silently changes the PA's acceptance window, which is a
hearing-relevant difference with no log line.

Reference = art/audio-6.0.1/live/tfa-dt-props.PD1610.tsv (read off this machine's live tree, §232).
Values are read big-endian from /sys/firmware/devicetree/base, the way the kernel sees them.

Usage: tools/dt_check.py [--adb adb] [--node <dt path>]
"""
import argparse
import csv
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NODE = "/sys/firmware/devicetree/base/soc/i2c@75b6000/spkamp@34"
# struct offset <- property, and the value tfa98xx_i2c_probe stores when the read fails
DEFAULTS = {
    "vivo,tfa98xx-impedance-min": ("+0xb8", 500),
    "vivo,tfa98xx-impedance-max": ("+0xbc", 1100),
    "vivo,tfa98xx-frequency-min": ("+0xc0", 600),
    "vivo,tfa98xx-frequency-max": ("+0xc4", 1000),
    "vivo,tfa98xx-Qt-min": ("+0xc8", 135),
}


SU = os.environ.get("SU", "su")
# on the 7.1.1 firmware the vendor name gate refuses execve of any path whose last component is
# exactly "su" (measured: a symlink NAMED su is refused too, while the same file reached under another
# name runs) -- so the client is mounted as `sux` and run as SU=sux.  Silent zero here would otherwise
# be read as "the device tree lost its properties".

def sh(adb, cmd):
    """exec-out (no PTY) with stdin closed: `adb shell su -c ...` allocates a pty and blocks
    forever when nobody is feeding it -- that hung this tool's first run"""
    try:
        p = subprocess.run([adb, "exec-out", f"{SU} -c '{cmd}'"], capture_output=True, text=True,
                           stdin=subprocess.DEVNULL, timeout=30)
    except subprocess.TimeoutExpired:
        sys.exit("gate: adb call timed out (30 s) -- not reporting that as a device difference")
    return p.stdout


def read_props(adb, node):
    """one round trip for every property: od prints hex, shell prints name=hex"""
    out = sh(adb, f'cd {node} && for f in vivo,tfa98xx-*; do echo "$f=$(od -An -tx1 "$f" | tr -d " \\n")"; done')
    got = {}
    for line in out.replace("\r", "").splitlines():
        m = re.match(r"^(vivo,tfa98xx-[A-Za-z0-9._-]+)=([0-9a-f ]*)$", line.strip())
        if m:
            got[m.group(1)] = bytes.fromhex(m.group(2).replace(" ", "")) if m.group(2) else None
    return got


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--adb", default="adb")
    ap.add_argument("--node", default=NODE)
    ap.add_argument("--ref", default=os.path.join(ROOT, "art/audio-6.0.1/live/tfa-dt-props.PD1610.tsv"))
    args = ap.parse_args()

    if not os.path.exists(args.ref):
        sys.exit(f"gate: reference DT dump missing ({args.ref}) -- that is §232's artifact")
    ref = {}
    for r in csv.reader(open(args.ref), delimiter="\t"):
        if len(r) >= 3 and r[0].strip().startswith("vivo,tfa98xx"):
            ref[r[0].strip()] = (r[1].strip(), r[2].strip())
    if len(ref) < 5:
        sys.exit(f"gate: reference has only {len(ref)} vivo,tfa98xx-* rows -- refusing a partial denominator")

    bad = 0
    props = read_props(args.adb, args.node)
    print(f"node {args.node}  (reference: {len(ref)} vivo,tfa98xx-* properties; "
          f"device returned {len(props)})")
    if not props:
        sys.exit("gate: the device call produced no parseable properties -- that is a tool/transport "
                 "failure, NOT evidence about the tree")
    for name, (kind, want) in sorted(ref.items()):
        raw = props.get(name)
        if raw is None:
            fallback = DEFAULTS.get(name)
            bad += 1
            if fallback:
                print(f"  MISSING  {name}: absent -> driver uses compiled default {fallback[1]} at {fallback[0]} "
                      f"(baseline wanted {want})")
            else:
                print(f"  MISSING  {name}: absent (baseline wanted {want!r})")
            continue
        nums = re.fullmatch(r"\d+(,\s*\d+)*", want.strip())
        if nums and len(raw) % 4 == 0:
            got = ",".join(str(int.from_bytes(raw[i:i + 4], "big")) for i in range(0, len(raw), 4))
        else:
            got = raw.split(b"\0")[0].decode("latin-1", "replace")
        norm = lambda s: [x.strip() for x in str(s).split(",")]
        if norm(got) != norm(want):
            bad += 1
            print(f"  DIFFER   {name}: now {got!r} vs baseline {want!r}   [{raw.hex(' ')}]")
        else:
            print(f"  OK       {name} = {got}")
    print(f"\nverdict: mismatched/missing={bad}")
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
