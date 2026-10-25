#!/usr/bin/env python3
"""Dump the FULL type name -> live index table out of a loaded-policy blob.

The record layout is the one tools/policy_types.py measured (primary symbol records:
[u32 len][u32 value][u32 flavor==1][u32 0][name], names length-prefixed).  This tool emits
the complete "index<TAB>name" table the gates compare exemption lists against, plus a
provenance header -- the same shape art/policy-types-7-live.tsv has, so the authority for
a firmware is a file whose source dump, size and md5 are written where the numbers are.

usage: gen_policy_tsv.py <policy.bin> <label> [<control name=expect> ...]
       control re-runs the positive-control assert policy_types.py made famous: one
       name/value pair that was PROVEN on-device (planted bit == exempt domain) pins the
       whole numbering, file-vs-runtime drift included (ledger 545).
"""
import hashlib
import struct
import sys

path, label = sys.argv[1], sys.argv[2]
controls = dict(a.split("=", 1) for a in sys.argv[3:])
d = open(path, "rb").read()
by_name = {}
H = 16
for o in range(0, len(d) - H):
    ln, val, flav, zero = struct.unpack_from("<IIII", d, o)
    if not (2 <= ln <= 64) or not (1 <= val <= 0x8000) or flav != 1 or zero:
        continue
    nm = d[o + H:o + H + ln]
    if len(nm) != ln or not all(32 <= c < 127 for c in nm):
        continue
    name = nm.decode("latin1")
    if name not in by_name:          # first record wins, same as policy_types.py
        by_name[name] = val

vals = sorted(by_name.values())
print("# LIVE type index table, parsed from %s (%s)." % (path.split("/")[-1], label))
print("# source dump: %d bytes, md5 %s ; %d primary types, values %d..%d"
      % (len(d), hashlib.md5(d).hexdigest(), len(by_name), vals[0], vals[-1]))
for k, v in controls.items():
    want = by_name.get(k)
    if want is None:
        raise SystemExit("positive control %s: ABSENT from the policy" % k)
    if str(want) != v:
        raise SystemExit("positive control failed: %s = %d, expected %s" % (k, want, v))
    print("# positive control: %s = %s" % (k, v))
if not controls:
    print("# single-source until an on-device control names them (planted bit == exempt domain)")
for v, n in sorted((v, n) for n, v in by_name.items()):
    print("%d\t%s" % (v, n))
