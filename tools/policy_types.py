#!/usr/bin/env python3
"""Dump SELinux type name -> value for the policy the device actually loaded.

Record layout (measured on fw/policy.running, which is byte-identical to the
ramdisk's sepolicy at the symbol tables): [u32 len][u32 value][u32 flavor][u32 0][name].
Names are length-prefixed, NOT NUL-terminated -- the next record's len follows the
last name byte immediately, which is why a name+NUL search finds nothing.

qti_init_shell must come out as 241: that value is the one whose bit in
policydb.permissive_map was verified to exempt the daemon on the device.
"""
import struct, sys

path = sys.argv[1]
d = open(path, "rb").read()
H = 16
recs = {}
for o in range(0, len(d) - H):
    ln, val, flav, zero = struct.unpack_from("<IIII", d, o)
    if not (2 <= ln <= 64) or not (1 <= val <= 0x8000) or flav > 3 or zero:
        continue
    nm = d[o + H:o + H + ln]
    if len(nm) != ln or not all(32 <= c < 127 for c in nm):
        continue
    if flav == 1:                       # TYPE_PRIMARY
        recs.setdefault(nm.decode("latin1"), val)

print("# %s: %d primary types, values %d..%d" % (path, len(recs), min(recs.values()), max(recs.values())))
for want in ("kernel", "init", "shell", "qti_init_shell", "untrusted_app",
             "untrusted_app_25", "priv_app", "platform_app", "system_app", "radio"):
    print("%-18s %s" % (want, recs.get(want, "ABSENT")))
assert recs.get("qti_init_shell") == 241, "positive control failed: %r" % recs.get("qti_init_shell")
out = sys.argv[2] if len(sys.argv) > 2 else None
if out:
    with open(out, "w") as f:
        for n, v in sorted(recs.items(), key=lambda kv: kv[1]):
            f.write("%d\t%s\n" % (v, n))
    print("# wrote %s" % out)
