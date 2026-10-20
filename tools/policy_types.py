#!/usr/bin/env python3
"""Dump SELinux type name -> value for the policy the device actually loaded.

Record layout (measured on fw/policy.running, which is byte-identical to the
ramdisk's sepolicy at the symbol tables): [u32 len][u32 value][u32 flavor][u32 0][name].
Names are length-prefixed, NOT NUL-terminated -- the next record's len follows the
last name byte immediately, which is why a name+NUL search finds nothing.

qti_init_shell must come out as 241: that value is the one whose bit in
policydb.permissive_map was verified to exempt the daemon on the device.
"""
import os
import struct
import sys

path = sys.argv[1]
d = open(path, "rb").read()
H = 16
by_name = []
allrec = []
recs = {}
for o in range(0, len(d) - H):
    ln, val, flav, zero = struct.unpack_from("<IIII", d, o)
    if not (2 <= ln <= 64) or not (1 <= val <= 0x8000) or flav > 3 or zero:
        continue
    nm = d[o + H:o + H + ln]
    if len(nm) != ln or not all(32 <= c < 127 for c in nm):
        continue
    if flav == 1:                       # TYPE_PRIMARY
        by_name.append((nm.decode("latin1"), val))

recs = {}
for n, v in by_name:
    recs.setdefault(n, v)

for want in ("kernel", "init", "shell", "qti_init_shell", "untrusted_app",
             "untrusted_app_25", "priv_app", "platform_app", "system_app", "radio"):
    print("%-18s %s" % (want, recs.get(want, "ABSENT")))

# The positive control is per-firmware: 241 is the 6.0.1 qti_init_shell, the value whose
# permissive_map bit was measured on-device to exempt the daemon.  A second policy must be given
# its own expected value -- and until that number has been confirmed on that device the same way,
# the value below is ONE-source (this walker only), not two.  Structural arms were tried here and
# removed as invalid: the 16-byte [len][value][flavor][0][name] record shape is shared by the user,
# role and type tables, so "value 1 is claimed twice" (role `r@` and type `adbd_socket`) and "the
# primary values are not dense 1..n" both fire on a *correct* decode.  Rejecting the good case is
# worse than no arm, so the denominator reported is only the count and the range.
print("# %s: %d primary type records, values %d..%d -- single-source until an on-device control names them"
      % (path, len(recs), min(recs.values()), max(recs.values())))
ctrl = os.environ.get("EXPECT_CTRL", "241")
ctrl_name = os.environ.get("EXPECT_NAME", "qti_init_shell")
got = recs.get(ctrl_name)
assert got == int(ctrl), "positive control failed: %s = %r, expected %s" % (ctrl_name, got, ctrl)
print("# control: %s = %s as expected" % (ctrl_name, got))
out = sys.argv[2] if len(sys.argv) > 2 else None
if out:
    with open(out, "w") as f:
        for n, v in sorted(recs.items(), key=lambda kv: kv[1]):
            f.write("%d\t%s\n" % (v, n))
    print("# wrote %s" % out)
