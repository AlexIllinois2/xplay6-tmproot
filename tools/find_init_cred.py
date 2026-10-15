#!/usr/bin/env python3
"""Locate init_cred (and init_task) in our stock arm64 Image.

Neither is in kallsyms (CONFIG_KALLSYMS without KALLSYMS_ALL lists code symbols
only), and .bss is absent from the Image -- but init_cred and init_task are both in
.data (initialised), so their byte patterns are present.

Method 1 (cred shape): { usage(u32)=1, subscribers=0, uid..fsgid (8*u32)=0,
  securebits=0, cap_inheritable(u64)=0, cap_permitted=cap_effective=cap_bset=
  0x3fffffffff }.

Method 2 (independent): 3.18 arm64 task_struct starts with thread_info whose +0x10
  field is `task`, i.e. init_task+0x10 == &init_task -- a self-pointer into .data.
  Then init_cred = [init_task + 0x4a8] with the cred offset measured in ledger S32.
The two must agree; that agreement is the verification, not a bonus.
"""
import struct

TEXT_BASE = 0xFFFFFFC000080000
IMG = "/home/v/.local/project/xplay6/fw/Image"
OFF_CRED = 0x4a8
CAP_FULL = 0x0000003FFFFFFFFF

data = open(IMG, "rb").read()
print("Image size %x" % len(data))

pat = (struct.pack("<II", 1, 0) + b"\x00" * 40 + struct.pack("<Q", 0) +
       struct.pack("<QQQ", CAP_FULL, CAP_FULL, CAP_FULL))
cands = []
pos = 0
while True:
    i = data.find(pat, pos)
    if i < 0:
        break
    cands.append(i)
    pos = i + 1
print("method1 cred-shape candidates: %d" % len(cands))
for c in cands:
    print("   foff %x  VA %016x   next fields: %s" % (
        c, c + TEXT_BASE,
        " ".join("%016x" % f for f in struct.unpack("<4Q", data[c + 56:c + 88]))))

# method 2: slot V (a .data VA) whose own +0x10 dword equals V
ti = []
for i in range(0, len(data) - 0x18, 8):
    v = struct.unpack("<Q", data[i:i + 8])[0]
    if not (TEXT_BASE <= v < TEXT_BASE + len(data)):
        continue
    off = v - TEXT_BASE
    if off + 0x18 <= len(data) and struct.unpack("<Q", data[off + 0x10:off + 0x18])[0] == v:
        ti.append((v, i))
print("method2 thread_info-style self-pointer candidates: %d" % len(ti))
for v, i in ti[:10]:
    cred = struct.unpack("<Q", data[(v - TEXT_BASE) + OFF_CRED:
                                    (v - TEXT_BASE) + OFF_CRED + 8])[0]
    rc = struct.unpack("<Q", data[(v - TEXT_BASE) + 0x658:
                                  (v - TEXT_BASE) + 0x660])[0]
    print("   task VA %016x (referenced from foff %x)  cred=%016x real_cred=%016x %s" % (
        v, i, cred, rc,
        "<== cred MATCHES method1" if any(c + TEXT_BASE == cred for c in cands) else ""))
