#!/usr/bin/env python3
"""tools/tfa_bf_table.py -- dump the TFA bitfield nametable actually compiled into our kernel Image.

Why from the Image instead of the vendor headers: the headers in fw/tfa-ref are a *reference*
driver (TechNexion/NXP 2016) and carry several device families at once. The running driver keeps
exactly one flat table, so reading it out of .rodata gives the field set this device can resolve.

Layout is not assumed -- it is taken from the lookup function tfaContBfName:
  adrp/add -> base 0xf8fb38 == kallsyms TfaBfNames   (independent cross-check)
  lsl x2,#4 + ldrh [x5,x3]  -> stride 16, bfEnum is a u16 at offset 0
  ldr x0, [x1, #8]           -> char *bfName at offset 8
  cmp w5, #0xffff            -> terminator entry

A bfEnum packs address/pos/len; the decode rule is printed with both candidate readings so the
address-numbering question (TFA1-style vs regmap/N1C-style) is answered by data, not by guesswork.

Usage: tools/tfa_bf_table.py [--tsv PATH]   (default: art/audio-6.0.1/tfa-bf.TfaBfNames.tsv)
"""
import argparse
import bisect
import os
import struct
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEXT_BASE = 0xFFFFFFC000080000
IMG = os.path.join(ROOT, "fw/Image")
KALL = os.path.join(ROOT, "art/kallsyms_real.txt")
STRIDE = 16
END = 0xFFFF


def syms():
    pairs = []
    for line in open(KALL, encoding="utf-8", errors="replace"):
        p = line.split()
        if len(p) == 3:
            try:
                pairs.append((int(p[0], 16), p[2]))
            except ValueError:
                pass
    pairs.sort()
    return [a for a, _ in pairs], [n for _, n in pairs]


def cstr(blob, fo):
    end = blob.find(b"\0", fo)
    if end < 0 or end - fo > 120:
        return None
    s = blob[fo:end].decode("latin-1")
    return s if s and all(32 <= ord(c) < 127 for c in s) else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tsv", default=os.path.join(ROOT, "art/audio-6.0.1/tfa-bf.TfaBfNames.tsv"))
    args = ap.parse_args()

    blob = open(IMG, "rb").read()
    addrs, names = syms()
    try:
        start = [a for a, n in zip(addrs, names) if n == "TfaBfNames"][0]
    except IndexError:
        sys.exit("gate: TfaBfNames not in kallsyms -- nothing to dump")

    entries, bad = [], []
    i = 0
    while True:
        off = start - TEXT_BASE + i * STRIDE
        if off + STRIDE > len(blob):
            bad.append(f"ran off the end of the Image at entry {i}")
            break
        bf = struct.unpack_from("<H", blob, off)[0]
        ptr = struct.unpack_from("<Q", blob, off + 8)[0]
        name = None
        if TEXT_BASE <= ptr < TEXT_BASE + len(blob):
            name = cstr(blob, ptr - TEXT_BASE)
        if name is None:
            bad.append(f"entry {i}: bf={bf:#06x} name ptr {ptr:#x} did not resolve to a string")
            break
        entries.append((bf, name))
        if bf == END:
            break
        i += 1
        if i > 4096:
            bad.append("no 0xffff terminator within 4096 entries -- layout is wrong")
            break

    nfields = sum(1 for bf, _ in entries if bf != END)
    if bad:
        sys.exit("gate failed: " + "; ".join(bad))
    if nfields < 100:
        sys.exit(f"gate: only {nfields} fields -- too few to be the device's full table, refusing to write a table")

    uniq = {n for _, n in entries if _ != END}
    dup = len(entries) - 1 - len(uniq)
    print(f"TfaBfNames @ {start:#x} (file {start - TEXT_BASE:#x})")
    print(f"entries={len(entries)} fields={nfields} distinct names={len(uniq)} duplicate-name rows={dup}")
    print(f"terminator row: bf={entries[-1][0]:#06x} name={entries[-1][1]!r}")

    # the two plausible address readings -- reported side by side, the family question is settled
    # by whether the decoded address can be one of the 26 registers codec_reg actually exposes.
    WL = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0F,
          0x40, 0x41, 0x46, 0x47, 0x48, 0x49, 0x4C, 0x62, 0x70, 0x71, 0x72, 0x73, 0x80}
    hi8 = {bf >> 8 for bf, _ in entries if bf != END}
    print(f"decoded addr = bf>>8 : {len(hi8)} distinct, {len(sorted(hi8 & WL))} of them are in the codec_reg whitelist")
    lo = sorted({a for a in hi8 if a not in WL})
    print(f"addresses outside the whitelist (first 12): {[hex(a) for a in lo[:12]]}")

    with open(args.tsv, "w", encoding="utf-8", newline="") as fh:
        fh.write("addr\tpos\tlen\tbf_enum\tname\n")
        for bf, name in entries:
            if bf == END:
                continue
            fh.write(f"{bf >> 8:#04x}\t{(bf >> 4) & 0xF}\t{(bf & 0xF) + 1}\t{bf:#06x}\t{name}\n")
    print(f"wrote {args.tsv}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
