#!/usr/bin/env python3
"""tools/tfa_reg_fields.py -- name every register codec_reg exposes, from the running driver's own tables.

Three binary-derived inputs, no device counting:
  tfa98xx_regs   .rodata byte list in fw/Image = the whitelist codec_reg iterates
                 (loop bound cmp x20, #0x1a in tfa98xx_debug_reg_read)
  TfaBfNames     bitfield table dumped by tools/tfa_bf_table.py; decode rule addr = enum >> 8,
                 pos = (enum >> 4) & 0xf, len = (enum & 0xf) + 1  -- proven in tfaRunWriteBitfield
                 (ubfx #8,#8 -> snd_soc_read/snd_soc_write address, no TFA1->TFA2 remap)
  tfa-regs.PD1610.tsv  register names decoded from fw/tfa-ref/inc/tfa98xx_genregs_N1C.h

A register with no genregs name still gets a meaning: the set of bitfields the driver can
resolve inside it. That is how the 13 NO-NAME rows stop being blank.

Usage: tools/tfa_reg_fields.py [--out PATH]
"""
import argparse
import csv
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEXT_BASE = 0xFFFFFFC000080000
ART = os.path.join(ROOT, "art/audio-6.0.1")
IMG = os.path.join(ROOT, "fw/Image")
KALL = os.path.join(ROOT, "art/kallsyms_real.txt")


def sym_va(name):
    for line in open(KALL, encoding="utf-8", errors="replace"):
        p = line.split()
        if len(p) == 3 and p[2] == name:
            return int(p[0], 16)
    sys.exit(f"gate: symbol {name} not in kallsyms")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=os.path.join(ART, "tfa-reg-fields.PD1610.tsv"))
    args = ap.parse_args()

    blob = open(IMG, "rb").read()
    va = sym_va("tfa98xx_regs")
    fo = va - TEXT_BASE
    # the list is NOT NUL-terminated -- its first byte is register 0x00. Only the code knows the
    # length: tfa98xx_debug_reg_read loops until cmp x20, #0x1a.
    COUNT = 26
    wl = list(blob[fo:fo + COUNT])
    if len(wl) != COUNT:
        sys.exit(f"gate: tfa98xx_regs truncated at {len(wl)} bytes, expected {COUNT} (cmp x20,#0x1a)")
    pad = blob[fo + COUNT:fo + COUNT + 16]
    run = len(pad) - len(pad.lstrip(b"\0"))
    if run == 0:
        sys.exit(f"gate: byte 27 after the list is {pad[0]:#04x}, not a null -- the length {COUNT} is wrong")
    if wl != sorted(wl):
        sys.exit(f"gate: whitelist is not ascending ({[hex(a) for a in wl]}) -- re-read the table")

    bfpath = os.path.join(ART, "tfa-bf.TfaBfNames.tsv")
    if not os.path.exists(bfpath):
        sys.exit(f"gate: run tools/tfa_bf_table.py first -- {bfpath} missing")
    fields = {}
    for r in list(csv.DictReader(open(bfpath), delimiter="\t")):
        fields.setdefault(int(r["addr"], 16), []).append((r["name"], int(r["pos"]), int(r["len"])))

    regpath = os.path.join(ART, "tfa-regs.PD1610.tsv")
    regname = {}
    if os.path.exists(regpath):
        for r in csv.DictReader(open(regpath), delimiter="\t"):
            regname[int(r["reg"], 16)] = r["name"]

    rows, named, empty = [], 0, []
    for a in wl:
        fs = fields.get(a, [])
        names = sorted({f"{n}[{p + ln - 1}:{p}]" for n, p, ln in fs})
        rn = regname.get(a, "")
        if rn == "" or rn.startswith("NO-NAME"):
            rn = ""
        else:
            named += 1
        if not names:
            empty.append(a)
        rows.append((a, rn or "-", len(fs), " ".join(names) if names else "-"))

    with open(args.out, "w", encoding="utf-8", newline="") as fh:
        fh.write("reg\tgenregs_name\tnfields\tbitfields_addr_pos_len\n")
        for a, rn, nf, lst in rows:
            fh.write(f"{a:#04x}\t{rn}\t{nf}\t{lst}\n")

    print(f"whitelist from tfa98xx_regs @ {va:#x}: {len(wl)} registers, then {run} null byte(s)")
    print(f"genregs-named: {named}/{len(wl)}   with >=1 driver bitfield: {len(wl) - len(empty)}/{len(wl)}")
    if empty:
        print(f"registers with NO resolvable bitfield: {[hex(a) for a in empty]}")
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
