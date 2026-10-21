#!/usr/bin/env python3
"""tools/dt_string_refs.py -- which kernel function materialises the address of a device-tree
property NAME, i.e. who even mentions this string.  This is the other half of dt_prop_reads.py:
that tool walks `bl of_*` sites inside named functions; this one starts from the STRING and finds
the functions, so a property that appears on one firmware and not the other can be traced to code
without first guessing which driver reads it.

Method (and why it is not a grep):
  1. locate the NUL-terminated name in the image (a unique hit is required -- an ambiguous hit is
     reported, not silently picked);
  2. VA = file offset + link base;
  3. scan text for ADRP+ADD pairs that build exactly that VA (the ARM64 way of loading a string
     address; `adrp` alone only gives the page, so the pair is decoded together);
  4. map each site to its function by "next symbol" bounds (the same convention §325 had to adopt
     after a fixed instruction count walked out of a function into its neighbour).

Calibration is mandatory: --control asks for a string whose reader is already proven, and the tool
refuses to publish a 0-hit verdict for any other string unless the control hit.  §325/§355 both
produced a false "nobody reads it" from a blind scan, so silence is only ever reported as silence.

usage: tools/dt_string_refs.py --strings vivo,wcd-hph-gain,vivo,wcd-imped-defs \
       [--control vivo,param-num --control-reader es9038_i2c_probe] [--out TSV]
       DT_IMG=/path/to/Image DT_KALL=/path/to/kallsyms  (defaults: the 6.0.1 pair)
"""
import argparse
import bisect
import csv
import os
import re
import struct
import sys

from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, Cs

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IMG = os.environ.get("DT_IMG") or os.path.join(ROOT, "fw", "Image")
KALL = os.environ.get("DT_KALL") or os.path.join(ROOT, "art", "kallsyms_real.txt")
TEXT_BASE = int(os.environ.get("DT_TEXT_BASE", "0xFFFFFFC000080000"), 0)


def load():
    img = open(IMG, "rb").read()
    syms = []
    for line in open(KALL):
        p = line.split()
        if len(p) != 3:
            continue
        try:
            va = int(p[0], 16)
        except ValueError:
            continue
        if va >= TEXT_BASE:
            syms.append((va, p[2]))
    syms.sort()
    return img, [s[0] for s in syms], syms


def owner(vas, syms):
    i = bisect.bisect_right(vas, syms[0][0] if syms else 0)
    return None


def name_of(sorted_vas, names, va):
    i = bisect.bisect_right(sorted_vas, va) - 1
    return names[i] if i >= 0 else None


def find_string(img, s):
    """all file offsets holding the NUL-terminated name, plus an occurrence NOT at a string start"""
    pat = s.encode() + b"\0"
    hits = [m.start() for m in re.finditer(re.escape(pat), img)]
    # keep only hits whose previous byte is NUL or non-printable => a string start, not a suffix
    starts = [o for o in hits if o == 0 or not (32 <= img[o - 1] < 127)]
    return hits, starts


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--strings", default="", help="semicolon-separated DT property names")
    ap.add_argument("--vas", default="",
                    help="extra absolute addresses to look for (e.g. a global the DT array is read into)"
                    " -- same ADRP+ADD machinery, reported per VA")
    ap.add_argument("--control", default="vivo,param-num")
    ap.add_argument("--control-reader", default="es9038_i2c_probe",
                    help="the function §287 proved reads --control; the control must land in it")
    ap.add_argument("--out")
    ap.add_argument("--max-text", type=int, default=0, help="cap on decoded bytes (0 = all text)")
    a = ap.parse_args()

    img, vas, pairs = load()
    names = [n for _v, n in pairs]
    text_lo = vas[0] if vas else TEXT_BASE
    text_hi = vas[-1] if vas else len(img) + TEXT_BASE
    lo, hi = text_lo - TEXT_BASE, min(len(img), text_hi - TEXT_BASE + 0x400000)
    if a.max_text:
        hi = min(hi, lo + a.max_text)
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True

    want = {}
    # ";" is the separator because DT property NAMES contain commas (vivo,wcd-hph-gain)
    extra = [x for x in a.vas.split(";") if x]
    for s in [x for x in a.strings.split(";") if x] + ([a.control] if a.control else []):
        hits, starts = find_string(img, s)
        want[s] = (hits, starts, [TEXT_BASE + o for o in starts])
        print(f"  string {s:34} raw hits {len(hits)} string-starts {len(starts)} "
              f"VA {['%x' % v for v in want[s][2]][:4]}")
    targets = {}
    for s, (_h, _st, ves) in want.items():
        for v in ves:
            targets.setdefault(v, []).append(s)
    for x in extra:
        targets.setdefault(int(x, 16), []).append("<va:" + x + ">")
    if not want and not extra:
        sys.exit("gate: nothing asked for")
    if not targets:
        sys.exit("gate: none of the requested names is in the image as a string -- "
                 "that is a claim about the naming, not about the code")

    # decode text once, tracking adrp pages per register (ADRP gives page, ADD completes the offset)
    pages = {}
    sites = []
    chunk = 0x40000
    for base in range(lo, hi, chunk):
        code = img[base:min(base + chunk + 8, hi)]
        for ins in md.disasm(code, base + TEXT_BASE):
            m = ins.mnemonic
            ops = ins.op_str
            if m == "adrp":
                r, val = ops.split(", ")
                pages[r] = int(val.lstrip("#"), 0)
            elif m == "add" and ", #" in ops:
                parts = ops.split(", ")
                if len(parts) < 3:
                    continue
                r, base2, off = parts[0], parts[1], parts[-1]
                if not off.startswith("#"):
                    continue
                if base2 in pages:
                    try:
                        va = pages[base2] + int(off.lstrip("#"), 0)
                    except ValueError:
                        continue
                    # CUMULATIVE ADDS: the compiler emits `adrp x2,page` then `add x2,x2,#0x218` then
                    # `add x2,x2,#0x430`, so the tracked value must move with the register -- keeping the
                    # bare page made every second-and-later address wrong (and any target in the middle
                    # invisible).  This is the same class of slip as §356's "write invalidates the page".
                    pages[r] = va
                    if va in targets:
                        sites.append((ins.address, targets[va]))
            elif m in ("ldr", "ldrb", "ldrh", "ldrsb", "ldrsh", "str", "strb", "strh", "stp", "ldp"):
                # a data global is usually reached as `adrp x, page` + `ldr x0, [x, #lo]` -- NOT via ADD.
                # Only ADD was recognised before, so every reference to a plain array looked like absence.
                mm = re.search(r"\[(x\d+|sp)(?:, #(0x[0-9a-f]+|-?\d+))?", ops)
                if mm and mm.group(1) in pages and mm.group(2):
                    try:
                        va2 = pages[mm.group(1)] + int(mm.group(2).lstrip("#"), 0)
                    except ValueError:
                        va2 = None
                    if va2 in targets:
                        sites.append((ins.address, [t + " [via " + m + "]" for t in targets[va2]]))
                for rr in re.findall(r"\b(x\d+|w\d+|sp)\b", ops):
                    pages.pop(rr, None)
            elif m in ("cbz", "cbnz", "tbz", "tbnz", "cmp", "subs"):
                # a write/compare through the register means the page value is no longer a plain
                # string address -- invalidate so a later ADD cannot fabricate a reference
                for rr in re.findall(r"\b(x\d+|w\d+|sp)\b", ops):
                    pages.pop(rr, None)
            elif m == "bl":
                # A call clobbers only the CALLER-SAVED registers (x0-x18, x30). Wiping everything made
                # every `adrp x19/20/21.. ; bl ...; ldr [x19, #off]` pattern invisible -- which is exactly
                # how a known-referenced global (es9038_data, proven by §323) came back as "no referrer".
                for rr in [f"x{i}" for i in range(19)] + ["x30", "w0", "w18"]:
                    pages.pop(rr, None)

    rows = []
    control_ok = not bool(a.control)
    for addr, labels in sites:
        fn = name_of(vas, names, addr)
        for s in labels:
            rows.append((s, "%x" % addr, fn or "?"))
            if s == a.control and fn == a.control_reader:
                control_ok = True
    if a.control:
        print(f"\ncalibration: does the tool place `{a.control}` inside {a.control_reader}? "
              + ("YES" if control_ok else "NO"))
    else:
        print("\ncalibration: no --control given, so nothing here is anchored -- "
              "0-hit lines are UNMEASURED, not absences")
    if not control_ok:
        print("  => every 0-hit line below is UNMEASURED, not a finding. Printing the sites that were "
              "found anyway:")
    for s in list(want) + ["<va:" + x + ">" for x in extra]:
        got = sorted({r[2] for r in rows if r[0] == s})
        print(f"  {s:34} sites {sum(1 for r in rows if r[0] == s):3} functions: "
              f"{', '.join(got) if got else ('NO REFERRER FOUND' + ('' if control_ok else ' (UNMEASURED)'))}")
    if a.out:
        with open(a.out, "w", encoding="utf-8") as fh:
            fh.write("property\tsite_va\tfunction\n")
            for r in rows:
                fh.write("\t".join(r) + "\n")
        print(f"wrote {a.out} ({len(rows)} sites)")
    return 0 if control_ok else 1


if __name__ == "__main__":
    sys.exit(main())
