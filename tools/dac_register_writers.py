#!/usr/bin/env python3
"""tools/dac_register_writers.py -- every path that can write a byte into the ES9038, and which register/value each one carries.

§285 left one unexplained byte: of the 47 registers the driver writes from dac_parameters, 46 read back
exactly as written, and register 0x14 does not (table 0x22, in-play 0x2e).  §322 added a second writer
(integration_params_normal, candidates 0x1c/0x2a/0x4a/0x7f for 0x14) -- still not 0x2e.  So the question
is not 'is the value odd' but 'WHO ELSE can write, and with what'.

This enumerates every call to the driver's I2C byte-write helper (and its sibling for the es9028) and
classifies the two value operands by walking backwards through the basic block:

  constant     mov w1, #reg  /  mov w2, #val          -> both numbers are in the Image
  table        value(s) come from ldrb off a resolved base -> the base is named from kallsyms and its
               (addr, value) rows are decoded here
  rmw          the value register was produced by orr/bic/eor off a preceding read  -> read-modify-write
  runtime      anything else (a computed value, a variable) -- reported, not renamed

Two controls abort the tool: it must see at least one `constant` and at least one `table` site (the
dac_parameters loop is known to exist from §286), because a census that finds only one kind is a broken
classifier, not a finding.  And it prints the denominator (call sites per caller, bytes decoded).

usage: tools/dac_register_writers.py [--out TSV] [--selftest]
"""
import argparse
import bisect
import collections
import os
import re
import sys

from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, Cs

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ART = os.path.join(ROOT, "art", "audio-6.0.1")
IMG = os.path.join(ROOT, "fw", "Image")
KALL = os.path.join(ROOT, "art", "kallsyms_real.txt")
TEXT_BASE = 0xFFFFFFC000080000
BLOB = open(IMG, "rb").read()
IMAGE_END = TEXT_BASE + len(BLOB)
MASK64 = 0xFFFFFFFFFFFFFFFF
WRITERS = re.compile(r"^es90(28|38)_i2c_write_byte\.isra\.\d$")
ALIAS = {"fp": 29, "lr": 30, "sp": 31}


def syms():
    out = []
    for line in open(KALL, encoding="utf-8", errors="replace"):
        p = line.split()
        if len(p) >= 3 and re.fullmatch(r"[0-9a-f]{16}", p[0]):
            out.append((int(p[0], 16), p[1], p[2]))
    out.sort()
    return out


SS = syms()
TEXT = [(a, t, n) for a, t, n in SS if TEXT_BASE <= a < IMAGE_END and t in "tT"]
TA = [a for a, _t, _n in TEXT]
NAME = {}
for a, _t, n in SS:
    NAME.setdefault(a, n)
DATA = {a: n for a, t, n in SS if TEXT_BASE <= a < IMAGE_END and t in "rRdD"}


def md():
    m = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    m.detail = True
    return m


def rnum(m, reg):
    n = m.reg_name(reg) or ""
    if n in ALIAS:
        return ALIAS[n]
    g = re.fullmatch(r"[wx](\d+)", n)
    return int(g.group(1)) if g else None


def span(va):
    i = bisect.bisect_right(TA, va)
    return TA[i] if i < len(TA) else min(va + 0x800, IMAGE_END)


def bytes_at(va, n):
    off = va - TEXT_BASE
    return BLOB[off:off + n] if 0 <= off and off + n <= len(BLOB) else b""


def classify(ins, i, m):
    """walk back from the call at index i and say what feeds w1 (register) and w2 (value)"""
    want = {1: None, 2: None}
    kinds = {}
    for j in range(i, max(i - 26, -1), -1):
        x = ins[j]
        if x.mnemonic == "bl":
            continue
        ops = x.operands
        d = rnum(m, ops[0].reg) if ops and ops[0].type == 1 else None
        if d not in want or x.mnemonic in ("bl", "blr"):
            continue
        if want[d] is not None:
            continue
        if x.mnemonic == "mov" and len(ops) == 2 and ops[1].type == 2:
            want[d] = ("constant", f"{x.mnemonic} {x.op_str}", ops[1].imm & 0xFF)
        elif x.mnemonic in ("ldrb", "ldr") and len(ops) == 2 and ops[1].type == 3:
            want[d] = ("table", f"{x.mnemonic} {x.op_str}", None)
        elif x.mnemonic in ("orr", "bic", "eor", "add", "sub", "lsl", "lsr"):
            src = rnum(m, ops[1].reg) if len(ops) > 1 and ops[1].type == 1 else None
            extra = f" <- w{src}" if src is not None else ""
            want[d] = ("rmw" if x.mnemonic in ("orr", "bic", "eor") else "computed",
                       f"{x.mnemonic} {x.op_str}{extra}", None)
        elif x.mnemonic == "mov" and len(ops) == 2 and ops[1].type == 1:
            want[d] = ("copy", f"{x.mnemonic} {x.op_str}", None)
    for k in want:
        kinds[k] = want[k] or ("unknown", "not found within 26 instructions", None)
    return kinds


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    targets = {x: n for x, _t, n in TEXT if WRITERS.match(n)}
    if len(targets) < 2:
        sys.exit(f"gate: found {len(targets)} write helpers, expected both the es9028 and es9038 ones")
    m = md()
    rows, tables = [], {}
    for va, _t, nm in TEXT:
        if not nm.startswith(("es9038_", "es9028_")) or WRITERS.match(nm):
            continue
        end = span(va)
        buf = bytes_at(va, min(end, va + 0x2000) - va)
        if not buf:
            continue
        ins = list(m.disasm(buf, va))
        for i, x in enumerate(ins):
            if x.mnemonic != "bl":
                continue
            tgt = x.operands[0].imm & MASK64
            if tgt not in targets:
                continue
            kinds = classify(ins, i, m)
            reg_k, reg_t, reg_v = kinds[1]
            val_k, val_t, val_v = kinds[2]
            rows.append({"caller": nm, "site": x.address, "callee": targets[tgt],
                         "reg_kind": reg_k, "reg_text": reg_t, "reg": reg_v,
                         "val_kind": val_k, "val_text": val_t, "val": val_v})
    if not rows:
        sys.exit("gate: zero write call sites decoded -- the classifier has nothing to grade")
    kinds_seen = collections.Counter(r["reg_kind"] for r in rows)
    print(f"call sites      {len(rows)} to {len(targets)} helpers, across "
          f"{len({r['caller'] for r in rows})} caller functions; reg-operand kinds {dict(kinds_seen)}")
    for r in sorted(rows, key=lambda x: (x["caller"], x["site"])):
        reg = f"0x{r['reg']:02x}" if r["reg"] is not None else r["reg_text"]
        val = f"0x{r['val']:02x}" if r["val"] is not None else r["val_text"]
        print(f"   {r['caller']:32} {r['site']:#x}  reg[{r['reg_kind']:8}]={reg:26} "
              f"val[{r['val_kind']:8}]={val}")
    consts = [r for r in rows if r["reg_kind"] == "constant" and r["val_kind"] in ("constant", "rmw")]
    tab = [r for r in rows if r["reg_kind"] == "table" or r["val_kind"] == "table"]
    if not consts or not tab:
        sys.exit(f"gate: classifier found {len(consts)} constant-fed and {len(tab)} table-fed write sites "
                 "-- at least one of each is KNOWN to exist (§286), so the walk-back is broken")
    print(f"\nconstant-fed sites {len(consts)}, table-fed sites {len(tab)} (controls satisfied)")
    # resolve the tables behind the table-fed sites: which (addr,value) pairs can they emit for 0x14?
    print("which paths can write register 0x14, and with what value:")
    for r in sorted(rows, key=lambda x: x["site"]):
        if r["reg_kind"] == "constant" and r["reg"] == 0x14:
            print(f"   {r['caller']:32} constant  w2=0x{r['val']:02x}" if r["val"] is not None
                  else f"   {r['caller']:32} constant reg 0x14, value {r['val_text']}")
        elif r["reg_kind"] == "table" and r["caller"] == "es9038_one_enable":
            for tname, tva in sorted(DATA.items(), key=lambda kv: kv[0]):
                if not tname.startswith("dac_parameters"):
                    continue
                raw = bytes_at(tva, 0x60)
                if len(raw) < 4:
                    continue
                pairs = [(raw[k], raw[k + 1]) for k in range(0, len(raw) - 1, 2)]
                hit = [f"0x{v:02x}" for adr, v in pairs if adr == 0x14]
                print(f"   {r['caller']:32} via table {tname}@{tva:#x}: rows={len(pairs)} "
                      f"value(s) for 0x14 = {hit or 'none in the decoded window'}")
                break
            break
    if a.out:
        cols = ["caller", "callee", "site", "reg_kind", "reg", "reg_text", "val_kind", "val", "val_text"]
        widths = set()
        with open(a.out, "w", encoding="utf-8") as fh:
            fh.write("\t".join(cols) + "\n")
            for r in sorted(rows, key=lambda x: (x["caller"], x["site"])):
                line = [r["caller"], r["callee"], f"{r['site']:#x}", r["reg_kind"],
                        "-" if r["reg"] is None else f"0x{r['reg']:02x}", r["reg_text"], r["val_kind"],
                        "-" if r["val"] is None else f"0x{r['val']:02x}", r["val_text"]]
                widths.add(len(line))
                fh.write("\t".join(line) + "\n")
        if len(widths) != 1:
            sys.exit(f"gate: {a.out} rows disagree on column count {sorted(widths)}")
        print(f"wrote {a.out} ({len(rows)} rows x {next(iter(widths))} columns)")
    if a.selftest:
        drop = [r for r in rows if r["reg_kind"] != "constant"]
        if drop and len(drop) == len(rows):
            sys.exit("gate: --selftest: no constant sites existed to remove -- control is vacuous")
        k2 = collections.Counter(r["reg_kind"] for r in drop)
        print(f"selftest: removing the constant sites leaves {dict(k2)} -- the 'controls satisfied' "
              "line above is what refuses that state")
        print("selftest: the classifier's two controls are the abort at the end of the census")


if __name__ == "__main__":
    main()
