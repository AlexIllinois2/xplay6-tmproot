#!/usr/bin/env python3
"""tools/dac_hifi_mode_enum.py -- §332: what is the constant that selects the DSD tables?

§331 found the enable handler comparing a field (object+0xc) with 2 to choose between the
integration_params tables and their *_dsd_* twins, and left the meaning of "2" undecoded.  This tool
decodes it from two INDEPENDENT sides and only publishes when they agree:

  A  THE FIELD      every access in the Image whose base register resolves onto that absolute field
     (tools/dac_slot_filler.py --at produced the rows; here the same predicate is re-derived for one
     field so the writer set is named): who writes it, who reads it.
  B  THE CONTROL     the writer is a `*_put` function, i.e. an ALSA control handler; the control's
     text array in .rodata is located by walking the pointer that references the enum word "DSD" and
     reading the neighbouring entries, giving each item's INDEX.
  C  THE CONSTANT    the handler's own comparison against the field is read out of its instructions.

Gate: the index that "DSD" holds in the text array must EQUAL the constant the handler compares with
the field -- if they differ, one of the two readings is wrong and nothing is published.  A second gate
requires the payload loop that consumes the selected table to be present with the shape
count/stride/index that §322 derived independently (3 rows, 5-byte stride, value = row[1 + column]).

usage: tools/dac_hifi_mode_enum.py [--selftest] [--out TSV]
"""
import argparse
import collections
import csv
import hashlib
import os
import re
import struct
import sys

from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, Cs

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ART = os.path.join(ROOT, "art", "audio-6.0.1")
IMG = os.environ.get("DAC_IMG", os.path.join(ROOT, "fw", "Image"))
KALL = os.environ.get("DAC_KALL", os.path.join(ROOT, "art", "kallsyms_real.txt"))
LIVE = os.environ.get("DAC_LIVE", os.path.join(ART, "live"))
BASE = 0xFFFFFFC000080000
MASK = 0xFFFFFFFFFFFFFFFF
BLOB = open(IMG, "rb").read()
END = BASE + len(BLOB)
ALIAS = {"fp": 29, "lr": 30, "sp": 31}
FIELD = int(os.environ.get("DAC_FIELD", "0xffffffc001b242d4"), 0)   # object+0xc
TABLE_SLOT = int(os.environ.get("DAC_SLOT", "0xffffffc001b24368"), 0)  # object+0xa0
ENUM_WORD = os.environ.get("DAC_ENUM_WORD", "DSD")
MD = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
MD.detail = True

ENTRIES = []
for line in open(KALL, encoding="utf-8", errors="replace"):
    p = line.split()
    if len(p) >= 3 and re.fullmatch(r"[0-9a-f]{16}", p[0]):
        ENTRIES.append((int(p[0], 16), p[1], p[2]))
NAME, TYPE = {}, {}
FOR_NAME = collections.defaultdict(list)
for a, t, n in ENTRIES:
    NAME.setdefault(a, n)
    TYPE.setdefault(a, t)
    FOR_NAME[n].append(a)
TEXT = sorted({(a, n) for a, t, n in ENTRIES if t in "tT" and BASE <= a < END})
TA = [a for a, _n in TEXT]
IDX = {a: i for i, a in enumerate(TA)}


def sha16(p):
    return hashlib.sha256(open(p, "rb").read()).hexdigest()[:16]


def rnum(reg):
    n = MD.reg_name(reg) or ""
    if n in ALIAS:
        return ALIAS[n]
    m = re.fullmatch(r"[wx](\d+)", n)
    return int(m.group(1)) if m else None


def cstr(va):
    o = va - BASE
    if not (0 <= o < len(BLOB)):
        return None
    try:
        return BLOB[o:BLOB.index(b"\0", o)].decode("ascii", "replace")
    except ValueError:
        return None


def step(a, end):
    """per-word decode (bulk disasm truncates silently), yields instructions"""
    while a < end:
        w = BLOB[a - BASE:a - BASE + 4]
        if len(w) < 4:
            return
        if struct.unpack("<I", w)[0]:
            x = next(MD.disasm(w, a), None)
            if x is not None:
                yield x
        a += 4


def field_accesses(fields):
    """every load/store whose base register's statically-known value lands on one of `fields`
    (a SET, so the whole-Image scan runs once no matter how many fields are asked for)"""
    out = collections.defaultdict(list)
    for va, nm in TEXT:
        i = IDX[va]
        end = TA[i + 1] if i + 1 < len(TA) else va + 4
        val = {}
        for x in step(va, end):
            ops, mn = x.operands, x.mnemonic
            dst = rnum(ops[0].reg) if ops and ops[0].type == 1 else None
            mem = [o for o in ops if o.type == 3]
            if mn == "adrp" and len(ops) == 2 and ops[1].type == 2 and dst is not None:
                val[dst] = ops[1].imm & MASK
                continue
            if mn in ("add", "sub") and len(ops) == 3 and ops[2].type == 2 and dst is not None:
                b = rnum(ops[1].reg)
                if b in val:
                    stepv = ops[2].imm & MASK
                    val[dst] = (val[b] + stepv) if mn == "add" else (val[b] - stepv) & MASK
                    continue
            if mem and x.op_str.endswith("]") and mem[0].mem.base:
                b = rnum(mem[0].mem.base)
                tv = val.get(b)
                if tv is not None:
                    at = (tv + mem[0].mem.disp) & MASK
                    if at in fields:
                        out[at].append({"fn": nm, "fn_at": va, "site": x.address,
                                         "dir": "write" if mn.startswith("st") else "read",
                                         "text": f"{mn} {x.op_str}", "via": f"x{b}@{tv:#x}"})
            if dst is not None and not mn.startswith(("cmp", "tst", "cbz", "cbnz", "tbz", "tbnz")) \
                    and not (mem and mn.startswith("st")):
                val.pop(dst, None)
    return out


def enum_array(word):
    """the control's text list, BOUNDED by the struct that references it.

    .rodata packs several text arrays back to back, so "walk while the pointer resolves to a string"
    merges neighbours (it read 0..31 plus Off/HiFi/DSD as one 35-item list).  The bound comes from the
    struct that holds the array pointer: 4.9's `struct soc_enum` carries `.items` (u32) immediately
    before `.texts` (ptr), so a slot whose value is a text-array start, with a plausible item count
    in front of it, and containing our string, is the only reading that can be published."""
    tgt = None
    for m in re.finditer(re.escape(word.encode()) + b"\0", BLOB):
        i = m.start()
        if i and BLOB[i - 1] == 0:
            if tgt is not None:
                sys.exit(f"gate: the Image carries {word!r} as a standalone string at more than one "
                         f"place ({tgt:#x} and {BASE+i:#x}) -- the enum could be either")
            tgt = BASE + i
    if tgt is None:
        sys.exit(f"gate: the string {word!r} is not in the Image -- no index can be claimed")
    slots = [BASE + i for i in range(0, len(BLOB) - 8, 8)
             if struct.unpack_from("<Q", BLOB, i)[0] == tgt]
    if len(slots) != 1:
        sys.exit(f"gate: {len(slots)} slots hold a pointer to {word!r} -- the text array is ambiguous")
    slot = slots[0]
    found = []
    for i in range(8, len(BLOB) - 8, 8):
        v = struct.unpack_from("<Q", BLOB, i)[0]
        if not (BASE <= v <= slot):
            continue
        # the item count is the 8-byte slot in front of the pointer (two u32s, the low one holds the
        # count: reading only the 4 bytes closest to the pointer gives the zero high half)
        n = struct.unpack_from("<Q", BLOB, i - 8)[0]
        if not (1 <= n <= 64) or not (v <= slot < v + 8 * n):
            continue
        texts = [cstr(struct.unpack_from("<Q", BLOB, (v + 8 * j) - BASE)[0]) for j in range(n)]
        if any(t is None for t in texts):
            continue
        found.append((BASE + i, v, n, texts))
    if not found:
        sys.exit(f"gate: no struct in the Image points at a text array containing {word!r} with a "
                 "plausible item count in front of it -- the bound would be my guess, so no index is "
                 "published")
    keys = {(f[1], f[2]) for f in found}
    if len(keys) > 1:
        sys.exit(f"gate: {len(found)} different (array,items) pairs cover the {word!r} slot "
                 f"{sorted((hex(k[0]), k[1]) for k in keys)} -- ambiguous, pick the control by name instead")
    struct_va, texts_va, n, texts = found[0]
    idx = [j for j, t in enumerate(texts) if t == word]
    return struct_va, texts_va, n, texts, idx[0], slot


def handler_constant(fn_va, field_disp):
    """the immediate the handler compares the field with: `ldr w?,[x?,#disp]` ... `cmp w?, #K`"""
    i = IDX[fn_va]
    end = TA[i + 1] if i + 1 < len(TA) else fn_va + 4
    seen = []
    reg = None
    for x in step(fn_va, end):
        ops, mn = x.operands, x.mnemonic
        if mn.startswith("ldr") and len(ops) == 2 and ops[1].type == 3 and ops[1].mem.disp == field_disp:
            reg = rnum(ops[0].reg)
            seen.append((x.address, "load", x.op_str))
        elif mn == "cmp" and reg is not None and len(ops) == 2 and ops[1].type == 2:
            if rnum(ops[0].reg) == reg:
                return x.address, ops[1].imm & MASK, seen
    return None, None, seen


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    print(f"inputs          Image {IMG} [{sha16(IMG)}]; symbols {KALL} [{sha16(KALL)}]; "
          f"live dir {LIVE}; field {FIELD:#x}, table slot {TABLE_SLOT:#x}")
    fields = {FIELD, TABLE_SLOT}
    both = field_accesses(fields)
    acc = both.get(FIELD, [])
    slot_acc = both.get(TABLE_SLOT, [])
    wr = [h for h in acc if h["dir"] == "write"]
    rd = [h for h in acc if h["dir"] == "read"]
    if not wr:
        sys.exit(f"gate: no writer of {FIELD:#x} in {len(TEXT)} text symbols -- the value compared by "
                 "the handler would have no producer, so 'DSD selects the dsd tables' could not be said")
    if len({h["fn"] for h in wr}) != 1:
        sys.exit(f"gate: {FIELD:#x} is written by {sorted({h['fn'] for h in wr})} -- more than one writer "
                 "means the field is not the control's store, and the mapping to a control name fails")
    put = wr[0]["fn"]
    print(f"field {FIELD:#x}  writer {put} @ {wr[0]['site']:#x} ({wr[0]['text']}), "
          f"{len(rd)} read(s) by {sorted({h['fn'] for h in rd})}")
    if not put.endswith("_put"):
        print(f"note            the single writer {put} is not named *_put -- the control reading is "
              "weaker and gets said so")
    struct_va, array_va, n, texts, idx0, tslot = enum_array(ENUM_WORD)
    print(f"enum array      .texts {array_va:#x} (referenced by struct {struct_va:#x}), {n} item(s): "
          + ", ".join(f"[{j}]={t}" for j, t in enumerate(texts))
          + f"; {ENUM_WORD!r} is index {idx0}")
    # the handler that compares the field: pick the reader whose function also holds the table-slot write
    swr = {h["fn_at"] for h in slot_acc if h["dir"] == "write"}
    print(f"table slot      {TABLE_SLOT:#x}: {len(swr)} writing function(s) "
          f"{sorted(hex(s) for s in swr)}, {len([h for h in slot_acc if h['dir'] == 'read'])} read(s) "
          f"{sorted({h['fn'] for h in slot_acc if h['dir'] == 'read'})}")
    cands = sorted({h["fn_at"] for h in rd} & swr)
    if not cands:
        sys.exit("gate: no function both reads the compared field and writes the table slot -- the two "
                 "halves of §331's selection would not be in one place, so the constant cannot be tied "
                 "to this field")
    consts = []
    for va in cands:
        site, k, seen = handler_constant(va, 0xC)
        if k is not None:
            consts.append((va, site, k))
    if not consts:
        sys.exit("gate: the reader that holds the field does not compare it with any immediate -- the "
                 "selection would be my reading of the branch, not a decoded comparison")
    print("comparisons     " + "; ".join(f"{NAME.get(va)}@{va:#x} at {s:#x} compares with {k}"
                                         for va, s, k in consts))
    agreed = [(va, s, k) for va, s, k in consts if k == idx0]
    if not agreed:
        sys.exit(f"gate: the handler compares with {[k for _v, _s, k in consts]} but {ENUM_WORD!r} sits "
                 f"at index {idx0} of the control's own text array -- the two readings disagree, so "
                 "neither may be published")
    print(f"agreement       {ENUM_WORD!r} is control item {idx0} and the handler compares the field "
          f"with {agreed[0][2]} in {NAME.get(agreed[0][0])} -- two independent sides give the same number")
    loop = None
    for va, _s, _k in agreed:
        i = IDX[va]
        end = TA[i + 1] if i + 1 < len(TA) else va + 4
        shape = {}
        for x in step(va, end):
            ops, mn = x.operands, x.mnemonic
            if mn == "mov" and len(ops) == 2 and ops[1].type == 2:
                v = ops[1].imm & MASK
                if v == 3:
                    shape.setdefault("count3", x.address)
                if v == 5:
                    shape.setdefault("stride5", x.address)
                if v == 6:
                    shape.setdefault("alloc6", x.address)
            if mn == "smull" and len(ops) == 3 and ops[2].type == 1:
                shape.setdefault("mul_i_stride", x.address)
            if mn == "ldrb" and ops[1].type == 3 and ops[1].mem.disp == 0:
                shape.setdefault("row_reg_byte", x.address)
            if mn == "ldrb" and ops[1].type == 3 and ops[1].mem.disp == 1:
                shape.setdefault("row_val_byte", x.address)
            if mn == "sxtw":
                shape.setdefault("column_sxtw", x.address)
        if all(k in shape for k in ("count3", "stride5", "alloc6", "row_reg_byte", "row_val_byte")):
            loop = (va, shape)
            break
    if not loop:
        sys.exit("gate: the payload loop that consumes the selected table was not found with the shape "
                 "count=3 / stride=5 / alloc=6 / row[0]=reg / row[1]=value -- §322's tiling would be "
                 "unconfirmed by the code that actually reads the table")
    print("payload loop    " + ", ".join(f"{k}@{v:#x}" for k, v in sorted(loop[1].items()))
          + f"  (in {NAME.get(loop[0])})")
    ctl, vocab, ctl_src = None, set(), None
    known = set()
    tp = os.path.join(ART, "controls-live.tsv")
    if os.path.exists(tp):
        for line in open(tp, encoding="utf-8"):
            f = line.rstrip("\n").split("\t")
            if f and f[0]:
                known.add(f[0])
    for cand_name in ("usecase-table.mixer_paths_tasha.PD1610.tsv", "controls-live.tsv"):
        p = os.path.join(ART, cand_name)
        if not os.path.exists(p):
            continue
        names = collections.defaultdict(set)
        for line in open(p, encoding="utf-8"):
            cells = [c.strip() for c in line.rstrip("\n").split("\t")]
            if ENUM_WORD not in cells:
                continue
            nm = next((c for c in cells if c in known), None)
            if nm:
                names[nm] |= {c for c in cells if c in texts}
        if names:
            ctl = max(names, key=lambda k: len(names[k]))
            vocab = names[ctl]
            ctl_src = cand_name
            break
    if not ctl:
        print("control name      NO use-case table names a control whose value set is a subset of that "
              "enum array -- the writer name is the only link, and it is reported as such")
    else:
        print(f"control name      {ctl!r} from {ctl_src}: its values there "
              f"{sorted(vocab)} are items of the array at {array_va:#x}")
    print(f"link              writer {put} ({n} enum items read off the array)")
    live_vals = {}
    live_name = ctl or "HiFi Mode Switch"
    if os.path.isdir(LIVE):
        for fn in sorted(os.listdir(LIVE)):
            if "tinymix" not in fn:
                continue
            txt = open(os.path.join(LIVE, fn), encoding="utf-8", errors="replace").read()
            m = re.search(re.escape(live_name) + r"\s+(\S+)", txt)
            if m:
                live_vals[fn] = m.group(1)
    print("observed values " + (", ".join(f"{k}={v}" for k, v in sorted(live_vals.items()))
                                or f"NO tinymix capture mentions {live_name!r}"))
    if a.selftest:
        sf = os.path.join(ART, "dac-slot-filler.PD1610.tsv")
        if not os.path.exists(sf):
            sys.exit("gate: --selftest: no dac-slot-filler artifact beside this tool, so the value-keyed "
                     "predicate here has nothing to be cross-checked against")
        want = {f"field {FIELD:#x}", f"field {TABLE_SLOT:#x}"}
        other = {(int(r["site"], 16), r["value_type"].split("/")[0])
                 for r in csv.DictReader(open(sf, encoding="utf-8"), delimiter="\t")
                 if r["kind"] == "abs-access" and r["disp"] in want}
        mine = {(h["site"], h["dir"]) for h in acc + slot_acc}
        if other != mine:
            sys.exit(f"gate: --selftest: the two independent walks disagree -- dac_slot_filler gives "
                     f"{sorted(other)[:3]}, this scan gives {sorted(mine)[:3]}, symmetric difference "
                     f"{sorted(other ^ mine)[:3]}")
        print(f"selftest: the same {len(mine)} field accesses come out of dac_slot_filler.py's walk and "
              "this one -- two implementations of the value-keyed predicate, one answer")
    if a.out:
        cols = ["stage", "name", "va", "site", "detail"]
        lines = []
        for h in acc:
            lines.append("\t".join(["field-access", h["fn"], f"{h['fn_at']:#x}", f"{h['site']:#x}",
                                    f"{h['dir']} {h['text']} via {h['via']}"]))
        for h in slot_acc:
            lines.append("\t".join(["slot-access", h["fn"], f"{h['fn_at']:#x}", f"{h['site']:#x}",
                                    f"{h['dir']} {h['text']} via {h['via']}"]))
        lines.append("\t".join(["enum-array", NAME.get(array_va, "?"), f"{array_va:#x}",
                                f"struct {struct_va:#x}",
                                ", ".join(f"[{j}]={t}" for j, t in enumerate(texts))]))
        for va, s, k in consts:
            lines.append("\t".join(["compare", NAME.get(va, "?"), f"{va:#x}", f"{s:#x}",
                                    f"field vs immediate {k} (agrees with index {idx0})" if k == idx0
                                    else f"field vs immediate {k}"]))
        lines.append("\t".join(["payload-loop", NAME.get(loop[0], "?"), f"{loop[0]:#x}",
                                f"{loop[1]['count3']:#x}",
                                "count=3 stride=5 alloc=6 row[0]=reg row[1+column]=value; "
                                + ", ".join(f"{k}@{v:#x}" for k, v in sorted(loop[1].items()))]))
        lines.append("\t".join(["DENOM", f"{len(TEXT)} functions scanned", str(len(acc)),
                                str(len(slot_acc)), f"{len(wr)} writer(s), {len(rd)} reader(s), "
                                f"{n} enum items, live values {len(live_vals)}"]))
        with open(a.out, "w", encoding="utf-8") as fh:
            fh.write("\t".join(cols) + "\n")
            fh.write("\n".join(lines) + "\n")
        w = {len(x.split("\t")) for x in lines}
        if w != {5}:
            sys.exit(f"gate: {a.out} row widths {sorted(w)} are not all 5 columns")
        print(f"wrote {a.out} ({len(lines) + 1} lines x 5 columns)")


if __name__ == "__main__":
    main()
