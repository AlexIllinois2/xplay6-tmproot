#!/usr/bin/env python3
"""tools/dac_integration_params.py -- what feeds the Hi-Fi DAC enable path's "special params", derived.

Ledger 286/287 left this open: `es9038_one_enable` hands `es9038_setting_special_params` a
{count, pointer} struct read through [arg+0x18], and I could not say who fills that slot, which
registers those bytes name, or whether the DT `vivo,params` array is that payload at all.  §286's
sentence ("count = param-num[0]x[1] = 16, so the DT array feeds the writes") was an inference from
code shapes and was never checked against the writer side.

Everything is derived from the running Image plus the board's own device tree, with no hard-coded
addresses.  The extraction is anchored on the CONVERTER LOOP inside the widget event handler, because
that is the object the claim is about:

  stride  <- the `mov #S` feeding the loop's `smull` (row size in bytes)
  elem    <- the `sbfiz #SH` feeding the destination index (payload size per row)
  slot    <- the stack slot the loop-bound `cmp` re-loads
  count   <- the `mov #N` stored into that same slot
  alloc   <- the size argument in front of kmem_cache_alloc_trace
  table   <- the adrp/add chain whose register is stored to [ptr+8]
  field   <- the offset the `add x?, x29, #slot` register is stored to
  obj     <- the `add x0, x0, #OB` in front of the `ldr x2,[x1,#0x48] ; blr x2` ops call

Identities that must hold, or the tool aborts:
  count * elem == alloc                       (the buffer really is count pairs)
  obj + 0x18 == field                         (what one_enable reads IS where the handler wrote)
  stride - elem == distinct constants the selector can return   (one candidate per column)

Each register row's candidate bytes are then falsified against the in-play DAC capture: is the live
byte one of them?  Printing NO is a legitimate outcome.  What is NOT claimed: the impedance-to-column
mapping (the selector's identity and output width are measured and its instructions exported, but no
band boundaries are asserted -- a wrong emulator would be worse than no answer).

usage: tools/dac_integration_params.py [--out TSV] [--selftest]
"""
import argparse
import bisect
import csv
import glob
import os
import re
import struct
import sys

from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, Cs
from capstone.arm64 import ARM64_OP_IMM, ARM64_OP_MEM, ARM64_OP_REG, ARM64_REG_W0

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ART = os.path.join(ROOT, "art", "audio-6.0.1")
IMG = os.path.join(ROOT, "fw", "Image")
KALL = os.path.join(ROOT, "art", "kallsyms_real.txt")
TEXT_BASE = 0xFFFFFFC000080000
MASK64 = 0xFFFFFFFFFFFFFFFF   # capstone hands adrp pages and bl targets back SIGN-extended; mask before comparing
TEXT_END = TEXT_BASE + os.path.getsize(IMG)   # derived, never typed: a hand-set 0x1290000
                                               # silently hid the module-init functions (§323)
WIDGETS_P = os.path.join(ART, "dapm-widgets.PD1610.tsv")
DTCAP = os.path.join(ART, "live", "dac-dt-raw.txt")
SLOT_READ = 0x18
OPS_ENABLE = 0x48
KMALLOC = "kmem_cache_alloc_trace"
BLOB = open(IMG, "rb").read()


def arch():
    m = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    m.detail = True
    return m


def syms():
    out = []
    for line in open(KALL, encoding="utf-8", errors="replace"):
        p = line.split()
        if len(p) >= 3 and re.fullmatch(r"[0-9a-f]{16}", p[0]):
            out.append((int(p[0], 16), p[2]))
    out.sort()
    return out


SS = syms()
SA = sorted({a for a, _n in SS})
NAME = {}
for _a, _n in SS:
    NAME.setdefault(_a, _n)

from capstone.arm64 import ARM64_REG_W0, ARM64_REG_X0, ARM64_REG_INVALID


def _reg_names():
    """id -> printed name, built by asking capstone to disassemble 'mov xN, xN' shapes once"""
    m = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    m.detail = True
    out = {}
    for cand in list(range(ARM64_REG_INVALID + 1, ARM64_REG_INVALID + 400)):
        try:
            n = m.reg_name(cand)
        except Exception:
            n = None
        if n:
            out[cand] = n
    return out


NAME_BY_REG = _reg_names()


def va_of(name):
    hits = [a for a, n in SS if n == name]
    if not hits:
        sys.exit(f"gate: symbol {name} not in {KALL}")
    if len(hits) > 1:
        print(f"collision       {name} has {len(hits)} addresses {sorted(hex(h) for h in hits)} -- "
              f"taking the lowest; identity should be pinned by address, not by name (see --rows-at)")
    return min(hits)


def span_of(va):
    i = bisect.bisect_right(SA, va)
    return (SA[i] - va) if i < len(SA) else 0x100


def disasm(va, nbytes):
    off = va - TEXT_BASE
    if off < 0 or off >= len(BLOB):        # BSS symbols have no bytes in the Image
        return []
    return list(arch().disasm(BLOB[off:off + nbytes], va))


def mem_disp(x):
    for o in x.operands:
        if o.type == ARM64_OP_MEM:
            return o.mem.disp
    return None


def mem_base(x):
    for o in x.operands:
        if o.type == ARM64_OP_MEM:
            return o.mem.base
    return None


def imm(x, pos):
    try:
        return x.operands[pos].imm if x.operands[pos].type == ARM64_OP_IMM else None
    except Exception:
        return None


def addr(x, pos=0):
    v = imm(x, pos)
    return None if v is None else v & MASK64


def find_event_fn(path=None):
    WIDGETS = path or WIDGETS_P
    if not os.path.exists(WIDGETS):
        sys.exit(f"gate: {WIDGETS} missing -- run tools/kssym_dapm.py")
    rows = list(csv.DictReader(open(WIDGETS, encoding="utf-8"), delimiter="\t"))
    hits = [r for r in rows if r["name"] == "HiFi DAC" and r.get("event_va")]
    if not hits:
        sys.exit(f"gate: no 'HiFi DAC' widget with an event handler in {WIDGETS}; that handler is the "
                 "anchor of this whole chain")
    va = int(hits[0]["event_va"], 16)
    if not (TEXT_BASE <= va < TEXT_END):
        sys.exit(f"gate: handler VA {va:#x} is outside .text -- the widget table is stale")
    return va, hits[0]["event"]


ALIAS = {"fp": 29, "lr": 30, "sp": 31}


def ridnum(reg):
    n = (NAME_BY_REG.get(reg) or "").lstrip("%")
    if n in ALIAS:
        return ALIAS[n]
    m = re.fullmatch(r"[wx](\d+)", n)
    return int(m.group(1)) if m else None


def rid(x, pos=0):
    """normalised register number: capstone calls x29 'fp' and x30 'lr', so a [wx]\\d+ regex alone
    silently returns None for every frame-pointer operand -- which is how the struct-slot hunt
    came back empty"""
    try:
        op = x.operands[pos]
    except Exception:
        return None
    return ridnum(op.reg) if op.type == ARM64_OP_REG else None


def decode_site(fn_va):
    ins = disasm(fn_va, span_of(fn_va))
    if not ins:
        sys.exit(f"gate: {fn_va:#x} decoded to 0 instructions")
    stride = elem = alloc = table = field = obj = None
    idxreg = None
    for i, x in enumerate(ins):
        if x.mnemonic == "smull" and len(x.operands) == 3 and stride is None:
            sreg = rid(x, 2)
            idxreg = rid(x, 1)
            for y in reversed(ins[:i]):
                if y.mnemonic == "mov" and rid(y, 0) == sreg and imm(y, 1):
                    stride = imm(y, 1)
                    break
        if x.mnemonic == "sbfiz" and imm(x, 2) is not None and elem is None and rid(x, 1) == idxreg:
            elem = 1 << imm(x, 2)
    kva = va_of(KMALLOC)
    for i, x in enumerate(ins):
        if x.mnemonic == "bl" and addr(x, 0) == kva:
            for y in reversed(ins[max(0, i - 12):i]):
                if y.mnemonic == "mov" and rid(y, 0) == 2 and imm(y, 1) is not None and 0 < imm(y, 1) <= 0x200:
                    alloc = imm(y, 1)
                    break
            break
    pages = {}
    for x in ins:
        if x.mnemonic == "adrp":
            pages[rid(x, 0)] = addr(x, 1)
        elif x.mnemonic == "add" and len(x.operands) == 3 and imm(x, 2) is not None \
                and rid(x, 1) in pages:
            pages[rid(x, 0)] = pages[rid(x, 1)] + imm(x, 2)
        elif x.mnemonic == "str" and rid(x, 0) in pages and mem_disp(x) == 8 and table is None:
            table = pages[rid(x, 0)]
    for i, x in enumerate(ins):
        if x.mnemonic == "blr":
            for y in reversed(ins[max(0, i - 12):i]):
                if y.mnemonic == "ldr" and mem_disp(y) == OPS_ENABLE:
                    for z in reversed(ins[max(0, i - 12):i]):
                        if z.mnemonic == "add" and imm(z, 2) is not None and rid(z, 0) == rid(z, 1):
                            obj = imm(z, 2)
                            break
                    break
            if obj is not None:
                break
    # the payload struct lives on the stack: find EVERY slot that some compare re-loads, then keep
    # the one whose stored count satisfies the two arithmetic identities.  Letting the identities do
    # the choosing is the point -- a slot picked by first-match would be a guess.
    cands = []
    for i, x in enumerate(ins):
        if x.mnemonic in ("cmp", "subs") and len(x.operands) == 2 and x.operands[1].type == ARM64_OP_REG:
            breg = rid(x, 1)
            for y in reversed(ins[:i]):
                if y.mnemonic == "ldr" and rid(y, 0) == breg and mem_disp(y) is not None:
                    cands.append((mem_disp(y), mem_base(y)))
                    break
    ok = []
    for slot, base in set(cands):
        for i, x in enumerate(ins):
            if x.mnemonic == "str" and mem_disp(x) == slot and mem_base(x) == base:
                for y in reversed(ins[:i]):
                    if y.mnemonic == "mov" and rid(y, 0) == rid(x, 0) and imm(y, 1) is not None:
                        cnt = imm(y, 1)
                        if stride and elem and alloc and cnt * elem == alloc:
                            fs = None
                            for z in ins[i + 1:]:
                                if z.mnemonic == "add" and imm(z, 2) == slot and rid(z, 1) == 29:
                                    sreg = rid(z, 0)
                                    for w in ins[ins.index(z) + 1:]:
                                        if w.mnemonic == "str" and rid(w, 0) == sreg and mem_disp(w):
                                            fs = mem_disp(w)
                                            break
                                    break
                            if fs is not None and obj is not None and obj + SLOT_READ == fs:
                                ok.append({"slot": slot, "count": cnt, "stride": stride, "elem": elem,
                                           "alloc": alloc, "table": table, "field": fs, "obj": obj})
                        break
                break
    uniq = {(c["slot"], c["count"], c["field"]) for c in ok}
    if len(uniq) != 1:
        sys.exit(f"gate: {len(uniq)} stack slots satisfy count*elem==alloc AND the ops+0x18 identity "
                 f"(candidates {sorted(uniq)}) -- the payload struct is not uniquely identified, so "
                 "the chain may not be published")
    if any(c != ok[0] for c in ok):
        sys.exit(f"gate: the surviving slots agree on (slot,count,field) but disagree elsewhere: "
                 f"{ok}")
    d = dict(ok[0])
    for k in ("stride", "elem", "slot", "count", "alloc", "table", "field", "obj"):
        if d.get(k) is None:
            sys.exit(f"gate: could not derive {k!r} from the handler at {fn_va:#x} -- the code shape "
                     "is not the one this tool knows, so nothing about this chain may be published")
    return d, ins


def find_selector(ins, want):
    """the callee whose largest column immediate is exactly `want`-1 -- i.e. the only function that
    can hand back a column index for this row width"""
    out = []
    for x in ins:
        if x.mnemonic != "bl":
            continue
        t = addr(x, 0)
        if not t or not (TEXT_BASE <= t < TEXT_END) or t not in NAME:
            continue
        if t == va_of(KMALLOC):
            continue
        sub = disasm(t, min(span_of(t), 0x80))
        cons = sorted({imm(y, 1) for y in sub if y.mnemonic == "mov" and imm(y, 1) is not None
                       and 0 <= imm(y, 1) < 8})
        extra = sorted({y.mnemonic for y in sub if y.mnemonic.startswith("cs")})
        if len(cons) >= 2:
            out.append((t, cons, extra))
    good = [c for c in out if c[1] and max(c[1]) + 1 == want]
    if len(good) != 1:
        sys.exit(f"gate: {len(good)} callees' largest column immediate is {want - 1} -- saw "
                 f"{[(hex(a), b, c) for a, b, c in out]}; the selector is not uniquely identified, "
                 "so the candidate bytes may not be read as a chosen column")
    return good[0]


def read_table(va, count, stride):
    sp = span_of(va)
    if sp < count * stride:
        sys.exit(f"gate: {NAME.get(va, hex(va))} spans {sp} B but the loop reads {count}x{stride} "
                 f"= {count * stride} B -- the row count does not belong to this object")
    off = va - TEXT_BASE
    if off < 0 or off + count * stride > len(BLOB):
        sys.exit(f"gate: {NAME.get(va, hex(va))} @ {va:#x} -> file offset {off:#x} with {count}x{stride} "
                 f"B does not fit the {len(BLOB)} B Image -- pass a virtual address, and remember .bss "
                 "objects have no bytes here at all")
    rows = []
    for i in range(count):
        row = BLOB[off + i * stride: off + (i + 1) * stride]
        rows.append((row[0], list(row[1:stride])))
    if len({r[0] for r in rows}) != count:
        sys.exit(f"gate: two rows name the same register ({rows}) -- stride {stride} is wrong")
    if any(all(c == 0 for c in cs) for _r, cs in rows):
        sys.exit(f"gate: a row has only zero candidates ({rows}) -- stride/offset misread")
    return rows


def dt_rows(path):
    if not os.path.exists(path):
        sys.exit(f"gate: {path} missing -- the DAC's own DT node (soc/i2c@75b6000/dac@48) was only "
                 "found on 2026-10-16; re-run tools/dacdtnode.sh and save its output")
    txt = open(path, encoding="utf-8", errors="replace").read()
    if "DACSLOT_DONE" not in txt:
        sys.exit(f"gate: {path} lacks the DACSLOT_DONE marker -- truncated capture, not evidence")
    rows = []
    for line in txt.splitlines():
        m = re.match(r"(\S[\w,-]*) = (\d+) bytes ?: ?([0-9a-f ]*)", line.strip())
        if not m:
            continue
        hx = [int(h, 16) for h in m.group(3).split() if re.fullmatch(r"[0-9a-f]{2}", h)]
        if not hx and int(m.group(2)) != 0:
            sys.exit(f"gate: {path} row {m.group(1)} claims {m.group(2)} bytes but none parsed")
        if len(hx) != int(m.group(2)):
            sys.exit(f"gate: {path} row {m.group(1)} claims {m.group(2)} bytes, parsed {len(hx)}")
        nb = bytes(hx)
        as_u32 = [struct.unpack_from(">I", nb, 4 * i)[0] for i in range(len(nb) // 4)]
        try:
            s = nb.split(b"\0")[0].decode("ascii")
            txtv = s if re.fullmatch(r"[\x20-\x7e]{2,}", s) else "-"
        except UnicodeDecodeError:
            txtv = "-"
        rows.append({"kind": "dt-prop", "name": m.group(1), "bytes": len(hx),
                     "value": " ".join(f"{h:02x}" for h in hx),
                     "as_u32": " ".join(str(v) for v in as_u32) if as_u32 else "(empty)",
                     "reg": txtv, "candidates": "-", "live": "-", "verdict": "board DT (read-only)"})
    if not rows:
        sys.exit(f"gate: no properties parsed out of {path}")
    return rows


def live_capture():
    """ONLY the es9038 section.  The same file carries the PA section with 4-padded addresses
    (reg{0014}) and the DAC section with bare hex (reg{14}); a regex that matches one shape silently
    reads the OTHER chip's bytes -- the §285 cross-section bug in a new costume."""
    fs = sorted(glob.glob(os.path.join(ART, "live", "dac-hpplay-*.txt")), key=os.path.getmtime)
    if not fs:
        return {}, False, "NO in-play DAC capture (the §282 headphone-play snapshot)"
    txt = open(fs[-1], encoding="utf-8", errors="replace").read()
    m = re.search(r"^## es9038/reg\s*$", txt, re.M)
    if not m:
        return {}, False, os.path.basename(fs[-1]) + " has no '## es9038/reg' section"
    tail = txt[m.end():]
    nxt = re.search(r"^## ", tail, re.M)
    tail = tail[:nxt.start()] if nxt else tail
    out = {int(a, 16): int(v, 16) for a, v in re.findall(r"reg\{([0-9a-f]{1,4})\}:([0-9a-f]+)", tail)}
    if len(out) < 40:
        return out, False, f"{os.path.basename(fs[-1])}: only {len(out)} DAC registers (want >=40)"
    return out, True, os.path.basename(fs[-1])


def identities(d, cons, sel_extra):
    msgs = []
    if d["count"] * d["elem"] != d["alloc"]:
        raise SystemExit(f"identity fails: {d['count']} rows x {d['elem']} payload bytes != the "
                         f"{d['alloc']}-byte allocation")
    if d["obj"] + SLOT_READ != d["field"]:
        raise SystemExit(f"identity fails: the handler publishes the struct at +{d['field']:#x} but "
                         f"one_enable reads [base+{d['obj']:#x} + {SLOT_READ:#x}] = "
                         f"+{d['obj'] + SLOT_READ:#x}")
    cands = d["stride"] - 1
    if max(cons) + 1 != cands:
        raise SystemExit(f"identity fails: the selector's largest immediate is {max(cons)} but each "
                         f"row carries {cands} candidate bytes")
    missing = sorted(set(range(cands)) - set(cons))
    if missing and not sel_extra:
        raise SystemExit(f"identity fails: columns {missing} are never produced by an immediate and "
                         f"the selector has no conditional-select instruction -- {cands} candidate "
                         "bytes cannot all be reachable")
    return [f"{d['count']}x{d['elem']}B == {d['alloc']}B alloc",
            f"base+{d['obj']:#x} + {SLOT_READ:#x} == field+{d['field']:#x}",
            f"row {d['stride']}B -> {cands} candidates, selector columns {cons} "
            f"(+{missing} from {sel_extra or 'no conditional select'})"]


ARMS_TSV = os.environ.get("DIP_ARMS", os.path.join(ART, "arm64-cfg-arms.PD1610.tsv"))
IMP_TSV = os.environ.get("DIP_IMP", os.path.join(ART, "dac-impedance-chain.PD1610.tsv"))
ENUM_TSV = os.path.join(ART, "live", "enum-items.tsv")
HP_TINYMIX = os.path.join(ART, "live", "tinymix-D0-playing-headphones.txt")
MODE_CTL = "HiFi Mode Switch"


def regname(x, pos=0):
    try:
        o = x.operands[pos]
        return None if o.type != ARM64_OP_REG else NAME_BY_REG.get(o.reg)
    except Exception:
        return None


def getter_default(name):
    """what a getter hands back when its pointer slot is NULL, read off its own instructions: the shape
    is  mov wD,#K  /  cbz xP,#T  /  ldrb wD,[xP]  -- the load writes the SAME register the default
    seeded, and only runs when the pointer is not NULL.  Exactly one such shape must exist."""
    va = va_of(name)
    ins = disasm(va, min(span_of(va), 0x80))
    if not ins:
        sys.exit(f"gate: {name}@{va:#x} has no decodable bytes -- its default cannot be read")
    hits = []
    for i, x in enumerate(ins):
        if x.mnemonic != "mov" or imm(x, 1) is None:
            continue
        d = regname(x)
        if not d or not d.startswith("w"):
            continue
        for j in range(i + 1, min(i + 6, len(ins))):
            cb = ins[j]
            if cb.mnemonic != "cbz":
                continue
            p = regname(cb)
            for m in range(j + 1, min(j + 5, len(ins))):
                ld = ins[m]
                if (ld.mnemonic.startswith("ldrb") and regname(ld) == d
                        and NAME_BY_REG.get(mem_base(ld) or 0) == p):
                    hits.append({"default": imm(x, 1) & 0xFFFFFFFF, "reg": d, "mov": x.address,
                                 "cbz": cb.address, "load": ld.address,
                                 "load_text": f"{ld.mnemonic} {ld.op_str}", "slot_reg": p})
    if len(hits) != 1:
        sys.exit(f"gate: {name} has {len(hits)} NULL-default shapes (want exactly 1) -- the value that "
                 "feeds the comparison would be my guess, so nothing is derived")
    h = hits[0]
    h["fn"] = name
    h["fn_va"] = va
    return h


def mode_item():
    """the control's item ORDER (from the sheet) and the selected item in the two states the device was
    captured in: idle and headphone playback.  The derivation needs the IN-PLAY item -- the sheet's own
    marker is a different moment, so the two are reported side by side instead of required to agree."""
    if not (os.path.exists(ENUM_TSV) and os.path.exists(HP_TINYMIX)):
        sys.exit(f"gate: {ENUM_TSV} or {HP_TINYMIX} missing -- the live mode item is one of the two "
                 "inputs of the derivation, it cannot be typed in")
    row = next((l.rstrip("\n").split("\t") for l in open(ENUM_TSV, encoding="utf-8", errors="replace")
                if l.split("\t")[0] == MODE_CTL), None)
    if not row:
        sys.exit(f"gate: {MODE_CTL} not in {ENUM_TSV}")
    items = [t.lstrip(">") for t in row[2:]]
    sel = [t for t in row[2:] if t.startswith(">")]
    if len(sel) != 1:
        sys.exit(f"gate: {MODE_CTL} marks {len(sel)} selected items in {ENUM_TSV} (want exactly 1)")
    cap = [l for l in open(HP_TINYMIX, encoding="utf-8", errors="replace") if MODE_CTL in l]
    if len(cap) != 1:
        sys.exit(f"gate: {MODE_CTL} appears {len(cap)} times in {HP_TINYMIX} (want exactly 1)")
    # tinymix prints "<num>\t<type>\t<value>\t<name><padding><selected item>": the last field is the
    # control name AND the item, separated only by spaces, so split on the padded gap
    m = re.match(r"^(.*?)\s\s+(\S+)\s*$", cap[0].rstrip("\n").split("\t")[-1])
    if not m:
        sys.exit(f"gate: cannot split the item out of {cap[0].rstrip()!r} -- the capture's own format "
                 "is not what this reads")
    if m.group(1).strip() != MODE_CTL:
        sys.exit(f"gate: the capture line names {m.group(1).strip()!r}, not {MODE_CTL!r}")
    live = m.group(2)
    if live not in items:
        sys.exit(f"gate: the in-play item {live!r} is not among {items} read off {ENUM_TSV} -- the sheet "
                 "and the capture disagree about the item list itself")
    return {"item": live, "index": items.index(live), "items": items,
            "idle_item": sel[0].lstrip(">"), "idle_index": items.index(sel[0].lstrip(">"))}


def live_selection(copy_fn):
    """the impedance the device reported under headphone playback and the column the INLINING copy's
    own bucket table gives it (both read off dac-impedance-chain's stage-2b rows)"""
    if not os.path.exists(IMP_TSV):
        sys.exit(f"gate: {IMP_TSV} missing -- the impedance side of the chain has no second witness")
    rows = [r for r in csv.DictReader(open(IMP_TSV, encoding="utf-8"), delimiter="\t")
            if r["stage"] == "2b" and (r["text"] or "").startswith("live playing-headphones")]
    rows = [r for r in rows if r["fn"] == copy_fn]
    if not rows:
        sys.exit(f"gate: no stage-2b live row for {copy_fn} in {IMP_TSV} -- that copy's column for the "
                 "reading the device gave is unpublished")
    out = []
    for r in rows:
        m = re.fullmatch(r"(\d+) ohm", r["site"])
        if not m:
            sys.exit(f"gate: stage-2b live row site {r['site']!r} is not N ohm")
        out.append({"ctl": r["text"], "ohm": int(m.group(1)), "column": int(r["value"])})
    if len({o["column"] for o in out}) != 1:
        sys.exit(f"gate: the two ear-side impedance readings give different columns "
                 f"{[(o['ctl'], o['column']) for o in out]} -- the derivation needs one column")
    return out


def pin_column():
    """the column the ALSA override control picks, read off dac-impedance-chain's stage-7 row (that tool
    already emulated the pin's own constant through the selector)"""
    rows = [r for r in csv.DictReader(open(IMP_TSV, encoding="utf-8"), delimiter="\t")
            if r["stage"] == "7"]
    if len(rows) != 1:
        sys.exit(f"gate: {IMP_TSV} stage 7 has {len(rows)} rows -- the pinned column must come from one "
                 "reading, not from my arithmetic here")
    m = re.search(r"column (\d+)", rows[0]["meaning"] or "")
    if not m:
        sys.exit(f"gate: {IMP_TSV} stage-7 row does not state a column: {(rows[0]['meaning'])!r}")
    return int(m.group(1)), rows[0]["fn"], rows[0]["value"]


def derive(d, table, live, fn_name):
    """compose the four sides into ONE predicted register byte and gate it against the capture"""
    arms = [r for r in csv.DictReader(open(ARMS_TSV, encoding="utf-8"), delimiter="\t")
            if r["kind"] == "arm"]
    if not arms:
        sys.exit(f"gate: {ARMS_TSV} holds no arm rows -- the per-arm binding is what this derivation "
                 "consumes, so it cannot run on prose")
    want_names = sorted({r["fn"] for r in arms})
    if len(want_names) != 1:
        sys.exit(f"gate: {ARMS_TSV} binds arms for {want_names} -- one artifact, one function, otherwise "
                 "the derivation would mix two handler copies")
    want = want_names[0]
    if not want.startswith(f"{fn_name}@"):
        sys.exit(f"gate: the binding artifact covers {want} but this run anchored on {fn_name} -- the "
                 "derivation must be composed against the SAME function the arms came from")
    mine = [r for r in arms if r["fn"] == want]
    print(f"binding copy     {want} -- the artifact keys it by address, not by name "
          f"({fn_name} has {len([a for a, n in SS if n == fn_name])} addresses in this Image)")
    imp = [r for r in csv.DictReader(open(IMP_TSV, encoding="utf-8"), delimiter="\t")
           if r["stage"] == "3b" and "callee slot" in (r["meaning"] or "")
           and "EXCLUDED" not in (r["meaning"] or "")]
    if len(imp) != 1:
        sys.exit(f"gate: {IMP_TSV} names {len(imp)} callee-slot writers -- the derivation needs exactly "
                 "one callee to ask for its NULL default")
    callee = imp[0]["value"]
    cal = getter_default(callee)
    md = mode_item()
    dsd_index = md["items"].index("DSD") if "DSD" in md["items"] else None
    if dsd_index is None:
        sys.exit(f"gate: {md['items']} has no DSD item -- the mode axis of the binding has no name")
    sel = live_selection(mine[0]["fn"])
    plug_eq2 = (cal["default"] == 2)
    mode_eq2 = (dsd_index is not None and md["index"] == dsd_index)
    pick = []
    for r in mine:
        nm = r["value_name"]
        is_dsd = "_dsd_" in nm
        is_hp = nm.endswith("headphone")
        if is_dsd == mode_eq2 and is_hp == plug_eq2:
            pick.append(r)
    if len(pick) != 1:
        sys.exit(f"gate: mode=={md['index']} (DSD at {dsd_index}) and the getter's NULL default "
                 f"{cal['default']} select {len(pick)} of the {len(mine)} bound arms, not 1 -- the "
                 "binding is not a 2x2 after all, so nothing is derived")
    arm = pick[0]
    tva = int(arm["value"], 16)
    rows_ = read_table(tva, 1, d["stride"])
    reg, cands = rows_[0][0], rows_[0][1]
    col = sel[0]["column"]
    if col >= len(cands):
        sys.exit(f"gate: column {col} is past the {len(cands)} candidates of {arm['value_name']}")
    pred = cands[col]
    lv = live.get(reg)
    rows = [{"kind": "derived", "name": f"{callee}@{cal['fn_va']:#x}", "bytes": 4,
             "value": f"NULL default={cal['default']}", "as_u32": f"==2 -> {plug_eq2}",
             "reg": f"mov@{cal['mov']:#x} cbz@{cal['cbz']:#x}", "candidates": cal["load_text"],
             "live": "-", "verdict": "the compared plug value when nothing was measured (read off the "
                                      "getter's own instructions)"},
            {"kind": "derived", "name": MODE_CTL, "bytes": len(md["items"]),
             "value": f"in-play item={md['item']} index={md['index']}",
             "as_u32": " ".join(md["items"]), "reg": f"DSD at index {dsd_index}",
             "candidates": f"==2 -> {mode_eq2}", "live": f"idle item={md['idle_item']} index={md['idle_index']}",
             "verdict": "the sheet marks the IDLE state while the in-play capture names another item, so "
                        "the use case sets this control -- the derivation reads the in-play one"},
            {"kind": "derived", "name": arm["value_name"] + f"@{tva:#x}", "bytes": d["stride"],
             "value": f"0x{reg:02x}", "as_u32": " ".join(f"0x{c:02x}" for c in cands),
             "reg": f"0x{reg:02x}", "candidates": " ".join(f"0x{c:02x}" for c in cands),
             "live": (f"0x{lv:02x}" if lv is not None else "-"),
             "verdict": (f"bound arm: mode{'==' if mode_eq2 else '!='}DSD x plug"
                         f"{'==' if plug_eq2 else '!='}2; column {col} from "
                         f"{sel[0]['ohm']} ohm -> predicted 0x{pred:02x}"
                         + (f" == the captured byte" if lv == pred else
                            f" != the captured byte 0x{lv:02x}" if lv is not None else
                            " (no capture)"))}]
    if lv is None:
        sys.exit(f"gate: register 0x{reg:02x} has no in-play byte -- the derivation's own check is "
                 "missing, so the prediction is unverified and must not be published as agreed")
    if lv != pred:
        sys.exit(f"gate: the derived byte 0x{pred:02x} for register 0x{reg:02x} does NOT equal the "
                 f"in-play 0x{lv:02x} -- one of the four inputs (arm binding / live item / getter "
                 "default / impedance column) is wrong on this Image, so neither the derivation nor "
                 "the table may be published")
    def choose(is_dsd, is_hp):
        n = [r for r in mine if ("_dsd_" in r["value_name"]) == is_dsd
             and r["value_name"].endswith("headphone") == is_hp]
        if len(n) != 1:
            return None
        t = int(n[0]["value"], 16)
        rg, cs = read_table(t, 1, d["stride"])[0]
        return {"arm": n[0], "reg": rg, "cands": cs, "byte": cs[col] if col < len(cs) else None}
    pin_col, pin_fn, pin_val = pin_column()
    alt = []
    for is_dsd, is_hp, which_col, why in ((not mode_eq2, plug_eq2, col, "mode flipped to the DSD pair"),
                                          (mode_eq2, not plug_eq2, col, "plug flipped to ==2"),
                                          (mode_eq2, plug_eq2, 3, "same arm, the idle 0-ohm column"),
                                          (mode_eq2, plug_eq2, pin_col,
                                           f"the override pin ({pin_fn} says {pin_val} ohm -> column "
                                           f"{pin_col})")):
        c = choose(is_dsd, is_hp)
        if not c:
            alt.append((why, "NO ARM", None, []))
            continue
        cs = c["cands"]
        b = cs[which_col] if which_col < len(cs) else None
        alt.append((why, c["arm"]["value_name"] + f"@{int(c['arm']['value'], 16):#x}", b, cs))
    if len({a[2] for a in alt if a[2] is not None}) == 1:
        sys.exit(f"gate: every perturbation predicts the SAME byte {[a[2] for a in alt]} -- the byte "
                 "cannot tell these cases apart, so do not claim the derivation is falsifiable on it")
    for why, nm, b, cs in alt:
        rows.append({"kind": "derived", "name": nm, "bytes": d["stride"], "value": f"0x{reg:02x}",
                     "as_u32": " ".join(f"0x{c:02x}" for c in cs), "reg": f"0x{reg:02x}",
                     "candidates": " ".join(f"0x{c:02x}" for c in cs), "live": f"0x{lv:02x}",
                     "verdict": f"perturbation: {why} would predict "
                                + (f"0x{b:02x}" if b is not None else "no byte")
                                + ("  <- identical to the real byte, so this axis is NOT decidable "
                                   "from the register value alone" if b == pred else "")})
    print("derive        callee " + callee + f"@{cal['fn_va']:#x} returns {cal['default']} when its "
          f"slot is NULL ({cal['load_text']} at {cal['load']:#x})")
    print(f"              in-play mode item {md['item']} (index {md['index']}; idle was "
          f"{md['idle_item']} at {md['idle_index']}; DSD is {dsd_index}) => mode"
          f"{'==' if mode_eq2 else '!='}2")
    print(f"              {sel[0]['ctl']} = {sel[0]['ohm']} ohm -> column {col} of the inlining copy")
    print(f"              arm {arm['value_name']}@{tva:#x} row 0x{reg:02x} "
          f"{[f'0x{c:02x}' for c in cands]} -> predicted 0x{pred:02x}, capture says "
          f"0x{lv:02x}  AGREE")
    print("              perturbations: " + "; ".join(
        f"{w} -> " + (f"0x{b:02x}" if b is not None else "NO ARM") for w, _n, b, _c in alt))
    return rows, {"alt": alt, "pred": pred, "live": lv, "reg": reg, "col": col,
                  "cands": cands, "arm": arm, "table_va": tva}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out")
    ap.add_argument("--image", default=IMG, help="kernel Image to read (7's Image on the 7 side)")
    ap.add_argument("--kall", default=KALL, help="kallsyms table for that Image")
    ap.add_argument("--widgets", default=WIDGETS_P, help="decoded widget table for that Image")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--derive", action="store_true",
                    help="compose the arm binding, the live enum item, the getter's NULL default and "
                         "the impedance column into ONE predicted register byte, and gate it against "
                         "the in-play capture")
    ap.add_argument("--rows-at", default="",
                    help="comma-separated table addresses: tile each one with the SAME count/stride the "
                         "handler's loop was derived to use, and report which column matches the live byte")
    a = ap.parse_args()
    global BLOB, SS, SA, NAME, WIDGETS_ACTIVE, TEXT_END
    if a.image != IMG or a.kall != KALL:
        BLOB = open(a.image, "rb").read()
        SS = [(int(p[0], 16), p[2]) for line in open(a.kall, encoding="utf-8", errors="replace")
              for p in [line.split()] if len(p) >= 3 and re.fullmatch(r"[0-9a-f]{16}", p[0])]
        SS.sort()
        SA = sorted({x for x, _n in SS})
        NAME = {}
        for x, n in SS:
            NAME.setdefault(x, n)
        print(f"reading {os.path.basename(a.image)} with {os.path.basename(a.kall)} "
              f"({len(SS)} symbols) -- not the 6.0.1 defaults")
    WIDGETS_ACTIVE = a.widgets
    fn_va, fn_name = find_event_fn(WIDGETS_ACTIVE)
    d, ins = decode_site(fn_va)
    sel_va, cons, extra = find_selector(ins, d["stride"] - 1)
    msgs = identities(d, cons, extra)
    table = read_table(d["table"], d["count"], d["stride"])
    dtr = dt_rows(DTCAP)
    live, live_ok, cap = live_capture()
    hits = sum(1 for r, cs in table if live.get(r) in cs)
    print(f"anchor        {fn_name} @ {fn_va:#x}  (name+handler from {os.path.basename(WIDGETS_ACTIVE)})")
    print(f"loop          count={d['count']} row={d['stride']}B payload={d['elem']}B "
          f"struct=frame+{d['slot']:#x}")
    print(f"identities    " + "; ".join(msgs))
    print(f"table         {NAME.get(d['table'], '?')} @ {d['table']:#x} (span {span_of(d['table'])} B)")
    for r, cs in table:
        lv = live.get(r)
        print(f"   reg 0x{r:02x}  candidates {[f'0x{c:02x}' for c in cs]}  "
              f"live={f'0x{lv:02x}' if lv is not None else '-'}  {'HIT' if lv in cs else 'NO'}")
    print(f"selector      {NAME[sel_va]} @ {sel_va:#x} -- returns {cons}; band boundaries NOT decoded")
    print(f"against live  {cap}: {hits}/{len(table)} integration registers hold a candidate byte"
          + ("   <-- the mechanism is NOT confirmed by the capture" if hits == 0 else ""))
    print(f"dt node       {len(dtr)} properties read off the board")
    rows = [{"kind": "site", "name": fn_name, "bytes": d["count"], "value": f"row={d['stride']}B",
             "as_u32": f"alloc={d['alloc']}", "reg": f"frame+{d['slot']:#x}",
             "candidates": f"field+{d['field']:#x}", "live": f"base+{d['obj']:#x}",
             "verdict": "; ".join(msgs)}]
    for r, cs in table:
        lv = live.get(r)
        rows.append({"kind": "param", "name": f"{NAME.get(d['table'], '?')}@{d['table']:#x}",
                     "bytes": d["stride"],
                     "value": f"0x{r:02x}", "as_u32": " ".join(f"0x{c:02x}" for c in cs),
                     "reg": f"0x{r:02x}", "candidates": " ".join(f"0x{c:02x}" for c in cs),
                     "live": (f"0x{lv:02x}" if lv is not None else "-"),
                     "verdict": ("HIT" if lv in cs else ("NO" if lv is not None else "no-capture"))})
    if a.rows_at:
        print("other same-named tables, tiled by the same ruler (count=1 row, handler stride):")
        for at in [int(x, 0) for x in a.rows_at.split(",") if x.strip()]:
            rr = read_table(at, 1, d["stride"])
            r, cs = rr[0]
            lv = live.get(r)
            col = cs.index(lv) if lv in cs else None
            how = (f"column index {col} equals the in-play byte" if col is not None
                   else "no column equals the in-play byte")
            print(f"   {NAME.get(at, '?')}@{at:#x}  reg 0x{r:02x} columns "
                  f"{[f'0x{c:02x}' for c in cs]}  live={'-' if lv is None else f'0x{lv:02x}'}  {how}")
            rows.append({"kind": "alt-table", "name": f"{NAME.get(at, '?')}@{at:#x}",
                         "bytes": d["stride"], "value": f"0x{r:02x}",
                         "as_u32": " ".join(f"0x{c:02x}" for c in cs), "reg": f"0x{r:02x}",
                         "candidates": " ".join(f"0x{c:02x}" for c in cs),
                         "live": (f"0x{lv:02x}" if lv is not None else "-"), "verdict": how})
    if a.derive:
        drows, _dres = derive(d, table, live, fn_name)
        rows.extend(drows)
    for x in disasm(sel_va, min(span_of(sel_va), 0x80)):
        rows.append({"kind": "selector-insn", "name": NAME[sel_va], "bytes": 4,
                     "value": f"{x.mnemonic} {x.op_str}", "as_u32": "-", "reg": "-",
                     "candidates": "-", "live": "-", "verdict": "exported, not decoded"})
    rows += dtr
    if a.out:
        cols = ["kind", "name", "bytes", "value", "as_u32", "reg", "candidates", "live", "verdict"]
        widths = set()
        with open(a.out, "w", encoding="utf-8") as fh:
            fh.write("\t".join(cols) + "\n")
            for r in rows:
                line = "\t".join(str(r.get(c, "-")) for c in cols)
                widths.add(len(line.split("\t")))
                fh.write(line + "\n")
        if len(widths) != 1:
            sys.exit(f"gate: {a.out} rows disagree on column count {sorted(widths)}")
        print(f"wrote {a.out} ({len(rows)} rows x {next(iter(widths))} columns)")
    if a.selftest:
        bad = []
        for key, val in (("count", d["count"] + 1), ("elem", d["elem"] + 1),
                         ("obj", d["obj"] + 8), ("stride", d["stride"] + 1)):
            p = dict(d)
            p[key] = val
            try:
                identities(p, cons, extra)
            except SystemExit as e:
                print(f"selftest: perturbing {key}->{val} aborts -> {str(e)[:130]}")
            else:
                bad.append(key)
        if bad:
            sys.exit(f"gate: --selftest: perturbing {bad} still satisfied every identity -- that "
                     "gate is inert and cannot certify the chain")
        print("selftest: all four perturbations abort")


if __name__ == "__main__":
    main()
