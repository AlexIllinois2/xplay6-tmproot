#!/usr/bin/env python3
"""tools/dac_impedance_chain.py -- where does the number that picks the DAC's impedance column come from?

§322 proved the enable path writes (addr,value) pairs out of the compiled-in table
integration_params_normal, and that ONE OF FOUR candidate columns is picked by get_hp_imp_index.  What
was never named is the INPUT of that selector, and §289 left the trampoline
`ldr x0,[vivo_codec]; ldr x0,[x0,#0x60]; ldr x0,[x0,#0x98]; blr x0` untraced.  They are the same
question, and the answer is portable: on 7 the DAC column can only be predicted if the impedance
measurement behind that pointer exists.

Four stages, each with a control:

  1  the DAPM handler itself: the two cbz guards, the `blr`, and the driver's own printk format
     strings -- it prints "%s: impedance %u", so the value it saw is a live, readable number.
  2  the selector's arithmetic: read the compare immediates out of get_hp_imp_index and rebuild the
     whole bucket table (including what happens below the lowest threshold).  Nothing here is typed in.
  2b every symbol named hifi_codec_dac_event, BY ADDRESS: which copy calls the selector and which
     inlines the same decision tree.  The inlined window is located by its own shape (two sub, three
     cmp, b.hi, b.ls, one conditional-select) and run through the same emulator, so the two tables can
     be compared input by input instead of by my reading of the disassembly.
  3  who fills the slot the handler calls: scan the audio family for stores at displacement +0x98 whose
     value is a materialised text address, and name the function.
  3b the same question for the INLINING copy, whose blr target is [[obj+0x68]+0xa0]: name the store that
     fills +0xa0 (8-byte value holding a text address only) and print the +0x68 census as the link that
     is NOT decidable offline.
  4  cross-check against the device: the ALSA integer controls "HPHL/HPHR Impedance" and the enum
     "HP imped fixed" in the three captures (idle / playing headphones / playing speaker), put the
     measured number through stage 2's buckets, and compare with the column that §322's own
     candidate-vs-live table implies for the DAC registers.

usage: tools/dac_impedance_chain.py [--out TSV] [--selftest]
"""
import argparse
import bisect
import collections
import csv
import os
import re
import struct
import sys

from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, Cs

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
ART = os.path.join(ROOT, "art", "audio-6.0.1")
IMG = os.environ.get("DAC_IMG", os.path.join(ROOT, "fw", "Image"))
KALL = os.environ.get("DAC_KALL", os.path.join(ROOT, "art", "kallsyms_real.txt"))
LIVE = os.environ.get("DAC_LIVE", os.path.join(ART, "live"))
TEXT_BASE = 0xFFFFFFC000080000
TEXT_END = TEXT_BASE + os.path.getsize(IMG)
MASK64 = 0xFFFFFFFFFFFFFFFF
ALIAS = {"fp": 29, "lr": 30, "sp": 31}
HANDLER = "hifi_codec_dac_event"
SELECTOR = "get_hp_imp_index"
FAMILY = re.compile(r"^(es90|vivo_|hifi_|tasha_|tomtom_|wcd9|wcd_|dsd|smart_pa|tfa98xx)")
CAPTURES = {"idle": "tinymix-D0.txt", "playing-headphones": "tinymix-D0-playing-headphones.txt",
            "playing-speaker": "tinymix-D0-playing-speaker.txt"}
BLOB = open(IMG, "rb").read()
_MD = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
_MD.detail = True
MD = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
MD.detail = True

ENTRIES = []
for _line in open(KALL, encoding="utf-8", errors="replace"):
    _p = _line.split()
    if len(_p) >= 3 and re.fullmatch(r"[0-9a-f]{16}", _p[0]):
        ENTRIES.append((int(_p[0], 16), _p[1], _p[2]))
NAME = {}
for _a, _t, _n in ENTRIES:
    NAME.setdefault(_a, _n)
ADDR = {}
for _a, _t, _n in ENTRIES:
    ADDR.setdefault(_n, _a)
TEXT = sorted([(a, n) for a, t, n in ENTRIES if t in "tT" and TEXT_BASE <= a < TEXT_END])
TA = [a for a, _n in TEXT]
ADDR_BY_NAME = {}
for _a, _t, _n in ENTRIES:
    ADDR_BY_NAME.setdefault(_n, []).append(_a)


def fn_end_up_to(va):
    """start of the next text symbol AFTER va -- the span end for a site inside a function"""
    for a, _n in TEXT:
        if a > va:
            return a
    return va + 4


def fn_end(va):
    i = bisect.bisect_right(TA, va)
    return TEXT[i][0] if i < len(TA) else va + 0x4000


def owner(va):
    i = bisect.bisect_right(TA, va) - 1
    return TEXT[i][1] if i >= 0 else "?"


def decode(va, end):
    out, a = [], va
    while a < end:
        w = BLOB[a - TEXT_BASE:a - TEXT_BASE + 4]
        if len(w) < 4:
            break
        if struct.unpack("<I", w)[0] == 0:
            a += 4
            continue
        x = next(MD.disasm(w, a), None)
        if x is not None:
            out.append(x)
        a += 4
    return out


def rnum(md, reg):
    n = md.reg_name(reg) or ""
    if n in ALIAS:
        return ALIAS[n]
    m = re.fullmatch(r"[wx](\d+)", n)
    return int(m.group(1)) if m else None


def cstr(va):
    o = va - TEXT_BASE
    if o < 0 or o >= len(BLOB):
        return None
    end = BLOB.find(b"\x00", o)
    if end < 0 or end - o > 200:
        return None
    s = BLOB[o:end]
    if not s:
        return None
    if s.startswith(b"\x01"):          # printk log-level prefix, e.g. KERN_DEBUG
        s = s[1:]
    if min(c for c in s if c not in (0x09, 0x0a)) < 0x20 or max(s) > 0x7e:
        return None
    return s.decode("latin1")


def walk_chain(name):
    """the same pointer/format model as handler_stage(), reusable for the getter behind the slot"""
    va = ADDR.get(name)
    if va is None or not (TEXT_BASE <= va < TEXT_END):
        return None
    ins = decode(va, fn_end(va))
    pg, ptrs, chain, fmts, calls, defaults = {}, set(), [], [], [], []
    for x in ins:
        ops, mn = x.operands, x.mnemonic
        dst = rnum(MD, ops[0].reg) if ops and ops[0].type == 1 else None
        m = [o for o in ops if o.type == 3]
        if mn == "adrp" and len(ops) == 2 and ops[1].type == 2 and dst is not None:
            pg[dst] = ops[1].imm & MASK64
            continue
        if mn in ("add", "mov") and len(ops) == 3 and ops[2].type == 2:
            b = rnum(MD, ops[1].reg)
            if b in pg and dst is not None:
                pg[dst] = (pg[b] + (ops[2].imm & 0xFFF)) & MASK64
                s = cstr(pg[dst])
                if s and "%" in s:
                    fmts.append((x.address, pg[dst], s))
            elif b in ptrs and dst is not None:
                ptrs.add(dst)
            continue
        if mn == "mov" and len(ops) == 2 and ops[1].type == 1:
            s = rnum(MD, ops[1].reg)
            if s in pg and dst is not None:
                pg[dst] = pg[s]
            elif s in ptrs and dst is not None:
                ptrs.add(dst)
            continue
        if mn == "mov" and ops[1].type == 2:
            defaults.append((x.address, ops[1].imm & MASK64))
        if m:
            base = rnum(MD, m[0].mem.base)
            val = pg.get(base)
            at = (val + m[0].mem.disp) & MASK64 if val is not None else None
            s = cstr(at) if at is not None else None
            if s and "%" in s:
                fmts.append((x.address, at, s))
            elif val is not None or base in ptrs:
                chain.append({"site": x.address, "text": f"{mn} {x.op_str}",
                              "disp": m[0].mem.disp, "global": at})
                if dst is not None and mn.startswith("ldr"):
                    ptrs.add(dst)
            if dst is not None:
                pg.pop(dst, None)
        if mn in ("bl", "b") and ops and ops[0].type == 2:
            t = ops[0].imm & MASK64
            calls.append((x.address, t, NAME.get(t, f"?{t:#x}")))
        elif mn == "blr" and ops and ops[0].type == 1:
            chain.append({"site": x.address, "text": f"blr {x.op_str}", "disp": None,
                          "global": None, "via_ptr": rnum(MD, ops[0].reg) in ptrs})
    return {"fn": name, "ins": len(ins), "chain": chain, "fmts": fmts, "calls": calls,
            "defaults": defaults}


def handler_stage():
    """walk the DAPM handler with a page/pointer model: a register either holds a materialised address
    (adrp+add), or is a pointer we got out of one.  Format strings are recognised by their bytes, and
    every dereference along the pointer path is reported with the displacement it used."""
    ins = decode(ADDR[HANDLER], fn_end(ADDR[HANDLER]))
    if len(ins) < 60:
        sys.exit(f"gate: {HANDLER} decoded to {len(ins)} instructions -- too few to be the DAPM "
                 "handler this chain is about")
    pg, ptrs, chain, fmts, calls = {}, set(), [], [], []
    for x in ins:
        ops, mn = x.operands, x.mnemonic
        dst = rnum(MD, ops[0].reg) if ops and ops[0].type == 1 else None
        m = [o for o in ops if o.type == 3]
        if mn == "adrp" and len(ops) == 2 and ops[1].type == 2 and dst is not None:
            pg[dst] = ops[1].imm & MASK64
            continue
        if mn in ("add", "mov") and len(ops) == 3 and ops[2].type == 2:
            b = rnum(MD, ops[1].reg)
            if b in pg and dst is not None:
                pg[dst] = (pg[b] + (ops[2].imm & 0xFFF)) & MASK64
                s = cstr(pg[dst])                      # a format string is materialised as an ADDRESS
                if s and "%" in s:
                    fmts.append((x.address, pg[dst], s))
            elif b in ptrs and dst is not None:
                ptrs.add(dst)
            continue
        if mn == "mov" and len(ops) == 2 and ops[1].type == 1:
            s = rnum(MD, ops[1].reg)
            if s in pg and dst is not None:
                pg[dst] = pg[s]
            elif s in ptrs and dst is not None:
                ptrs.add(dst)
            continue
        if m:
            base = rnum(MD, m[0].mem.base)
            val = pg.get(base)
            at = (val + m[0].mem.disp) & MASK64 if val is not None else None
            s = cstr(at) if at is not None else None
            if s and "%" in s:
                fmts.append((x.address, at, s))
            elif val is not None or base in ptrs:
                chain.append({"site": x.address, "text": f"{mn} {x.op_str}",
                              "disp": m[0].mem.disp, "global": at})
                if dst is not None and mn.startswith("ldr"):
                    ptrs.add(dst)
            if dst is not None:
                pg.pop(dst, None)
        if mn in ("bl", "b") and ops and ops[0].type == 2:
            t = ops[0].imm & MASK64
            calls.append((x.address, t, NAME.get(t, f"?{t:#x}")))
        elif mn == "blr" and ops and ops[0].type == 1:
            chain.append({"site": x.address, "text": f"blr {x.op_str}", "disp": None,
                          "global": None, "via_ptr": rnum(MD, ops[0].reg) in ptrs})
    return ins, chain, fmts, calls


def selector_stage():
    va = ADDR.get(SELECTOR)
    if va is None:
        sys.exit(f"gate: {SELECTOR} is not in {KALL} -- the selector whose column we are tracing has "
                 "no address, so nothing downstream can be named")
    ins = decode(va, fn_end(va))
    end = next((i for i, x in enumerate(ins) if x.mnemonic == "ret"), None)
    if end is None:
        sys.exit(f"gate: {SELECTOR} has no ret in its first {len(ins)} instructions -- the decode ran "
                 "past the function and the immediates below are not its arithmetic")
    body = ins[:end + 1]
    subs = [x.operands[2].imm & MASK64 for x in body if x.mnemonic == "sub" and len(x.operands) == 3
            and x.operands[2].type == 2]
    cmps = [x.operands[1].imm & MASK64 for x in body if x.mnemonic in ("cmp",) and x.operands[1].type == 2]
    moves = [x.operands[1].imm & MASK64 for x in body if x.mnemonic == "mov" and x.operands[1].type == 2]
    conds = [x.op_str.rsplit(",", 1)[-1].strip() for x in body if x.mnemonic.startswith("cs")]
    if not (subs and cmps and moves):
        sys.exit(f"gate: {SELECTOR} yielded subs={subs} cmps={cmps} moves={moves} -- cannot rebuild "
                 "the bucket table from its own immediates")
    # a column can also come from `csinc wd, wn, wzr, cond` (= zero plus one), which is not a mov
    cs_extra = sorted({1 for x in body if x.mnemonic.startswith("cs")
                       and x.op_str.replace(",", " ").split()[-2] in ("wzr", "xzr")})
    return body, subs, cmps, sorted(set(moves) | set(cs_extra)), conds, cs_extra


def family_writers(disp):
    """stage 3: stores at `disp` whose value register was materialised from a TEXT address.

    The page map must be INVALIDATED by anything that redefines the register -- a load, a call
    (caller-saved x0-x17), an untracked arithmetic op.  Without that, a value materialised 0x300 bytes
    earlier is still on the books when `ldr x0,[x29,#0x68]` has long since overwritten x0, and the row
    claims a function pointer the code never stores (§343 found exactly this on
    vivo_codec_platform_probe's +0x68, whose real content is a kmalloc(0xd0) block)."""
    out = []
    stats = {"invalidated": 0, "clobbered": 0}
    text_set = set(TA)
    for va, nm in TEXT:
        if not FAMILY.match(nm):
            continue
        ins = decode(va, fn_end(va))
        pg = {}
        for x in ins:
            ops = x.operands
            mn = x.mnemonic
            tracked = False
            if mn == "adrp" and len(ops) == 2 and ops[1].type == 2 and ops[0].type == 1:
                pg[rnum(MD, ops[0].reg)] = (ops[1].imm & MASK64)
                tracked = True
            elif mn in ("add", "sub", "mov") and len(ops) == 3 and ops[2].type == 2 \
                    and ops[0].type == 1 and ops[1].type == 1:
                b = rnum(MD, ops[1].reg)
                if b in pg:
                    pg[rnum(MD, ops[0].reg)] = (pg[b] + (ops[2].imm & 0xFFF)) & MASK64
                    tracked = True
            elif mn == "mov" and len(ops) == 2 and ops[0].type == 1 and ops[1].type == 1:
                s = rnum(MD, ops[1].reg)
                d = rnum(MD, ops[0].reg)
                if s in pg:
                    pg[d] = pg[s]
                    tracked = True
            elif mn.startswith("st") and ops:
                m = [o for o in ops if o.type == 3]
                if m and m[0].mem.disp == disp:
                    src = rnum(MD, ops[0].reg)
                    val = pg.get(src)
                    out.append({"fn": nm, "site": x.address, "text": f"{x.mnemonic} {x.op_str}",
                                "disp": disp, "value_va": val,
                                "value_fn": NAME.get(val) if val in text_set else None,
                                "width": 8 if MD.reg_name(ops[0].reg).startswith("x") else 4,
                                "base": MD.reg_name(m[0].mem.base)})
                # a store defines nothing
                continue
            if mn in ("bl", "blr", "braa", "brba"):
                for r in [k for k in pg if k <= 17]:
                    pg.pop(r)
                    stats["clobbered"] += 1
                continue
            if not tracked:
                for o in ops:
                    if o.type == 1:
                        r = rnum(MD, o.reg)
                        if r in pg:
                            pg.pop(r)
                            stats["invalidated"] += 1
    return [w for w in out if w["fn"] != HANDLER], stats


def live_stage():
    """stage 4: the impedance as the device itself reports it, plus the fixed-override control"""
    rows = []
    for tag, fn in sorted(CAPTURES.items()):
        path = os.path.join(LIVE, fn)
        if not os.path.exists(path):
            continue
        vals = {}
        for line in open(path, encoding="utf-8", errors="replace"):
            p = line.rstrip("\n").split("\t")
            if len(p) < 4:
                continue
            m = re.match(r"^(.*?)\s\s+(\S+)\s*$", p[3])   # "<name><padding><value>"
            if m and m.group(1) in ("HPHL Impedance", "HPHR Impedance", "HP imped fixed"):
                vals[m.group(1)] = m.group(2)
        if vals:
            rows.append({"capture": tag, "file": fn, "controls": vals})
    return rows


CONDS = {"hi": lambda c, z: c and not z, "ls": lambda c, z: (not c) or z,
         "hs": lambda c, z: c, "lo": lambda c, z: not c,
         "eq": lambda c, z: z, "ne": lambda c, z: not z,
         "gt": lambda c, z: not z and c and not z, "cc": lambda c, z: not c}


def selector_body():
    ins = decode(ADDR[SELECTOR], fn_end(ADDR[SELECTOR]))
    end = next((i for i, x in enumerate(ins) if x.mnemonic == "ret"), None)
    if end is None:
        sys.exit(f"gate: {SELECTOR} has no ret in its first {len(ins)} instructions -- the decode ran "
                 "past the function, so the immediates would not be its arithmetic")
    return ins[:end + 1]


def emulate(body, value, in_reg=0, out_reg=None, init=None):
    """run the selector's own decoded instructions.  Anything outside the handful of mnemonics it
    actually uses aborts -- an emulator that silently skips an instruction would report a bucket table
    it never executed.  `in_reg`/`out_reg` let the same machine model the window INLINED inside a handler
    (where the value arrives in some register and the column leaves in another, with no `ret`), and
    `init` is a (register, value) pair the window enters already holding, read off the `mov` before it."""
    r = [0] * 31
    r[in_reg] = value & 0xFFFFFFFF
    if init:
        r[init[0]] = init[1] & 0xFFFFFFFF
    c = z = False
    pc, steps = 0, 0
    while pc < len(body):
        x = body[pc]
        steps += 1
        if steps > 400:
            sys.exit(f"gate: the {SELECTOR} emulator looped -- the body is not the straight-line "
                     "decision tree this tool models")
        mn, ops = x.mnemonic, x.operands
        last = x.op_str.rsplit(",", 1)[-1].strip()
        try:
            if mn == "ret":
                return r[0 if out_reg is None else out_reg]
            elif mn == "mov" and ops[1].type == 2:
                r[rnum(MD, ops[0].reg)] = ops[1].imm & 0xFFFFFFFF
            elif mn == "mov" and ops[1].type == 1:
                r[rnum(MD, ops[0].reg)] = r[rnum(MD, ops[1].reg)]
            elif mn == "sub" and len(ops) == 3:
                a = r[rnum(MD, ops[1].reg)]
                b = (ops[2].imm & 0xFFFFFFFF) if ops[2].type == 2 else r[rnum(MD, ops[2].reg)]
                r[rnum(MD, ops[0].reg)] = (a - b) & 0xFFFFFFFF
            elif mn == "cmp":
                a = r[rnum(MD, ops[0].reg)]
                b = (ops[1].imm & 0xFFFFFFFF) if ops[1].type == 2 else r[rnum(MD, ops[1].reg)]
                z, c = (a == b), (a >= b)
            elif mn.startswith("b.") and ops[0].type == 2:
                cond = mn[2:]
                if cond not in CONDS:
                    sys.exit(f"gate: unmodelled branch condition {mn!r} in {SELECTOR}")
                if CONDS[cond](c, z):
                    t = ops[0].imm & MASK64
                    idx = next((i for i, y in enumerate(body) if y.address == t), None)
                    if idx is None:
                        if out_reg is not None:
                            return r[out_reg]      # the window's exits are the handler's own blocks
                        sys.exit(f"gate: {SELECTOR} branches to {t:#x}, outside the modelled body")
                    pc = idx
                    continue
            elif mn.startswith("cs") and len(ops) >= 3:
                tok = [t.strip() for t in x.op_str.split(",")]
                cond = tok[-1]
                if cond not in CONDS:
                    sys.exit(f"gate: unmodelled conditional-select suffix {cond!r} in {SELECTOR}")

                def idx(name):
                    if name in ("wzr", "xzr"):
                        return None
                    m = re.fullmatch(r"[wx](\d+)", name)
                    if not m:
                        sys.exit(f"gate: cannot read the operand {name!r} of {x.op_str}")
                    return int(m.group(1))

                wd, wn, wm = idx(tok[0]), idx(tok[1]), idx(tok[2])
                v_n = 0 if wn is None else r[wn]
                v_m = 0 if wm is None else r[wm]
                r[wd] = v_n if CONDS[cond](c, z) else (v_m + 1) & 0xFFFFFFFF
            else:
                sys.exit(f"gate: the emulator does not model {mn!r} ({x.op_str}) found in "
                         f"{SELECTOR} -- refusing to report a bucket table it did not execute")
        except TypeError as e:
            sys.exit(f"gate: emulator tripped on {x.mnemonic} {x.op_str}: {e}")
        pc += 1
    if out_reg is not None:
        return r[out_reg]
    sys.exit(f"gate: the {SELECTOR} emulation fell off the end without a ret")


def inline_windows(fn_va):
    """the same decision tree INLINED inside a handler: located by its own shape (two `sub`, three
    `cmp`, one `b.hi`, one `b.ls`, one conditional-select) rather than by a name, and executed by the
    emulator above.  Returns [] for a copy that calls the selector instead of inlining it."""
    end = fn_end(fn_va)
    ins = decode(fn_va, end)
    out = []
    for ci, x in enumerate(ins):
        if not x.mnemonic.startswith("cs"):
            continue
        j, subs, cmps = ci, 0, 0
        while j >= 0:
            mn = ins[j].mnemonic
            if mn == "sub":
                subs += 1
            elif mn == "cmp":
                cmps += 1
            elif mn in ("bl", "blr", "b", "ret"):
                break
            if subs == 2 and cmps == 3:
                break
            j -= 1
        if not (subs == 2 and cmps == 3):
            continue
        span = ins[j:ci + 1]
        toks = [t.strip() for t in x.op_str.split(",")]
        m = re.fullmatch(r"[wx](\d+)", toks[0])
        if not m:
            sys.exit(f"gate: cannot read the destination of {x.mnemonic} {x.op_str} at {x.address:#x}")
        out_reg = int(m.group(1))
        written = {rnum(MD, y.operands[0].reg) for y in span
                   if y.operands and y.operands[0].type == 1}
        if out_reg not in written:
            sys.exit(f"gate: the window {span[0].address:#x}..{x.address:#x} never writes w{out_reg}, "
                     "the conditional-select's destination -- the emulator would report a column that "
                     "the code does not produce")
        # the column register can enter the window already holding the top bucket's constant, set by a
        # `mov` BEFORE the tree; without that the emulator would return 0 where the code returns 3
        init = None
        for k in range(j - 1, max(-1, j - 33), -1):
            y = ins[k]
            if y.operands and y.operands[0].type == 1 and rnum(MD, y.operands[0].reg) == out_reg:
                if y.mnemonic == "mov" and len(y.operands) == 2 and y.operands[1].type == 2:
                    init = (out_reg, y.operands[1].imm & 0xFFFFFFFF, y.address)
                break
        if init is None:
            sys.exit(f"gate: the window at {span[0].address:#x} enters with w{out_reg} neither written "
                     "inside nor by a `mov #imm` in the 32 instructions before it -- the emulator would "
                     "invent a 0 for that register, so no bucket table may be published")
        first = next(y for y in span if y.mnemonic == "sub")
        in_reg = rnum(MD, first.operands[1].reg)
        over = [y.address for y in span if y.mnemonic not in ("cmp", "cmn", "tst", "teq")
                and y.operands and y.operands[0].type == 1
                and rnum(MD, y.operands[0].reg) == in_reg]
        out.append({"start": span[0].address, "end": x.address, "body": span,
                    "in_reg": in_reg, "out_reg": out_reg, "n": len(span), "overwrite": over,
                    "init": init})
    return out


def bucket_table(body, hi=200, in_reg=0, out_reg=None, init=None):
    """the decision table as EXECUTED: which bucket each input lands in, compressed into ranges"""
    seq = [(v, emulate(body, v, in_reg, out_reg, init)) for v in range(hi)]
    ranges, cur = [], None
    for v, b in seq:
        if cur and cur[2] == b:
            cur[1] = v
        else:
            cur = [v, v, b]
            ranges.append(cur)
    return ranges, sorted({b for _v, b in seq})


def col_at(ranges, value):
    for lo, hi, b in ranges:
        if lo <= value <= hi:
            return b
    return None


def image_scan(global_vas, target_names):
    """ONE pass over every decodable text symbol (span-bounded by its successor) collecting two things:
      hits  -- every read/write whose computed address equals one of `global_vas`
      calls -- every `bl`/`b` whose target is one of `target_names`
    The page of a register that gets written is dropped (§325's rule), otherwise a stale page turns
    later accesses through that register into phantom hits on the watched slot."""
    tgts = {ADDR[n] for n in target_names if n in ADDR}
    hits, calls, decoded = [], [], 0
    for k, (va, nm) in enumerate(TEXT):
        end = TEXT[k + 1][0] if k + 1 < len(TEXT) else va + 4
        ins = decode(va, end)
        decoded += len(ins)
        pg = {}
        for x in ins:
            ops, mn = x.operands, x.mnemonic
            dst = rnum(MD, ops[0].reg) if ops and ops[0].type == 1 else None
            if mn == "adrp" and len(ops) == 2 and ops[1].type == 2 and dst is not None:
                pg[dst] = ops[1].imm & MASK64
                continue
            if mn in ("add", "mov") and len(ops) == 3 and ops[2].type == 2:
                b = rnum(MD, ops[1].reg)
                if b in pg and dst is not None:
                    pg[dst] = (pg[b] + (ops[2].imm & 0xFFF)) & MASK64
                    continue
            if mn in ("bl", "b") and ops and ops[0].type == 2:
                t = ops[0].imm & MASK64
                if t in tgts:
                    calls.append({"caller": nm, "site": x.address, "target": NAME.get(t, f"?{t:#x}")})
            m = [o for o in ops if o.type == 3]
            if m:
                base = rnum(MD, m[0].mem.base)
                val = pg.get(base)
                if val is not None:
                    at = (val + m[0].mem.disp) & MASK64
                    if at in global_vas:
                        hits.append({"fn": nm, "site": x.address, "text": f"{mn} {x.op_str}",
                                     "global": at,
                                     "dir": "write" if mn.startswith("st") else "read"})
            if dst is not None and not mn.startswith(("st", "cmp", "tst")):
                pg.pop(dst, None)
    return hits, calls, decoded


def override_pins(hits, watched):
    """the shape the second handler copy uses: read the override flag, branch if it is zero, and
    overwrite the impedance register with a constant.  Reported as (reader, flag site, pinned value)."""
    pins = []
    for h in hits:
        if h["global"] != watched["vivo_hp_imped_fixed"] or h["dir"] != "read":
            continue
        va = ADDR_BY_NAME.get(h["fn"], [])
        start = min([a for a in va if a <= h["site"]], default=None)
        if start is None:
            continue
        ins = decode(start, fn_end_up_to(h["site"]))
        idx = next((i for i, x in enumerate(ins) if x.address == h["site"]), None)
        if idx is None:
            continue
        guard = next((x for x in ins[idx + 1:idx + 8] if x.mnemonic.startswith("cb")), None)
        movs = [x for x in ins[idx + 1:idx + 12] if x.mnemonic == "mov" and x.operands[1].type == 2]
        if guard is not None and movs:
            pins.append({"fn": h["fn"], "site": h["site"], "guard": f"{guard.mnemonic} "
                         f"{guard.op_str}", "value": movs[0].operands[1].imm & 0xFFFFFFFF,
                         "mov": f"{movs[0].mnemonic} {movs[0].op_str}"})
    return pins


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if HANDLER not in ADDR or SELECTOR not in ADDR:
        sys.exit(f"gate: {HANDLER} or {SELECTOR} missing from {KALL} -- this tool is about that chain")
    ins, chain, fmts, calls = handler_stage()
    named = [f for _, _, f in fmts if f and "impedance" in f]
    if not named:
        sys.exit(f"gate: {HANDLER} prints {len(fmts)} format string(s) but none says 'impedance' -- "
                 "the value the handler reads is not the quantity this chain claims, stop")
    sel_body, subs, cmps, moves, conds, cs_extra = selector_stage()
    body = selector_body()
    ranges, reachable = bucket_table(body)
    if reachable != moves:
        sys.exit(f"gate: emulating {SELECTOR} reaches buckets {reachable} but the function contains "
                 f"the result constants {moves} -- the emulator and the code disagree, so neither the "
                 "table nor any bucket below may be published")
    lives = live_stage()
    if not lives:
        sys.exit(f"gate: no capture in {LIVE} exposes HPHL/HPHR Impedance -- the live half of this "
                 "chain cannot be checked, so only the static reading would be published")
    measured = []
    for r in lives:
        for k in ("HPHL Impedance", "HPHR Impedance"):
            v = r["controls"].get(k)
            if v is not None and re.fullmatch(r"\d+", v):
                measured.append((r["capture"], k, int(v), emulate(body, int(v))))
    ipath = os.path.join(ART, "dac-integration-params.PD1610.tsv")
    implied = []
    if os.path.exists(ipath):
        for row in csv.DictReader(open(ipath, encoding="utf-8"), delimiter="\t"):
            if row["kind"] != "param":
                continue
            cands = row["candidates"].split()
            if row["live"] in cands:
                implied.append((row["reg"], cands.index(row["live"]), len(cands)))
    writes, st98 = family_writers(0x98)
    fn_named = [w for w in writes if w["value_fn"]]
    print(f"handler         {HANDLER} @ {ADDR[HANDLER]:#x}, {len(ins)} instructions")
    for site, va, s in fmts:
        print(f"                 printk format @ {va:#x}: {s!r}  (loaded at {site:#x})")
    print("                dereferences on the path to the getter: " +
          ", ".join(f"{c['text']} @ {c['site']:#x}"
                  + (f" (global {c['global']:#x} = {NAME.get(c['global'], '?')})"
                     if c.get("global") else "")
                  + (" [blr through a pointer we followed]" if c.get("via_ptr") else "")
                  for c in chain))
    out_calls = [(s, n) for s, _t, n in calls if n != "printk"]
    print(f"                 calls out ({len(out_calls)} of {len(calls)} non-printk): " +
          ", ".join(f"{n} @ {s:#x}" for s, n in out_calls))
    print(f"selector        {SELECTOR}: subs={subs} cmps={cmps} columns={moves} "
          f"({cs_extra or []} of them only reachable through the conditional-select {conds})")
    print(f"                emulated buckets (input -> column): " +
          ", ".join(f"{lo}..{hi}=>{b}" for lo, hi, b in ranges) +
          f"   [all four columns reachable: {reachable == moves}]")
    # every symbol named HANDLER is handled BY ADDRESS (two exist here and they are not the same code)
    copies = []
    for va in sorted(set(ADDR_BY_NAME.get(HANDLER, []))):
        hin = decode(va, fn_end(va))
        n_calls = sum(1 for x in hin if x.mnemonic == "bl" and x.operands
                      and x.operands[0].type == 2 and (x.operands[0].imm & MASK64) == ADDR[SELECTOR])
        wins = []
        for w in inline_windows(va):
            rr, reach = bucket_table(w["body"], in_reg=w["in_reg"], out_reg=w["out_reg"],
                                     init=w["init"][:2])
            if reach != moves:
                sys.exit(f"gate: the tree inlined in {HANDLER}@{va:#x} reaches {reach} but the selector "
                         f"function yields {moves} -- the two readings of the same decision disagree, so "
                         "publish neither")
            wins.append((w, rr))
        copies.append({"va": va, "calls": n_calls, "wins": wins})
    if not any(c["calls"] for c in copies) or not any(c["wins"] for c in copies):
        sys.exit(f"gate: over the {len(copies)} copy(ies) of {HANDLER} I found "
                 + ", ".join(f"{c['va']:#x} calls={c['calls']} inlined={len(c['wins'])}" for c in copies)
                 + " -- the published shape is one copy calling the selector and one inlining it, and "
                 "this image does not say that")
    desc = []
    for c in copies:
        parts = []
        if c["calls"]:
            parts.append(f"{c['calls']} bl to {SELECTOR}")
        for w, _rr in c["wins"]:
            parts.append(f"inlined tree {w['start']:#x}..{w['end']:#x} "
                         f"(in w{w['in_reg']}, column w{w['out_reg']})")
        desc.append((f"{c['va']:#x} = " + ", ".join(parts)) if parts
                    else f"{c['va']:#x} = NEITHER a call nor an inlined tree (not evidence of anything)")
    print(f"copies          {len(copies)} symbol(s) named {HANDLER}, read by address: "
          + "; ".join(desc))
    for c in copies:
        for w, rr in c["wins"]:
            if w["overwrite"]:
                print(f"                note {c['va']:#x}: this copy rewrites its own input register "
                      f"w{w['in_reg']} at {', '.join(hex(o) for o in w['overwrite'])} -- the emulator "
                      "runs the window in order, so that later subtract uses whatever the model holds "
                      "there; the table below is only right if that matches the code's intent")
            print(f"                inlined buckets at {c['va']:#x}: "
                  + ", ".join(f"{lo}..{hi}=>{b}" for lo, hi, b in rr))
            diff = [v for v in range(200) if col_at(ranges, v) != col_at(rr, v)]
            if diff:
                print(f"                inline vs function DIFFER on inputs "
                      f"{diff[0]}..{diff[-1]} ({len(diff)} of 200): " +
                      ", ".join(f"input {v} -> function col{col_at(ranges, v)}, inline col{col_at(rr, v)}"
                                for v in (diff[0], diff[-1])))
            else:
                print("                inline and function agree on every input 0..199")
            for cap, k, v, _col in measured:
                print(f"                live reading {cap}/{k}={v} ohm: function col{col_at(ranges, v)}, "
                      f"this inline copy col{col_at(rr, v)}"
                      + ("  <- the two tables disagree on a value the device reported"
                         if col_at(ranges, v) != col_at(rr, v) else ""))
    getters = sorted({w["value_fn"] for w in fn_named if w["value_fn"] and "imped" in w["value_fn"]})
    if not getters:
        sys.exit(f"gate: nothing stored at +0x98 in the audio family has an impedance-shaped name "
                 f"(saw {sorted({w['value_fn'] for w in fn_named})}) -- the handler's call would be "
                 "unnamed, so the chain stops being a chain")
    walked = {g: walk_chain(g) for g in getters}
    for g, w in sorted(walked.items()):
        if w is None:
            sys.exit(f"gate: {g} is not decodable text -- cannot read its own format strings")
        ohm = [s for _a, _v, s in w["fmts"] if "ohm" in s]
        glob = sorted({f"{c['global']:#x} = {NAME.get(c['global'], 'unresolved')}"
                       for c in w["chain"] if c.get("global")})
        if not ohm:
            sys.exit(f"gate: {g} prints no format containing 'ohm' -- the units of the number feeding "
                     f"the selector would be unproven (its formats: {[s for _a,_v,s in w['fmts']]})")
        print(f"getter          {g}: {w['ins']} ins, prints {ohm!r}, reads {glob}, "
              f"defaults {sorted({v for _a, v in w['defaults']})}")
    print(f"slot writers    stores at +0x98 in the audio family: {len(writes)}; "
          f"{len(fn_named)} of them store a named function address; the value map dropped "
          f"{st98['invalidated']} register value(s) at loads/arithmetic and "
          f"{st98['clobbered']} at calls in this pass (a register that was reloaded is NOT credited "
          "with the address materialised earlier -- §343)")
    for w in fn_named:
        print(f"                {w['fn']:32} {w['text']:30} @ {w['site']:#x} -> {w['value_fn']}")
    if not fn_named:
        print("                none -- the slot is filled from a value that is not a static text "
              "address, so the getter's identity is only knowable at run time (§288's shape)")
    # stage 3b: the INLINING copy calls one level deeper -- its blr target is [[obj+0x68]+0xa0] -- so the
    # callee's slot is +0xa0 of whatever +0x68 holds.  Name the store that fills it and say which link
    # (the +0x68 object) stays unproven offline.
    mid, st68 = family_writers(0x68)
    deep, sta0 = family_writers(0xa0)
    d_named = [w for w in deep if w["value_fn"] and w["width"] == 8]
    d_32 = [w for w in deep if w["value_fn"] and w["width"] != 8]
    m_named = [w for w in mid if w["value_fn"] and w["width"] == 8]
    print(f"callee slot     +0xa0, the target the inlining copy blrs: {len(deep)} store(s) in the audio "
          f"family, {len(d_named)} of them 64-bit with a named function, {len(d_32)} 32-bit (a function "
          "pointer is 8 bytes, those are excluded)")
    for w in d_named:
        print(f"                {w['fn']} @ {w['site']:#x} {w['text']} -> {w['value_fn']} "
              f"(base register {w['base']})")
    if any(c["wins"] for c in copies) and len(d_named) != 1:
        sys.exit(f"gate: the inline copy's callee slot +0xa0 has {len(d_named)} writers holding a named "
                 "function -- the row can only name ONE blr target, so publishing a list would be my "
                 "guess about which object [obj+0x68] points at")
    mid_desc = ", ".join(f"{w['fn']}@{w['site']:#x} -> {w['value_fn']}" for w in m_named) or "none"
    print(f"                the middle link is NOT proven: +0x68 holds {len(m_named)} named-function "
          f"store(s) in the family ({mid_desc}); that the object written there is the same one whose "
          "+0xa0 the row above filled is only checkable at run time")
    for r in lives:
        print(f"live            {r['capture']:20} {r['file']}: " +
              "; ".join(f"{k}={v}" for k, v in sorted(r["controls"].items())))
    for cap, k, v, b in measured:
        print(f"                {cap}/{k} = {v} -> column {b}")
    print("column implied by the DAC's own live bytes: " +
          (", ".join(f"{reg}={idx}" for reg, idx, _n in implied) or "none of the candidate sets "
                                                                    "contains the live byte"))
    if a.selftest:
        no_csel = [x for x in body if not x.mnemonic.startswith("cs")]
        try:
            _r, reach = bucket_table(no_csel, hi=200)
        except SystemExit as e:
            print(f"selftest: dropping the conditional-select makes the emulator refuse -> "
                  f"{str(e)[:90]}")
        else:
            if reach == moves:
                sys.exit("gate: --selftest: removing the cs* instruction still reached every column "
                         "-- the bucket table would not depend on the code it claims to execute")
            print(f"selftest: dropping the conditional-select shrinks the reachable columns to "
                  f"{reach} (gate fires)")
        for c in copies:
            for w, rr in c["wins"]:
                _r2, reach2 = bucket_table(w["body"], in_reg=w["in_reg"], out_reg=w["out_reg"])
                if reach2 == moves:
                    sys.exit(f"gate: --selftest: the window at {c['va']:#x} still reaches {reach2} with "
                             f"its entering mov at {w['init'][2]:#x} removed -- that row is not "
                             "load-bearing and should not be published")
                print(f"selftest: {c['va']:#x} window without its entering mov reaches {reach2} "
                      f"(against {moves}) -- the init reading is load-bearing")
                wrong = next(k for k in range(19) if k not in (w["in_reg"], w["out_reg"]))
                r3, _reach3 = bucket_table(w["body"], in_reg=wrong, out_reg=w["out_reg"],
                                           init=w["init"][:2])
                if len(r3) > 1:
                    sys.exit(f"gate: --selftest: feeding the window from w{wrong} instead of "
                             f"w{w['in_reg']} still gives {len(r3)} ranges -- the published table would "
                             "not depend on the value being tested")
                print(f"selftest: {c['va']:#x} window fed from w{wrong} collapses to "
                      f"{[f'{lo}..{hi}=>{b}' for lo, hi, b in r3]} (against "
                      f"{[f'{lo}..{hi}=>{b}' for lo, hi, b in rr]} on w{w['in_reg']})")
    watched = {}
    for g in ("vivo_hp_imped_fixed", "mbhc_hp_impedance"):
        gs = [a for a, _t, n in ENTRIES if n == g]
        if not gs:
            sys.exit(f"gate: {g} is not an exact kallsyms symbol -- the override path cannot be "
                     "tracked by name")
        watched[g] = min(gs)
    hits, calls, ndecoded = image_scan(set(watched.values()),
                                       ("get_hp_imped_fixed_state", "msm_mbhc_get_impedance"))
    by_glob = collections.defaultdict(list)
    for h in hits:
        by_glob[[k for k, v in watched.items() if v == h["global"]][0]].append(h)
    put_hit = [h for h in by_glob["vivo_hp_imped_fixed"]
               if h["dir"] == "write" and h["fn"] == "vivo_hp_imped_fixed_put"]
    get_hit = [h for h in by_glob["vivo_hp_imped_fixed"]
               if h["dir"] == "read" and h["fn"] == "vivo_hp_imped_fixed_get"]
    if not (put_hit and get_hit):
        sys.exit(f"gate: the whole-Image scan sees {len(by_glob['vivo_hp_imped_fixed'])} accesses to "
                 "vivo_hp_imped_fixed but not the control's own put (write) and get (read) -- the "
                 "address matcher is blind, so any 'nobody else reads the override' below is noise")
    print(f"stage 6         scanned {len(TEXT)} text symbols / {ndecoded} instructions; watched "
          + ", ".join(f"{k}@{v:#x}" for k, v in sorted(watched.items())))
    for g, hs in sorted(by_glob.items()):
        rd = sorted({h["fn"] for h in hs if h["dir"] == "read"})
        wr = sorted({h["fn"] for h in hs if h["dir"] == "write"})
        print(f"                {g}: {len(hs)} accesses -- read by {rd or 'nobody'}, written by "
              f"{wr or 'nobody'}")
    for nm, site in sorted({(c["caller"], c["site"]) for c in calls}):
        print(f"                caller {nm} @ {site:#x} -> "
              f"{[c['target'] for c in calls if c['caller'] == nm and c['site'] == site]}")
    pins = override_pins(hits, watched)
    flag_readers = sorted({h["fn"] for h in by_glob["vivo_hp_imped_fixed"] if h["dir"] == "read"})
    if [f for f in flag_readers if f == HANDLER or f.startswith(HANDLER)] and not pins:
        sys.exit(f"gate: a copy of {HANDLER} reads {watched['vivo_hp_imped_fixed']:#x} but no "
                 "flag-guard-then-constant pattern was found in it -- the override's effect would be "
                 "unnamable, so do not publish a verdict about it")
    dupes = {n: len(set(a)) for n, a in ADDR_BY_NAME.items() if len(set(a)) > 1
             and n in (HANDLER, "vivo_codec")}
    print(f"                kallsyms name collisions in this chain: "
          + ", ".join(f"{n} x{c}" for n, c in sorted(dupes.items())))
    for p in pins:
        col = emulate(body, p["value"])
        print(f"                override pin: {p['fn']} @ {p['site']:#x} reads the flag, "
              f"{p['guard']}, then {p['mov']} -> impedance {p['value']} -> column {col}")
    if not pins:
        print("                override pin: none found (no handler copy pins the impedance)")
    if a.out:
        cols = ["stage", "fn", "site", "text", "value", "meaning"]
        lines, widths = [], set()

        def emit(d):
            row = []
            for c in cols:
                v = str(d.get(c, "-"))
                if "\t" in v:
                    sys.exit(f"gate: refusing to write a TSV field containing a tab: {v!r}")
                row.append(v.replace("\n", "\\n").replace("\r", "\\r"))
            widths.add(len(row))
            lines.append("\t".join(row))

        for site, va, s in fmts:
            emit({"stage": 1, "fn": HANDLER, "site": f"{site:#x}", "value": f"{va:#x}",
                  "text": s, "meaning": "the handler's own printk format"})
        for c in chain:
            emit({"stage": 1, "fn": HANDLER, "site": f"{c['site']:#x}", "text": c["text"],
                  "value": (f"{c['disp']:#x}" if c.get("disp") is not None
                            else ("blr via followed pointer" if c.get("via_ptr") else "-")),
                  "meaning": (f"global {c['global']:#x} = {NAME.get(c['global'], 'unresolved')}"
                              if c.get("global") else "dereference on the path to the getter")})
        for s, t, n in calls:
            emit({"stage": 1, "fn": HANDLER, "site": f"{s:#x}", "text": f"bl {n}", "value": f"{t:#x}",
                  "meaning": "call out of the handler"})
        for x in body:
            emit({"stage": 2, "fn": SELECTOR, "site": f"{x.address:#x}", "text": f"{x.mnemonic} "
                  f"{x.op_str}", "meaning": "selector arithmetic, executed by the emulator"})
        for lo, hi, b in ranges:
            emit({"stage": 2, "fn": SELECTOR, "site": f"{lo}..{hi}", "text": "input -> column",
                  "value": b, "meaning": "bucket as emulated from the function's own instructions"})
        for c in copies:
            for w, rr in c["wins"]:
                who = f"{HANDLER}@{c['va']:#x}"
                for lo, hi, b in rr:
                    emit({"stage": "2b", "fn": who, "site": f"{lo}..{hi}", "text": "input -> column",
                          "value": b, "meaning": f"bucket emulated from this copy's own inlined tree "
                                                 f"{w['start']:#x}..{w['end']:#x} (input w{w['in_reg']}, "
                                                 f"column w{w['out_reg']})"})
                same = [v for v in range(200) if col_at(ranges, v) == col_at(rr, v)]
                diff = [v for v in range(200) if col_at(ranges, v) != col_at(rr, v)]
                emit({"stage": "2b", "fn": who, "site": f"{diff[0]}..{diff[-1]}" if diff else "-",
                      "text": "inline vs function", "value": len(diff),
                      "meaning": (f"the two tables pick different columns on these {len(diff)} of 200 "
                                  f"inputs; they agree on {len(same)}" if diff else
                                  "the two tables agree on every input 0..199")})
                for cap, k, v, _col in measured:
                    emit({"stage": "2b", "fn": who, "site": f"{v} ohm", "text": f"live {cap}/{k}",
                          "value": col_at(rr, v),
                          "meaning": f"function gives col{col_at(ranges, v)}, this inline copy gives "
                                     f"col{col_at(rr, v)}"
                                     + (" -- the copies disagree on a value the device reported"
                                        if col_at(ranges, v) != col_at(rr, v) else " -- both copies agree")})
        for w in writes:
            emit({"stage": 3, "fn": w["fn"], "site": f"{w['site']:#x}", "text": w["text"],
                  "value": w["value_fn"] or (hex(w["value_va"]) if w["value_va"] else "-"),
                  "meaning": "store into displacement +0x98"})
        for w in d_named + d_32:
            emit({"stage": "3b", "fn": w["fn"], "site": f"{w['site']:#x}", "text": w["text"],
                  "value": w["value_fn"] or "-",
                  "meaning": (f"store into +0xa0, the callee slot of the INLINING copy "
                              f"(base {w['base']}, value register {w['width']} bytes)"
                              + ("" if w["width"] == 8 else " -- EXCLUDED: a function pointer needs 8 "
                                 "bytes, this writes half a word"))})
        for w in m_named:
            emit({"stage": "3b", "fn": w["fn"], "site": f"{w['site']:#x}", "text": w["text"],
                  "value": w["value_fn"],
                  "meaning": ("store into +0x68 -- the MIDDLE link: whether the object written here is "
                              "the one whose +0xa0 the row above filled is not decidable offline")})
        for g, w in sorted(walked.items()):
            for site, va, s in w["fmts"]:
                emit({"stage": 5, "fn": g, "site": f"{site:#x}", "text": s, "value": f"{va:#x}",
                      "meaning": "the getter's own printk format (names the unit)"})
            for c in w["chain"]:
                if c.get("global"):
                    emit({"stage": 5, "fn": g, "site": f"{c['site']:#x}", "text": c["text"],
                          "value": f"{c['global']:#x}",
                          "meaning": f"reads {NAME.get(c['global'], 'unresolved')}"})
            for site, v in w["defaults"]:
                emit({"stage": 5, "fn": g, "site": f"{site:#x}", "text": "mov immediate",
                      "value": v, "meaning": "constant inside the getter (default when unset)"})
        for r in lives:
            for k, v in sorted(r["controls"].items()):
                emit({"stage": 4, "fn": r["capture"], "site": r["file"], "text": k, "value": v,
                      "meaning": "ALSA control value in this capture"})
        for cap, k, v, b in measured:
            emit({"stage": 4, "fn": cap, "site": k, "text": f"{k}={v}", "value": b,
                  "meaning": "column this measured impedance selects"})
        for reg, idx, n in implied:
            emit({"stage": 4, "fn": "dac-integration-params", "site": reg,
                  "text": f"live byte is candidate #{idx} of {n}", "value": idx,
                  "meaning": "column the DAC's own in-play bytes imply"})
        for h in sorted(hits, key=lambda r: (r["global"], r["site"])):
            emit({"stage": 6, "fn": h["fn"], "site": f"{h['site']:#x}", "text": h["text"],
                  "value": f"{h['global']:#x}", "meaning": f"{h['dir']} of "
                  f"{[k for k, v in watched.items() if v == h['global']][0]}"})
        for p in pins:
            emit({"stage": 7, "fn": p["fn"], "site": f"{p['site']:#x}",
                  "text": f"{p['guard']} then {p['mov']}", "value": p["value"],
                  "meaning": f"override pins the impedance to {p['value']} -> column "
                             f"{emulate(body, p['value'])}"})
        for c in sorted(calls, key=lambda r: (r["caller"], r["site"])):
            emit({"stage": 6, "fn": c["caller"], "site": f"{c['site']:#x}",
                  "text": f"bl {c['target']}", "value": c["target"], "meaning": "plain caller"})
        emit({"stage": "DENOM", "fn": "-", "site": "-", "value": str(len(TEXT)),
              "text": f"stage 6: {len(hits)} global accesses, {len(calls)} callers, "
                      f"{ndecoded} instructions decoded",
              "meaning": "text symbols scanned for the override path"})
        emit({"stage": "DENOM", "fn": "-", "site": "-", "value": str(len(ins)),
              "text": f"{len(fmts)} formats, {len(writes)} +0x98 stores, {len(lives)} captures",
              "meaning": "handler instructions decoded"})
        with open(a.out, "w", encoding="utf-8") as fh:
            fh.write("\t".join(cols) + "\n")
            fh.write("\n".join(lines) + "\n")
        if len(widths) != 1:
            sys.exit(f"gate: {a.out} rows disagree on column count {sorted(widths)}")
        print(f"wrote {a.out} ({len(lines) + 1} rows x {next(iter(widths))} columns)")


if __name__ == "__main__":
    main()
