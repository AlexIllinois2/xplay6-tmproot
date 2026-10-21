#!/usr/bin/env python3
"""tools/dt_prop_reads.py -- which device-tree properties does the Hi-Fi codec layer actually ask for,
and what does the code do with each answer?

§287 proved `es9038_i2c_probe` reads `vivo,param-num` and `vivo,params`; §325 then showed nobody consumes
the array. §353 found the enable path's payload pointer is only ever zeroed -- but the es9028 side sets
flag bits per property (`orr #0x100 / #0x1000 / #0x200 / #0x300` into [dev+0x18]) and registration of
`&es9028_enable` at [table+0x48] sits behind bit 12 of that field. So "which property sets which bit" is
the missing link between the device tree and which DAC answers.

This tool reads it mechanically: every `bl` to an `of_*` helper is located, the property name is taken from
the register the ARM64 calling convention puts argument 2 in (x1 for of_find_property / of_property_read_u32
/ of_property_read_u32_array / of_property_read_string), resolved through an adrp/add page map, and checked
to be a printable NUL-terminated string inside the image. What follows the call, up to the next `of_*` call,
is attributed to it: `orr reg, #imm` against the field that later gates something, and `str` into a struct
displacement.

usage: tools/dt_prop_reads.py [--funcs a,b] [--out TSV] [--selftest]
"""
import argparse
import bisect
import csv
import os
import re
import string
import sys

from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, Cs

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# 6.0.1 by default; DT_IMG/DT_KALL point the same ruler at another firmware (the official 7.1.1 Image)
# so "which property does this kernel ask for" can be answered on BOTH sides of the port.
IMG = os.environ.get("DT_IMG") or os.path.join(ROOT, "fw", "Image")
KALL = os.environ.get("DT_KALL") or os.path.join(ROOT, "art", "kallsyms_real.txt")
TEXT = 0xFFFFFFC000080000
MASK64 = (1 << 64) - 1
OF_CALLEES = ("of_find_property", "of_property_read_u32", "of_property_read_u32_array",
              "of_property_read_string", "of_property_read_bool", "of_get_property")
NAME_REG = "1"  # page-map keys are register NUMBER STRINGS ("1" for x1/w1)
FLAGBITS = {0x100: 8, 0x200: 9, 0x300: "8+9", 0x1000: 12, 0x2000: 13, 0x10000: 16}
FLAGREG_FIELD = {}
REG, IMM, MEM = 1, 2, 3   # this capstone: 0 is INVALID, register operands are type 1
PRINTABLE = set(string.ascii_letters + string.digits + ",-_.:/@[]")

syms = []
for line in open(KALL, encoding="utf-8", errors="replace"):
    p = line.split()
    if len(p) != 3:
        continue
    try:
        v = int(p[0], 16)
    except ValueError:
        continue
    if v >= TEXT:
        syms.append((v, p[2]))
syms.sort()
VAS = [a for a, _ in syms]
DATA = open(IMG, "rb").read()


def owner(v):
    i = bisect.bisect_right(VAS, v) - 1
    return syms[i][1] if i >= 0 else None


def span_of(name):
    out = []
    for i, (a, n) in enumerate(syms):
        if n == name:
            end = VAS[i + 1] if i + 1 < len(syms) else a + 0x400
            out.append((a, max(end - a, 4)))
    return out


def ins_window(va, n):
    off = va - TEXT
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    i, out = 0, []
    while i < n - 3:
        got = list(md.disasm(DATA[off + i:off + i + 4], va + i))
        if got:
            out.extend(got)
        i += 4
    return out


def cstring(va, limit=64):
    if va is None or va < TEXT or va - TEXT >= len(DATA):
        return None
    raw = b""
    k = va - TEXT
    while k < len(DATA) and len(raw) < limit:
        b = DATA[k:k + 1]
        if b == b"\x00":
            break
        raw += b
        k += 1
    try:
        s = raw.decode("ascii")
    except UnicodeDecodeError:
        return None
    return s if s and all(c in PRINTABLE for c in s) else None


def scan(name, control_shift=False):
    rows, unresolved, sites = [], 0, 0
    for start, size in span_of(name):
        ins = ins_window(start, size)
        page, frame, alias = {}, {}, {}
        pending = None
        for x in ins:
            ops, mn = x.operands, x.mnemonic

            def _key(idx):
                nm = x.reg_name(idx)
                if not nm:
                    return None
                k = nm.lstrip("xw")
                # capstone calls register 29 "fp"/"x29"/"29" and 31 "sp" depending on the operand shape --
                # without this the out-parameter `add x2, x29, #k` never matched and no field linked at all
                return {"fp": "29", "sp": "31", "": None}.get(k, k)

            if mn == "bl" and ops and ops[0].type == IMM:
                tgt = ops[0].imm & MASK64
                callee = owner(tgt)
                if callee in OF_CALLEES:
                    sites += 1
                    reg = "2" if control_shift else NAME_REG
                    key = page.get(reg)
                    sname = cstring(key)
                    if pending:
                        rows.append(pending)
                        pending = None
                    out_slot = frame.get("2") if callee.endswith("_array") or callee in (
                        "of_property_read_u32", "of_property_read_string") else None
                    out_reg = None if callee == "of_find_property" else "2"
                    buf = set()
                    if out_reg:
                        # the buffer argument is usually set up as `mov x2, x26` from the allocation
                        # result, so follow the copy chain back to the register that later gets stored
                        seen_reg, chain, r = out_reg, {out_reg}, alias.get(out_reg)
                        while r and r not in chain:
                            chain.add(r)
                            r = alias.get(r)
                        out_reg = None
                        buf = chain
                    if sname is None:
                        unresolved += 1
                    else:
                        pending = {"bufregs": set(buf), "site": x.address, "callee": callee,
                                   "name": sname, "name_va": key,
                                   "bits": [], "fields": [], "kind": [],
                                   "ev": ["out=%s" % ("frame+%#x" % out_slot if out_slot is not None
                                                      else ("r%s" % out_reg if out_reg else "-"))],
                                   "out_slot": out_slot, "out_reg": "2",
                                   "vregs": set(), "flagreg": set()}
                if pending and len(ops) == 1:
                    pass
                for r in [str(k) for k in range(18)] + [f"x{k}" for k in range(18)]:
                    page.pop(r, None)
                continue
            dst = _key(ops[0].reg) if (ops and ops[0].type == REG) else None
            if dst is not None and mn in ("adrp",) and len(ops) == 2 and ops[1].type == IMM:
                page[dst] = ops[1].imm & MASK64
            elif dst is not None and mn == "add" and len(ops) == 3 and ops[2].type == IMM:
                b = _key(ops[1].reg) if ops[1].type == REG else None
                if b in ("29", "31"):
                    frame[dst] = ops[2].imm & MASK64      # an out-parameter buffer on the frame
                elif b in page:
                    page[dst] = (page[b] + (ops[2].imm & MASK64)) & MASK64
            elif dst is not None and mn in ("add", "mov") and len(ops) == 3 and ops[2].type == IMM:
                b = _key(ops[1].reg)
                if b in page:
                    page[dst] = (page[b] + (ops[2].imm & MASK64)) & MASK64
            elif dst is not None and mn in ("mov", "orr") and len(ops) == 3 and ops[2].type == 3:
                pass
            elif dst is not None and mn == "mov" and len(ops) == 2 and ops[1].type == REG:
                if _key(ops[1].reg):
                    alias[dst] = _key(ops[1].reg)
                b = _key(ops[1].reg)
                if b in page:
                    page[dst] = page[b]
                else:
                    page.pop(dst, None)
            elif dst is not None and mn.startswith("ldr"):
                page.pop(dst, None)
            mem = [o for o in ops if o.type == MEM]
            if pending is not None:
                # a register that gets REWRITTEN after the call is no longer the out-buffer: without this
                # the registration stores (`str x0,[x23,#0x48]`) join the chain and the link over-claims
                if dst is not None and not mn.startswith("st"):
                    pending["bufregs"].discard(dst)
                for o in ops:
                    if o.type == 0 and hasattr(o, "reg"):
                        pass
                if mn.startswith("ldr") and len(ops) == 2 and mem:
                    base = _key(mem[0].mem.base) if mem[0].mem.base else None
                    off = mem[0].mem.disp & MASK64
                    d = _key(ops[0].reg)
                    if pending["out_slot"] is not None and base in ("29", "31") and \
                            pending["out_slot"] <= off < pending["out_slot"] + 8:
                        # a 2-element u32 array read into frame+slot and frame+slot+4
                        if d:
                            pending["vregs"].add(d)
                            pending["ev"].append(f"value element +{off - pending['out_slot']:#x} read "
                                                 f"back at {x.address:#x}")
                if mn in ("str", "stp") and mem:
                    off = mem[0].mem.disp & MASK64
                    srcs = [_key(o.reg) for o in ops if o.type == REG]
                    base_key = _key(mem[0].mem.base) if mem[0].mem.base else "?"
                    base = base_key
                    if srcs and base not in ("29", "31"):
                        if srcs[0] in pending["vregs"]:
                            pending["fields"].append(hex(off))
                            pending["kind"].append("value")
                            pending["ev"].append(f"{mn} -> [{base_key}+{off:#x}] at {x.address:#x}")
                        elif srcs[0] in pending["bufregs"]:
                            pending["fields"].append(hex(off))
                            pending["kind"].append("buffer-pointer")
                            pending["ev"].append(f"{mn} out-buffer [{base_key}+{off:#x}] at {x.address:#x}")
                    for o in ops:
                        if o.type == REG:
                            pending["vregs"].discard(_key(o.reg))
                if mn == "mov" and len(ops) == 2 and ops[1].type == REG:
                    a, b2 = _key(ops[0].reg), _key(ops[1].reg)
                    if b2 in pending["bufregs"] and a:
                        pending["bufregs"].add(a)
                if mn == "orr" and len(ops) == 3 and ops[2].type == IMM and FLAGBITS.get(ops[2].imm):
                    d = _key(ops[0].reg)
                    if d:
                        pending["flagreg"].add(d)
                        pending["ev"].append(f"orr #{ops[2].imm:#x} at {x.address:#x}")
                        if hex(ops[2].imm) not in pending["bits"]:
                            pending["bits"].append(hex(ops[2].imm))
                if mn in ("str", "stp") and mem and FLAGREG_FIELD.get(ops[0].reg and
                                                                      _key(ops[0].reg) or ""):
                    pass
        if pending:
            rows.append(pending)
            pending = None
    return rows, unresolved, sites


FAMILY = re.compile(r"^(es9028_|es9038_|vivo_hifi|hifi_codec|vivo_codec)")
FLAGS_OFF = 0x18
CONSUMERS = ("tbz", "tbnz", "tst", "and", "orr", "cmp")
# mnemonics whose FIRST register operand is a destination -- used to drop lineage on definitions the
# walk does not model (see flag_writers)
DEST_WRITERS = re.compile(
    r"^(mov|mvn|neg|add|adds|sub|subs|adc|sbc|orr|and|eor|bic|orn|ldr|ldur|ldrb|ldrh|ldrsb|ldrsh|"
    r"ldrsw|ldp|adrp|adr|csinv|csel|cset|csetm|sxtb|sxth|uxtb|uxth|sbfx|ubfx|bfi|bics|madd|msub|"
    r"smull|umull|lsl|lsr|asr|ror|rbit|clz|cnt)$")


def flag_consumers():
    """who READS the flag field the probes write (`ldr w?, [x?, #0x18]` then a test/mask on that value)?

    The walk resets per function -- carrying the last field-read across a function boundary produced a
    cross-witness-free phantom once, so `last` is not allowed to survive a symbol change. Bit numbers are
    taken from the immediate the disassembler prints, not inferred. `near_w1_imm` is only "the last
    immediate that sat in w1 before this test" (a register number for the byte helpers, a line number for
    warn_slowpath_null) -- it is context, NOT a claim that the bit controls that register."""
    rows = []
    scanned = 0
    for i, (a, n) in enumerate(syms):
        if not FAMILY.match(n):
            continue
        scanned += 1
        end = VAS[i + 1] if i + 1 < len(VAS) and VAS[i + 1] > a else a + 0x400
        last, w1, other = None, None, {}
        for x in ins_window(a, min(end - a, 0x1400)):
            ops = x.operands
            mem = [o for o in ops if o.type == MEM]
            if x.mnemonic.startswith("ldr") and len(ops) == 2 and mem and \
                    (mem[0].mem.disp & MASK64) == FLAGS_OFF and ops[0].type == REG:
                base = x.reg_name(mem[0].mem.base) if mem[0].mem.base else None
                if base in ("sp", "x29", "fp"):
                    continue
                last = (x.address, x.reg_name(ops[0].reg), base)
                continue
            if x.mnemonic == "mov" and len(ops) == 2 and ops[1].type == IMM and ops[0].type == REG \
                    and x.reg_name(ops[0].reg) in ("w1", "x1"):
                w1 = ops[1].imm & MASK64
            # remember the most recent NON-flag load into the same register: that is the other operand
            # the test compares against, and publishing it is what keeps a sentence from guessing
            # "read from the chip" when the value actually comes from the caller's parameter block
            if x.mnemonic.startswith("ldr") and len(ops) == 2 and ops[0].type == REG and mem and \
                    (mem[0].mem.disp & MASK64) != FLAGS_OFF:
                b = x.reg_name(mem[0].mem.base) if mem[0].mem.base else "?"
                other[x.reg_name(ops[0].reg)] = (x.address, f"[{b}+{mem[0].mem.disp & MASK64:#x}]")
            if last and x.mnemonic in CONSUMERS:
                regs = [x.reg_name(o.reg) for o in ops if o.type == REG]
                if last[1] in regs:
                    imms = [o.imm & MASK64 for o in ops if o.type == IMM]
                    bit = None
                    if x.mnemonic in ("tbz", "tbnz"):
                        # tbz prints [reg, bit, target]: the target is ALSO an immediate and it is huge
                        # (a sign-extended VA), so the bit index is the only immediate below 64 -- taking
                        # imms[1] blindly published a 20-digit number where bit 12 belongs
                        small = [v for v in imms if v < 64]
                        bit = f"bit {small[0]}" if small else "?"
                    elif x.mnemonic in ("and", "orr", "tst", "cmp") and imms:
                        bit = f"mask {imms[-1]:#x}"
                    rows.append({"kind": "flag-consumer", "fn": n, "fn_at": f"{a:#x}",
                                 "near_w1_imm": (hex(w1) if w1 is not None else "-"),
                                 "site": f"{x.address:#x}", "callee": x.mnemonic,
                                 "property": bit or "?", "name_va": "-", "bits": bit or "?",
                                 "fields": f"read at {last[0]:#x} from [{last[2]}+{FLAGS_OFF:#x}]",
                                 "link_kind": "consumer", "evidence": x.op_str,
                                 "value_origin": (f"{other[last[1]][1]} bits around "
                                                  f"{x.address - other[last[1]][0]:#x} before the test"
                                                  if last[1] in other else "-")})
                    last = None
    return rows, scanned


def flag_writers(off=FLAGS_OFF):
    """who WRITES the flag field (`[x?+0x18]`): direct stores of a constant, and read-modify-write
    `orr`s whose source is a previous read of the same field.

    This is the other half of the census flag_consumers() answers: a bit that is tested but never
    written is zero (allocator) unless some writer outside this scope sets it, and a bit that is
    written but never tested means the DT property behind it changes nothing.  Lineage is dropped on
    bl/blr because those clobber x0-x17 -- carrying it across a call is how a phantom control-flow
    edge gets invented (same rule the field linker follows).
    """
    rows = []
    scanned = 0
    for i, (a, n) in enumerate(syms):
        if not FAMILY.match(n):
            continue
        scanned += 1
        end = VAS[i + 1] if i + 1 < len(VAS) and VAS[i + 1] > a else a + 0x400
        lin, defs, pg = {}, {}, {}   # lineage / constant / adrp-page map for argument strings
        ctx = None                  # nearest preceding call: (addr, symbol, DT-name-or-None)
        ofctx = None                # nearest preceding of_* call whose property name resolved
        for x in ins_window(a, min(end - a, 0x1400)):
            ops = x.operands
            mem = [o for o in ops if o.type == MEM]
            mn = x.mnemonic
            if mn == "adrp" and len(ops) == 2 and ops[0].type == REG and ops[1].type == IMM:
                r0 = x.reg_name(ops[0].reg)
                pg[re.sub(r"^[xw]", "", r0)] = ops[1].imm & MASK64
                # adrp overwrites the register, so any constant/lineage it carried is gone -- without
                # these two pops the page map turned `adrp/add ; str x0,[x19,#0x18]` back into a
                # "constant store of the previous mov" (the pointer-alias false positive, 2nd time)
                defs.pop(r0, None)
                lin.pop(r0, None)
                continue
            if mn == "add" and len(ops) == 3 and ops[2].type == IMM and ops[0].type == REG:
                r0 = x.reg_name(ops[0].reg)
                k = re.sub(r"^[xw]", "", r0)
                if k in pg and ops[1].type == REG and re.sub(r"^[xw]", "", x.reg_name(ops[1].reg)) == k:
                    pg[k] = (pg[k] + (ops[2].imm & MASK64)) & MASK64   # adrp+add = one pointer
                else:
                    defs.pop(r0, None)
                lin.pop(r0, None)
                continue
            if mn in ("bl", "blr", "br", "ret"):
                if mn == "bl" and ops and ops[0].type == IMM:
                    sym = owner(ops[0].imm & MASK64)
                    nm = cstring(pg.get(NAME_REG)) if sym in OF_CALLEES else None
                    ctx = (x.address, sym, nm)
                    if sym in OF_CALLEES and nm:
                        # the nearest call of ANY kind is usually the WARN on the other branch; the
                        # property the write belongs to is the nearest of_* call that resolved a name
                        ofctx = (x.address, sym, nm)
                for r in [f"x{k}" for k in range(18)] + [f"w{k}" for k in range(18)]:
                    lin.pop(r, None)
                    defs.pop(r, None)
                    pg.pop(re.sub(r"^[xw]", "", r), None)
                continue
            if mn.startswith("ldr") and len(ops) == 2 and mem and ops[0].type == REG:
                d = mem[0].mem.disp & MASK64
                r = x.reg_name(ops[0].reg)
                if d == off:
                    lin[r] = True
                    defs.pop(r, None)
                else:
                    lin.pop(r, None)
                continue
            if mn == "mov" and len(ops) == 2 and ops[0].type == REG and ops[1].type == IMM:
                r = x.reg_name(ops[0].reg)
                # capstone prints logical/`mov` immediates sign-extended into 64 bits; the flag field is
                # a u32, so a `mov w?, #-1` is 0xffffffff here -- masking to the DESTINATION width is the
                # difference between "sets bits 0..31" and "sets bits 0..35"
                defs[r] = ops[1].imm & (0xFFFFFFFF if r.startswith("w") else MASK64)
                lin.pop(r, None)
                continue
            if mn in ("orr", "eor", "bic", "orn") and len(ops) == 3 and ops[0].type == REG \
                    and ops[1].type == REG and ops[2].type == IMM:
                dst, src = x.reg_name(ops[0].reg), x.reg_name(ops[1].reg)
                w32 = dst.startswith("w")
                im = ops[2].imm & (0xFFFFFFFF if w32 else MASK64)
                eff = {"orr": "set", "orn": "set-inverse", "eor": "toggle", "bic": "clear"}[mn]
                if dst in lin or src in lin:
                    rows.append({"kind": "flag-writer", "fn": n, "fn_at": f"{a:#x}",
                                 "site": f"{x.address:#x}", "callee": f"{mn}",
                                 "property": f"mask {im:#x}", "name_va": "-",
                                 "bits": " ".join(f"bit {b}" for b in range(32) if im >> b & 1) or "-",
                                 "fields": f"{eff} by a read-modify-write (source of lineage is a read "
                                           "of the same field)",
                                 "link_kind": f"writer-{eff}", "evidence": x.op_str,
                                 "dt_name": ofctx[2] if ofctx else "-",
                                 "ctx_call": (f"{ctx[1]} @ {ctx[0]:#x}, {x.address - ctx[0]:#x} B before"
                                              if ctx and x.address > ctx[0] else "-"),
                                 "of_call": (f"{ofctx[1]} @ {ofctx[0]:#x}, "
                                             f"{x.address - ofctx[0]:#x} B before"
                                             if ofctx and x.address > ofctx[0] else "-"),
                                 "value_origin": f"[{x.reg_name(mem[0].mem.base) if mem else '?'}+{off:#x}]"})
                    # lineage only PROPAGATES when the instruction really consumed the field -- an
                    # unrelated `orr w21, w4, #0x80` must not hand w21 a flags lineage and then make the
                    # next `orr w21, w4, #0xe0` look like a write of the flag word (it did on the first run)
                    if mn in ("orr", "orn"):
                        lin[dst] = True
                continue
            if mn.startswith("st") and mem and (mem[0].mem.disp & MASK64) == off:
                r = x.reg_name(ops[0].reg) if ops and ops[0].type == REG else None
                if r is None:
                    continue
                if r in defs:
                    im = defs[r] & 0xFFFFFFFF      # the field is a u32; a wider store is masked here
                    rows.append({"kind": "flag-writer", "fn": n, "fn_at": f"{a:#x}",
                                 "site": f"{x.address:#x}", "callee": mn,
                                 "property": f"mask {im:#x}", "name_va": "-",
                                 "bits": " ".join(f"bit {b}" for b in range(32) if im >> b & 1) or "-",
                                 "fields": "constant store (sets those bits)", "link_kind": "writer-set",
                                 "evidence": x.op_str,
                                 "dt_name": ofctx[2] if ofctx else "-",
                                 "ctx_call": (f"{ctx[1]} @ {ctx[0]:#x}, {x.address - ctx[0]:#x} B before"
                                              if ctx and x.address > ctx[0] else "-"),
                                 "of_call": (f"{ofctx[1]} @ {ofctx[0]:#x}, "
                                             f"{x.address - ofctx[0]:#x} B before"
                                             if ofctx and x.address > ofctx[0] else "-"),
                                 "value_origin": f"mov #{im:#x} then store"})
                else:
                    rows.append({"kind": "flag-writer", "fn": n, "fn_at": f"{a:#x}",
                                 "site": f"{x.address:#x}", "callee": mn, "property": "opaque",
                                 "name_va": "-", "bits": "-",
                                 "fields": "stored value has no in-function definition this walk can name",
                                 "link_kind": "writer-opaque", "evidence": x.op_str,
                                 "dt_name": ofctx[2] if ofctx else "-",
                                 "ctx_call": (f"{ctx[1]} @ {ctx[0]:#x}, {x.address - ctx[0]:#x} B before"
                                              if ctx and x.address > ctx[0] else "-"),
                                 "of_call": (f"{ofctx[1]} @ {ofctx[0]:#x}, "
                                             f"{x.address - ofctx[0]:#x} B before"
                                             if ofctx and x.address > ofctx[0] else "-"),
                                 "value_origin": f"lineage={'flags' if r in lin else 'unknown'}"})
                lin.pop(r, None)
                defs.pop(r, None)
                continue
            # any other write to a register must drop its lineage/constant -- the first run of this walk
            # called `adrp x0,#… ; add x0,x0,#0x8c ; str x0,[x19,#0x18]` a store of the stale `mov x0,
            # #0xfffffffe0` eight instructions earlier, i.e. it published a POINTER to another struct as
            # a flags write.  Dropping on unmodelled definitions under-counts; guessing does not.
            if ops and ops[0].type == REG and DEST_WRITERS.match(mn):
                r = x.reg_name(ops[0].reg)
                if r not in ("wzr", "xzr", "sp"):
                    lin.pop(r, None)
                    defs.pop(r, None)
                if mn == "ldp" and len(ops) > 1 and ops[1].type == REG:
                    r2 = x.reg_name(ops[1].reg)
                    if r2 not in ("wzr", "xzr", "sp"):
                        lin.pop(r2, None)
                        defs.pop(r2, None)
    return rows, scanned


def bits_census(writers, consumers):
    """per-bit table: which sites SET it, which CLEAR it, which TEST it, and the honest verdict.  A bit
    that is only ever cleared is 0 whatever the DT says; a bit set but never read in this scope means
    the property behind it changes nothing observable here (both are claims about this walk's scope)."""
    bits = {}
    for w in writers:
        eff = w["link_kind"]
        for b in re.findall(r"bit (\d+)", w["bits"]):
            d = bits.setdefault(int(b), {"set": [], "clear": [], "toggle": [], "test": []})
            d["set" if eff.endswith("set") else ("clear" if eff.endswith("clear") else "toggle")].append(w)
    wsite = {w["site"] for w in writers}
    for c in consumers:
        if c["site"] in wsite:
            # the same instruction is both the read and the modify in a read-modify-write; counting it as
            # an independent reader would let a bit look "tested" only because something writes it
            continue
        f = c.get("bits") or ""
        msk = re.search(r"mask (0x[0-9a-f]+)", f)
        idx = [int(x) for x in re.findall(r"bit (\d+)", f)]
        if msk:
            v = int(msk.group(1), 16)
            # a `tst/and/cmp` against a mask IS a read of every bit the mask covers -- §357/§358 found
            # bits 8/9 consumed that way, and a census that only counted tbz/tbnz published them as
            # "written but never read"
            idx = sorted({*idx, *(b for b in range(32) if v >> b & 1)})
        for b in idx:
            bits.setdefault(b, {"set": [], "clear": [], "toggle": [], "test": []})["test"].append(c)
    out = []
    for b in sorted(bits):
        d = bits[b]
        if d["set"] and d["test"]:
            v = "WRITTEN+TESTED"
        elif d["set"]:
            v = f"WRITTEN-UNTESTED (no read of bit {b} in the family scope)"
        elif d["clear"] and not d["set"]:
            v = f"CLEARED-ONLY (bit {b} is 0 unless a writer exists outside the family scope)"
        else:
            v = f"TESTED-UNWRITTEN (zero unless a writer exists outside the family scope)"
        out.append({"kind": "flag-bit", "fn": "-", "fn_at": "-", "site": f"bit {b}",
                    "callee": f"{len(d['set'])} set / {len(d['clear'])} clear / {len(d['test'])} test",
                    "property": v, "name_va": "-", "bits": str(b),
                    "fields": ("set by " + ",".join(w["site"] for w in d["set"][:6])) if d["set"]
                    else ("clear by " + ",".join(w["site"] for w in d["clear"][:6]) if d["clear"]
                          else "set by -"),
                    "link_kind": "census",
                    "dt_name": ",".join(sorted({w["dt_name"] for w in (d["set"] + d["clear"])
                                                if w.get("dt_name") and w["dt_name"] != "-"})) or "-",
                    "evidence": ("testers=" + ",".join(t["site"] for t in d["test"][:6])) if d["test"]
                    else "testers=-",
                    "value_origin": "-"})
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--funcs", default="es9028_i2c_probe,es9038_i2c_probe,vivo_codec_dai_link_init")
    ap.add_argument("--out")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--bits", action="store_true",
                    help="census the flag field itself (writers + testers + per-bit verdict) instead of "
                         "the of_* reads; needs no --funcs")
    a = ap.parse_args()
    if a.bits:
        wr, n_fam = flag_writers()
        cons, n_fam2 = flag_consumers()
        if not wr:
            sys.exit(f"gate: no writer of [{FLAGS_OFF:#x}] found in {n_fam} family function(s) -- the "
                     "census would read as 'this field is never set' which is a claim about the walk, "
                     "not about the driver")
        census = bits_census(wr, cons)
        masks = set()
        for w in wr:
            m = re.search(r"0x[0-9a-f]+", w["property"])
            if m:
                masks.add(int(m.group(0), 16))
        # §354 measured these four immediates being folded into the flag field by the two probes; if the
        # writer walk cannot reproduce them it is not looking at the same field
        for want in (0x100, 0x200, 0x300, 0x1000):
            if want not in masks:
                sys.exit(f"gate: writer masks are {sorted(hex(x) for x in masks)} and lack {want:#x} -- "
                         "§354 established that immediate, so this census is not the same mechanism")
        # the pairing must be DERIVED here, not remembered: §354 reached these three names from the
        # property side, this walk reaches them from the writer side, and the two have to agree
        named = {}
        for w in wr:
            if w["dt_name"] != "-":
                named.setdefault(w["dt_name"], set()).update(int(b) for b in re.findall(r"bit (\d+)", w["bits"]))
        # §354's own wording: left-channel-only -> 0x100; right-channel-only -> 0x200 OR 0x300 (two
        # branches, the second also folds bit 8); i2s-master -> 0x1000.  So the right-channel property
        # may legitimately reach {9} or {8,9} -- but it must always reach 9, and it must not be the only
        # explanation for bit 8.
        want = {"i2s-master": [{12}], "left-channel-only": [{8}], "right-channel-only": [{9}, {8, 9}]}
        for prop, allowed in want.items():
            got = named.get(prop)
            if got is None or got not in allowed:
                sys.exit(f"gate: {prop} folded into bits {sorted(got) if got else 'nothing'}; §354 allows "
                         f"only {sorted(sorted(s) for s in allowed)} -- the pairing drifted")
        if 8 not in named.get("left-channel-only", set()):
            sys.exit("gate: bit 8 is not reachable from left-channel-only after the pairing check")
        if named.get("printk"):
            sys.exit(f"gate: a printk call is being credited as the property behind bits {sorted(named['printk'])}")
        init = [w for w in wr if w["dt_name"] == "-" and w["property"] != "opaque"]
        if not any(w["property"] == "mask 0x1" for w in init):
            sys.exit("gate: the probe-entry store of #1 is not listed as a property-less writer, so bit 0 "
                     "would be published as if a DT property set it")
        for w in wr:
            m = re.fullmatch(r"mask (0x[0-9a-f]+)", w["property"])
            if m and int(m.group(1), 16) in FLAGBITS:
                fb = FLAGBITS[int(m.group(1), 16)]
                got = sorted(int(b) for b in re.findall(r"bit (\d+)", w["bits"]))
                exp = sorted([fb] if isinstance(fb, int) else [8, 9])
                if got != exp:
                    sys.exit(f"gate: mask {m.group(1)} decoded to bits {got} but the table says {exp} "
                             f"at {w['site']} -- the bit decode and FLAGBITS disagree")
        if not any(c.get("bits") == "bit 12" for c in cons):
            sys.exit("gate: no consumer reads bit 12, which §357/§358 located at 0xbb8b00 -- the "
                     "registration gate would be missing from the published table")
        if a.selftest:
            ctrl, _n = flag_writers(off=FLAGS_OFF + 4)
            if {w["site"] for w in ctrl} == {w["site"] for w in wr}:
                sys.exit("gate: offset 0x1c yields the identical writer set -- the census is not bound "
                         "by the offset it claims to read")
            print(f"selftest: control offset {FLAGS_OFF + 4:#x} gives {len(ctrl)} writer(s) against "
                  f"{len(wr)} at {FLAGS_OFF:#x} (different sites, so the field really is the discriminator)")
            NAME_REG_BACKUP = NAME_REG
            globals()["NAME_REG"] = "2"     # the property name is x1; keying it on x2 must lose them all
            try:
                names = {w["dt_name"] for w in flag_writers()[0] if w["dt_name"] != "-"}
            finally:
                globals()["NAME_REG"] = NAME_REG_BACKUP
            if names:
                sys.exit(f"gate: reading the property name out of x2 still resolved {sorted(names)} -- "
                         "the pairing is not keyed on the register the ABI passes lname in")
            print("selftest: keying the property name on x2 resolves 0 name(s), so x1 keying is load-bearing")
        rows = wr + cons + census
        print(f"flag writers    {n_fam} family function(s), {len(wr)} write site(s) "
              f"({sum(1 for w in wr if w['link_kind'] == 'writer-opaque')} opaque), "
              f"{len(cons)} read site(s); per-bit census {len(census)} bit(s)")
        for c in census:
            print(f"   bit {c['bits']:>2}  {c['callee']:18} {c['property']}")
            print(f"        {c['fields']} ; {c['evidence']}")
        if a.out:
            keys = ["kind", "fn", "fn_at", "site", "callee", "property", "name_va", "bits", "fields",
                    "link_kind", "evidence", "value_origin", "dt_name", "of_call", "ctx_call"]
            with open(a.out, "w", encoding="utf-8", newline="") as fh:
                w = csv.DictWriter(fh, fieldnames=keys, delimiter="\t", extrasaction="ignore")
                w.writeheader()
                w.writerows(rows)
            print(f"wrote {a.out} ({len(rows)} rows x {len(keys)} columns)")
        return
    all_rows = []
    for fn in [x.strip() for x in a.funcs.split(",") if x.strip()]:
        rows, unres, n_sites = scan(fn)
        good = [r for r in rows if r["name"]]
        print(f"{fn}: {n_sites} of_* call site(s) found, {len(good)} with a resolvable property name, "
              f"{unres} unresolved")
        for r in good:
            all_rows.append({"kind": "dt-read", "fn": fn, "fn_at": "-", "site": f"{r['site']:#x}", "callee": r["callee"],
                             "property": r["name"], "name_va": f"{r['name_va']:#x}",
                             "bits": " ".join(r["bits"]) or "-", "fields": " ".join(r["fields"]) or "-",
                             "link_kind": " ".join(sorted(set(r["kind"]))) or "-", "evidence": " ; ".join(r["ev"])})
            print(f"   {r['site']:#x} {r['callee']:28} {r['name']:22} bits=[{' '.join(r['bits']) or '-'}] "
                  f"fields=[{' '.join(r['fields']) or '-'}]")
        if rows and not good:
            sys.exit(f"gate: {fn} has {len(rows)} of_* site(s) but no property name resolves -- the walk is "
                     "blind here and an empty name column would read as 'this driver reads no properties'")
    if not all_rows:
        sys.exit("gate: no resolvable of_* reads anywhere in the requested functions -- say which functions "
                 "were scanned instead of publishing nothing")
    cons, n_fam = flag_consumers()
    print(f"flag consumers  {n_fam} family function(s) scanned, {len(cons)} read(s) of the "
          f"+{FLAGS_OFF:#x} flag field")
    for c in cons:
        print(f"   {c['fn']}@{c['fn_at']}: {c['callee']:5} {c['bits']:12} at {c['site']} ({c['fields']})")
    # §352's registration gate is a *semantic* fact (a `tbz #12` inside es9028_i2c_probe); its ADDRESS
    # is a property of one image.  Pinning the address made a cross-image run (the 7.1.1 Image) abort on
    # a walk that had in fact found the gate at the other image's own site -- so the address is required
    # only of the baseline, and any other image must produce the same shape and say where it is.
    BASELINE = os.path.abspath(IMG) == os.path.abspath(os.path.join(ROOT, "fw", "Image"))
    known = [c for c in cons if c["site"] == "0xffffffc000bb8b00"]
    if BASELINE:
        if known and known[0]["bits"] != "bit 12":
            sys.exit(f"gate: the registration gate at 0xbb8b00 reads {known[0]['bits']!r} but §352/§354 "
                     "established bit 12 (i2s-master) there -- the bit index is being taken from the "
                     "wrong operand")
        if not known:
            sys.exit("gate: the consumer walk does not find `tbz #0xc` at 0xbb8b00 in es9028_i2c_probe -- "
                     "that site is §352's established registration gate, so a walk that misses it is blind "
                     "and the 0-or-few count below would mean nothing")
    else:
        shape = [c for c in cons if c["bits"] == "bit 12" and c["fn"] == "es9028_i2c_probe"]
        if not shape:
            sys.exit("gate: on this image no `tbz` of bit 12 was found inside es9028_i2c_probe -- the "
                     "walk is blind here, so publish nothing (the baseline's 0xbb8b00 cannot be reused "
                     "as the proof for another image)")
        print(f"  gate-anchoring note: this is not the baseline Image; the §352 registration gate is "
              f"present at this image's own site {shape[0]['site']} (bit 12 in es9028_i2c_probe), so the "
              "address pin from 6.0.1 was replaced by the shape check")
    seen = {r["property"] for r in all_rows}
    if a.selftest:
        if "vivo,params" not in seen or "vivo,param-num" not in seen:
            sys.exit(f"gate: --selftest: the es9038 probe reads resolved to {sorted(seen)} -- §287/§325 "
                     "established `vivo,params` and `vivo,param-num` from this same Image, so a walk that "
                     "misses them cannot be trusted for the rest")
        if not any(r["bits"] != "-" or r["fields"] != "-" for r in all_rows):
            sys.exit("gate: --selftest: every resolved read has neither a flag bit nor a struct field "
                     "attached -- the following-window attribution would be printing names only, and the "
                     "row claims it says what the answer is used for")
        # cross-witness: §325 read these struct slots with a DIFFERENT instrument (the store-site walk in
        # kobj_span_refs), so the linker must reproduce them -- a link that disagrees with that earlier,
        # independent measurement is a link this tool got wrong
        want = {("es9038_i2c_probe", "vivo,param-num"): {"0x60", "0x64"},
                ("es9038_i2c_probe", "vivo,params"): {"0x68"},
                ("es9028_i2c_probe", "vivo,param-num"): {"0x68", "0x6c"},
                ("es9028_i2c_probe", "vivo,params"): {"0x70"}}
        got = {}
        for r in all_rows:
            if r["fields"] != "-":
                got.setdefault((r["fn"], r["property"]), set()).update(r["fields"].split())
        off = {k: (want[k], got.get(k, set())) for k in want if got.get(k, set()) != want[k]}
        if off:
            sys.exit(f"gate: --selftest: the field linker reproduces {sorted(got)} but §325's independent "
                     f"slots differ here: {off} -- refuse to publish a link that contradicts the earlier "
                     "measurement (and refuse to re-derive §325 from this same walk)")
        im = [r for r in all_rows if r["property"] == "i2s-master"]
        if not im or "0x1000" not in im[0]["bits"]:
            sys.exit(f"gate: --selftest: `i2s-master` no longer links to bit 0x1000 ({im[:1]}) -- §354/§355 "
                     "publish that bit as the es9028 registration gate")
        shifted, _s1, _n1 = scan("es9038_i2c_probe", control_shift=True)
        sg = [r for r in shifted if r["name"]]
        if len(sg) >= len([r for r in all_rows if r["fn"] == "es9038_i2c_probe"]):
            sys.exit(f"gate: --selftest: reading the name from x2 instead of x1 resolves {len(sg)} name(s) "
                     "-- then the argument position is not load-bearing and the x1 keying is unproven")
        print(f"selftest: the known pair resolves; the field linker reproduces §325's slots "
              f"{sorted(got.items())}; `i2s-master` -> bit 0x1000; and the same walk pointed at argument 2 "
              f"(x2) resolves {len(sg)} name(s) instead -- x1 keying is load-bearing")
    if a.out:
        for c in cons:
            all_rows.append(c)
        cols = ["kind", "fn", "fn_at", "site", "callee", "property", "name_va", "bits", "fields",
                "link_kind", "evidence", "near_w1_imm", "value_origin"]
        with open(a.out, "w", encoding="utf-8") as fh:
            fh.write("\t".join(cols) + "\n")
            for r in all_rows:
                line = "\t".join(str(r.get(c, "-")) for c in cols)
                if len(line.split("\t")) != len(cols):
                    sys.exit("gate: a row does not have the declared column count")
                fh.write(line + "\n")
        print(f"wrote {a.out} ({len(all_rows)} rows x {len(cols)} columns)")
    sys.exit(0)


if __name__ == "__main__":
    main()
