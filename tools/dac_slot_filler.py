#!/usr/bin/env python3
"""tools/dac_slot_filler.py -- §331: who fills the pointer slots the Hi-Fi trigger chain reads?

The chain has one link that the static call graph cannot show (§280/§288 established that shape:
a call made through a function-pointer slot leaves no `bl` edge).  Two objects are involved and this
tool answers, mechanically and over the whole Image, three questions about them:

  1  ALLOCATION  `vivo_codec_platform_probe` -- kallsyms carries TWO copies under that name -- calls
     `kmem_cache_alloc_trace(wflags, size)` and installs the result into the codec object at +0x60 or
     +0x68.  Both the displacement and the *size* are read from the code (`mov w2, #...` immediately
     before the `bl`), never typed here.  A struct that reaches +0xa0 must be at least 0xa8 bytes,
     and that arithmetic check is what makes "this allocation is the object the handler dereferences"
     more than a name match.
  2  FILL        for the displacements that matter (0x8, 0x60, 0x68, 0x98, 0xa0) every `str` in the
     Image whose stored value is a known symbol, plus the provenance of the base register:
        const@<va> / <sym>        the base is a statically-known address -> the target object is named
        new:<callee>              the base is a pointer returned by an allocator in this same function
        arg:x0..x7                the base entered as a parameter -> last link stays runtime-only
        caller:x19                callee-saved, written by a different function -> one hop unmade
        spill[+0x58]<-...          the base was reloaded from this function's own stack slot
  3  IDENTITY     the value stored is named from kallsyms and its symbol *type* is reported, so a
     text symbol (a function pointer) is distinguishable from a data pointer in the same column.

Controls, all of which abort: the four displacements must each be seen somewhere in the Image; at
least one store at +0x98 must carry a text symbol; the two known getter names from §327's manual
reading must come back (a positive control against this tool, not for it); no allocation row may have
a typed-in size; the alignment shadow (odd displacements, impossible for scaled 64-bit `str`) must
stay empty, which is what proves the matcher is reading the displacement field and not a shifted one.

usage: tools/dac_slot_filler.py [--out TSV] [--selftest] [--disps 0x60,0x68,0x98,0xa0] [--only SUBSTR]
"""
import argparse
import collections
import hashlib
import os
import re
import struct
import sys

from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, Cs

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IMG = os.environ.get("DAC_IMG", os.path.join(ROOT, "fw", "Image"))
KALL = os.environ.get("DAC_KALL", os.path.join(ROOT, "art", "kallsyms_real.txt"))
TEXT_BASE = 0xFFFFFFC000080000
TEXT_END = TEXT_BASE + os.path.getsize(IMG)
MASK = 0xFFFFFFFFFFFFFFFF
ALIAS = {"fp": 29, "lr": 30, "sp": 31}
ALLOCATORS = {"kmem_cache_alloc_trace", "kmem_cache_alloc", "kzalloc", "kmalloc", "__kmalloc",
              "devm_kzalloc", "kcalloc"}
# §327's manual reading of these two slots; used here as a positive control on the tool.
EXPECTED_GETTERS = ("msm_mbhc_get_impedance", "msm_mbhc_get_plug_pype")
# functions the Hi-Fi trigger chain is known to consist of (ledger 286-289, 322, 327); rows at other
# displacements are only kept for these, because +0x8 writes are everywhere in a kernel.
CHAIN = ("vivo_codec_platform_probe", "vivo_codec_dai_link_init", "hifi_codec_dac_event",
         "es9038_enable", "es9038_mute", "setting_special_params")
BLOB = open(IMG, "rb").read()

ENTRIES = []
for line in open(KALL, encoding="utf-8", errors="replace"):
    p = line.split()
    if len(p) >= 3 and re.fullmatch(r"[0-9a-f]{16}", p[0]):
        ENTRIES.append((int(p[0], 16), p[1], p[2]))
NAME, TYPE = {}, {}
FOR_NAME = collections.defaultdict(list)
for addr, typ, nm in ENTRIES:
    NAME.setdefault(addr, nm)
    TYPE.setdefault(addr, typ)
    FOR_NAME[nm].append(addr)
TEXT = sorted({(a, n) for a, t, n in ENTRIES if t in "tT" and TEXT_BASE <= a < TEXT_END})
TA = [a for a, _n in TEXT]
TA_SET = set(TA)
IDX = {a: i for i, a in enumerate(TA)}
MD = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
MD.detail = True


def sha16(p):
    return hashlib.sha256(open(p, "rb").read()).hexdigest()[:16]


def rnum(reg):
    n = MD.reg_name(reg) or ""
    if n in ALIAS:
        return ALIAS[n]
    m = re.fullmatch(r"[wx](\d+)", n)
    return int(m.group(1)) if m else None


def decode(va, end):
    out, a, undecodable = [], va, 0
    while a < end:
        q = BLOB[a - TEXT_BASE:a - TEXT_BASE + 4]
        if len(q) < 4:
            break
        w = struct.unpack("<I", q)[0]
        if w == 0:
            a += 4
            continue
        x = next(MD.disasm(q, a), None)
        if x is None:
            undecodable += 1
        else:
            out.append(x)
        a += 4
    return out, undecodable


def base_label(base, val, orig):
    if base in val:
        va = val[base]
        if va in NAME:
            where = "inside the file-backed Image" if TEXT_BASE <= va < TEXT_END else \
                    "past the file-backed span, i.e. .bss -- the file has no bytes for it"
            return f"{NAME[va]}@{va:#x} ({where})"
        if TEXT_BASE <= va < TEXT_END:
            return f"{va:#x} (inside the Image, no symbol there)"
        return f"{va:#x} (outside the file-backed span; a .bss global or not an address at all)"
    if base in orig:
        return orig[base]
    if base in (29, 31):
        return "frame"
    if base is None:
        return "no-base"
    if base <= 7:
        return f"arg:x{base}"
    if 19 <= base <= 28:
        return f"caller-saved:x{base}"
    return f"caller-clobberable:x{base}"


def walk(ins, targets, at_targets=()):
    """single-pass provenance walk; returns (bracketed store rows, allocator events,
    alignment-shadow sites, pre/post-indexed stores that merely look like the target displacement,
    accesses whose BASE REGISTER'S OWN VALUE lands on one of at_targets -- a different keying
    dimension: absolute VA rather than displacement, so the two must agree where they overlap)"""
    val, orig, slots, rows, allocs, shadow, writeback, abs_hits = {}, {}, {}, [], [], [], [], []
    for x in ins:
        ops, mn = x.operands, x.mnemonic
        dst = rnum(ops[0].reg) if ops and ops[0].type == 1 else None
        mem = [o for o in ops if o.type == 3]
        if mem and mn.startswith("st"):
            base = rnum(mem[0].mem.base)
            n = 2 if mn == "stp" else 1
            for k in range(n):
                if k >= len(ops) or ops[k].type != 1:
                    continue
                r = rnum(ops[k].reg)
                if r is None:
                    continue
                vname = MD.reg_name(ops[k].reg) or ""
                at = mem[0].mem.disp + (8 * k if mn == "stp" else 0)
                # ARM writes a struct field with the offset INSIDE the brackets; pre/post-indexed forms
                # (str x0, [x1], #197) put a writeback offset there instead, and capstone reports both in
                # the same mem.disp field. Only the bracketed form addresses a field.
                bracketed = x.op_str.endswith("]") and at >= 0
                tv = val.get(base)
                if bracketed and tv is not None and ((tv + at) & MASK) in at_targets:
                    abs_hits.append({"site": x.address, "dir": "write", "tgt": (tv + at) & MASK,
                                     "text": f"{mn} {x.op_str}", "reg": f"x{r}", "base_reg": base,
                                     "value_va": val.get(r),
                                     "value_name": NAME.get(val[r]) if val.get(r) is not None else None,
                                     "base_kind": base_label(base, val, orig),
                                     "width": "64" if vname.startswith("x") else "32"})
                if mn == "str" and vname.startswith("x") and bracketed and at % 8:
                    shadow.append((x.address, at))
                if not bracketed:
                    if at in targets:
                        writeback.append((x.address, at, mn))
                    continue
                if at in targets:
                    rows.append({"site": x.address, "disp": at, "text": f"{mn} {x.op_str}",
                                 "value_reg": r, "width": "64" if vname.startswith("x") else "32",
                                 "base_va": tv,
                                 "value_va": val.get(r),
                                 "value_kind": orig.get(r, f"x{r}(no origin in this function)"),
                                 "value_name": NAME.get(val[r]) if val.get(r) is not None else None,
                                 "value_type": TYPE.get(val[r]) if val.get(r) is not None else None,
                                 "base": base, "base_kind": base_label(base, val, orig)})
                if base in (29, 31):
                    slots[at] = (val.get(r), orig.get(r, f"x{r}"))
            continue
        if mn in ("bl", "blr"):
            tgt = (ops[0].imm & MASK) if (mn == "bl" and ops and ops[0].type == 2) else None
            callee = NAME.get(tgt) if tgt is not None else None
            lbl = f"ret:{callee or 'indirect'}"
            if callee in ALLOCATORS:
                lbl = f"new:{callee}@{x.address:#x}"
                allocs.append({"site": x.address, "label": lbl, "callee": callee,
                               "wflags": val.get(1), "size": val.get(2),
                               "size_from_code": 2 in val})
            for r in list(val):
                if r <= 17:
                    val.pop(r)
            for r in list(orig):
                if r <= 17:
                    orig.pop(r)
            orig[0] = lbl
            continue
        if mn == "adrp" and len(ops) == 2 and ops[1].type == 2 and dst is not None:
            val[dst] = ops[1].imm & MASK
            orig[dst] = f"adrp@{ops[1].imm & MASK:#x}"
            continue
        if mn in ("add", "sub") and len(ops) == 3 and ops[2].type == 2 and dst is not None:
            b = rnum(ops[1].reg)
            if b in val:
                step = ops[2].imm & MASK
                val[dst] = (val[b] + step) if mn == "add" else (val[b] - step) & MASK
                orig[dst] = orig.get(b, f"x{b}")
                continue
        if mn == "mov" and len(ops) == 2 and dst is not None:
            if ops[1].type == 2:
                val[dst] = ops[1].imm & MASK
                orig[dst] = f"const:{ops[1].imm & MASK:#x}"
            elif ops[1].type == 1:
                s = rnum(ops[1].reg)
                if s in (30, 31) or s is None:
                    val.pop(dst, None)
                else:
                    if s in val:
                        val[dst] = val[s]
                    else:
                        val.pop(dst, None)
                    orig[dst] = orig.get(s) or base_label(s, val, orig)
            continue
        if mem and (mn.startswith("ldr") or mn.startswith("ldur") or mn == "ldp"):
            base = rnum(mem[0].mem.base)
            n = 2 if mn == "ldp" else 1
            for k in range(n):
                if k >= len(ops) or ops[k].type != 1:
                    continue
                d = rnum(ops[k].reg)
                if d is None:
                    continue
                at = mem[0].mem.disp + (8 * k if mn == "ldp" else 0)
                tv = val.get(base)
                if x.op_str.endswith("]") and at >= 0 and tv is not None \
                        and ((tv + at) & MASK) in at_targets:
                    vn = MD.reg_name(ops[k].reg) or ""
                    abs_hits.append({"site": x.address, "dir": "read", "tgt": (tv + at) & MASK,
                                     "text": f"{mn} {x.op_str}", "reg": f"x{d}", "base_reg": base,
                                     "value_va": None, "value_name": None,
                                     "base_kind": base_label(base, val, orig),
                                     "width": "64" if vn.startswith("x") else "32"})
                val.pop(d, None)
                if base in (29, 31) and at in slots:
                    sv, so = slots[at]
                    if sv is not None:
                        val[d] = sv
                    orig[d] = f"spill[{at:+#x}]<-{so}"
                elif base in val:
                    orig[d] = f"mem[{NAME.get((val[base] + at) & MASK) or f'{(val[base] + at) & MASK:#x}'}]"
                else:
                    orig[d] = f"mem[{base_label(base, val, orig)}{at:+#x}]"
            continue
        if mn.startswith(("cbz", "cbnz", "tbz", "tbnz", "cmp", "cmn", "tst", "ccmp", "fcmp")):
            continue
        if mn == "br" or mn.startswith("b."):
            continue
        if dst is not None:
            val.pop(dst, None)
            orig.pop(dst, None)
    return rows, allocs, shadow, writeback, abs_hits


def base_union(ins, site, reg):
    """Is the base register's value at `site` single-valued?

    Counting every earlier definition over-reports: what matters is whether some path can jump INTO
    the window between the last definition and the use, carrying another value.  So: take the last
    definition of the register before the site (in listing order), resolve it if the pattern allows,
    and count branch targets that land strictly between that definition and the site.  Returns
    (resolved value or None, number of branch targets in the window)."""
    targets = set()
    for x in ins:
        for o in x.operands:
            if o.type == 2 and x.address <= o.imm & MASK < x.address + 0x400000 and \
                    (o.imm & MASK) != x.address and (x.mnemonic == "b" or x.mnemonic.startswith("b.")
                                                     or x.mnemonic.startswith(("cbz", "cbnz", "tbz", "tbnz"))):
                targets.add(o.imm & MASK)
    val, last_def, resolvable = {}, None, None
    for x in ins:
        if x.address == site:
            break
        ops, mn = x.operands, x.mnemonic
        dst = rnum(ops[0].reg) if ops and ops[0].type == 1 else None
        mem = [o for o in ops if o.type == 3]
        if mn == "adrp" and len(ops) == 2 and ops[1].type == 2 and dst is not None:
            val[dst] = ops[1].imm & MASK
        elif mn in ("add", "sub") and len(ops) == 3 and ops[2].type == 2 and dst is not None:
            b = rnum(ops[1].reg)
            if b in val:
                step = ops[2].imm & MASK
                val[dst] = (val[b] + step) if mn == "add" else (val[b] - step) & MASK
            else:
                val.pop(dst, None)
        elif mn == "mov" and len(ops) == 2 and dst is not None:
            if ops[1].type == 2:
                val[dst] = ops[1].imm & MASK
            elif ops[1].type == 1 and rnum(ops[1].reg) in val:
                val[dst] = val[rnum(ops[1].reg)]
            else:
                val.pop(dst, None)
        elif dst is not None and not mn.startswith(("cmp", "tst", "cbz", "cbnz", "tbz", "tbnz")) \
                and not (mem and mn.startswith("st")) and mn not in ("bl", "blr", "br"):
            val.pop(dst, None)
        if dst == reg:
            last_def, resolvable = x.address, val.get(reg)
    between = sum(1 for t in targets if last_def is not None and last_def < t <= site) if last_def else 0
    return resolvable, between


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--disps", default="0x8,0x60,0x68,0x98,0xa0")
    ap.add_argument("--only", default="", help="substring filter over function names (exploration only)")
    ap.add_argument("--at", default="",
                    help="absolute field(s) to census by VALUE of the base register: 0x… or name or "
                         "name+0x10 -- a second, independent keying dimension next to --disps")
    ap.add_argument("--allow-absent", action="store_true",
                    help="permit a requested --at field to have no static accessor (the sentence then "
                         "has to state the denominator instead of aborting)")
    a = ap.parse_args()
    targets = {int(s, 0) for s in a.disps.split(",") if s.strip()}

    def resolve(tok):
        tok = tok.strip()
        if not tok:
            return None
        if tok.startswith("0x"):
            return {int(tok, 0)}
        name, _, extra = tok.partition("+")
        hits = sorted(set(FOR_NAME.get(name, [])))
        if not hits:
            sys.exit(f"gate: --at {tok}: symbol {name!r} is not in {KALL} -- cannot census a field "
                     "whose address is unknown")
        if len(hits) > 1:
            sys.exit(f"gate: --at {tok}: {name} has {len(hits)} addresses {[hex(h) for h in hits]} -- "
                     "identity must be by address, so pass the exact VA (name alone is not enough here)")
        return {(hits[0] + (int(extra, 0) if extra else 0)) & MASK}

    at_targets = set()
    at_labels = {}
    abs_summary = []
    for tok in a.at.split(","):
        got = resolve(tok)
        if got:
            at_targets |= got
            for g in got:
                at_labels[g] = tok
    if a.only:
        print(f"NOTE --only={a.only}: this is a scoped run, the DENOM rows below are NOT whole-Image")
    todo = [(va, nm) for va, nm in TEXT if (not a.only or a.only in nm)]
    all_rows, all_allocs, shadow, all_wb, all_abs = [], [], [], [], []
    n_instr = n_bad = n_pad = n_split = 0
    for k, (va, nm) in enumerate(todo):
        # span comes from the FULL text list, never the filtered one: a --only run would otherwise cut
        # each function at its own start+4 and silently scan one instruction.
        i = IDX[va]
        end = TA[i + 1] if i + 1 < len(TA) else va + 4
        ins, bad = decode(va, end)
        n_instr += len(ins)
        n_bad += bad
        n_pad += (end - va) // 4 - len(ins) - bad
        rows, allocs, sh, wb, ah = walk(ins, targets, at_targets)
        for r in rows:
            r["fn"] = nm
            r["fn_at"] = va
            r["name_collisions"] = len({x for x in FOR_NAME[nm] if x != va}) + 1
        all_rows += rows
        n_split += sum(1 for x in ins if x.address != va and x.mnemonic == "stp"
                       and "x29" in x.op_str and "[sp" in x.op_str and x.op_str.endswith("!"))
        for s in allocs:
            s["fn"] = nm
            s["fn_at"] = va
        all_allocs += allocs
        shadow += sh
        all_wb += [w for w in wb]
        for h in ah:
            h["fn"] = nm
            h["fn_at"] = va
        all_abs += ah
    named = [r for r in all_rows if r["value_name"]]
    by_disp = collections.Counter(r["disp"] for r in all_rows)
    print(f"inputs          Image {IMG} [{sha16(IMG)}] size {os.path.getsize(IMG)}; "
          f"symbols {KALL} [{sha16(KALL)}] entries {len(ENTRIES)}")
    print(f"scan            {len(todo)} functions, {n_instr} instructions decoded, "
          f"{n_bad} undecodable words, {n_pad} zero-pad words skipped")
    print(f"span caveat     {n_split} extra function prologues found inside these windows -- the span "
          "rule cuts each window at the NEXT kallsyms text symbol, so a store can be labelled with a "
          "neighbouring symbol's name when kallsyms has no entry for the body that holds it")
    print(f"displacements   " + "  ".join(f"+{d:#x}: {by_disp.get(d, 0)} stores" for d in sorted(targets)))
    print(f"                {len(all_wb)} pre/post-indexed writes whose writeback offset happens to equal "
          f"one of these numbers are NOT counted as field writes "
          f"({sorted({w[2] for w in all_wb})[:6]})")
    if shadow:
        sys.exit(f"gate: {len(shadow)} 64-bit scaled `str` with a displacement that is not a multiple of "
                 f"8 ({shadow[:3]}) -- that encoding cannot exist, so the field being read is not the "
                 "displacement")
    for d in sorted(targets):
        if not by_disp.get(d):
            sys.exit(f"gate: displacement +{d:#x} never appears as a store target in this scan -- the "
                     f"census denominator is empty for it, so nothing about that slot can be claimed")
    at98 = [r for r in named if r["disp"] == 0x98 and r["width"] == "64"]
    texty = [r for r in at98 if (r["value_type"] or "").lower() == "t"]
    narrow = [r for r in named if r["width"] != "64"]
    if narrow:
        print(f"note            {len(narrow)} named store(s) at these displacements are 32-bit writes "
              "(a halfword of a pointer, or a value that is not a pointer) -- kept in the table, "
              "excluded from the pointer-fill claim")
    if 0x98 in targets and not texty:
        sys.exit("gate: no store at +0x98 carries a *text* symbol -- the getter-slot claim could not be "
                 "made, so the tool would print a table that says nothing")
    getter_rows = [r for r in named if r["disp"] in (0x98, 0xa0) and r["width"] == "64"]
    got = {r["value_name"] for r in getter_rows}
    missing = [g for g in EXPECTED_GETTERS if g not in got]
    if missing and (targets & {0x98, 0xa0}) and not a.only:
        sys.exit(f"gate: §327's manual reading put {EXPECTED_GETTERS} in the +0x98/+0xa0 slots; this scan "
                 f"does not see {missing} -- either the walk is blind or that reading was wrong, and the "
                 "ledger must not carry either until they agree")
    if a.only and missing:
        print(f"note            --only run: the getter control is missing {missing} because the scan is "
              "scoped, not because the Image lacks them")
    print("chain-relevant named stores (value resolved from kallsyms):")
    scope = [r for r in named if r["disp"] in (0x98, 0xa0) or r["fn"] in CHAIN]
    for r in scope:
        print(f"   +{r['disp']:#04x} in {r['fn']}@{r['fn_at']:#x}  {r['text']:30} "
              f"= {r['value_name']} [{r['value_type']}/{r['width']}-bit]  base=x{r['base']} "
              f"({r['base_kind']})"
              + (f"  [name shared x{r['name_collisions']}]" if r["name_collisions"] > 1 else ""))
    kinds = collections.Counter(r["base_kind"].split("[")[0].split("(")[0].split(":")[0] for r in scope)
    if a.only:
        kept = {id(r) for r in scope}
        for r in [x for x in all_rows if x["disp"] in targets and id(x) not in kept][:40]:
            va = r["value_va"]
            print(f"   +{r['disp']:#04x} in {r['fn']}@{r['fn_at']:#x}  {r['text']:30} "
                  f"value={'-' if va is None else f'{NAME.get(va) or hex(va)}'} at {va if va is None else hex(va)}"
                  f"  base=x{r['base']} ({r['base_kind']})  provenance={r['value_kind']}")
    for d in (0x98, 0xa0):
        rows_d = [r for r in scope if r["disp"] == d]
        txt = [r for r in rows_d if (r["value_type"] or "").lower() == "t"]
        codec = [r for r in txt if re.search(r"codec|hifi|vivo|mbhc|wcd", r["fn"], re.I)]
        print(f"slot census +{d:#x} {by_disp.get(d, 0)} stores image-wide, {len(rows_d)} with a resolvable "
              f"value, {len(txt)} of those a *function* symbol, {len(codec)} filled by a function inside a "
              f"codec-named function ({sorted({r['fn'] for r in codec})})")
    print(f"base provenance   {dict(kinds)}")
    probes = [(va, nm) for va, nm in TEXT if nm == "vivo_codec_platform_probe"]
    if not probes:
        sys.exit("gate: no vivo_codec_platform_probe in the symbol table -- the allocation side of the "
                 "chain cannot be checked")
    probe_at = {va for va, _nm in probes}
    scan_probe = bool(probe_at & {va for va, _nm in todo})
    if (targets & {0x60, 0x68}) and not scan_probe:
        print("note            --only run that excludes vivo_codec_platform_probe: the allocation/install "
              "arms are skipped, so this output says nothing about +0x60/+0x68")
    alloc_rows, installs, rest = [], [], []
    if (targets & {0x60, 0x68}) and scan_probe:
        alloc_rows = [s for s in all_allocs if s["fn_at"] in probe_at]
        if not alloc_rows:
            sys.exit("gate: neither vivo_codec_platform_probe copy contains a slab allocation call -- the "
                     "struct installed at +0x60/+0x68 would have no allocation witness, so the size "
                     "argument that identifies it could not be made")
        print(f"allocations inside the probe copies (all {len(all_allocs)} allocator call sites seen in "
              f"the scan, {len(all_allocs) - len(alloc_rows)} of them elsewhere):")
        for s in alloc_rows:
            if s["size_from_code"]:
                shape = ("large enough to hold +0x98/+0xa0" if s["size"] >= 0xa0 + 8
                         else "TOO SMALL for a +0xa0 slot -- this is not that struct")
            else:
                shape = "SIZE NOT READABLE FROM CODE (gate below)"
            print(f"   alloc {s['fn']}@{s['fn_at']:#x} {s['callee']} wflags={s['wflags']} "
                  f"size={s['size']} ({shape})")
        by_label = {s["label"]: s for s in all_allocs}
        lbl_re = re.compile(r"new:[A-Za-z0-9_.]+@0x[0-9a-f]+")

        def pair(kind):
            m = lbl_re.search(kind)
            return (m.group(0), by_label.get(m.group(0))) if m else (None, None)

        def tier(kind):
            head = kind.split("<-")[-1]
            return "direct" if head.startswith("new:") else "derived"

        fresh = [r for r in all_rows if r["disp"] in (0x60, 0x68) and "new:" in r["value_kind"]]
        frame = [r for r in fresh if r["base"] in (29, 31)]
        image_wide = [r for r in fresh if r["base"] not in (29, 31)]
        installs = [r for r in image_wide if r["fn_at"] in probe_at]
        rest = [r for r in all_rows if r["disp"] in (0x60, 0x68) and "new:" not in r["value_kind"]]
        if frame:
            print(f"              {len(frame)} store(s) at the same numeric displacement off x29/sp are "
                  "frame spills, not struct installs -- excluded (a shared number is not a shared object)")
        print(f"              image-wide, {len(image_wide)} allocator-result install(s) at +0x60/+0x68 in "
              f"{len({r['fn_at'] for r in image_wide})} functions, "
              f"{collections.Counter(tier(r['value_kind']) for r in image_wide)} -- "
              f"{len(installs)} of them inside the two probe copies, which is what the chain needs")
        if not installs:
            sys.exit("gate: no store at +0x60/+0x68 inside either probe copy has a value the walk traces "
                     "to an allocator result -- the install step would be unattributed and §331's "
                     "two-objects story would be my inference rather than a reading")
        for r in installs:
            label, src = pair(r["value_kind"])
            r["alloc"] = src
            if src is None:
                sys.exit(f"gate: probe install at {r['site']:#x} names allocation {label!r} which the scan "
                         "did not record -- the pairing between the install and its allocation is broken")
            print(f"   install {r['fn']}@{r['fn_at']:#x} +{r['disp']:#x} {r['text']:22} "
                  f"size={src['size']:5} from bl@{src['site']:#x} [{tier(r['value_kind'])}] "
                  f"base=x{r['base']} ({r['base_kind']})")
        print(f"              {len(rest)} other stores at +0x60/+0x68 carry values that are not fresh "
              "allocations (fields, globals, copies) -- they are not installs of a freshly allocated struct")
        unreadable = [s for s in alloc_rows if not s["size_from_code"]]
        if unreadable:
            sys.exit(f"gate: {len(unreadable)} probe allocation(s) whose size is not an immediate next to "
                     f"the bl ({unreadable[:2]}) -- the arithmetic check that identifies the struct would "
                     "be a guess")
        big = [r for r in installs if r["alloc"]["size"] >= 0xa0 + 8]
        if not big:
            sys.exit("gate: no +0x60/+0x68 install carries a struct of 0xa8 bytes or more -- the object "
                     "that holds a +0x98 slot would have no allocation witness, so §331's size argument "
                     "fails even though installs exist")
        if not all(any(r["fn_at"] == va and r in big for r in installs) for va, _p in probes):
            print("note            not every probe copy has a >=0xa8 install; the copies are two different "
                  "builds and the arithmetic only holds where it is reported")
    print(f"verdict         +0x98/+0xa0 hold {sorted(got)} filled by "
          f"{sorted({(r['fn'], r['fn_at']) for r in getter_rows})}; "
          f"{len(installs)} allocator-result install(s) at +0x60/+0x68 in "
          f"{sorted({(r['fn'], r['fn_at']) for r in installs})}, probe allocation sizes "
          f"{[s['size'] for s in alloc_rows]}")
    print("                a base of kind arg:/caller-saved: means the last link is runtime-only -- the "
          "same shape §280/§288 hit for the ops table, reported rather than smoothed over")
    if at_targets:
        by_t = collections.defaultdict(list)
        for h in all_abs:
            by_t[h["tgt"]].append(h)
        print(f"absolute-value keyed census (--at): {len(all_abs)} access(es) over {len(todo)} functions")
        for t in sorted(at_targets):
            hs = by_t.get(t, [])
            rd = sorted({h["fn"] for h in hs if h["dir"] == "read"})
            wr = sorted({h["fn"] for h in hs if h["dir"] == "write"})
            print(f"   {at_labels[t]} = {t:#x}  writes {len(wr)} {wr}  reads {len(rd)} {rd}")
            abs_summary.append({
                "tgt": t, "label": at_labels[t], "writes": len(wr), "readers": len(rd),
                "writer_fns": "; ".join(wr) or "-", "reader_fns": "; ".join(rd) or "-",
                "sites": "; ".join(f"{h['fn']}@{h['site']:#x}" for h in hs if h["dir"] == "write") or "-"})
            for h in hs:
                i2 = IDX[h["fn_at"]]
                e2 = TA[i2 + 1] if i2 + 1 < len(TA) else h["fn_at"] + 4
                ins2, _ = decode(h["fn_at"], e2)
                bval, jumps = base_union(ins2, h["site"], h["base_reg"])
                h["base_value"], h["base_jumps"] = bval, jumps
                print(f"      {h['dir']:5} {h['site']:#x} in {h['fn']}@{h['fn_at']:#x}  {h['text']:28} "
                      f"via {h['base_kind']}  value={h['value_name'] or '-'}  "
                      f"base here: {hex(bval) if bval is not None else 'UNRESOLVED'}, "
                      + (f"{jumps} branch target(s) land between its last definition and this use "
                         "-> NOT single-valued" if jumps else
                         ("no such jump -> the base is single-valued at this use"
                          if bval is not None else "base value not statically resolvable")))
            if not hs and not a.allow_absent:
                sys.exit(f"gate: --at {at_labels[t]} ({t:#x}) matched nothing: no access in these "
                         f"{len(todo)} functions has a base register the walk could resolve onto it -- "
                         "say so with --allow-absent and the sentence must then read 'no accessor in this "
                         "scan', never 'nobody touches it'")
        known = [r for r in all_rows if r.get("base_va") is not None
                 and ((r["base_va"] + r["disp"]) & MASK) in at_targets]
        disagree = [r for r in known if not any(h["site"] == r["site"] for h in all_abs)]
        if disagree:
            sys.exit(f"gate: the two keyings disagree for {len(disagree)} store(s) "
                     f"({[hex(m['site']) for m in disagree[:3]]}) -- the displacement scan sees a write "
                     "to a requested absolute field that the --at scan missed, so at least one of the "
                     "two predicates is wrong and neither may be quoted")
        print(f"cross-check      the displacement-keyed rows landing on the requested fields "
              f"({len(known)}) all appear in the value-keyed scan: two predicates, same sites")
    if a.selftest:
        unres = [r for r in all_rows if not r["value_name"]]
        if not unres:
            sys.exit("gate: --selftest: every store at these displacements resolved its value, so the "
                     "'value must be a known symbol' filter is not doing any work here")
        print(f"selftest: dropping the value-resolution filter would print {len(all_rows)} rows instead of "
              f"{len(named)} ({len(unres)} stores whose base register holds a pointer the walk cannot "
              "name) -- the filter is load-bearing and the DENOM row keeps the difference visible")
        home = scope[0]["fn_at"]
        probe_ins, _ = decode(home, TA[IDX[home] + 1] if IDX[home] + 1 < len(TA) else home + 4)
        shifted = walk(probe_ins, {d + 1 for d in targets})[0]
        if shifted:
            sys.exit(f"gate: --selftest: matching every target displacement one byte off found "
                     f"{len(shifted)} stores -- the displacement is not read exactly, so the census could "
                     "be an offset bug")
        exact = walk(probe_ins, targets)[0]
        if not exact:
            sys.exit("gate: --selftest: the positive arm is empty (the function chosen for the control "
                     f"has no rows at {sorted(targets)}), so 'zero rows one byte off' would prove nothing")
        print(f"selftest: {scope[0]['fn']} re-walked on its own: the real displacements yield {len(exact)} "
              "rows and the same parser one byte off yields 0 -- the displacement field is read exactly "
              "(a shifted mask would fill both arms)")
        if at_targets and all_abs:
            home2 = all_abs[0]["fn_at"]
            ins2, _ = decode(home2, TA[IDX[home2] + 1] if IDX[home2] + 1 < len(TA) else home2 + 4)
            off8 = walk(ins2, targets, {t + 8 for t in at_targets})[4]
            if off8:
                sys.exit("gate: --selftest: the value-keyed arm found accesses at fields shifted by 8, so "
                         "the base-value arithmetic is not exact and the --at census cannot be quoted")
            real = walk(ins2, targets, at_targets)[4]
            if not real:
                sys.exit("gate: --selftest: the value-keyed positive arm is empty on the very function "
                         "that produced the first hit -- the scan is not reproducible inside walk()")
            print(f"selftest: value-keyed arm on {all_abs[0]['fn']}: the requested fields give {len(real)} "
                  "access(es), the same fields 8 bytes away give 0 -- the absolute arithmetic is exact, "
                  "so a hit is not a rounding accident")
    if a.out:
        cols = ["kind", "fn", "fn_at", "site", "disp", "text", "value", "value_type",
                "base", "base_kind", "detail"]
        lines, widths = [], set()

        def emit(d):
            line = [str(d.get(c, "-")).replace("\t", " ").replace("\n", " ") for c in cols]
            widths.add(len(line))
            lines.append("\t".join(line))

        scope = [r for r in named if r["disp"] in (0x98, 0xa0) or r["fn"] in CHAIN]
        print(f"              {len(named) - len(scope)} named store(s) at +0x60/+0x68 elsewhere in the "
              f"Image are out of this artifact's scope ({len(scope)} rows kept): the table records the "
              "trigger chain, not every struct write that shares a number")
        for r in scope:
            emit({"kind": "store" if r["disp"] in (0x60, 0x68) else "getter-fill",
                  "fn": r["fn"], "fn_at": f"{r['fn_at']:#x}", "site": f"{r['site']:#x}",
                  "disp": f"{r['disp']:#x}", "text": r["text"], "value": r["value_name"],
                  "value_type": f"{r['value_type']}/{r['width']}bit", "base": f"x{r['base']}",
                  "base_kind": r["base_kind"],
                  "detail": (f"provenance={r['value_kind']}; "
                             + (f"name shared by {r['name_collisions']} addresses"
                                if r["name_collisions"] > 1 else "unique name"))})
        for r in installs:
            emit({"kind": "install", "fn": r["fn"], "fn_at": f"{r['fn_at']:#x}",
                  "site": f"{r['site']:#x}", "disp": f"{r['disp']:#x}", "text": r["text"],
                  "value": f"(slab pointer from {r['value_kind'].split('<-')[-1]}, "
                           f"size={r['alloc']['size']})",
                  "value_type": f"{r['width']}bit",
                  "base": f"x{r['base']}", "base_kind": r["base_kind"],
                  "detail": ("struct is big enough to hold +0x98/+0xa0" if r["alloc"]["size"] >= 0xa8
                             else "smaller than 0xa8: a different object")})
        for h in all_abs:
            emit({"kind": "abs-access", "fn": h["fn"], "fn_at": f"{h['fn_at']:#x}",
                  "site": f"{h['site']:#x}", "disp": f"field {h['tgt']:#x}", "text": h["text"],
                  "value": h["value_name"] or "-", "value_type": f"{h['dir']}/{h['width']}bit",
                  "base": f"x{h['base_reg']}", "base_kind": h["base_kind"],
                  "detail": f"requested as {at_labels.get(h['tgt'], '?')}; base at this use "
                            f"{h.get('base_value') and hex(h['base_value']) or 'UNRESOLVED'}, "
                            f"branch targets between its definition and this use: "
                            f"{h.get('base_jumps', '?')}"})
        for s in abs_summary:
            emit({"kind": "abs-summary", "fn": s["label"], "fn_at": f"{s['tgt']:#x}",
                  "site": f"writes {s['writes']} / readers {s['readers']}", "disp": "whole field",
                  "text": f"writers [{s['writer_fns']}]", "value": f"{s['writes']} writer(s)",
                  "value_type": f"{s['readers']} reader function(s)", "base": "-",
                  "base_kind": "-", "detail": f"write site(s): {s['sites']}; readers: "
                                              f"{s['reader_fns']}"})
        for d in sorted(targets):
            rs = [r for r in all_rows if r["disp"] == d]
            fresh = [r for r in rs if "new:" in (r["value_kind"] or "")]
            nonframe = [r for r in fresh if r["base"] not in (29, 31)]
            codec = [r for r in rs if re.search(r"codec|hifi|vivo|mbhc|wcd", r["fn"], re.I)]
            resolvable = [r for r in rs if r["value_name"]]
            emit({"kind": "slot-census", "fn": "disp %#x" % d, "fn_at": "-",
                  "site": "stores %d" % len(rs), "disp": "%#x" % d,
                  "text": "%d with a resolvable value, %d traced to an allocator result (%d not off "
                          "x29/sp)" % (len(resolvable), len(fresh), len(nonframe)),
                  "value": "%d inside codec-named functions" % len(codec),
                  "value_type": str(sorted({r["fn"] for r in codec})[:6]), "base": "-", "base_kind": "-",
                  "detail": "image-wide stores at this numeric displacement %d; sites %s"
                            % (by_disp.get(d, 0), [hex(r["site"]) for r in codec][:6])})
            owners = sorted({r["fn"] for r in nonframe})
            inchain = [r for r in nonframe if r["fn_at"] in (probe_at | {va for va, nm in TEXT
                                                                      if nm == "vivo_codec_dai_link_init"})]
            print("slot census + %#x   %d in scope, %d resolvable value(s), %d allocator-result (%d not "
                  "frame) owned by %s -- inside the probe copies or dai_link_init: %d (%s)"
                  % (d, len(rs), len(resolvable), len(fresh), len(nonframe), owners[:6], len(inchain),
                     sorted({r["fn"] for r in inchain})))
        for s in alloc_rows:
            emit({"kind": "alloc", "fn": s["fn"], "fn_at": f"{s['fn_at']:#x}", "site": f"{s['site']:#x}",
                  "disp": "-", "text": f"bl {s['callee']}", "value": f"size={s['size']}",
                  "value_type": "code", "base": "-", "base_kind": f"wflags={s['wflags']}",
                  "detail": ("size read from the mov immediately before the bl; "
                             + ("holds +0x98/+0xa0" if s["size"] >= 0xa8 else "TOO SMALL for +0xa0"))
                  if s["size_from_code"] else "SIZE NOT READABLE"})
        emit({"kind": "DENOM", "fn": f"{len(todo)} functions scanned", "fn_at": str(n_instr),
              "site": str(n_bad),
              "disp": "  ".join(f"+{d:#x}={by_disp.get(d, 0)}" for d in sorted(targets)),
              "value": f"{len(named)} named + {len(installs)} installs of {len(all_rows)} stores",
              "value_type": "count", "base": "-", "base_kind": str(dict(kinds)),
              "detail": f"allocator sites in scan {len(all_allocs)}, inside probe copies "
                        f"{len(alloc_rows)}, prologues inside other symbols' windows {n_split}"})
        with open(a.out, "w", encoding="utf-8") as fh:
            fh.write("\t".join(cols) + "\n")
            fh.write("\n".join(lines) + "\n")
        if len(widths) != 1:
            sys.exit(f"gate: {a.out} rows disagree on column count {sorted(widths)}")
        print(f"wrote {a.out} ({len(lines) + 1} lines x {next(iter(widths))} columns)")


if __name__ == "__main__":
    main()
