#!/usr/bin/env python3
"""tools/dac_dt_params_consumer.py -- does anything read the DT vivo,params array?  (name it, or prove nobody does)

§322 proved the DAC enable path's (addr,value) pairs come from the kernel's own integration_params_normal
table, not from the device tree.  What is left is the DT array itself.  es9038_i2c_probe reads
'vivo,param-num' (two u32) and 'vivo,params' (n0*n1 u32) and stores them at data+0x60, data+0x64 and
data+0x68.  Nobody has ever been named who reads them back -- and "+0x68 is read in 8 functions" would
be a worthless answer, because the audio code has several structs and they all have a field at 0x68.

Five stages, each with a control that must be visible before any census means anything:

  A  enumerate memory operands at exactly those displacements, and say whether the BASE is the frame
     pointer (a stack slot that merely happens to be at +0x68 -- the trap that made a first draft of
     this tool report phantom readers, and the same trap that produced §233's "three readers") or an
     object register.
  B  resolve the object's identity: find the probe's escape store `str xObj, [xG, #off]` where xG is a
     materialised global, and name that address from kallsyms.
  C  walk the audio family's functions, follow the adrp/add/mov pages and the load from that global,
     and list which fields each function touches THROUGH the object register.  The DT slots count as
     read only if they appear there.
  D  the same walk over EVERY decodable text symbol in the Image (span-bounded by its successor), so
     the answer is not an artifact of the family regex.
  E  one hop further: a callee can read a field through a pointer it was handed (x0-x7 at a `bl`) and
     never touch the global -- that is the debugfs private_data shape, and the only way stage D alone
     could still miss a reader.

Controls (all abort, none are decoration): the probe's own three writes; the escape store; at least
one family function dereferencing a field of the object; the probe among the whole-Image referencers;
at least one dereferencer there; and at least one followed handoff in stage E.

usage: tools/dac_dt_params_consumer.py [--out TSV] [--fast] [--selftest]
"""
import argparse
import bisect
import collections
import os
import re
import struct
import sys

from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, Cs

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ART = os.path.join(ROOT, "art", "audio-6.0.1")
IMG = os.environ.get("DAC_IMG", os.path.join(ROOT, "fw", "Image"))
KALL = os.environ.get("DAC_KALL", os.path.join(ROOT, "art", "kallsyms_real.txt"))
TEXT_BASE = 0xFFFFFFC000080000
TEXT_END = TEXT_BASE + os.path.getsize(IMG)   # derived, never typed: a hand-set 0x1290000
                                               # silently hid the module-init functions (§323)
MASK64 = 0xFFFFFFFFFFFFFFFF
SLOTS = {0x60: "n0 (vivo,param-num[0])", 0x64: "n1 (vivo,param-num[1])", 0x68: "buffer (vivo,params)"}
FAMILY = re.compile(r"^(es9028_|es9038_|vivo_codec|vivo_hifi|hifi_|vivo_digital|vivo_spk|dsd)")
PROBE = "es9038_i2c_probe"
ALIAS = {"fp": 29, "lr": 30, "sp": 31}
FRAME_REGS = {29, 31}
BLOB = open(IMG, "rb").read()   # DAC_IMG / DAC_KALL point both at 7's Image and its kallsyms


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


def fn_span(va):
    i = bisect.bisect_right(SA, va)
    return SA[i] if i < len(SA) else va + 0x4000


def decode(va, end):
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    out, bad, a = [], 0, va
    while a < end:
        w = BLOB[a - TEXT_BASE: a - TEXT_BASE + 4]
        if len(w) < 4:
            break
        if struct.unpack("<I", w)[0] == 0:
            bad += 1
            a += 4
            continue
        x = next(md.disasm(w, a), None)
        if x is None:
            bad += 1
        else:
            out.append(x)
        a += 4
    return out, bad


def rnum(md, reg):
    """capstone prints x29/x30 as fp/lr; without that alias every frame-pointer operand reads as None"""
    n = md.reg_name(reg) or ""
    if n in ALIAS:
        return ALIAS[n]
    m = re.fullmatch(r"[wx](\d+)", n)
    return int(m.group(1)) if m else None


def mem_operand(x):
    for o in x.operands:
        if o.type == 3:
            return o
    return None


def family_symbols(family):
    """text symbols of the driver family that the captured Image can actually show.  BSS symbols live
    past the file end and have no bytes to decode -- say so instead of pretending they were scanned"""
    out, past = [], []
    for a, n in SS:
        if not family.match(n):
            continue
        if a >= TEXT_END:
            past.append(n)
        elif TEXT_BASE <= a:
            out.append((a, n))
    if past:
        print(f"   NOTE {len(past)} family symbols lie past the Image end (BSS/bss-zero data, nothing "
              f"to decode): {sorted(set(past))[:6]}")
    return out


OPS_LIKE = (0x8, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38, 0x40, 0x48, 0x50, 0x58, 0x60, 0x68, 0x70, 0x78, 0x80,
           0x88, 0x90, 0x98)


def call_after(ins, idx, dreg):
    """is the loaded value used as a function table (ldr x?,[d,#slot] ; blr x?)?  that is how a
    '+0x60' belonging to some OTHER struct announces itself"""
    for y in ins[idx + 1:idx + 12]:
        o = mem_operand(y)
        if y.mnemonic == "blr" and o is None:
            continue
        if y.mnemonic in ("ldr", "ldrb") and o is not None and rnum(_MD, o.mem.base) == dreg \
                and o.mem.disp in OPS_LIKE:
            for z in ins[ins.index(y):ins.index(y) + 4]:
                if z.mnemonic == "blr":
                    return o.mem.disp
    return None


def census(items):
    """stage A: every access at the DT displacements, with the base classified.
    Returns (rows, instructions_decoded) -- the denominator travels with the result on purpose."""
    rows, total = [], 0
    for va, nm in items:
        ins, _bad = decode(va, fn_span(va))
        total += len(ins)
        per = collections.defaultdict(set)
        for x in ins:
            o = mem_operand(x)
            if o is None or o.mem.disp not in SLOTS:
                continue
            b = rnum(_MD, o.mem.base)
            if b is None:
                continue
            per[b].add(o.mem.disp)
            d = rnum(_MD, x.operands[0].reg) if x.operands and x.operands[0].type == 1 else None
            rows.append({"fn": nm, "va": x.address, "slot": o.mem.disp,
                         "base": b, "kind": "frame" if b in FRAME_REGS else "object",
                         "dir": "write" if x.mnemonic.startswith("st") else "read",
                         "text": f"{x.mnemonic} {x.op_str}",
                         "deref": call_after(ins, ins.index(x), d) if d is not None else None})
    for r in rows:
        r["multi"] = len(per_of(rows, r["fn"], r["base"])) >= 2
    return rows, total


def per_of(rows, fn, base):
    return {r["slot"] for r in rows if r["fn"] == fn and r["base"] == base}


def escape_store(items, probe):
    """stage B: how the probe publishes its object pointer -> the object's home address"""
    for va, nm in items:
        if nm != probe:
            continue
        ins, _bad = decode(va, fn_span(va))
        pages = {}
        for x in ins:
            ops = x.operands
            if x.mnemonic == "adrp" and len(ops) == 2:
                pages[rnum(_MD, ops[0].reg)] = ops[1].imm & MASK64
            elif x.mnemonic in ("add", "mov") and len(ops) == 3 and ops[2].type == 2:
                b = rnum(_MD, ops[1].reg)
                if b in pages:
                    pages[rnum(_MD, ops[0].reg)] = pages[b] + (ops[2].imm & 0xFFF)
            elif x.mnemonic == "str":
                o = mem_operand(x)
                s = rnum(_MD, ops[0].reg) if ops and ops[0].type == 1 else None
                if o is None or s is None:
                    continue
                base = rnum(_MD, o.mem.base)
                if base in pages and pages[base] >= 0xffffffc001000000 and s in pages:
                    continue
                if base in pages and pages[base] >= 0xffffffc001000000:
                    return {"fn": nm, "va": x.address, "home": pages[base] + o.mem.disp,
                            "text": f"{x.mnemonic} {x.op_str}", "reg": s}
    return None


_MD = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
_MD.detail = True


def require_probe_writes(rows):
    pw = [r for r in rows if r["fn"] == PROBE and r["dir"] == "write" and r["kind"] == "object"]
    got = {r["slot"] for r in pw}
    if set(SLOTS) - got:
        sys.exit(f"gate: the probe's own writes at {sorted(hex(s) for s in set(SLOTS) - got)} were not "
                 f"found (got {sorted(hex(s) for s in got)}) -- the decode is not reaching that code, "
                 "so no census from it means anything")
    return pw


def require_readers_visible(walk, nitems, home):
    readers = {k: v for k, v in walk.items() if v["fields"]}
    if not readers:
        sys.exit(f"gate: no function in {nitems} symbols dereferenced the object at {home:#x} -- the "
                 "walk is blind (the probe itself must show up), so a 'no reader' answer would be an "
                 "artifact of this tool")
    return readers


def text_symbols():
    """every decodable text symbol in the captured Image, span-bounded by the NEXT one.  Stage D needs
    the whole kernel, not the driver family: §233's false 'three readers' claim was a fixed-window
    decode that ran past es9038_regdump_callback into es9038_debug_read's stack slots, so span honesty
    is part of the answer, not plumbing."""
    out = []
    for line in open(KALL, encoding="utf-8", errors="replace"):
        p = line.split()
        if len(p) >= 3 and re.fullmatch(r"[0-9a-f]{16}", p[0]) and p[1] in ("t", "T"):
            a = int(p[0], 16)
            if TEXT_BASE <= a < TEXT_END:
                out.append((a, p[2]))
    out.sort()
    return out


def walk_function(ins, home, seed=()):
    """one function: does it materialise `home`, and which fields does it touch through the object?
    Two state rules, both learned the hard way (§277/§288, and again here):
      * a register that gets *written* can no longer hold a page base -- `ldr x0,[x0,#0x10]` reuses x0,
        and if the stale page is kept the home-load branch swallows every later field access, which
        under-reports readers (the dangerous direction for an absence claim);
      * the object set only grows (`ldr xD,[xObj,#k]`, `mov xD,xObj`) -- a may-hold over-approximation.
        With 5 candidate functions in the whole Image, a false reader is cheap to refute by hand; a
        missed one is not.
    `seed` is for stage E: the callee's argument registers that the caller was holding.
    Returns (refs_home, obj, fields, handoff) where handoff lists (site, target, arg) for every
    `bl target` whose x0-x7 held the object at that point."""
    pages, obj, fields, refs_home, handoff = {}, set(seed), collections.defaultdict(list), False, []
    for x in ins:
        ops = x.operands
        mn = x.mnemonic
        dst = rnum(_MD, ops[0].reg) if ops and ops[0].type == 1 else None
        o = mem_operand(x)
        base = rnum(_MD, o.mem.base) if o is not None else None
        val = pages.get(base) if base is not None else None      # read before any invalidation
        if mn == "adrp" and len(ops) == 2 and ops[1].type == 2 and dst is not None:
            pages[dst] = ops[1].imm & MASK64
            continue
        if mn in ("add", "mov") and len(ops) == 3 and ops[2].type == 2 and dst is not None:
            b = rnum(_MD, ops[1].reg)
            if b in pages:
                pages[dst] = pages[b] + (ops[2].imm & 0xFFF)
            elif b in obj:
                obj.add(dst)
            continue
        if dst is not None and not mn.startswith(("st", "cmp", "tst")):
            pages.pop(dst, None)
        if mn == "mov" and len(ops) == 2 and ops[1].type == 1:
            s = rnum(_MD, ops[1].reg)
            if s in obj and dst is not None:
                obj.add(dst)
        if mn in ("bl", "b") and ops and ops[0].type == 2 and obj & set(range(8)):
            t = ops[0].imm & MASK64
            for k in sorted(obj & set(range(8))):
                handoff.append((x.address, t, k))
        if o is None:
            continue
        if val is not None and (val + o.mem.disp) & MASK64 == home:
            refs_home = True
            if mn.startswith("ldr") and dst is not None:
                obj.add(dst)
        elif base in obj:
            fields[o.mem.disp].append((x.address, mn, x.op_str))
            if mn.startswith("ldr") and dst is not None:
                obj.add(dst)
    return refs_home, obj, dict(fields), handoff


def field_walk(items, home):
    """stage C: which fields each family function touches THROUGH the register loaded from `home`"""
    out = {}
    for va, nm in items:
        ins, _bad = decode(va, fn_span(va))
        refs, obj, fields, _hand = walk_function(ins, home)
        out[nm] = {"fields": fields, "nobj": len(obj), "ins": len(ins), "refs_home": refs}
    return out


def wide_walk(items, home):
    """stage D + E over the whole Image.  D: functions that materialise the global slot themselves.
    E: one hop further -- a function can read a field through a pointer it was *given* (a debugfs
    i_private, a helper argument) and never touch the global, so every `bl` from a D-function that
    passed one of x0-x7 while it held the object is decoded with that argument seeded as a holder.
    Returns (refs, deref, slot, hop): hop is (caller, site, callee, callee fields, DT-slot hits,
    further handoffs the hop did not follow)."""
    idx = {}
    for k, (va, nm) in enumerate(items):
        idx[va] = (nm, items[k + 1][0] if k + 1 < len(items) else va + 4)
    refs, deref, slot, hop = [], [], [], []
    for va, nm in items:
        ins, _bad = decode(va, idx[va][1])
        r, obj, fields, hand = walk_function(ins, home)
        if not r:
            continue
        refs.append(nm)
        if fields:
            deref.append((nm, sorted(fields), len(obj), len(ins)))
        hit = {d: v for d, v in fields.items() if d in SLOTS}
        if hit:
            slot.append((nm, hit, "loads the global itself"))
        for site, t, arg in hand:
            if t not in idx or idx[t][0] == nm:
                continue
            cn, cend = idx[t]
            cins, _cb = decode(t, cend)
            _cr, _cobj, cfields, chand = walk_function(cins, home, seed={arg})
            chit = {d: v for d, v in cfields.items() if d in SLOTS}
            hop.append((nm, site, cn, sorted(cfields), sorted(chit), len(chand)))
            if chit:
                slot.append((cn, chit, f"given the object by {nm} @ {site:#x} in x{arg}"))
    return refs, deref, slot, hop


def require_hops(hop, refs):
    """stage E may only say 'nothing one hop away reads it' if it actually followed hops"""
    if not hop:
        sys.exit(f"gate: stage E found {len(refs)} functions at the object slot but followed 0 calls "
                 "with the object in x0-x7 -- the hop walk never left the caller, so its silence "
                 "proves nothing")
    return hop


def require_wide_refs(refs, deref, ntext, home):
    """the wide scan may only answer 'nobody reads it' if it can show the two things it must see:
    the probe (which stores the object into the slot) and one function that dereferences a field."""
    if PROBE not in refs:
        sys.exit(f"gate: stage D scanned {ntext} text symbols and none of them stored/loaded "
                 f"{home:#x} as {PROBE} does -- the address matching is broken, so its 'no reader' "
                 "would be blindness")
    if not deref:
        sys.exit(f"gate: stage D found {len(refs)} functions at the object slot but none dereferences "
                 "a field through the loaded pointer -- the walk cannot follow the object, so no "
                 "absence claim is admissible")
    return refs, deref


def wide_selftest(refs, deref, ntext, home, hop):
    bad = []
    try:
        require_wide_refs([r for r in refs if r != PROBE], deref, ntext, home)
    except SystemExit as e:
        print(f"selftest: dropping the probe from stage D aborts -> {str(e)[:100]}")
    else:
        bad.append("wide-probe control")
    try:
        require_wide_refs(refs, [], ntext, home)
    except SystemExit as e:
        print(f"selftest: blinding stage D's field walk aborts -> {str(e)[:100]}")
    else:
        bad.append("wide-deref control")
    try:
        require_hops([], refs)
    except SystemExit as e:
        print(f"selftest: a stage E that followed no hops aborts -> {str(e)[:100]}")
    else:
        bad.append("wide-hop control")
    if bad:
        sys.exit(f"gate: --selftest: {bad} never fired -- stage D would be published on a blind scan")
    print("selftest: all three stage D/E controls fire")


def jsonish(d):
    return "; ".join(f"{k}:{sorted(v)}" for k, v in sorted(d.items()))


def selftest(rows, walk, home, nitems):
    """each control must be able to refuse: strip the probe's object writes, then strip every field
    access.  A control that cannot fail is not a control."""
    bad = []
    no_write = [r for r in rows if not (r["fn"] == PROBE and r["dir"] == "write")]
    try:
        require_probe_writes(no_write)
    except SystemExit as e:
        print(f"selftest: hiding the probe's writes aborts -> {str(e)[:110]}")
    else:
        bad.append("probe-write control")
    blind = {k: dict(v, fields={}) for k, v in walk.items()}
    try:
        require_readers_visible(blind, nitems, home)
    except SystemExit as e:
        print(f"selftest: an empty field walk aborts -> {str(e)[:110]}")
    else:
        bad.append("reader-visibility control")
    if bad:
        sys.exit(f"gate: --selftest: {bad} never fired -- the census would be published on a blind scan")
    print("selftest: both controls fire")


def repro233():
    """§233 claimed debug_open / debug_write / regdump_callback read the DT slots.  Re-run that exact
    reading -- ksdis.py decodes a FIXED instruction count from the symbol start -- and show who really
    owns each hit.  Kept executable because a published retraction must be re-checkable, not folklore."""
    tsyms = text_symbols()
    idx = {va: (nm, tsyms[k + 1][0] if k + 1 < len(tsyms) else va + 4)
           for k, (va, nm) in enumerate(tsyms)}
    byname = {}
    for va, (nm, _e) in idx.items():
        byname.setdefault(nm, va)
    import bisect
    addrs = sorted(idxs for idxs in idx)
    for nm in ("es9038_debug_open", "es9038_debug_write", "es9038_regdump_callback"):
        if nm not in byname:
            print(f"   {nm}: not a text symbol in this Image")
            continue
        start = byname[nm]
        end = idx[start][1]
        ins, _bad = decode(start, min(start + 120 * 4, TEXT_END))   # the ksdis window, spill included
        hits = []
        for x in ins:
            o = mem_operand(x)
            if o is None or o.mem.disp not in SLOTS:
                continue
            i = bisect.bisect_right(addrs, x.address) - 1
            hits.append((x.address, x.mnemonic, x.op_str, idx[addrs[i]][0],
                         rnum(_MD, o.mem.base)))
        print(f"   {nm:24} true span {(end - start) // 4:3} ins, ksdis window 120 -> "
              f"decoded {len(ins):3}; DT-slot-shaped lines: {len(hits)}")
        for addr, mn, txt, own, base in hits:
            print(f"      {addr:#x} {mn:5} {txt:26} owner={own:24} base=x{base} "
                  f"{'(fp stack slot, past the cited function)' if own != nm or base in FRAME_REGS else ''}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out")
    ap.add_argument("--fast", action="store_true",
                    help="skip stage D (the whole-Image scan, ~2 min) -- the answer is then only "
                         "'no reader in this family', which is what §323 first published")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--repro-233", action="store_true",
                    help="print the fixed-window artifact that produced §233's false 'three readers', "
                         "then exit (seconds, no census)")
    a = ap.parse_args()
    if a.repro_233:
        repro233()
        return
    items = family_symbols(FAMILY)
    if not items:
        sys.exit(f"gate: no symbols matched {FAMILY.pattern} in {KALL} -- the scan had nothing to "
                 "look at, so 'nobody reads it' would mean nothing")
    rows, total = census(items)
    require_probe_writes(rows)
    es = escape_store(items, PROBE)
    if es is None:
        sys.exit(f"gate: {PROBE} never published its object through a global -- without the object's "
                 "identity, the question 'does anything read the DT array' cannot be answered, only "
                 "guessed at by offset")
    home = es["home"]
    walk = field_walk(items, home)
    readers = require_readers_visible(walk, len(items), home)
    dt_readers = {k: sorted(hex(d) for d in v["fields"] if d in SLOTS)
                  for k, v in readers.items() if any(d in SLOTS for d in v["fields"])}
    frame_only = [r for r in rows if r["kind"] == "frame"]
    obj_rows = [r for r in rows if r["kind"] == "object"]
    wide = None
    if not a.fast:
        tsyms = text_symbols()
        if len(tsyms) < 1000:
            sys.exit(f"gate: stage D found only {len(tsyms)} text symbols in {KALL} -- a whole-kernel "
                     "absence claim needs the real denominator")
        refs, deref, slot, hop = wide_walk(tsyms, home)
        require_wide_refs(refs, deref, len(tsyms), home)
        require_hops(hop, refs)
        wide = (tsyms, refs, deref, slot, hop)
    if a.selftest:
        selftest(rows, walk, home, len(items))
        if wide:
            wide_selftest(wide[1], wide[2], len(wide[0]), home, wide[4])
    print(f"family          {len(items)} symbols, {total} instructions decoded")
    print(f"stage A         {len(rows)} accesses at {sorted(hex(s) for s in SLOTS)}; "
          f"{len(frame_only)} of them are STACK slots reached through fp (not the object at all), "
          f"{len(obj_rows)} through a pointer register:")
    for r in sorted(obj_rows, key=lambda x: (x["fn"], x["va"])):
        print(f"                   {r['fn']:32} +0x{r['slot']:02x} {r['dir']:5} {r['text']} "
              f"@ {r['va']:#x}")
    print(f"stage B         probe publishes its object via {es['text']} @ {es['va']:#x} -> "
          f"home {home:#x} = {NAME.get(home, 'unresolved')}")
    print("stage C         functions that dereference the object: " +
          (", ".join(f"{k}{{{','.join(sorted(hex(d) for d in v['fields']))}}}"
                     for k, v in sorted(readers.items())) or "none"))
    tbl = [r for r in obj_rows if r.get("deref") and r["dir"] == "read"]
    if wide:
        tsyms, refs, deref, slot, hop = wide
        print(f"stage D         {len(tsyms)} text symbols span-bounded by their successor, "
              f"{len(refs)} of them materialise {home:#x}: {sorted(set(refs))}")
        print("                fields reached through the object: " +
              ", ".join(f"{n}{{{','.join(hex(d) for d in f)}}}" for n, f, _o, _i in sorted(deref)))
        print(f"stage E         {len(hop)} calls hand the object to a callee (x0-x7); the callees' "
              "fields seen through it:")
        for cn, site, name, cf, chit, deeper in sorted(hop, key=lambda h: (h[0], h[2])):
            print(f"                   {cn:24} -> {name:32} fields "
                  f"{[hex(d) for d in cf] or 'none'}  DT slots {[hex(d) for d in chit] or 'none'}  "
                  f"passes it on {deeper} more time(s)")
        unfollowed = sum(h[5] for h in hop)
        print("                DT slots read through the object, whole Image + 1 hop: " +
              (jsonish({n: sorted(hex(d) for d in h) for n, h, _v in slot}) or "NONE"))
        answer = ("NONE anywhere in the Image -- " if not slot else
                  f"{jsonish({n: sorted(hex(d) for d in h) for n, h, _v in slot})} -- ")
        answer += ("the object is read only for its power state (+0x10); the count/array the probe "
                   f"stored at +0x60/+0x64/+0x68 is never read back (probe-time debug print only). "
                   f"{unfollowed} further handoff(s) beyond the first hop were not followed.")
    else:
        answer = (jsonish(dt_readers) if dt_readers else
                  "NONE in this family -- the array is written once by the probe and never read back "
                  "(--fast: stage D not run)")
    print(f"answer          DT slots read through the object: {answer}")
    print(f"disambiguation  {len(tbl)} of those {len(obj_rows)} pointer accesses load a value that is "
          f"immediately used as a FUNCTION TABLE (ldr then blr), i.e. that +0x60/+0x68 is some other "
          "struct's ops pointer, not the DT count/array")
    if a.out:
        cols = ["stage", "fn", "va", "slot", "slot_meaning", "base_is_frame", "dir", "text"]
        widths = set()
        lines = []

        def emit(row):
            line = [str(row.get(c, "-")) for c in cols]
            widths.add(len(line))
            lines.append("\t".join(line))

        for r in sorted(rows, key=lambda x: (x["fn"], x["va"])):
            emit({"stage": "A", "fn": r["fn"], "va": f"{r['va']:#x}", "slot": f"0x{r['slot']:02x}",
                  "slot_meaning": SLOTS[r["slot"]], "base_is_frame": str(r["kind"] == "frame"),
                  "dir": r["dir"],
                  "text": r["text"] + (f"   [used as a function table via +{r['deref']:#x}]"
                                       if r.get("deref") else "")})
        emit({"stage": "B", "fn": es["fn"], "va": f"{es['va']:#x}", "slot": "-",
              "slot_meaning": f"object home {home:#x} = {NAME.get(home, 'unresolved')}",
              "base_is_frame": "False", "dir": "write", "text": es["text"]})
        for k, v in sorted(readers.items()):
            for d, hits in sorted(v["fields"].items()):
                for addr, mn, txt in hits:
                    emit({"stage": "C", "fn": k, "va": f"{addr:#x}", "slot": f"0x{d:02x}",
                          "slot_meaning": SLOTS.get(d, "other field"),
                          "base_is_frame": "False",
                          "dir": "write" if mn.startswith("st") else "read", "text": txt})
        if wide:
            tsyms, refs, deref, slot, hop = wide
            for n, f, no, ni in sorted(deref):
                emit({"stage": "D", "fn": n, "va": "-",
                      "slot": ",".join(hex(d) for d in f),
                      "slot_meaning": f"whole-Image dereferencer, {no} object regs, {ni} ins",
                      "base_is_frame": "False", "dir": "meta",
                      "text": "loads " + NAME.get(home, "?") + " then touches these fields"})
            for cn, site, name, cf, chit, deeper in sorted(hop, key=lambda h: (h[0], h[2], h[1])):
                emit({"stage": "E", "fn": name, "va": f"{site:#x}",
                      "slot": ",".join(hex(d) for d in cf) or "-",
                      "slot_meaning": (f"object handed over by {cn}; DT slots seen: "
                                       + (",".join(hex(d) for d in chit) or "none")),
                      "base_is_frame": "False", "dir": "meta",
                      "text": f"callee sees these fields through its argument, {deeper} further "
                              "handoff(s) not followed"})
            for n, h, via in sorted(slot, key=lambda s: s[0]):
                for d, hits in sorted(h.items()):
                    for addr, mn, txt in hits:
                        emit({"stage": "D/E", "fn": n, "va": f"{addr:#x}", "slot": f"0x{d:02x}",
                              "slot_meaning": SLOTS[d], "base_is_frame": "False",
                              "dir": "write" if mn.startswith("st") else "read",
                              "text": txt + f"   [{via}]"})
            emit({"stage": "DENOM", "fn": "-", "va": str(len(tsyms)), "slot": "-",
                  "slot_meaning": f"stage D: {len(refs)} functions at the object slot, "
                                  f"{len(deref)} dereference fields, {len(hop)} handoffs followed "
                                  f"one hop, {len(slot)} read a DT slot",
                  "base_is_frame": "False", "dir": "meta", "text": "-"})
        emit({"stage": "DENOM", "fn": "-", "va": str(total), "slot": "-",
              "slot_meaning": f"{len(items)} family symbols, {len(dt_readers)} DT-slot readers "
                              "through the object",
              "base_is_frame": "False", "dir": "meta", "text": "-"})
        with open(a.out, "w", encoding="utf-8") as fh:
            fh.write("\t".join(cols) + "\n")
            fh.write("\n".join(lines) + "\n")
        if len(widths) != 1:
            sys.exit(f"gate: {a.out} rows disagree on column count {sorted(widths)}")
        print(f"wrote {a.out} ({len(lines) + 1} rows x {next(iter(widths))} columns)")


if __name__ == "__main__":
    main()
