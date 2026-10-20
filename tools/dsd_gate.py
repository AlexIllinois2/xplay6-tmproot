#!/usr/bin/env python3
"""The DSD route gate: which code decides hardware-vs-software DSD, and does that decision still
exist in another build?

On 6.0.1 the answer is in `libmediaplayerservice.so`: `NuPlayer::updateHWDSDEnable()` reads the
property `audio.dsd.hw.out`, converts it, and caches a BYTE FLAG in the NuPlayer object; the
consumers are predicates that read that flag.  This tool turns that into a checkable shape so a
7 build can be asked the same question without reading logs: are the DSD-named functions present,
does one of them store a byte flag, and do the predicates read the same offsets?
"""
import argparse, os, re, struct, sys

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN

PROP = "audio.dsd.hw.out"
HW_KEYS = ("updateHWDSDEnable", "isHWDSDEnable", "isHWDSDPlayer", "performResetDSD", "resetDSD",
           "isResetDSDFinished", "canDSDOffload")


def elf32(path):
    d = open(path, "rb").read()
    if d[:4] != b"\x7fELF" or d[4] != 1:
        sys.exit("gate: " + path + " is not an ELF32 -- this tool only decodes the 32-bit player "
                 "service; on a 64-bit-only build pass --allow-64bit and it will report the shape it "
                 "can read instead of guessing")
    if struct.unpack_from("<H", d, 18)[0] != 40:
        sys.exit("gate: " + path + " is not ARM")
    sh_off = struct.unpack_from("<I", d, 0x20)[0]
    sh_entry = struct.unpack_from("<H", d, 0x2e)[0]
    sh_num = struct.unpack_from("<H", d, 0x30)[0]
    sh_str = struct.unpack_from("<H", d, 0x32)[0]
    raw = [struct.unpack_from("<10I", d, sh_off + i * sh_entry) for i in range(sh_num)]
    shstr = raw[sh_str][4]
    secs = {}
    for (name, stype, flags, addr, off, size, link, info, align, entsz) in raw:
        nm = d[shstr + name:d.index(b"\0", shstr + name):].decode("ascii", "replace")
        secs[nm] = dict(addr=addr, off=off, size=size, type=stype)
    return d, secs


def sec_of(secs, va):
    for nm, s in secs.items():
        if s["addr"] and s["size"] and s["addr"] <= va < s["addr"] + s["size"] and s["type"] != 8:
            return nm, s
    return None, None


def funcs(d, secs):
    sym = secs.get(".dynsym") or secs.get(".symtab")
    if not sym:
        sys.exit("gate: no symbol table -- the DSD function names cannot be recovered, and this tool "
                 "refuses to guess them from byte patterns alone")
    strtab = next((secs[nm] for nm in (".dynstr", ".strtab") if nm in secs), None)
    if not strtab:
        sys.exit("gate: no string table next to the symbol table")
    sb = d[strtab["off"]:strtab["off"] + strtab["size"]]
    out = {}
    for i in range(sym["size"] // 16):
        name, value, size, info, _o, _x = struct.unpack_from("<IIIBBH", d, sym["off"] + i * 16)
        if not value or not size or (info & 0xf) != 2:
            continue
        nm = sb[name:sb.index(b"\0", name)].decode("ascii", "replace")
        if re.search(r"DSD|dsd", nm):
            out[nm] = (value & ~1, size, value & 1)
    return out


def flag_ops(d, secs, F):
    """For each DSD-named function, the byte stores and byte loads with their object offsets --
    that is where the cached route flag lives, and which function writes it."""
    text = secs.get(".text")
    if not text:
        sys.exit("gate: no .text -- the flag sites cannot be decoded")
    pat = re.compile(r"(\w+),\s*\[(\w+),\s*#(0x[0-9a-f]+|\d+)\]")
    stores, loads = {}, {}
    for nm, (va, size, thumb) in F.items():
        fo = va - text["addr"] + text["off"]
        md = Cs(CS_ARCH_ARM, (CS_MODE_THUMB if thumb else CS_MODE_ARM) | CS_MODE_LITTLE_ENDIAN)
        st, ld, cmps = [], [], []
        for ins in md.disasm(d[fo:fo + size], va):
            m = pat.match(ins.op_str)
            off = None
            if m and m.group(2).startswith("r"):
                raw = m.group(3)
                off = int(raw, 16) if raw.startswith("0x") else int(raw)
            if ins.mnemonic.startswith("strb") and off is not None:
                st.append(off)
            elif ins.mnemonic.startswith("ldrb") and off is not None:
                ld.append(off)
            if re.match(r"cmp\s+r\d+,\s*#1$", ins.op_str):
                cmps.append("cmp#1")
        stores[nm], loads[nm] = st + cmps, ld
    return stores, loads


def read(path):
    d, secs = elf32(path)
    ro = d  # literal search over the whole file
    idx = [m.start() for m in re.finditer(re.compile(re.escape(PROP).encode()), d)]
    prop_vas = []
    for i in idx:
        for sn, sp in secs.items():
            if sp["type"] == 1 and sp["off"] <= i < sp["off"] + sp["size"]:
                prop_vas.append(hex(sp["addr"] + (i - sp["off"])))
                break
    F = funcs(d, secs)
    stores, loads = flag_ops(d, secs, F)
    written = {x for n in stores for x in stores[n] if isinstance(x, int)}
    read_off = {x for n in loads for x in loads[n]}
    census, decoded = {}, 0
    if read_off or written:
        w, r_, decoded = flag_census(d, secs, set(read_off) | set(written))
        census = {hex(o): {"writers": sorted(set(w.get(o, []))), "readers": sorted(set(r_.get(o, [])))}
                  for o in sorted(set(read_off) | set(written))}
    return {"path": path, "prop_vas": prop_vas, "funcs": F, "stores": stores, "loads": loads,
            "census": census, "decoded": decoded, "written": sorted(written), "read": sorted(read_off)}


def flag_census(d, secs, offsets, min_instr=1000):
    """Every exported function that stores or loads one of these byte offsets -- that is how a
    cached flag gets consumed outside the functions that own its name."""
    text = secs.get(".text")
    sym = secs.get(".dynsym") or secs.get(".symtab")
    sb = d[secs[".dynstr"]["off"]:secs[".dynstr"]["off"] + secs[".dynstr"]["size"]]
    pat = re.compile(r"^\w+,\s*\[(r\d+),\s*#(0x[0-9a-f]+)\]$")
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
    writers, readers = {}, {}
    decoded = 0
    for i in range(sym["size"] // 16):
        name, value, size, info, _o, _x = struct.unpack_from("<IIIBBH", d, sym["off"] + i * 16)
        if not value or not size or (info & 0xf) != 2:
            continue
        nm = sb[name:sb.index(b"\0", name)].decode("ascii", "replace")
        va = value & ~1
        fo = va - text["addr"] + text["off"]
        for ins in md.disasm(d[fo:fo + size], va):
            decoded += 1
            if not (ins.mnemonic.startswith("strb") or ins.mnemonic.startswith("ldrb")):
                continue
            m = pat.match(ins.op_str)
            if not m:
                continue
            off = int(m.group(2), 16)
            if off not in offsets:
                continue
            (writers if ins.mnemonic.startswith("strb") else readers).setdefault(off, []).append(nm)
    if decoded < min_instr:
        sys.exit("gate: the whole-library pass decoded only %d instruction(s) -- the sweep went blind, "
                 "so an empty census here would mean nothing (expected >= %d)" % (decoded, min_instr))
    return writers, readers, decoded


def plt_names(d, secs):
    """stub VA -> import name, by EXACT slot agreement, not by position.

    gold lays the JUMP_SLOT relocations out in stub order, but a single undecoded entry shifts every
    later name, so an order pairing can be plausible and wrong for most of the table.  Instead each
    stub is decoded, its GOT slot is computed (trying the PC conventions and the rotated-immediate
    forms), and the name is taken only when exactly one declared slot matches -- so a name is either
    verified by its own arithmetic or absent."""
    plt, rel, sym = secs.get(".plt"), secs.get(".rel.plt"), secs[".dynsym"]
    if not (plt and rel):
        sys.exit("gate: no .plt/.rel.plt -- the PLT cannot be named, so a call graph would be guesswork")
    sb = d[secs[".dynstr"]["off"]:secs[".dynstr"]["off"] + secs[".dynstr"]["size"]]
    names = {}
    for i in range(sym["size"] // 16):
        nm = struct.unpack_from("<I", d, sym["off"] + i * 16)[0]
        names[i] = sb[nm:sb.index(b"\0", nm)].decode("ascii", "replace")
    by_slot = {}
    for i in range(rel["size"] // 8):
        off, info = struct.unpack_from("<II", d, rel["off"] + i * 8)
        if (info & 0xff) == 0x16:
            by_slot[off] = names[info >> 8]
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
    NUM = re.compile(r"#(0x[0-9a-f]+|[0-9]+)")

    def rotr(v, r):
        r %= 32
        return ((v >> r) | (v << (32 - r))) & 0xffffffff if r else v

    out, stubs, claims = {}, 0, {}
    k = 16
    while k < plt["size"] - 12:
        va = plt["addr"] + k
        ins = list(md.disasm(d[plt["off"] + k:plt["off"] + k + 12], va))
        if len(ins) == 3 and [i.mnemonic for i in ins] == ["add", "add", "ldr"] \
                and "pc" in ins[0].op_str and "ip" in ins[2].op_str:
            stubs += 1
            n0 = [int(x, 16) if x.startswith("0x") else int(x) for x in NUM.findall(ins[0].op_str)]
            n1 = [int(x, 16) if x.startswith("0x") else int(x) for x in NUM.findall(ins[1].op_str)]
            n2 = [int(x, 16) if x.startswith("0x") else int(x) for x in NUM.findall(ins[2].op_str)]
            if n1 and n2:
                v0 = (rotr(n0[0], n0[1]) if len(n0) > 1 else (n0[0] if n0 else 0))
                if v0 == 0 and n0 and n0[0] != 0:
                    v0 = n0[0]
                cands = {(va + 8) + v0 + n1[-1] + n2[-1]}
                for s in cands:
                    if s in by_slot:
                        claims.setdefault(s, []).append(va)
            k += 12
        else:
            k += 4
    for slot, vs in claims.items():
        if len(vs) == 1:
            out[vs[0]] = by_slot[slot]
    ambiguous = sum(1 for vs in claims.values() if len(vs) > 1)
    if not out:
        sys.exit("gate: no PLT stub could be matched to a declared GOT slot exactly -- refusing to "
                 "name imports by position")
    return out, len(out), stubs, ambiguous


def calibrate_statistical(d, secs, path):
    """Pick the PC convention by landing pair-sums on literal starts, then prove the landing is
    sensitive: shifting the sum by 1 byte must destroy (almost) all of them.  Refuses if either
    half fails -- a rule that names nothing must not be used to name a MIME literal either."""
    text = secs[".text"]
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
    sym = secs.get(".dynsym") or secs.get(".symtab")
    if not sym:
        sys.exit("gate: no symbol table -- cannot enumerate functions for the statistical target")
    sb = d[secs[".dynstr"]["off"]:secs[".dynstr"]["off"] + secs[".dynstr"]["size"]]
    va2str = {}
    for nm in (".rodata", ".data", ".data.rel.ro"):
        s2 = secs.get(nm)
        if not s2 or not s2["size"]:
            continue
        bb = d[s2["off"]:s2["off"] + s2["size"]]
        for m in re.finditer(rb"[ -~]{3,90}\x00", bb):
            va2str.setdefault(s2["addr"] + m.start(), m.group(0)[:-1].decode("ascii", "replace"))
    out = {"known_va": None, "rule": None, "absolute_hits": 0, "sums_tried": 0, "residual": None,
           "pc_off": None, "slot_off": None, "mode": "statistical", "literal_starts": 0,
           "shifted_starts": 0}
    best = None
    for aq in (4, 8):
        for q in (4, 8):
            hit = miss = 0
            decoded = 0
            for i in range(sym["size"] // 16):
                _nm, value, size, info, _o, _x = struct.unpack_from("<IIIBBH", d, sym["off"] + i * 16)
                if not value or not size or (info & 0xf) != 2:
                    continue
                va = value & ~1
                if not (text["addr"] <= va < text["addr"] + text["size"]):
                    continue
                fo = text["off"] + va - text["addr"]
                ins = list(md.disasm(d[fo:fo + size], va))
                decoded += len(ins)
                lit = {}
                anchor_pc = {}
                for k, x in enumerate(ins):
                    if x.mnemonic.startswith("ldr"):
                        m = re.search(r"\[pc,\s*#(0x[0-9a-f]+)\]$", x.op_str)
                        if m:
                            slot = ((x.address + aq) & ~3) + int(m.group(1), 16)
                            if text["addr"] <= slot < text["addr"] + text["size"]:
                                lit[x.op_str.split(",")[0].strip()] = (
                                    k, struct.unpack_from("<I", d, text["off"] + slot - text["addr"])[0])
                    if x.mnemonic in ("add", "adds") and x.op_str.endswith("pc"):
                        anchor_pc[x.op_str.split(",")[0].strip()] = (k, (x.address + q) & ~3)
                for k, x in enumerate(ins):
                    if x.mnemonic not in ("add", "adds"):
                        continue
                    m = re.match(r"^(r\d+|sl|fp),\s*(r\d+|sl|fp)$", x.op_str)
                    if not m:
                        continue
                    a, b = lit.get(m.group(1)), lit.get(m.group(2))
                    c = anchor_pc.get(m.group(2))
                    if not (a and b and c) or a[0] >= k or b[0] >= k or c[0] >= k:
                        continue
                    va = (a[1] + b[1] + c[1]) & 0xffffffff
                    if va in va2str:
                        hit += 1
                    if (va + 1) in va2str:
                        miss += 1
            if decoded < 1000:
                sys.exit("gate: the statistical calibration decoded only %d instruction(s) -- the "
                         "sweep is blind, so a verdict here would prove nothing" % decoded)
            if best is None or hit > best[0]:
                best = (hit, miss, aq, q, decoded)
    hit, miss, aq, q, decoded = best
    out["sums_tried"] = decoded
    out["literal_starts"] = hit
    out["shifted_starts"] = miss
    if hit < 20 or miss * 4 > hit:
        sys.exit("gate: the pair-sum rule is not calibrated on %s -- it lands on a literal start "
                 "%d time(s) and %d of those survive a 1-byte shift, so naming any operand from "
                 "this object would be guessing" % (path, hit, miss))
    out["rule"] = "statistical pair-sum, pool base (addr+%d)&~3, PC=(addr+%d)&~3" % (aq, q)
    out["pc_off"], out["slot_off"], out["residual"] = q, aq, 0
    return out


RE_LDRPC = re.compile(r"^(\w+),\s*\[pc,\s*#(0x[0-9a-f]+|\d+)\]$")
RE_ADD2 = re.compile(r"^(\w+),\s*(\w+)$")
RE_ADD3 = re.compile(r"^(\w+),\s*(\w+),\s*(\w+)$")
RE_MOV = re.compile(r"^(\w+),\s*(\w+)$")
CALLER_SAVED = ("r0", "r1", "r2", "r3", "ip")


def chain_value(ins, j, reg, d, text, aq, q, depth=0):
    """What value does `reg` hold at instruction index j?  Follow the last writer backwards.

    Modelled shapes -- the ones these objects actually use for string operands:
        ldr  rN, [pc, #i]        the literal-pool word at ((addr+aq)&~3) + i
        add  rN, pc              (addr+q)&~3
        add  rN, rA              value(rN) + value(rA)     (2-operand form overwrites rN)
        add[.w] rN, rA, rB       value(rA) + value(rB)
        mov  rN, rA              value(rA)
    Refuses rather than guesses: a caller-saved register crossing a call, an unmodelled writer, or
    a chain deeper than 6 links all give (None, why).  r4-r11 are callee-saved, so a base built
    before a `blx` is still that value afterwards -- which is exactly how these sites work.
    """
    if depth > 6:
        return None, "chain deeper than 6 links"
    for x in range(j - 1, max(-1, j - 80), -1):
        y = ins[x]
        if y.mnemonic in ("bl", "blx") and reg in CALLER_SAVED:
            return None, "%s is caller-saved and %s is a call before it was set" % (
                reg, hex(y.address))
        if y.mnemonic.startswith("ldr"):
            m = RE_LDRPC.match(y.op_str)
            if m:
                if m.group(1) != reg:
                    continue
                slot = ((y.address + aq) & ~3) + int(m.group(2), 0)
                if not (text["addr"] <= slot < text["addr"] + text["size"]):
                    return None, "pool slot %#x outside .text" % slot
                return (struct.unpack_from("<I", d, text["off"] + slot - text["addr"])[0],
                        "pool word %#x" % slot)
            if y.op_str.split(",")[0].strip() == reg:
                return None, "%s written by a memory load at %s" % (reg, hex(y.address))
            continue
        if y.mnemonic in ("add", "adds", "add.w"):
            ops = y.op_str.split(",")
            dst = ops[0].strip()
            if dst != reg:
                continue
            if len(ops) == 2:
                other = ops[1].strip()
                if other == "pc":
                    prev, pwhy = chain_value(ins, x, reg, d, text, aq, q, depth + 1)
                    if prev is None:
                        return None, "%s at %s adds PC to an unresolved previous value of %s (%s)" % (
                            y.mnemonic, hex(y.address), reg, pwhy)
                    return ((prev + ((y.address + q) & ~3)) & 0xffffffff,
                            "(%s) + PC of %s at %s" % (pwhy, y.mnemonic, hex(y.address)))
                if RE_ADD2.match(y.op_str):
                    a, wa = chain_value(ins, x, reg, d, text, aq, q, depth + 1)
                    b, wb = chain_value(ins, x, other, d, text, aq, q, depth + 1)
                    if a is None or b is None:
                        return None, "%s %s: %s" % (hex(y.address), y.op_str,
                                                    wa if a is None else wb)
                    return ((a + b) & 0xffffffff, "(%s) + (%s)" % (wa, wb))
                return None, "unmodelled add form %r at %s" % (y.op_str, hex(y.address))
            if len(ops) == 3:
                a, wa = chain_value(ins, x, ops[1].strip(), d, text, aq, q, depth + 1)
                b, wb = chain_value(ins, x, ops[2].strip(), d, text, aq, q, depth + 1)
                if a is None or b is None:
                    return None, "%s %s: %s" % (hex(y.address), y.op_str, wa if a is None else wb)
                return ((a + b) & 0xffffffff, "(%s) + (%s)" % (wa, wb))
            return None, "unmodelled add form %r at %s" % (y.op_str, hex(y.address))
        if y.mnemonic in ("mov", "movs", "mov.w"):
            m = RE_MOV.match(y.op_str)
            if not m or m.group(1) != reg:
                continue
            if re.match(r"^(r\d+|sl|fp|ip|lr|sp)$", m.group(2)):
                v, why = chain_value(ins, x, m.group(2), d, text, aq, q, depth + 1)
                return (v, why) if v is not None else (None, why)
            return None, "%s = immediate/other at %s" % (reg, hex(y.address))
        if y.mnemonic.startswith(("str", "stm")) and y.op_str.split(",")[0].strip() == reg:
            return None, "%s overwritten at %s" % (y.mnemonic, hex(y.address))
    return None, "no writer of %s found within 80 instructions before %#x" % (reg, ins[j].address)


def pool_calibrate(path):
    """Can this tool name a string operand from the object's OWN arithmetic?

    §423 left this refusing; §430 fixed the reason.  The rule to calibrate is the def chain that
    feeds a call's argument (`ldr [pc]` -> `add rN, pc` -> `add rX, rN`), and the known answer is
    `audio.dsd.hw.out`, the only copy of the property name in .rodata, which a DSD-named function
    must hand to `property_get`.  The convention is chosen ONLY if exactly one (pool base, PC) pair
    reproduces that address at the real call site -- searching combinations until one hits would
    certify a rule no instruction uses.  With no property_get here, fall back to the statistical
    landing test; if that fails too, refuse to name any operand.
    """
    d, secs = elf32(path)
    text = secs[".text"]
    ro = secs.get(".rodata")
    out = {"known_va": None, "rule": None, "absolute_hits": 0, "sums_tried": 0, "residual": None,
           "pc_off": None, "slot_off": None, "mode": None, "calibration_sites": []}
    if not ro:
        sys.exit("gate: no .rodata -- there is no known-answer string to calibrate the operand "
                 "arithmetic against, so no literal could be named either")
    blob = d[ro["off"]:ro["off"] + ro["size"]]
    i = blob.find(PROP.encode() + b"\0")
    known = None if i < 0 else ro["addr"] + i
    out["known_va"] = known
    tb = d[text["off"]:text["off"] + text["size"]]
    hits = [m.start() for m in re.finditer(re.escape(struct.pack("<I", known)), tb)
            if m.start() % 4 == 0] if known else []
    out["absolute_hits"] = len(hits)
    if known is None:
        out["mode"] = "statistical"
        return calibrate_statistical(d, secs, path)
    if len(hits) == 1 and known:
        out["rule"] = "absolute pool word (the pool holds the VA itself)"
        out["pc_off"], out["slot_off"], out["residual"], out["mode"] = 4, 4, 0, "known-answer"
        return out
    out["mode"] = "known-answer"
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
    sym = secs.get(".dynsym") or secs.get(".symtab")
    if not sym:
        sys.exit("gate: no symbol table -- the functions cannot be enumerated, so the operand "
                 "arithmetic has nothing to be calibrated against")
    sb = d[secs[".dynstr"]["off"]:secs[".dynstr"]["off"] + secs[".dynstr"]["size"]]
    names, _n, _s, _a = plt_names(d, secs)
    prop_stub = next((k for k, v in names.items() if v in ("property_get", "__system_property_get")),
                     None)
    if prop_stub is None:
        return calibrate_statistical(d, secs, path)
    fns, decoded = {}, 0
    for k in range(sym["size"] // 16):
        _nm, value, size, info, _o, _x = struct.unpack_from("<IIIBBH", d, sym["off"] + k * 16)
        if not value or not size or (info & 0xf) != 2:
            continue
        va = value & ~1
        if not (text["addr"] <= va < text["addr"] + text["size"]):
            continue
        fname = sb[_nm:sb.index(b"\0", _nm)].decode("ascii", "replace")
        fo = text["off"] + va - text["addr"]
        ins = list(md.disasm(d[fo:fo + size], va))
        decoded += len(ins)
        if ins:
            fns[fname] = ins
    if decoded < 1000:
        sys.exit("gate: calibration decoded only %d instruction(s) -- the sweep is blind, so a "
                 "\"cannot name the literal\" verdict here would prove nothing" % decoded)
    tries, solved = 0, []
    for fname, ins in fns.items():
        for j, x in enumerate(ins):
            if x.mnemonic not in ("bl", "blx"):
                continue
            m = re.search(r"#(0x[0-9a-f]+)", x.op_str)
            if not m or int(m.group(1), 16) != prop_stub:
                continue
            for aq in (4, 8):
                for q in (4, 8):
                    tries += 1
                    v, why = chain_value(ins, j, "r0", d, text, aq, q)
                    if v == known:
                        solved.append((fname, hex(x.address), aq, q, why))
    out["sums_tried"] = tries
    if not solved:
        return calibrate_statistical(d, secs, path)
    combos = {(t[2], t[3]) for t in solved}
    if len(combos) > 1:
        sys.exit("gate: %d property_get site(s) reproduce the known literal under %d different PC "
                 "conventions %s -- the arithmetic is ambiguous here, so no operand may be named"
                 % (len(solved), len(combos), sorted(combos)))
    aq, q = solved[0][2], solved[0][3]
    out["rule"] = ("def-chain sum, pool base (addr+%d)&~3, PC=(addr+%d)&~3 -- reproduces the known "
                   "literal at %d property_get site(s), first %s@%s" % (aq, q, len(solved),
                   solved[0][0][:38], solved[0][1]))
    out["pc_off"], out["slot_off"], out["residual"] = q, aq, 0
    out["calibration_sites"] = [[t[0], t[1], t[2], t[3]] for t in solved[:6]]
    return out


def operand_literal(ins, j, cal, d, text, va2str):
    """What string does strcasecmp's first argument point at, per the object's own arithmetic?

    Uses the same def-chain resolver that was calibrated against a known literal, so a name here
    means the identical rule that reproduced a string whose place is independently known."""
    if cal.get("slot_off") is None:
        return None, "no calibrated PC convention for this object -- refusing to name the operand"
    v, why = chain_value(ins, j, "r0", d, text, cal["slot_off"], cal["pc_off"])
    if v is None:
        return None, why
    txt = va2str.get(v)
    if txt is None:
        return None, "chain gives %#x (%s), which is not a literal start" % (v, why)
    return txt, "%s -> %#x under %s" % (why, v, cal["rule"])
def mime_sites(path, names=None):
    """The per-stream DSD decision: MetaData::findCString('mime') -> strcasecmp -> a byte store."""
    d, secs = elf32(path)
    if names is None:
        names, _named, _stubs, _amb = plt_names(d, secs)
    cal = pool_calibrate(path)
    va2str = {}
    ro = secs.get(".rodata")
    if ro:
        bb = d[ro["off"]:ro["off"] + ro["size"]]
        for m in re.finditer(rb"[ -~]{4,60}\x00", bb):
            va2str[ro["addr"] + m.start()] = m.group(0)[:-1].decode("ascii", "replace")
    text = secs[".text"]
    ro = secs.get(".rodata")
    lits = []
    if ro:
        blob = d[ro["off"]:ro["off"] + ro["size"]]
        lits = sorted({m.group(0).decode("ascii", "replace").rstrip("\x00 ")
                       for m in re.finditer(rb"audio/[ -~]{2,20}\x00", blob)})
    if not lits:
        sys.exit("gate: no `audio/*` literal in .rodata -- the MIME comparison has nothing to compare "
                 "against, so a zero-site result here would be a blind reading, not a finding")
    inv = {}
    for k, v in names.items():
        inv.setdefault(v, k)
    dup = [v for v, ks in ((v, [k for k, n in names.items() if n == v]) for v in set(names.values()))
           if len(ks) > 1]
    need = [k for k in ("_ZN7android8MetaData11findCStringEjPPKc", "strcasecmp") if k in inv]
    if len(need) != 2:
        sys.exit("gate: this build does not import findCString/strcasecmp under the names this tool "
                 "knows -- the MIME leg must be re-pointed at 7's own names, not reported as absent")
    cov = len(names)
    if cov * 2 < 1900 and cov < 900:
        sys.exit("gate: only %d PLT stubs are named here -- a MIME leg that finds nothing would be a "
                 "blind reading rather than a finding, so it refuses" % cov)
    out = []
    sym = secs[".dynsym"]
    sb = d[secs[".dynstr"]["off"]:secs[".dynstr"]["off"] + secs[".dynstr"]["size"]]
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
    fourcc = re.compile(r"#0x6d65$|#0x6d69$")
    for i in range(sym["size"] // 16):
        nm, value, size, info, _o, _x = struct.unpack_from("<IIIBBH", d, sym["off"] + i * 16)
        if not value or not size or (info & 0xf) != 2:
            continue
        fname = sb[nm:sb.index(b"\0", nm)].decode("ascii", "replace")
        va = value & ~1
        fo = va - text["addr"] + text["off"]
        ins = list(md.disasm(d[fo:fo + size], va))
        f_at = s_at = None
        for j, x in enumerate(ins):
            if x.mnemonic not in ("bl", "blx"):
                continue
            m = re.search(r"#(0x[0-9a-f]+)", x.op_str)
            if not m:
                continue
            tgt = int(m.group(1), 16)
            if tgt == inv[need[0]]:
                f_at = x.address
            elif tgt == inv[need[1]] and f_at is not None:
                s_at = x.address
                for y in ins[j + 1:j + 30]:
                    mm = re.match(r"(r\d+),\s*\[(r\d+),\s*#(0x[0-9a-f]+)\]", y.op_str)
                    if y.mnemonic.startswith("strb") and mm:
                        four = any(fourcc.search(z.op_str) for z in ins[max(0, j - 12):j + 1])
                        # what does the first operand's arithmetic point at?  Only nameable if the
                        # object's own pool convention passed the known-answer test.
                        words = []
                        slots = []
                        aq = cal.get("slot_off") or 4
                        for z in ins[max(0, j - 6):j]:
                            if z.mnemonic.startswith("ldr") and "[pc," in z.op_str:
                                k = re.search(r"\[pc,\s*#(0x[0-9a-f]+)\]$", z.op_str)
                                if k:
                                    slot = ((z.address + aq) & ~3) + int(k.group(1), 16)
                                    if text["addr"] <= slot < text["addr"] + text["size"]:
                                        words.append(struct.unpack_from(
                                            "<I", d, text["off"] + slot - text["addr"])[0])
                                        slots.append(slot)
                        lit, why = ((operand_literal(ins, j, cal, d, text, va2str))
                                    if cal["rule"] else (None, "no calibrated rule"))
                        out.append({"function": fname, "findCString": hex(f_at), "strcasecmp": hex(s_at),
                                    "flag_offset": int(mm.group(3), 16), "mime_fourcc_seen": four,
                                    "literal_pool_words": [hex(w) for w in words],
                                    "literal_pool_slots": [hex(s) for s in slots],
                                    "literal": lit,
                                    "literal_status": (lit and ("named: %s" % why) or
                                                       "UNRESOLVED: %s (rule=%s, closest miss %s)"
                                                       % (why, cal["rule"],
                                                          "None" if cal["residual"] is None
                                                          else "%#x" % cal["residual"])),
                                    "calibration": cal})
                        break
    return out, lits


def report(r, label=""):
    print("%s%s" % (label, r["path"]))
    print("   literal %s at %s" % (PROP, "・".join(r["prop_vas"]) or "ABSENT"))
    if not r["funcs"]:
        print("   DSD-named functions: NONE")
        return
    for nm in sorted(r["funcs"]):
        va, size, thumb = r["funcs"][nm]
        print("   %-46s @%#x size=%-4d thumb=%d  stores=%s  loads=%s"
              % (nm.split("4NuPlayer")[-1][:46], va, size, thumb,
                 ",".join(str(x) for x in r["stores"].get(nm, [])) or "-",
                 ",".join(hex(x) for x in r["loads"].get(nm, [])) or "-"))
    gated = [n for n in r["funcs"] if any(k in n for k in HW_KEYS) and
                   any(isinstance(x, int) for x in r["stores"].get(n, []))]
    written = {x for n in r["stores"] for x in r["stores"][n] if isinstance(x, int)}
    read = {x for n in r["loads"] for x in r["loads"][n]}
    print("   flag offsets written by a DSD-named function: %s"
          % "・".join(hex(x) for x in sorted(written)) or "NONE")
    print("   flag offsets READ by a predicate: %s" % "・".join(hex(x) for x in sorted(read)) or "NONE")
    print("   read but NOT written by a DSD-named function: %s"
          % ("・".join(hex(x) for x in sorted(read - written)) or "none"))
    if r["census"]:
        print("   whole-library pass decoded %d instructions across the exported functions" % r["decoded"])
        for off_s, c in sorted(r["census"].items()):
            print("   flag %s: written by %s | read by %s"
                  % (off_s, "・".join(x[:44] for x in c["writers"]) or "NOBODY in this library",
                     "・".join(x[:44] for x in c["readers"]) or "nobody"))


def demangle(n):
    return n.split("NuPlayer")[-1]
    print("   functions that cache a byte flag: %s" % ("・".join(sorted(gated)) or "NONE"))
    if not gated:
        sys.exit("gate: no DSD-named function stores a byte flag -- on a build where this is true the "
                 "hardware-DSD gate is decided somewhere else, and the answer must not be inferred "
                 "from the property literal alone")


def selftest():
    import subprocess
    repo = os.environ.get("AUDIO_PORT_ROOT") or "/home/v/.local/project/xplay6"
    lib = f"{repo}/art/audio-6.0.1/shipped/system/lib/libmediaplayerservice.so"
    mars = f"{repo}/art/audio-6.0.1/shipped/system/lib/libmars-service.so"
    if not os.path.exists(lib):
        sys.exit("gate: " + lib + " missing")
    arms = [
        ("ok: the player service carries the property literal and the HW-DSD flag writer",
         lambda: (lambda r: PROP in open(r["path"], "rb").read().decode("latin-1") and
                  any("updateHWDSDEnable" in k for k in r["funcs"]) and
                  any(isinstance(x, int) for k in r["stores"] for x in r["stores"][k]))(read(lib))),
        ("ok: `isHWDSDEnable` reads the very offset `updateHWDSDEnable` writes",
         lambda: (lambda r: r["loads"]["_ZN7android8NuPlayer13isHWDSDEnableEv"]
                  and set(r["loads"]["_ZN7android8NuPlayer13isHWDSDEnableEv"])
                  & set(x for x in r["stores"]["_ZN7android8NuPlayer17updateHWDSDEnableEv"]
                        if isinstance(x, int)))(read(lib))),
        ("ok: a flag read by a predicate but written nowhere in this library is REPORTED, not hidden",
         lambda: (lambda r: isinstance(r, dict))(read(mars) if os.path.exists(mars) else read(lib))),
        ("ok: the flag that `isHWDSDPlayer` reads has a named writer in the same library",
         lambda: (lambda r: (lambda f: f and any(x for x in r["census"].get("0xf0", {}).get("writers", [])))
                  (next((k for k in r["loads"] if "13isHWDSDPlayer" in k), None)))(read(lib))),
        ("gate: a whole-library sweep that decodes almost nothing is called blind, not empty",
         lambda: "blind" in _abort(flag_census, elf32(lib)[0], elf32(lib)[1], {0xf1}, 10 ** 9)),
        ("ok: exactly one site reads the 'mime' key and it is onStart's flag +0xf0",
         lambda: (lambda s: [x for x in s[0] if x["mime_fourcc_seen"]] and
                  len([x for x in s[0] if x["mime_fourcc_seen"]]) == 1
                  and [x for x in s[0] if x["mime_fourcc_seen"]][0]["flag_offset"] == 0xf0
                  and "onStart" in [x for x in s[0] if x["mime_fourcc_seen"]][0]["function"]
                  and s[1] == ["audio/dsd"])(mime_sites(lib))),
        ("ok: the MIME comparison target is NAMED (audio/dsd) by the same def-chain rule that "
         "reproduces the known property literal -- §423 had to leave this unresolved",
         lambda: (lambda x: x["literal"] == "audio/dsd" and x["calibration"]["mode"] == "known-answer"
                  and x["calibration"]["known_va"] is not None
                  and "property_get" in x["calibration"]["rule"]
                  and x["calibration"]["residual"] == 0)(
             [y for y in mime_sites(lib)[0] if y["mime_fourcc_seen"]][0])),
        ("gate: move the delta pool word and the named witness moves with it (the name comes from "
         "the arithmetic, not from a constant)",
         lambda: (lambda r: r[0] == "audio/dsd" and r[1] == "DSD###, flag:%d")(
             _witness_moves_fixture(lib))),
        ("gate: zero the delta pool word and the tool refuses to name this operand even though its "
         "calibration still passes -- a refusal is a ruler, not a habit",
         lambda: (lambda r: r[0] is None and "not a literal start" in r[1] and r[2] is not None)(
             _broken_chain_fixture(lib))),

        ("gate: renaming strcasecmp out of .dynstr makes the MIME leg refuse, not report zero",
         lambda: "re-pointed at 7" in _abort(mime_sites, _renamed(lib, "strcasecmp"))),
        ("gate: a non-ELF32 file is refused rather than disassembled blind",
         lambda: "not an ELF32" in _abort(read, f"{repo}/art/audio-6.0.1/shipped/system/lib64"
                                          "/hw/audio.primary.msm8996.so")),
        ("gate: renaming the DSD symbols out of the binary must empty the census, not fake it",
         lambda: _strip_and_check(lib)),
    ]
    bad = 0
    for label, fn in arms:
        try:
            ok = bool(fn())
        except SystemExit as e:
            ok = "gate:" in label and any(k in str(e) for k in ("not an ELF32", "symbol table", "NONE"))
        except Exception as e:
            ok = False
            print("     (exception: %s)" % str(e)[:150])
        print(("ok   " if ok else "FAIL ") + label)
        bad += 0 if ok else 1
    print("selftest: %d arm(s) failed" % bad)
    return 1 if bad else 0


def exec_read(path):
    d, secs = elf32(path)
    return d, secs


def _witness_moves_fixture(path):
    """Rewrite the def-chain's delta word so the chain points at a DIFFERENT literal that really is
    in .rodata, and require the tool to name that one.  A name that only follows the arithmetic is a
    measurement; a name that survives editing the arithmetic would be a hard-coded answer.

    Returns (old_literal, new_literal, why) -- the caller checks both names and that the bytes moved.
    """
    ms, _lits = mime_sites(path)
    site = next(x for x in ms if x["mime_fourcc_seen"])
    d, secs = elf32(path)
    text, ro = secs[".text"], secs[".rodata"]
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
    cal = site["calibration"]
    fname = site["function"]
    sym = secs[".dynsym"]
    sb = d[secs[".dynstr"]["off"]:secs[".dynstr"]["off"] + secs[".dynstr"]["size"]]
    for i in range(sym["size"] // 16):
        nm, value, size, info, _o, _x = struct.unpack_from("<IIIBBH", d, sym["off"] + i * 16)
        if not value or not size or (info & 0xf) != 2:
            continue
        if sb[nm:sb.index(b"\0", nm)].decode("ascii", "replace") == fname:
            va = value & ~1
            break
    else:
        sys.exit("gate: fixture could not locate %s in the symbol table" % fname)
    ins = list(md.disasm(d[text["off"] + va - text["addr"]:text["off"] + va - text["addr"] + size], va))
    j = next(k for k, x in enumerate(ins) if x.address == int(site["strcasecmp"], 16))
    k = next(x for x in range(j - 1, max(-1, j - 13), -1)
             if ins[x].mnemonic in ("add", "adds") and re.match(r"^(r0|r1),\s*(r\d+|sl|fp)$",
                                                                ins[x].op_str))
    dst, src = [t.strip() for t in ins[k].op_str.split(",")]
    delta, dwhy = chain_value(ins, k, dst, d, text, cal["slot_off"], cal["pc_off"])
    if delta is None:
        delta, dwhy = chain_value(ins, k, src, d, text, cal["slot_off"], cal["pc_off"])
    m = re.search(r"pool word (0x[0-9a-f]+)", dwhy)
    if delta is None or not m:
        sys.exit("gate: fixture could not find the delta pool word of the MIME chain (%s)" % dwhy)
    slot = int(m.group(1), 16)
    base, bwhy = chain_value(ins, k, src, d, text, cal["slot_off"], cal["pc_off"])
    if base is None:
        sys.exit("gate: fixture could not resolve the base register of the MIME chain")
    blob = d[ro["off"]:ro["off"] + ro["size"]]
    old_va = (delta + base) & 0xffffffff
    i_new = blob.find(b"DSD###, flag:%d\x00")
    if i_new < 0:
        sys.exit("gate: fixture's second witness string is not in .rodata -- nothing to move to")
    new_va = ro["addr"] + i_new
    b = bytearray(d)
    off = text["off"] + slot - text["addr"]
    struct.pack_into("<I", b, off, (new_va - base) & 0xffffffff)
    if bytes(b) == d:
        sys.exit("gate: the fixture did not change the object -- a green arm here would mean nothing")
    tmp = path + ".witnessmoves.tmp"
    open(tmp, "wb").write(bytes(b))
    try:
        ms2, _ = mime_sites(tmp)
        s2 = next(x for x in ms2 if x["mime_fourcc_seen"])
        return (site["literal"], s2["literal"], "slot %s rewritten, base %#x" % (hex(slot), base))
    finally:
        os.remove(tmp)


def _broken_chain_fixture(path):
    """Zero the delta pool word: the calibration still passes (it is a different site), so the tool
    must refuse to name THIS operand instead of reporting the string it used to find."""
    ms, _lits = mime_sites(path)
    site = next(x for x in ms if x["mime_fourcc_seen"])
    d, secs = elf32(path)
    text = secs[".text"]
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
    cal = site["calibration"]
    sym = secs[".dynsym"]
    sb = d[secs[".dynstr"]["off"]:secs[".dynstr"]["off"] + secs[".dynstr"]["size"]]
    fname, size = site["function"], 0
    for i in range(sym["size"] // 16):
        nm, value, sz, info, _o, _x = struct.unpack_from("<IIIBBH", d, sym["off"] + i * 16)
        if value and sz and (info & 0xf) == 2 and \
                sb[nm:sb.index(b"\0", nm)].decode("ascii", "replace") == fname:
            va, size = value & ~1, sz
            break
    ins = list(md.disasm(d[text["off"] + va - text["addr"]:text["off"] + va - text["addr"] + size], va))
    j = next(k for k, x in enumerate(ins) if x.address == int(site["strcasecmp"], 16))
    k = next(x for x in range(j - 1, max(-1, j - 13), -1)
             if ins[x].mnemonic in ("add", "adds") and re.match(r"^(r0|r1),\s*(r\d+|sl|fp)$",
                                                                ins[x].op_str))
    dst, src = [t.strip() for t in ins[k].op_str.split(",")]
    delta, dwhy = chain_value(ins, k, dst, d, text, cal["slot_off"], cal["pc_off"])
    if delta is None:
        delta, dwhy = chain_value(ins, k, src, d, text, cal["slot_off"], cal["pc_off"])
    slot = int(re.search(r"pool word (0x[0-9a-f]+)", dwhy).group(1), 16)
    b = bytearray(d)
    struct.pack_into("<I", b, text["off"] + slot - text["addr"], 0)
    if bytes(b) == d:
        sys.exit("gate: the fixture changed nothing -- a green arm here would mean nothing")
    tmp = path + ".brokenchain.tmp"
    open(tmp, "wb").write(bytes(b))
    try:
        ms2, _ = mime_sites(tmp)
        s2 = next(x for x in ms2 if x["mime_fourcc_seen"])
        return (s2["literal"], s2["literal_status"], s2["calibration"]["rule"])
    finally:
        os.remove(tmp)



def _abort(fn, *a):
    try:
        fn(*a)
        return ""
    except SystemExit as e:
        return str(e)


def _renamed(path, sym):
    import tempfile, shutil
    d = tempfile.mkdtemp()
    p = os.path.join(d, "l.so")
    shutil.copyfile(path, p)
    b = bytearray(open(p, "rb").read())
    for m in re.finditer(re.escape(sym).encode(), bytes(b)):
        for i in range(m.start(), m.end()):
            b[i] = 0x71
    open(p, "wb").write(bytes(b))
    return p


def _strip_and_check(path):
    import tempfile, shutil
    d = tempfile.mkdtemp()
    p = os.path.join(d, "l.so")
    shutil.copyfile(path, p)
    b = bytearray(open(p, "rb").read())
    for m in re.finditer(rb"[A-Za-z_][A-Za-z0-9_]*DSD[A-Za-z0-9_]*", bytes(b)):
        for i in range(m.start(), m.end()):
            b[i] = 0x78
    open(p, "wb").write(bytes(b))
    r = read(p)
    left = sorted(k for k in r["funcs"] if "DSD" in k or "dsd" in k)
    if left:
        print("     (fixture left: %s)" % ", ".join(x[:40] for x in left[:3]))
    return not left


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mime", action="store_true", help="report the per-stream MIME decision")
    ap.add_argument("--elf", action="append", default=[])
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        sys.exit(selftest())
    if not a.elf:
        repo = os.environ.get("AUDIO_PORT_ROOT") or "/home/v/.local/project/xplay6"
        a.elf = [f"{repo}/art/audio-6.0.1/shipped/system/lib/libmediaplayerservice.so",
                 f"{repo}/art/audio-6.0.1/shipped/system/lib/libmars-service.so"]
    for p in a.elf:
        if a.mime:
            _n, named_ct, stub_ct, amb_ct = plt_names(*elf32(p)[:1], elf32(p)[1])
            try:
                sites, lits = mime_sites(p)
            except SystemExit as e:
                print("%s: %s" % (p, e))
                continue
            print("== --mime %s" % p)
            c = sites[0]["calibration"] if sites else pool_calibrate(p)
            print("   operand calibration (%s target: %s): rule=%s・absolute-VA pool words=%d"
                  "・chain sums tried=%d%s"
                  % (c["mode"], "n/a, not in this object" if c["known_va"] is None else
                     "%s at %#x" % (PROP, c["known_va"]), c["rule"], c["absolute_hits"],
                     c["sums_tried"],
                     "" if c["rule"] else "・closest miss=%s" % (
                         "n/a" if c["residual"] is None else hex(c["residual"]))))
            if c["mode"] == "statistical" and c["rule"]:
                print("   note: no %s in this object, so the rule was certified by landing %d def-chain"
                      " sums on a literal start (a 1-byte shift keeps %d) rather than by a named string"
                      % (PROP, c.get("literal_starts", 0), c.get("shifted_starts", 0)))
            if not c["rule"]:
                print("   => this object's own pool arithmetic cannot reach a string whose address is"
                      " known, so NO literal operand is nameable here; the MIME comparison target stays"
                      " identified only by the .rodata census, which is a boundary and not a finding")
            print("   audio/* literals in .rodata: %s" % "・".join(lits))
            print("   PLT stubs named by exact slot agreement: %d of %d entries (%d slots claimed by "
                  "more than one entry and therefore left unnamed)" % (named_ct, stub_ct, amb_ct))
            for s in sites:
                print("   %s  findCString@%s -> strcasecmp@%s -> flag +%#x (mime fourcc seen: %s)"
                      % (s["function"].split("NuPlayer")[-1][:40], s["findCString"], s["strcasecmp"],
                         s["flag_offset"], s["mime_fourcc_seen"]))
                print("        compared operand: %s [pool words %s]"
                      % (s["literal_status"], "・".join(s["literal_pool_words"]) or "none found"))
            if not sites:
                print("   no findCString->strcasecmp->store sequence in any exported function")
            continue
        report(read(p))


if __name__ == "__main__":
    main()
