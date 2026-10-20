#!/usr/bin/env python3
"""tools/dapm_event_flags.py -- NAME the DAPM widget event_flags, with two independent readings.

The widget arrays were decoded structurally in ledger 291/294 (stride 0xF0, name +0x08, sname
+0x10, event_flags +0x78, event +0x80), but the flag numbers were left unnamed.  Two readings are
required before a number may be called a name (project rule: a single source is a hypothesis):

  reading A -- the source: fw/ksrc-audio/include/sound/soc-dapm.h #defines the bits
              (SND_SOC_DAPM_PRE_PMU 0x1 ...), and the struct declares the field's TYPE, which
              fixes the access width the compiler must use.
  reading B -- the running binary: fw/Image contains dapm_seq_check_event(), whose switch pairs
              each bit value (cmp #imm) with its own debug name string in .rodata.  This is OUR
              kernel's naming, not upstream's.

A gate on top of both: the extracted tree is only allowed to speak if its Makefile version matches
the version the device itself reported (live/kernel-version.txt), because a name from a different
kernel is not a name.

usage: tools/dapm_event_flags.py [--out TSV] [--symbol NAME] [--selftest]
"""
import argparse
import bisect
import csv
import os
import re
import struct
import sys

from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, Cs
from capstone.arm64 import ARM64_OP_IMM, ARM64_OP_MEM, ARM64_OP_REG

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IMG = os.path.join(ROOT, "fw", "Image")
KALL = os.path.join(ROOT, "art", "kallsyms_real.txt")
ART = os.path.join(ROOT, "art", "audio-6.0.1")
TEXT_BASE = 0xFFFFFFC000080000
MASK64 = 0xFFFFFFFFFFFFFFFF   # capstone hands back branch targets and adrp pages as SIGNED imm;
                              # without this mask 0xffffffc000b17948 arrives as -0x3fff4e86b8
HEADER = os.path.join(ROOT, "fw", "ksrc-audio", "include", "sound", "soc-dapm.h")
MAKEFILE = os.path.join(ROOT, "fw", "ksrc-audio", "Makefile")
UNAME = os.path.join(ART, "live", "kernel-version.txt")
WIDGETS = os.path.join(ART, "dapm-widgets.PD1610.tsv")
DEFINE = re.compile(r"^#define\s+(SND_SOC_DAPM_([A-Z_0-9]+))\s+(0x[0-9a-fA-F]+)\s*(?:/\*\s*(.*?)\s*\*/)?")
EVENT_NAME = re.compile(r"(?:PRE|POST|WILL)_(?:PMU|PMD|REG)")
MEMBER = re.compile(r"^\s*((?:const\s+)?(?:unsigned\s+)?[a-z_]+(?:\s+\*)?)\s*"
                    r"(?:\(\s*\*\s*([a-z_]+)\s*\)\s*(?:\([^;]*\))?|([a-z_]+)\s*(?:\[[^\]]*\])?"
                    r"(?:\s*:\s*\d+)?)\s*;")
ALIGN8 = 8


def syms():
    out = []
    for line in open(KALL, encoding="utf-8", errors="replace"):
        p = line.split()
        if len(p) >= 3 and re.fullmatch(r"[0-9a-f]{16}", p[0]):
            out.append((int(p[0], 16), p[2]))
    out.sort()
    return out


def sym_addr(ss, name):
    """look up by NAME (kallsyms reuses addresses for aliases, so addr->name is not a function)"""
    hits = [a for a, n in ss if n == name]
    if not hits:
        return None
    return min(hits)


def header_vocab(path):
    """(name, value, line, comment) for the '#define SND_SOC_DAPM_<X> 0xN /* ... */' event bits.
    Filtered by the event-bit NAME SHAPE, not by a loose substring: 'REG' also matches
    SND_SOC_DAPM_REGULATOR_BYPASS 0x1, a regulator widget flag that collides with PRE_PMU -- my
    first version swallowed it and the decode would have named a bit that is not an event."""
    vocab, lines = {}, {}
    for i, line in enumerate(open(path, encoding="utf-8", errors="replace").read().splitlines(), 1):
        m = DEFINE.match(line)
        if m and EVENT_NAME.fullmatch(m.group(2)):
            val = int(m.group(3), 16)
            if val & (val - 1):
                sys.exit(f"gate: {path}:{i} says {m.group(2)}={val:#x}, which is not a single bit")
            if val in vocab.values():
                sys.exit(f"gate: {path}:{i} gives {m.group(2)} the value {val:#x} already used by "
                         f"{[k for k, v in vocab.items() if v == val]} -- two flags on one bit means "
                         "no naming is possible")
            vocab[m.group(2)] = val
            lines[m.group(2)] = (i, (m.group(4) or "").strip())
    if not vocab:
        sys.exit(f"gate: no SND_SOC_DAPM_* event bits parsed out of {path} -- reading A is empty, "
                 "so no flag may be named")
    if "/* dapm event types */" not in open(path, encoding="utf-8", errors="replace").read():
        sys.exit(f"gate: {path} has no 'dapm event types' block -- the vocabulary shape changed, "
                 "so the filtered defines may not be the event bits")
    need = {"PRE_PMU": 0x1, "POST_PMU": 0x2, "PRE_PMD": 0x4, "POST_PMD": 0x8}
    for k, v in need.items():
        if vocab.get(k) != v:
            sys.exit(f"gate: {path} defines {k}={vocab.get(k)!r} not {v:#x} -- the field layout the "
                     "binary shows cannot be reconciled with this header, do not name anything")
    return vocab, lines


def struct_field(path):
    """the declared type of event_flags, and of the member that follows it -- the pair decides the
    access width AND the offset gap the binary must show"""
    inside, members = False, []
    for i, line in enumerate(open(path, encoding="utf-8", errors="replace").read().splitlines(), 1):
        if line.startswith("struct snd_soc_dapm_widget {"):
            inside = True
            continue
        if inside and line.startswith("};"):
            break
        if not inside:
            continue
        m = MEMBER.match(line)
        if not m:
            continue
        name = m.group(2) or m.group(3)
        if name:
            members.append((name, m.group(1).strip(), i, line.strip(), m.group(1)))
    hit = [k for k, mem in enumerate(members) if mem[0] == "event_flags"]
    if not hit:
        sys.exit(f"gate: no event_flags member found inside struct snd_soc_dapm_widget in {path} -- "
                 "the width cross-check would have nothing to check against")
    k = hit[0]
    if k + 1 >= len(members):
        sys.exit("gate: event_flags is the last member of the struct -- there is no handler pointer "
                 "after it to explain the +0x80 load")
    f = members[k]
    return f[1], f[2], f[3], members[k + 1][:4]


def tree_version(makefile):
    v = {}
    for line in open(makefile, encoding="utf-8", errors="replace"):
        m = re.match(r"^(VERSION|PATCHLEVEL|SUBLEVEL)\s*=\s*(\S+)", line)
        if m:
            v[m.group(1)] = m.group(2)
        if line.startswith("EXTRAVERSION"):
            v["EXTRAVERSION"] = line.split("=", 1)[1].strip()
        if len(v) == 4:
            break
    if not {"VERSION", "PATCHLEVEL", "SUBLEVEL"} <= set(v):
        sys.exit(f"gate: {makefile} does not state VERSION/PATCHLEVEL/SUBLEVEL -- the extracted "
                 "tree cannot be pinned to a kernel")
    return f"{v['VERSION']}.{v['PATCHLEVEL']}.{v['SUBLEVEL']}"


def device_version(uname_file):
    if not os.path.exists(uname_file):
        sys.exit(f"gate: {uname_file} missing -- without the device's own 'uname -r' the extracted "
                 "tree is an unsourced copy and its names prove nothing")
    txt = open(uname_file, encoding="utf-8", errors="replace").read().split("\n")[0].strip()
    if not txt:
        sys.exit(f"gate: {uname_file} is empty -- read the live version again (adb shell uname -r)")
    return txt


def arch():
    m = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    m.detail = True          # operand types/regs are unavailable unless detail is on
    return m


def binary_pairing(symbol, image=IMG):
    """walk the switch that prints the event names: (cmp #imm -> b.eq target | b.ne fallthrough)
    paired with the .rodata string each block loads.  Returns {short_name: (value, how, va)}"""
    ss = syms()
    addrs = sorted({a for a, _ in ss})
    start = sym_addr(ss, symbol)
    if start is None:
        sys.exit(f"gate: symbol {symbol} not in {KALL} -- reading B has no object to walk")
    end = addrs[bisect.bisect_right(addrs, start)]
    blob = open(image, "rb").read()
    off = start - TEXT_BASE
    code = blob[off:end - TEXT_BASE]
    ins = list(arch().disasm(code, start))
    if not ins:
        sys.exit(f"gate: {symbol} decoded to 0 instructions -- nothing can be paired")
    idx = {inx.address: i for i, inx in enumerate(ins)}
    owner = {}
    for i, inx in enumerate(ins):
        if inx.mnemonic != "cmp":
            continue
        imms = [o.imm for o in inx.operands if o.type == ARM64_OP_IMM]
        if not imms:
            continue
        for j in range(i + 1, min(i + 13, len(ins))):
            nj = ins[j]
            if nj.mnemonic in ("b.eq", "b.ne") and nj.operands and nj.operands[0].type == ARM64_OP_IMM:
                if nj.mnemonic == "b.eq":
                    t = idx.get(nj.operands[0].imm & MASK64)
                    if t is not None:
                        owner.setdefault(t, (imms[0], "cmp+b.eq"))
                else:
                    owner.setdefault(j + 1, (imms[0], "cmp+b.ne fallthrough"))
                break
            if nj.mnemonic in ("cmp", "b", "bl", "blr", "ret"):
                break
    page, out, loads = {}, {}, []
    for i, inx in enumerate(ins):
        ops = inx.operands
        if not ops:
            continue
        if inx.mnemonic == "adrp" and len(ops) == 2:
            page[ops[0].reg] = ops[1].imm & MASK64
        elif inx.mnemonic == "add" and len(ops) == 3 and ops[2].type == ARM64_OP_IMM \
                and ops[1].type == ARM64_OP_REG:
            base = page.get(ops[1].reg)
            if base is None:
                continue
            va = base + ops[2].imm
            s = cstr(blob, va - TEXT_BASE)
            if not s:
                continue
            for j in range(i, max(i - 7, -1), -1):
                if j in owner:
                    out[s] = (owner[j][0], owner[j][1], va, j, i)
                    break
        elif inx.mnemonic in ("ldrh", "ldrh", "ldr", "ldrb", "ldrw", "strh") and \
                any(o.type == ARM64_OP_MEM for o in ops):
            mem = [o for o in ops if o.type == ARM64_OP_MEM][0]
            loads.append((inx.address, inx.mnemonic, mem.mem.disp, inx.op_str))
    return out, len(ins), start, end, loads


def cstr(blob, off):
    if off < 0 or off >= len(blob):
        return None
    e = blob.find(b"\0", off)
    if e < 0 or e - off > 96:
        return None
    raw = blob[off:e]
    try:
        s = raw.decode("ascii")
    except UnicodeDecodeError:
        return None
    return s if re.fullmatch(r"[A-Za-z0-9_ ./%-]+", s) else None


def cross_check(vocab, lines, binmap, field_type, field_line, next_member, flags_off, event_off):
    """compare the two readings and return per-name rows; aborts on any disagreement"""
    width = {"unsigned short": 2, "unsigned char": 1, "unsigned int": 4, "int": 4}.get(field_type)
    if width is None:
        sys.exit(f"gate: unrecognised declared type {field_type!r} at {HEADER}:{field_line} -- "
                 "the access-width witness cannot be computed")
    nname, ntype, nline, ntext = next_member
    if nname != "event" or "(*" not in ntext:
        sys.exit(f"gate: the member after event_flags is {ntype} {nname} ({HEADER}:{nline}: "
                 f"{ntext!r}), not the event handler pointer -- the +0x78/+0x80 pairing the binary "
                 "shows would be a coincidence, not a reading")
    if (flags_off + width + (ALIGN8 - 1)) // ALIGN8 * ALIGN8 != event_off:
        sys.exit(f"gate: field offset {flags_off:#x} + width {width} cannot align to {event_off:#x} "
                 "(the offset the binary uses for the handler pointer) -- the layout story is wrong")
    rows, matched = [], []
    for name, val in sorted(vocab.items(), key=lambda kv: (kv[1], kv[0])):
        b = binmap.get(name)
        how = "header only (the running kernel never names it)"
        agree = "NO-BINARY"
        if b:
            how = b[1]
            agree = "agree" if b[0] == val else "DISAGREE"
            if b[0] != val:
                sys.exit(f"gate: the header says {name}={val:#x} but the kernel binary pairs the "
                         f"string {name!r} with {b[0]:#x} -- naming would be a guess, not a reading")
            matched.append(name)
        rows.append({"kind": "bit", "bit": name, "value": f"0x{val:x}", "header_line": lines[name][0],
                     "header_comment": lines[name][1] or "-", "binary_value": f"0x{b[0]:x}" if b else "-",
                     "binary_pairing": how, "agree": agree})
    if len(matched) < 4:
        sys.exit(f"gate: only {len(matched)} event bits were confirmed by the binary -- the four "
                 "power-transition bits are the ones the widgets actually use, so a reading that "
                 "misses them is not a witness")
    for k in ("PRE_PMU", "POST_PMU", "PRE_PMD", "POST_PMD"):
        if k not in matched:
            sys.exit(f"gate: {k} was not paired in the binary -- the decode of the widget flags "
                     "would rest on the header alone")
    return rows, matched, width


def decode_widgets(vocab, used, path=WIDGETS):
    if not os.path.exists(path):
        sys.exit(f"gate: {path} missing -- run tools/kssym_dapm.py first")
    rows = list(csv.DictReader(open(path, encoding="utf-8"), delimiter="\t"))
    if not rows:
        sys.exit(f"gate: {path} has no widget rows")
    bits = {}
    for r in rows:
        f = int(r["event_flags"], 16)
        names = [n for n, v in sorted(vocab.items(), key=lambda kv: kv[1]) if f & v]
        outside = [b for b in (1 << i for i in range(16)) if f & b and not any(v & b for v in vocab.values())]
        if outside:
            sys.exit(f"gate: widget {r['name']} carries event_flags {r['event_flags']} with bit(s) "
                     f"{[hex(b) for b in outside]} that no header definition covers -- the field is "
                     "not the thing I think it is")
        r["flags_named"] = "|".join(names) if names else ("NONE" if f == 0 else "?")
        r["bits_used"] = "|".join(names) if names else "-"
        for n in names:
            used.add(n)
    return rows


def template_combos(path, vocab):
    """which event_flags combinations the HEADER'S OWN widget templates already produce.  A combo that
    a stock template produces is something 7's driver gets for free; a combo that appears only as a
    passed-in wflags argument has to be read off 7's machine driver."""
    cur, out = None, {}
    text = open(path, encoding="utf-8", errors="replace").read().splitlines()
    for i, line in enumerate(text, 1):
        d = re.match(r"^#define\s+SND_SOC_DAPM_([A-Z_0-9]+)\(", line)
        if d:
            cur = d.group(1)
        m = re.search(r"\.event_flags\s*=\s*([^}]+?)(?:\s*\\)?\s*[},]", line)
        if not m or cur is None:
            continue
        total, ok = 0, True
        for tok in m.group(1).split("|"):
            tok = tok.strip().replace("\\", "")
            if not tok:
                continue
            short = tok.replace("SND_SOC_DAPM_", "")
            if short in vocab:
                total |= vocab[short]
            else:
                ok = False            # 'wflags' -- the caller chooses, no default
        if ok:
            out.setdefault(total, []).append(f"{cur}@{i}")
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out")
    ap.add_argument("--symbol", default="dapm_seq_check_event.isra.28")
    ap.add_argument("--flags-off", type=lambda x: int(x, 16), default=0x78)
    ap.add_argument("--event-off", type=lambda x: int(x, 16), default=0x80)
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()

    tv, dv = tree_version(MAKEFILE), device_version(UNAME)
    if not dv.startswith(tv):
        sys.exit(f"gate: the extracted tree says {tv} but the device runs {dv} -- a macro value from "
                 "another kernel is not a name for this one")
    vocab, lines = header_vocab(HEADER)
    ftype, fline, ftext, nxt = struct_field(HEADER)
    binmap, nins, s_start, s_end, loads = binary_pairing(a.symbol)
    print(f"reading A  {HEADER} -> {len(vocab)} event-bit defines; struct member declared as "
          f"{ftype} event_flags at line {fline}: {ftext}; next member line {nxt[2]}: {nxt[3]}")
    print(f"reading B  {a.symbol} @ {s_start:#x} ({nins} instrs, span {s_end - s_start:#x} B) -> "
          f"{len(binmap)} names paired: " + ", ".join(f"{k}={v[0]:#x}({v[1]})"
                                                      for k, v in sorted(binmap.items(), key=lambda kv: kv[1][0])))
    fl = [l for l in loads if l[2] == a.flags_off and l[1].startswith("ldr")]
    ev = [l for l in loads if l[2] == a.event_off and l[1] == "ldr"]
    if not fl:
        sys.exit(f"gate: {a.symbol} reads no register at +{a.flags_off:#x} -- the offset I was about "
                 "to credit to event_flags is not touched by the function that names the events")
    WID = {"ldrh": 2, "ldrb": 1, "ldr": 8}
    seen_wid = WID.get(fl[0][1])
    print(f"reading C  the same function reads the field with {fl[0][3]!r} at {fl[0][0]:#x}"
          + (f" and the handler with {ev[0][3]!r} at {ev[0][0]:#x}" if ev else " (no handler load seen)"))
    if seen_wid != 2:
        sys.exit(f"gate: the header declares {ftype} event_flags (2 bytes) but the kernel loads "
                 f"+{a.flags_off:#x} with {fl[0][1]} ({seen_wid} bytes) -- source and binary disagree "
                 "about this struct, so no bit may be named")
    rows, matched, width = cross_check(vocab, lines, binmap, ftype, fline, nxt, a.flags_off, a.event_off)
    used = set()
    widgets = decode_widgets(vocab, used)
    unbacked = [n for n in sorted(used) if n not in matched]
    if unbacked:
        sys.exit(f"gate: the widgets use {unbacked}, which the binary never names -- those rows would "
                 "be published from a single reading")
    combos = sorted({r["event_flags"] for r in widgets})
    print(f"agreement  {len(matched)}/{len(vocab)} bits confirmed by both readings "
          f"(access width {width} B from the declared type, offsets {a.flags_off:#x}/{a.event_off:#x})")
    tmpl = template_combos(HEADER, vocab)
    if not tmpl:
        sys.exit(f"gate: no widget template in {HEADER} has an evaluable .event_flags default -- the "
                 "stock-versus-driver distinction cannot be made, so do not publish combo_in_stock_template")
    stock = 0
    for r in widgets:
        v = int(r["event_flags"], 16)
        r["combo_in_stock_template"] = ("no-event" if v == 0 else
                              ",".join(tmpl[v]) if v in tmpl else "DRIVER-PASSED")
        stock += v in tmpl
    print(f"widgets    {len(widgets)} rows, flag combinations seen: {combos}; "
          f"{stock}/{len(widgets)} rows sit on a combination a stock header template already produces")
    for f in combos:
        n = [r for r in widgets if r["event_flags"] == f]
        print(f"   {f}: {len(n):2} widgets  {n[0]['flags_named']:34} in-a-stock-template: {n[0]['combo_in_stock_template']}")
    spk = [r for r in widgets if "SmartPA" in (r["name"] or "") or "Speaker" in (r["name"] or "")]
    hp = [r for r in widgets if r["name"] in ("HiFi DAC", "HiFi AMP", "HP")]
    print("listening path  " + " ; ".join(f"{r['name']}={r['event_flags']}({r['flags_named']})"
                                          for r in spk + hp))
    if a.out:
        cols = ["kind", "bit", "value", "header_line", "header_comment", "binary_value",
                "binary_pairing", "agree", "array", "entry", "name", "sname", "event_flags",
                "flags_named", "combo_in_stock_template", "event"]
        widths = set()

        def emit(fh, d):
            row = [str(d.get(c, "-")) for c in cols]
            widths.add(len(row))
            fh.write("\t".join(row) + "\n")

        with open(a.out, "w", encoding="utf-8") as fh:
            emit(fh, {c: c for c in cols})
            for r in rows:
                emit(fh, r)
            for r in widgets:
                emit(fh, {"kind": "widget", "array": r["array"], "entry": r["entry"],
                          "name": r["name"] or "-", "sname": r["sname"] or "-",
                          "event_flags": r["event_flags"], "flags_named": r["flags_named"],
                          "combo_in_stock_template": r["combo_in_stock_template"],
                          "event": r["event"] or "-"})
        if len(widths) != 1:
            sys.exit(f"gate: {a.out} rows disagree on column count {sorted(widths)}")
        print(f"wrote {a.out} (every row {next(iter(widths))} columns)")
    if a.selftest:
        # the cross-check must be able to reject: pair one name with a wrong value and require abort
        bad = dict(binmap)
        bad["PRE_PMU"] = (0x2, binmap["PRE_PMU"][1], binmap["PRE_PMU"][2], binmap["PRE_PMU"][3])
        try:
            cross_check(vocab, lines, bad, ftype, fline, nxt, a.flags_off, a.event_off)
        except SystemExit as e:
            print(f"selftest: mis-pairing PRE_PMU with 0x2 aborts -> {str(e)[:110]}")
        else:
            sys.exit("gate: --selftest: the cross-check accepted a mis-paired name, so it is inert")
        # and the widget decode must reject a bit no header defines
        try:
            decode_widgets({k: v for k, v in vocab.items() if k != "POST_PMD"}, set(), path=WIDGETS)
        except SystemExit as e:
            print(f"selftest: hiding POST_PMD from the vocabulary aborts the widget decode -> {str(e)[:110]}")
        else:
            sys.exit("gate: --selftest: removing a defined bit from the vocabulary did not change the "
                     "widget decode, so that gate never fires")
        # the name-shape filter earns its keep: the loose substring version ('REG' among others)
        # also picks up SND_SOC_DAPM_REGULATOR_BYPASS 0x1, which collides with PRE_PMU.
        global EVENT_NAME
        keep = EVENT_NAME
        EVENT_NAME = re.compile(r".*(?:PMU|PMD|REG).*")
        try:
            header_vocab(HEADER)
        except SystemExit as e:
            print(f"selftest: loosening the vocabulary filter aborts -> {str(e)[:120]}")
        else:
            EVENT_NAME = keep
            sys.exit("gate: --selftest: the loose filter passed too, so the shape filter is not what "
                     "keeps REGULATOR_BYPASS out -- this tool's vocab gate is inert")
        EVENT_NAME = keep


if __name__ == "__main__":
    main()
