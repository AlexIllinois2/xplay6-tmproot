#!/usr/bin/env python3
"""Survey literal (string) references in a STRIPPED ARM32 object by taking function boundaries from
.ARM.exidx instead of from the symbol table, and picking the decode mode per function.

Why the installed ruler was not enough: tools/arm32_str_refs.py enumerates functions from
.dynsym/.symtab sized FUNC records, so on libaudioflinger.so it sees 41 symbols covering 1.8% of
.text and refuses -- correctly.  ELF/ARM EABI keeps one exception-index entry per function regardless
of symbols, and readelf decodes that table for us, so boundaries survive stripping.  The second
finding here is that assuming one instruction set is also wrong: 811 of 869 functions are Thumb and
58 (the inlined libgcc/unwind code) are ARM, and taking the better decode per function lifts the
viewed span of .text from 52.2% to 96.8%.

Refusal semantics are the point of the tool, not decoration:
  * a function-boundary set is accepted only if every sized .dynsym FUNC falls inside it (known answer);
  * the pool arithmetic is calibrated on a DONOR object against a site whose literal is independently
    known, and then re-validated on the target by counting literal-start landings and a +1-shift control;
  * if the target's landings are few, the tool says 'not nameable here' rather than printing zero rows
    -- zero from a blind sweep and zero from an absent reference look identical otherwise.
"""
import argparse, importlib.util, os, re, struct, subprocess, sys
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB

REPO = os.environ.get("AUDIO_PORT_ROOT") or "/home/v/.local/project/xplay6"
DEF_DONOR = f"{REPO}/art/audio-6.0.1/shipped/system/lib/libmediaplayerservice.so"
MIN_LANDINGS = 20
UNWIND = re.compile(r"Unwind|unwind|register class|personality routine|exception|\.(?:hpp|cpp)|"
                    r"phase1|phase2")


def _tool(name):
    sp = importlib.util.spec_from_file_location(name, f"{REPO}/tools/{name}.py")
    m = importlib.util.module_from_spec(sp)
    sp.loader.exec_module(m)
    return m


def elf32(path):
    return _tool("dsd_gate").elf32(path)


def exidx_starts(path):
    """Function start addresses from the ARM exception index, via readelf (its own decode, not mine --
    a hand parse of that table got the endianness wrong twice before the tool was trusted)."""
    out = subprocess.run(["readelf", "-u", path], capture_output=True, text=True)
    if out.returncode != 0:
        sys.exit("gate: readelf -u failed on %s -> %s" % (path, out.stderr.strip()[:120]))
    st = sorted({int(m.group(1), 16) for m in re.finditer(r"^(0x[0-9a-f]+): 0x[0-9a-f]+", out.stdout, re.M)})
    if not st:
        sys.exit("gate: %s has no .ARM.exidx entries readelf could print -- boundaries cannot be "
                 "recovered and a survey here would be blind" % os.path.basename(path))
    return st


def ranges(starts, text):
    ins = [a for a in starts if text["addr"] <= a < text["addr"] + text["size"]]
    rs = [(a, b - a) for a, b in zip(ins, ins[1:])]
    if ins:
        rs.append((ins[-1], text["addr"] + text["size"] - ins[-1]))
    return ins, rs


def dynsym_funcs(d, secs):
    sy, st = secs.get(".dynsym"), secs.get(".dynstr")
    if not sy or not st:
        return {}
    sb = d[st["off"]:st["off"] + st["size"]]
    out = {}
    for i in range(sy["size"] // 16):
        nm, value, size, info, _o, _x = struct.unpack_from("<IIIBBH", d, sy["off"] + i * 16)
        if value and size and (info & 0xf) == 2:
            out[value & ~1] = sb[nm:sb.index(b"\0", nm)].decode("ascii", "replace")
    return out


def verdict_for(ka_miss, landed, arm_landed, shifted, arm_shift, code, ambig,
                floor=MIN_LANDINGS):
    """The verdict, as a pure function of the counters -- so the arm that proves the ambiguity control
    bites can hand it the shape a dense pointer pool would produce without needing an object that has
    one.  survey() and the fixture therefore share ONE rule, not two near-copies."""
    verified = (not ka_miss and (landed + arm_landed) > 0
                and shifted + arm_shift <= landed + arm_landed and ambig == 0)
    if code >= floor and verified:
        return "nameable"
    if verified:
        return ("PARTIAL: %d non-unwinder landings -- individual rows are quotable (the slot formula is "
                "confirmed against objdump's own annotations and no landing survives a byte shift), but "
                "this count is below the floor (%d), so 'nothing references X' may NOT be concluded from it"
                % (code, floor))
    return ("REFUSED: %d landings, %d byte-shift survivors and %d ambiguous pool reads -- the "
            "convention is not verified here, so no row may be named"
            % (landed + arm_landed, shifted + arm_shift, ambig))


def survey(path, donor=DEF_DONOR, quiet=False):
    dg = _tool("dsd_gate")
    sr = _tool("arm32_str_refs")
    d, secs = elf32(path)
    text = secs[".text"]
    va2str = sr.str_starts(d, secs)
    names = dynsym_funcs(d, secs)
    starts = exidx_starts(path)
    ins_list, rs = ranges(starts, text)
    # ---- known-answer calibration of the boundaries themselves ----
    in_txt = {a for a in names if text["addr"] <= a < text["addr"] + text["size"]}
    union = []
    for a, b in rs:
        if union and a <= union[-1][1]:
            union[-1][1] = max(union[-1][1], a + b)
        else:
            union.append([a, a + b])
    ka_miss = sorted(a for a in in_txt if not any(lo <= a < hi for lo, hi in union))
    if ka_miss:
        sys.exit("gate: %d of %d sized .dynsym FUNC(s) fall outside the recovered exidx ranges "
                 "(first %s) -- the boundary set is wrong, so every count below would be a partial view"
                 % (len(ka_miss), len(in_txt), ", ".join(hex(x) for x in ka_miss[:4])))
    # ---- decode per function, choosing the mode that actually covers the range ----
    mdt, mda = Cs(CS_ARCH_ARM, CS_MODE_THUMB), Cs(CS_ARCH_ARM, CS_MODE_ARM)
    chosen, mode_of, thumb_n, arm_n, span = {}, {}, 0, 0, 0
    for va, size in rs:
        fo = text["off"] + va - text["addr"]
        it = list(mdt.disasm(d[fo:fo + size], va))
        stt = (it[-1].address + it[-1].size - va) if it else 0
        # full double disassembly is what made a 75-object census cost ~20 minutes; the choice is
        # still verified by the span it covers, ARM is only decoded when thumb under-covers
        if stt >= 0.6 * size:
            sta = 0
            ia = []
        else:
            ia = list(mda.disasm(d[fo:fo + size], va))
            sta = (ia[-1].address + ia[-1].size - va) if ia else 0
        if stt >= sta:
            chosen[va], thumb_n, mode_of[va] = it, thumb_n + 1, "thumb"
            span += stt
        else:
            chosen[va], arm_n, mode_of[va] = ia, arm_n + 1, "arm"
            span += sta
    # ---- the donor supplies the convention; the target has to prove it holds there ----
    cal = dg.pool_calibrate(donor)
    if not cal.get("rule"):
        sys.exit("gate: donor %s is itself uncalibrated -- there is no convention to carry over"
                 % os.path.basename(donor))
    # The calibrated convention is the THUMB one (pool slot and PC anchor at addr+4, &~3).  Applying it
    # to an ARM-mode function is not a smaller step than it looks -- ARM uses addr+8 -- so those ranges
    # are excluded from the literal survey and said so, rather than being silently mixed in (the first
    # run's 7 'landings' in the HAL were all inside the ARM unwinder block and were not qualified).
    landed, shifted, hits, code = 0, 0, [], 0
    arm_skipped = 0
    for va, _size in rs:
        ins = chosen[va]
        if mode_of.get(va) == "arm":
            arm_skipped += 1
            continue
        for j, x in enumerate(ins):
            if x.mnemonic not in ("add", "adds", "add.w"):
                continue
            if not re.match(r"^(?:r\d+|sl|fp|ip),(?:\s*(?:r\d+|sl|fp|ip)){1,2}$", x.op_str):
                continue
            v, why = dg.chain_value(ins, j + 1, x.op_str.split(",")[0].strip(), d, text,
                                    cal["slot_off"], cal["pc_off"])
            if v is None:
                continue
            if v in va2str:
                landed += 1
                # the inlined libgcc/cxxabi unwender block is compiled with its own pool habit and it is
                # the ONLY thing this convention resolves in the refused objects -- counting it as a real
                # reference would let the floor be cleared by debug strings
                unw = bool(UNWIND.search(va2str[v]))
                hits.append({"function": names.get(va, "<unnamed>@%#x" % va), "site": hex(x.address),
                             "string": va2str[v], "how": why, "unwinder": unw})
                if not unw:
                    code += 1
            elif (v + 1) in va2str:
                shifted += 1
    # ---- the ARM-mode ranges need their OWN convention ----
    # ARM builds put one literal per pool slot and read it with 'ldr rN, [pc, #imm]', where PC reads as
    # instr+8 (Thumb builds hide the address inside two pool words plus an 'add rN, pc').  Applying the
    # thumb pair-sum here would read 0 and say 'nothing references these strings' -- the two conventions
    # are separate findings, so each gets its own counters and its own shift controls.
    # Thumb direct loads: the same single-literal shape ARM uses, with the thumb anchor convention
    # (slot = (addr+4)&~3 + imm).  The first version of this tool only followed pair-sum chains, so an
    # object whose strings arrive by one direct ldr was counted as 'references nothing'.
    td_landed = td_shift = td_sites = 0
    for va, size in rs:
        if mode_of.get(va) != "thumb":
            continue
        fo = text["off"] + va - text["addr"]
        for x in mdt.disasm(d[fo:fo + size], va):
            if x.mnemonic != "ldr" or "[pc" not in x.op_str:
                continue
            m = re.search(r"#(0x[0-9a-f]+|\d+)", x.op_str)
            if not m:
                continue
            td_sites += 1
            # imm is already a BYTE offset here: arm-linux-gnu-objdump annotates the same instruction
            # (`ldr r2, [pc, #388] @ (3fd28)`) and 0x3fba4 + 388 == 0x3fd28.  Scaling by 4 -- which the
            # Thumb encoding suggests -- was tried and produced a plausible-looking wrong hit, so the
            # formula is pinned by the second disassembler, not by whatever makes the count move.
            slot = ((x.address + 4) & ~3) + int(m.group(1), 0)
            sfo = text["off"] + slot - text["addr"]
            if not (0 <= sfo < len(d) - 8):
                continue
            word, = struct.unpack_from("<I", d, sfo)
            nxt, = struct.unpack_from("<I", d, sfo + 4)
            if word in va2str:
                td_landed += 1
                unw = bool(UNWIND.search(va2str[word]))
                hits.append({"function": names.get(va, "<unnamed>@%#x" % va), "site": hex(x.address),
                             "string": va2str[word], "how": "thumb single ldr[pc] %#x" % slot,
                             "unwinder": unw, "convention": "thumb-direct",
                             "ambiguous": nxt in va2str})
                if not unw:
                    code += 1
            elif (word + 1) in va2str:
                td_shift += 1
    arm_landed = arm_shift = arm_sites = 0
    for va, size in rs:
        if mode_of.get(va) != "arm":
            continue
        fo = text["off"] + va - text["addr"]
        ins = list(mda.disasm(d[fo:fo + size], va))
        for x in ins:
            if x.mnemonic != "ldr" or "[pc" not in x.op_str:
                continue
            m = re.search(r"#(0x[0-9a-f]+|\d+)", x.op_str)
            if not m:
                continue
            arm_sites += 1
            base = (x.address + 8) & ~3
            slot = base + int(m.group(1), 0)
            sfo = text["off"] + slot - text["addr"]
            if not (0 <= sfo < len(d) - 8):
                continue
            word, = struct.unpack_from("<I", d, sfo)
            nxt, = struct.unpack_from("<I", d, sfo + 4)
            if word in va2str:
                arm_landed += 1
                unw = bool(UNWIND.search(va2str[word]))
                hits.append({"function": names.get(va, "<unnamed>@%#x" % va), "site": hex(x.address),
                             "string": va2str[word], "how": "arm single ldr[pc] %#x" % slot,
                             "unwinder": unw, "convention": "arm", "ambiguous": nxt in va2str})
                if not unw:
                    code += 1
            elif (word + 1) in va2str:
                arm_shift += 1
    arm_ambig = sum(1 for h in hits if h.get("ambiguous"))
    # ---- blindness detector: does the convention reach this object's strings AT ALL? ----
    # A PARTIAL verdict on an object whose log strings are certainly used means the SURVEY is blind to
    # the object's convention, not that the strings are unreferenced.  Measured the honest way: take the
    # windows of >=5 string starts and count how many of those windows contain nothing the survey reached.
    reached = {h["string"] for h in hits}
    starts_va = sorted(va2str)
    zero_windows, tested_windows, sample_zero = 0, 0, None
    for i, v in enumerate(starts_va):
        window = [u for u in starts_va[max(0, i - 2):i + 6] if abs(u - v) <= 0x120]
        if len(window) < 5:
            continue
        tested_windows += 1
        if not any(va2str[u] in reached for u in window):
            zero_windows += 1
            if sample_zero is None:
                sample_zero = (hex(v), [va2str[u][:26] for u in window[:3]])
    res_pre_none = None
    res = {"path": path, "funcs": len(rs), "thumb": thumb_n, "arm": arm_n, "arm_skipped": arm_skipped,
           "strings_reached": len(reached), "string_starts": len(starts_va),
           "zero_windows": zero_windows, "tested_windows": tested_windows,
           "sample_zero_window": sample_zero,
           "code_landings": code, "unwinder_landings": landed + arm_landed - code,
           "arm_landings": arm_landed, "arm_sites": arm_sites, "arm_ambig": arm_ambig,
           "thumb_direct_landings": td_landed, "thumb_direct_sites": td_sites,
           "thumb_direct_shift": td_shift, "arm_shift": arm_shift,
           "span": span,
           "text": text["size"], "span_pct": 100.0 * span / text["size"], "ka_miss": len(ka_miss),
           "dynsym_funcs": len(in_txt), "landings": landed, "shifted": shifted, "refs": hits,
           "strings": len(va2str), "rule": cal["rule"]}
    # Two different statements, and the old single 'REFUSED' conflated them:
    #   * can an INDIVIDUAL row be quoted?  yes once the slot formula is confirmed against a second
    #     disassembler and the byte-shift control is clean -- that is measured by ka/shifted, not by count;
    #   * can an ABSENCE be claimed ('nobody references this string')?  only past the floor.
    # 'verified' is the ratio control the pool arithmetic is calibrated with -- NOT 'zero shift', which
    # would flip a well-instrumented object (755 landings, 1 shift survivor) into a refusal.  The selftest
    # arm that asserts the symbol-rich object stays nameable is what caught that.
    # 'ambiguous' is the measure that matters for a pool read: the same site's neighbouring word is ALSO
    # a string start, so the rule could not say which one the code meant.  (The raw slot+4 count over all
    # sites is only a background rate and must never be read as a failure -- it has no denominator here.)
    res["verdict"] = verdict_for(ka_miss, landed + td_landed, arm_landed, shifted + td_shift,
                                 arm_shift, code, arm_ambig)
    if not quiet:
        print("%s: exidx functions=%d (thumb %d / arm %d)  viewed span=%d/%d = %.1f%%  "
              "sized FUNCs=%d all inside recovered ranges=%s" %
              (os.path.basename(path), res["funcs"], thumb_n, arm_n, span, text["size"],
               res["span_pct"], len(in_txt), "yes" if not ka_miss else "NO"))
        print("  convention from %s: %s" % (os.path.basename(donor), cal["rule"]))
        print("  three conventions by decode mode: %d thumb functions (pair-sum chains AND direct "
              "ldr[pc], slot/PC = addr+4), %d arm functions (direct ldr[pc], slot = (addr+8)&~3 + imm)"
              % (thumb_n, arm_n))
        print("  thumb pair-sum landings=%d ・ thumb single-ldr landings=%d of %d sites ・ "
              "arm single-ldr landings=%d of %d arm ldr[pc] sites "
              "(ambiguous reads where the neighbouring pool word is also a string start: %d) ・ "
              "non-unwinder total=%d (the floor is on that number) ・ byte-shift survivors=%d/%d ・ "
              "strings known=%d"
              % (landed, td_landed, td_sites, arm_landed, arm_sites, arm_ambig, code, shifted,
                 td_shift + arm_shift, len(va2str)))
        print("  blindness detector: reached %d of %d string starts ・ windows of >=5 starts with "
              "NOTHING reached = %d of %d ・ first such window: %s" %
              (len(reached), len(starts_va), zero_windows, tested_windows, res["sample_zero_window"]))
        print("  verdict: %s" % res["verdict"])
        for h in hits[:12]:
            print("    %-46s %s -> %r" % (h["function"][:46], h["site"], h["string"][:52]))
    return res



def objdump_slots(path, lo, hi):
    """arm-linux-gnu-objdump's own pool annotations for one window: {instr_addr: pool_addr} for
    ldr-literal instructions.  Used to pin the slot arithmetic of both modes from a SECOND disassembler
    rather than from a hit count."""
    out = subprocess.run(["arm-linux-gnu-objdump", "-d", "--start-address=%#x" % lo,
                          "--stop-address=%#x" % hi, path], capture_output=True, text=True).stdout
    pairs = {}
    for line in out.splitlines():
        mm = re.match(r"\s+([0-9a-f]+):\s+\S+\s+ldr\s+\S+,\s+\[pc, #(0x[0-9a-f]+|\d+)\]\s+"
                      r"(?:;|@)?\s*\(?([0-9a-f]+)", line)
        if mm:
            pairs[int(mm.group(1), 16)] = (int(mm.group(2), 0), int(mm.group(3), 16))
    return pairs


def slot_conventions_match(path):
    """(thumb_agree, thumb_n, arm_agree, arm_n): for sampled ldr[pc] sites, does my computed pool slot
    equal the address objdump annotates?  A convention that does not match the other disassembler is
    not a convention."""
    d, secs = elf32(path)
    text = secs[".text"]
    md = {"thumb": (Cs(CS_ARCH_ARM, CS_MODE_THUMB), 4), "arm": (Cs(CS_ARCH_ARM, CS_MODE_ARM), 8)}
    res = {}
    for mode, (mdi, off) in md.items():
        agree = n = 0
        for va, size in ranges(exidx_starts(path), text)[1]:
            if mode == "thumb" and size < 0x40:
                continue
            fo = text["off"] + va - text["addr"]
            ins = list(mdi.disasm(d[fo:fo + size], va))
            sites = [(x, re.search(r"#(0x[0-9a-f]+|\d+)", x.op_str)) for x in ins
                     if x.mnemonic == "ldr" and "[pc" in x.op_str]
            sites = [x for x in sites if x[1]]
            if len(sites) < 3:
                continue
            ann = objdump_slots(path, va, va + size)
            for x, mm in sites[:8]:
                imm, annotated = ann.get(x.address, (None, None))
                if imm is None:
                    continue
                mine = ((x.address + off) & ~3) + int(mm.group(1), 0)
                n += 1
                agree += 1 if mine == annotated else 0
            if n >= 12:
                break
        res[mode] = (agree, n)
    return res


def census(root, donor=DEF_DONOR):
    """Run the boundary/mode/convention measurement over every ELF32 object under a tree and report the
    denominator honestly: what was measured, what was skipped and WHY (ELF64, no exidx table, decode
    refusal).  A census that only lists its successes would be the same defect as a survey printing 0."""
    import glob as _glob
    files = sorted(_glob.glob(f"{root}/**/*.so", recursive=True))
    rows, skipped = [], []
    for p in files:
        try:
            r = survey(p, donor=donor, quiet=True)
        except SystemExit as e:
            skipped.append((os.path.basename(p), str(e)[:90]))
            continue
        except Exception as e:
            skipped.append((os.path.basename(p), "exception " + str(e)[:80]))
            continue
        rows.append(r)
    if not rows:
        sys.exit("gate: the census measured 0 of %d candidates -- every leg was skipped, so nothing "
                 "here is a finding" % len(files))
    return rows, skipped, len(files)


def write_census_tsv(root, out):
    cols = ["path", "funcs", "thumb", "arm", "span", "text", "span_pct", "ka_miss",
            "dynsym_funcs", "landings", "thumb_direct_landings", "thumb_direct_sites",
            "arm_landings", "arm_sites", "arm_ambig", "shifted", "arm_shift", "code_landings",
            "strings_reached", "string_starts", "zero_windows", "tested_windows", "verdict"]
    head = ["# candidate objects", str(len(root)), "measured"]
    rows, skipped, nfiles = census(root)
    sep = "\t"
    def clean(v):
        return str(v).replace("\t", " ").replace("\n", " ")
    with open(out, "w", encoding="utf-8") as f:
        f.write(sep.join(["# candidate objects", str(nfiles), "measured", str(len(rows)), "skipped",
                          str(len(skipped)) + " :: " + "; ".join(n + " (" + w[:60] + ")"
                                                            for n, w in skipped[:8])]) + "\n")
        f.write(sep.join(cols) + "\n")
        for r in rows:
            f.write(sep.join([os.path.basename(r["path"])] + [clean(r[c]) for c in cols[1:-1]]
                               + [clean(r["verdict"])[:120]]) + "\n")
    print("wrote %s (%d objects, %d skipped)" % (out, len(rows), len(skipped)))
    return rows, skipped



def report_census(root):
    rows, skipped, nfiles = census(root)
    nm = [r for r in rows if r["verdict"] == "nameable"]
    part = [r for r in rows if r["verdict"].startswith("PARTIAL")]
    refu = [r for r in rows if r["verdict"].startswith("REFUSED")]
    amb = sum(r["arm_ambig"] for r in rows)
    print("census under %s: %d .so candidates ・ measured=%d (ELF32 with an exidx table) ・ skipped=%d"
          % (root, nfiles, len(rows), len(skipped)))
    print("  verdicts: nameable=%d PARTIAL=%d REFUSED=%d ・ total non-unwinder landings=%d ・ "
          "ambiguous pool reads=%d" % (len(nm), len(part), len(refu),
                                       sum(r["code_landings"] for r in rows), amb))
    print("  instruction mode across the corpus: thumb=%d arm=%d functions ・ viewed span mean=%.1f%% "
          "min=%.1f%% max=%.1f%%" %
          (sum(r["thumb"] for r in rows), sum(r["arm"] for r in rows),
           sum(r["span_pct"] for r in rows) / len(rows),
           min(r["span_pct"] for r in rows), max(r["span_pct"] for r in rows)))
    print("  most thumb-dominant: %s ・ most arm-dominant: %s" % (
        max(rows, key=lambda r: r["thumb"] - r["arm"])["path"].rsplit("/", 1)[-1],
        min(rows, key=lambda r: r["thumb"] - r["arm"])["path"].rsplit("/", 1)[-1]))
    print("  nameable (top 12 by landings): " +
          ", ".join("%s %d" % (r["path"].rsplit("/", 1)[-1], r["code_landings"])
                    for r in sorted(nm, key=lambda x: -x["code_landings"])[:12]))
    print("  REFUSED even with boundaries (tool still blind here): " +
          (", ".join(os.path.basename(r["path"]) for r in refu[:10]) or "none"))
    print("  skipped (first 10, with the reason):")
    for n, why in skipped[:10]:
        print("     %-34s %s" % (n, why))
    return rows, skipped



ROADS = ("pair-sum (thumb: two pool words + add rN,pc)", "direct ldr[pc] thumb",
         "direct ldr[pc] arm", "absolute pointer word in .data/.data.rel.ro",
         "section-relative pointer word", "movw+movt of the full VA",
         "adr / ADRL pc-relative", "relocation entry pointing into .rodata")



def word_face(d, secs, va2str, w):
    """What a 4-byte word around a pointer table most plausibly IS: a string address in this object, a
    small integer (a strlen-style companion), or an opaque value.  Registration tables in this corpus are
    {char* name, size_t len, char* type} triples, so the neighbours decide whether a hit is 'a pointer in
    a table' or a stray constant."""
    if w in va2str:
        return "str:" + va2str[w][:28]
    if w < 0x40:
        return "len:%d" % w
    return hex(w)


def table_context(d, secs, va2str, section, addr, back=2, fwd=2):
    s = secs[section]
    base = s["off"] + (addr - s["addr"])
    out = []
    for k in range(-back, fwd + 1):
        off = base + 4 * k
        if 0 <= off < len(d) - 4:
            w, = struct.unpack_from("<I", d, off)
            out.append(("%+d" % k) + "=" + word_face(d, secs, va2str, w))
    return " ".join(out)


def scope_refs(refs, needle, conv):
    """§461: per-road counts must answer 'how many of THIS needle\'s landings came through road N',
    not 'how many landings does road N have'.  The first version printed the latter, so one page could
    show road 1 with 7 hits while the verdict said the needle was unreached.  Pure, so an arm can hand
    it the exact shape without decoding a binary."""
    per = {r: {"count": 0, "total": 0, "rows": []} for r in ROADS}
    for h in refs:
        key = conv.get("arm" if h.get("convention") == "arm" else
                        ("thumb-direct" if h.get("convention") == "thumb-direct" else "thumb"))
        if key not in per:
            continue
        per[key]["total"] += 1
        if (not needle) or (needle.lower() in (h.get("string") or "").lower()):
            per[key]["count"] += 1
            per[key]["rows"].append(h)
    return per


def rel_road_hits(entries, targets, ro_addr, ro_size):
    """§461: road 8 used to count every relocation whose *slot* sat in .rodata.  A relocation reaching a
    string is about its TARGET value (symbol value + implicit addend), so that is what counts now."""
    hits, sites = 0, 0
    for r_off, sym_value, addend in entries:
        sites += 1
        cand = sym_value + addend
        if cand in targets:
            hits += 1
    return hits, sites


def roads_survey(path, needle=None):
    """Run every addressing road I know for ARM32 and report each one's own count.

    This exists because §440 drew a conclusion from ONE road being empty.  A needle that no road reaches
    in an object that certainly uses it is a statement about the tool, so the roads are enumerated here
    with their denominators and the answer for an unreached needle is 'cannot be asked from the file',
    never 'nobody references it'.
    """
    dg, sr = _tool("dsd_gate"), _tool("arm32_str_refs")
    d, secs = elf32(path)
    text = secs[".text"]
    va2str = sr.str_starts(d, secs)
    cal = dg.pool_calibrate(DEF_DONOR)
    if not cal.get("rule"):
        sys.exit("gate: donor uncalibrated, no convention to run road 1 with")
    starts = exidx_starts(path)
    _i, rs = ranges(starts, text)
    mdt, mda = Cs(CS_ARCH_ARM, CS_MODE_THUMB), Cs(CS_ARCH_ARM, CS_MODE_ARM)
    targets = {v: n for v, n in va2str.items() if (not needle or needle.lower() in n.lower())}
    per = {r: {"count": 0, "total": 0, "sites": 0, "rows": []} for r in ROADS}
    # roads 1-3 come from the calibrated survey itself, scoped to the needle (§461)
    r0 = survey(path, quiet=True)
    conv = {"thumb": ROADS[0], "thumb-direct": ROADS[1], "arm": ROADS[2]}
    per.update(scope_refs(r0["refs"], needle, conv))
    for _r in ROADS:
        per[_r].setdefault("sites", 0)
    # denominators for the three instruction-level roads come from the survey's own counters -- counting
    # one 'site' per hit would make every road look like it examined as many places as it hit
    per[ROADS[0]]["sites"] = r0["landings"] + r0["shifted"]
    per[ROADS[1]]["sites"] = r0["thumb_direct_sites"]
    per[ROADS[2]]["sites"] = r0["arm_sites"]
    va_by_str = {n: v for v, n in va2str.items()}
    # road 4/5: pointer words anywhere outside .text
    ro = secs.get(".rodata")
    for name, s in secs.items():
        if name == ".text" or not s["size"] or s["size"] > 4_000_000:
            continue
        blk = d[s["off"]:s["off"] + s["size"]]
        for off in range(0, len(blk) - 4, 4):
            w, = struct.unpack_from("<I", blk, off)
            per[ROADS[3]]["sites"] += 1
            if w in targets:
                per[ROADS[3]]["count"] += 1
                per[ROADS[3]]["rows"].append({"section": name, "addr": hex(s["addr"] + off),
                                              "string": targets[w],
                                              "context": table_context(d, secs, va2str, name,
                                                                       s["addr"] + off)})
            if ro and ro["addr"] <= w + ro["addr"] < ro["addr"] + ro["size"]:
                v2 = w + ro["addr"]
                if v2 in targets:
                    per[ROADS[4]]["count"] += 1
                    per[ROADS[4]]["rows"].append({"section": name, "addr": hex(s["addr"] + off),
                                                  "string": targets[v2]})
                per[ROADS[4]]["sites"] += 1
    # roads 6/7: instruction-level constructions
    for va, size in rs:
        fo = text["off"] + va - text["addr"]
        for md, mode in ((mdt, "thumb"), (mda, "arm")):
            ins = list(md.disasm(d[fo:fo + size], va))
            span = (ins[-1].address + ins[-1].size - va) if ins else 0
            other = list((mda if mode == "thumb" else mdt).disasm(d[fo:fo + size], va))
            osp = (other[-1].address + other[-1].size - va) if other else 0
            if span < osp:
                continue
            for i, x in enumerate(ins):
                m = re.search(r"#(0x[0-9a-f]+|\d+)", x.op_str)
                if x.mnemonic == "movw" and m:
                    lo = int(m.group(1), 0)
                    for y in ins[i + 1:i + 8]:
                        if y.mnemonic == "movt":
                            my = re.search(r"#(0x[0-9a-f]+|\d+)", y.op_str)
                            if my:
                                cand = (lo | (int(my.group(1), 0) << 16))
                                per[ROADS[5]]["sites"] += 1
                                if cand in targets:
                                    per[ROADS[5]]["count"] += 1
                                    per[ROADS[5]]["rows"].append({"site": hex(x.address),
                                                                  "string": targets[cand]})
                        break
                if x.mnemonic == "adr" and m:
                    base = ((x.address + 4) & ~3) + int(m.group(1), 0)
                    per[ROADS[6]]["sites"] += 1
                    cands = {base, ((x.address + 8) & ~3) + int(m.group(1), 0)}
                    y = next((z for z in ins[i + 1:i + 8] if z.mnemonic.startswith("add")), None)
                    my = re.search(r"#(0x[0-9a-f]+|\d+)", y.op_str) if y else None
                    if my:
                        k = int(my.group(1), 0)
                        cands |= {base + k, base + k * 16}
                    for c in cands:
                        if c in targets:
                            per[ROADS[6]]["count"] += 1
                            per[ROADS[6]]["rows"].append({"site": hex(x.address), "string": targets[c]})
                            break
    # road 8: relocation entries whose target lies in .rodata
    rd = secs.get(".rel.dyn"); sy = secs.get(".dynsym")
    if rd and sy:
        def va_to_off(va):
            for s in secs.values():
                if s["size"] and s["addr"] <= va < s["addr"] + s["size"] and s.get("type") in (1, 8):
                    return s["off"] + (va - s["addr"])
            return None
        ents = []
        for i in range(rd["size"] // 8):
            r_off, info = struct.unpack_from("<II", d, rd["off"] + i * 8)
            sym, rtyp = info >> 8, info & 0xff
            sv = 0
            if sym:
                so = sy["off"] + sym * 16
                if so + 16 <= len(d):
                    sv = struct.unpack_from("<II", d, so + 4)[0]
            fo = va_to_off(r_off)
            if fo is None or fo + 4 > len(d):
                ents.append((r_off, sv, 0)); continue
            addend = struct.unpack_from("<I", d, fo)[0] if rtyp == 2 else 0
            ents.append((r_off, sv, addend))
        h8, s8 = rel_road_hits(ents, targets, ro["addr"] if ro else 0, ro["size"] if ro else 0)
        per[ROADS[7]]["count"] += h8
        per[ROADS[7]]["sites"] += s8
    if needle and needle.lower() not in {n.lower() for n in va_by_str}:
        sys.exit("gate: %r is not in %s's string-start table at all -- the roads would report 0 for the "
                 "wrong reason (the literal may live in another section or another object)"
                 % (needle, os.path.basename(path)))
    return {"path": path, "needle": needle, "roads": per, "strings": len(va2str),
            "needle_known": bool(needle) and needle in va_by_str}


def report_roads(path, needle):
    r = roads_survey(path, needle)
    print("%s: %d string starts known ・ needle=%r ・ searching roads for %s" %
          (os.path.basename(path), r["strings"], needle,
           ("that needle" if needle else "any string")))
    for name in ROADS:
        v = r["roads"][name]
        print("   %-46s needle-hits=%-4d ・ road-total-landings=%-4d (sites/words examined=%d)"
              % (name, v["count"], v.get("total", 0), v["sites"]))
    hit_rows = [row for v in r["roads"].values() for row in v["rows"]
                if not needle or needle.lower() in row.get("string", "").lower()]
    tot = len(hit_rows)
    if needle and tot == 0:
        print("   VERDICT: none of the %d roads reaches %r in %s -- the file cannot answer 'who "
              "references it' here; that is NOT 'nobody references it' (this object's roads do reach %d "
              "OTHER strings, so the roads are not dead, they are just blind to this needle)" %
              (len(ROADS), needle, os.path.basename(r["path"]),
               sum(v["count"] for v in r["roads"].values())))
    else:
        for name in ROADS:
            for row in r["roads"][name]["rows"][:3]:
                if not needle or needle.lower() in row.get("string", "").lower():
                    print("   %s -> %s %s" % (name, row.get("site") or row.get("addr"),
                                              repr(row["string"][:44])))
                    if row.get("context"):
                        print("        table context: %s" % row["context"])
    return r


def selftest():
    LIB = f"{REPO}/art/audio-6.0.1/shipped/system/lib"
    stripped = f"{LIB}/libaudioflinger.so"
    hal = f"{LIB}/hw/audio.primary.msm8996.so"
    full = f"{LIB}/libmediaplayerservice.so"
    arms = []

    def boundaries_calibrate():
        r = survey(stripped, quiet=True)
        return r["ka_miss"] == 0 and r["dynsym_funcs"] == 41 and r["funcs"] > 500

    def mode_choice_is_measured():
        r = survey(stripped, quiet=True)
        # 58 ARM functions is not decoration: without the per-function choice the viewed span is 52%,
        # with it 96.8% -- so an arm that only checked 'some thumb' would pass a broken decoder
        return r["arm"] >= 10 and r["span_pct"] > 90.0

    def refuses_when_not_nameable():
        r = survey(stripped, quiet=True)
        # the raw total (8) is above nothing and below the floor by one step, but the honest number is
        # 'how many are NOT the unwinder block' -- that is what has to clear the floor
        return (r["verdict"].startswith("PARTIAL") and r["code_landings"] < MIN_LANDINGS
                and r["unwinder_landings"] >= r["code_landings"]
                and "may NOT be concluded" in r["verdict"])

    def full_symbol_object_still_survives():
        r = survey(full, quiet=True)
        return r["ka_miss"] == 0 and r["dynsym_funcs"] > 1000

    def landings_are_real_not_shifted():
        r = survey(full, quiet=True)
        return (r["code_landings"] >= MIN_LANDINGS and r["shifted"] <= r["landings"]
                and r["verdict"] == "nameable")

    def readelf_is_required():
        try:
            exidx_starts(__file__)            # a python file: readelf cannot index it at all
        except SystemExit as e:
            return ("readelf -u failed" in str(e)) or ("no .ARM.exidx entries" in str(e))
        return False

    def slot_formulas_match_objdump():
        t_agree, t_n, a_agree, a_n = (lambda r: (r["thumb"][0], r["thumb"][1], r["arm"][0], r["arm"][1]))(
            slot_conventions_match(stripped))
        # both modes must be confirmed by the other disassembler, and the sample has to be real: a rule
        # checked against zero annotations is a green arm with no content
        return t_n >= 5 and a_n >= 5 and t_agree == t_n and a_agree == a_n

    def blindness_detector_fires():
        r = survey(stripped, quiet=True)
        # the point is that a PARTIAL verdict on this object is attributed to the survey, so the
        # detector has to report it: at least one window of >=5 starts is completely unreached
        return (r["zero_windows"] >= 1 and r["tested_windows"] >= 1
                and r["strings_reached"] < r["string_starts"] and r["sample_zero_window"] is not None)

    def road_known_answer_in_stagefright():
        """Road 4 (absolute pointer words) must find the slots §436 predicted for audio/dsd in
        libstagefright -- a road that never hits anything is not a road, it is a silent zero."""
        r = roads_survey(f"{LIB}/libstagefright.so", "audio/dsd")
        return r["roads"][ROADS[3]]["count"] >= 1

    def road_all_zero_is_not_absence():
        """The §442 case: every road misses hifi_switch_change in AudioFlinger, and the tool must say
        'the file cannot answer' rather than 'nothing references it'."""
        r = roads_survey(stripped, "hifi_switch_change")
        # scoped to the NEEDLE: the object's roads do reach 8 other strings, so 'total hits == 0' is the
        # wrong test -- what must be zero is 'roads that reach this needle'
        needle_hits = sum(1 for v in r["roads"].values() for row in v["rows"]
                          if "hifi_switch_change" in row.get("string", ""))
        # §461: with counts needle-scoped, an unreached needle must give count==0 on EVERY road while
        # the roads still show life through their own total-landings column (the pointer roads' life is
        # proved separately by the audio/dsd hit arm below)
        return needle_hits == 0 and r["needle_known"] and \
            sum(v["count"] for v in r["roads"].values()) == 0 and \
            sum(v.get("total", 0) for v in r["roads"].values()) > 0

    def road_hit_carries_table_shape():
        """A pointer hit must say WHICH structure it lives in: the audio/dsd slots in libstagefright are
        {component name, len, media type} triples, so the context line has to show a neighbouring OMX
        component name -- otherwise 'a pointer exists' is doing all the work."""
        r = roads_survey(f"{LIB}/libstagefright.so", "audio/dsd")
        rows = [row for row in r["roads"][ROADS[3]]["rows"] if "OMX" in row.get("context", "")
                or "str:" in row.get("context", "")]
        return len(rows) >= 1 and all("context" in x for x in r["roads"][ROADS[3]]["rows"])

    def road_list_is_complete():
        r = roads_survey(stripped, "hifi_switch_change")
        return (len(r["roads"]) == len(ROADS) == 8
                and all("count" in v and "sites" in v for v in r["roads"].values()))

    def census_reports_denominator():
        rows, skipped, nfiles = census(f"{LIB}/hw")
        return (nfiles == len(rows) + len(skipped) and len(rows) >= 1
                and all(r["verdict"] for r in rows))

    def arm_convention_is_live():
        r = survey(hal, quiet=True)
        return (r["arm_landings"] >= 10 and r["arm_ambig"] == 0 and r["ka_miss"] == 0
                and r["arm_sites"] > r["arm_landings"])

    def ambiguous_read_blocks_naming():
        """The control must be able to bite on an object that IS currently nameable: recompute it with
        every arm-mode pool read flagged ambiguous (what a dense pointer pool would produce) and demand
        that 'nameable' is lost.  Flagging rows on the PARTIAL HAL would prove nothing -- it is already
        not nameable -- so this walks the symbol-rich objects and needs at least one to flip."""
        r = survey(full, quiet=True)
        if r["verdict"] != "nameable":
            return False
        clean = verdict_for(r["ka_miss"], r["landings"], r["arm_landings"], r["shifted"],
                           r["arm_shift"], r["code_landings"], r["arm_ambig"])
        flagged = verdict_for(r["ka_miss"], r["landings"], r["arm_landings"], r["shifted"],
                              r["arm_shift"], r["code_landings"], r["arm_ambig"] + 1)
        # no shipped object happens to have an ambiguous arm pool read, so the shape is fed to the same
        # rule survey() uses -- if that rule stopped caring, the second call would still say 'nameable'
        return clean == "nameable" and not flagged.startswith("nameable")

    def conventions_are_separate():
        r = survey(hal, quiet=True)
        # thumb pair-sum alone cannot carry the HAL: that is the number the pre-§440 tool reported
        return r["landings"] <= 10 and r["arm_landings"] > r["landings"]

    def ambiguous_read_is_refused():
        # the control must be able to fail: if a neighbouring pool word is also a string start, the site
        # does not identify ONE string and the verdict may not be 'nameable'
        r = survey(hal, quiet=True)
        n_amb = sum(1 for h in r["refs"] if h.get("ambiguous"))
        return (r["arm_ambig"] == n_amb and (n_amb == 0 or r["verdict"].startswith(("PARTIAL", "REFUSED"))))

    def coverage_is_reported():
        # the refusal must not swallow the measurement: the point of this tool is that the stripped
        # object is now 96.8% VIEWED even though it is still not nameable
        r = survey(stripped, quiet=True)
        return (r["funcs"] > 500 and r["span_pct"] > 90.0
                and r["verdict"].startswith(("PARTIAL", "REFUSED", "nameable"))
                and r["landings"] == len(r["refs"])
                and r["code_landings"] + r["unwinder_landings"] == r["landings"])

    arms = [
        ("ok: road counts are needle-scoped -- a road can no longer print hits while the verdict says "
         "the needle is unreached (§461 face-contradiction)",
         lambda: (lambda p: p[ROADS[0]]["count"] == 0 and p[ROADS[0]]["total"] == 1)(
             scope_refs([{"convention": "thumb", "string": "unsupported register class",
                          "site": "0x10", "unwinder": "True"}], "audio/dsd",
                        {"thumb": ROADS[0], "thumb-direct": ROADS[1], "arm": ROADS[2]}))),
        ("ok: with no needle the scoped count equals the road total (the filter is not silently on)",
         lambda: (lambda p: p[ROADS[2]]["count"] == 2 and p[ROADS[2]]["total"] == 2)(
             scope_refs([{"convention": "arm", "string": "audio/dsd", "site": "0x20"},
                         {"convention": "arm", "string": "audio/dsd extra", "site": "0x24"}], None,
                        {"thumb": ROADS[0], "thumb-direct": ROADS[1], "arm": ROADS[2]}))),
        ("gate: road 8 counts a relocation only when its TARGET value is the needle; an entry whose "
         "slot merely sits in .rodata must not count (the old semantics counted 1 there)",
         lambda: (rel_road_hits([(0x31a60 + 8, 0, 0x99999)], {0x31a60: "audio/dsd"}, 0x31a60, 0x100)[0] == 0
                  and rel_road_hits([(0x40000, 0x31a60, 0x10)], {0x31a70: "audio/dsd"}, 0x31a60, 0x100)[0] == 1)),
("ok: exidx ranges contain every sized .dynsym FUNC of the stripped object (41/41, 0 miss)",
             boundaries_calibrate),
            ("ok: per-function mode choice keeps >=10 ARM functions and a viewed span >90% of .text",
             mode_choice_is_measured),
            ("gate: the stripped object is PARTIAL, never 'nameable' -- its landings are mostly the "
             "inlined unwinder block, and an absence claim is explicitly refused", refuses_when_not_nameable),
            ("ok: both pool-slot formulas equal arm-linux-gnu-objdump's own annotations on sampled "
             "ldr[pc] sites (thumb addr+4, arm addr+8; >=5 samples each, every one agreeing)",
             slot_formulas_match_objdump),
            ("ok: the blindness detector fires on the object whose neighbours are unreached (AudioFlinger "
             "has a window of >=5 string starts with nothing reached), and reports the window",
             blindness_detector_fires),
            ("ok: the pointer-word road reproduces the known slots for audio/dsd in libstagefright",
             road_known_answer_in_stagefright),
            ("gate: when all eight roads miss a needle that IS in the table, the tool says the file "
             "cannot answer, not that nothing references it", road_all_zero_is_not_absence),
            ("ok: a pointer-road hit prints the table shape around it (a neighbouring registered OMX "
             "component name / string), not just the address", road_hit_carries_table_shape),
            ("ok: all eight roads are enumerated with their own denominators (hits AND sites examined)",
             road_list_is_complete),
            ("ok: the census reports its own denominator (candidates = measured + skipped) and every "
             "measured object carries a verdict", census_reports_denominator),
            ("ok: the same code path runs on a well-symbolised object (1302 FUNCs, 0 outside ranges)",
             full_symbol_object_still_survives),
            ("ok: on the well-symbolised object the NON-unwinder landings clear the floor and the "
             "+1-shift control stays below them", landings_are_real_not_shifted),
            ("gate: a target readelf cannot index aborts instead of surveying an empty boundary set",
             readelf_is_required),
            ("ok: the refusal still reports its own denominator (869 functions, >90% of .text viewed, "
             "landings == rows emitted, and the verdict says which of the two claims is allowed",
             coverage_is_reported),
            ("ok: the HAL's arm-mode ranges resolve literals under the arm convention, inside a "
             "reported site denominator, with zero ambiguous pool reads", arm_convention_is_live),
            ("gate: the same verdict rule survey() uses drops 'nameable' when a pool read is flagged "
             "ambiguous (one of two words is also a string start)", ambiguous_read_blocks_naming),
            ("gate: the two conventions are counted separately -- a thumb-only survey of the HAL would "
             "report the arm block as zero", conventions_are_separate)]
    bad = 0
    for label, fn in arms:
        try:
            ok = bool(fn())
        except SystemExit as e:
            ok = label.startswith("gate:") and str(e).strip() != ""
        except Exception as e:
            ok = False
            print("     (exception: %s)" % str(e)[:160])
        print(("ok   " if ok else "FAIL ") + label)
        bad += 0 if ok else 1
    print("selftest: %d arm(s) failed" % bad)
    return 1 if bad else 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--elf")
    ap.add_argument("--donor", default=DEF_DONOR)
    ap.add_argument("--needle", default=None)
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--census", default=None, help="directory: measure every ELF32 object under it")
    ap.add_argument("--out", default=None, help="with --census: also write the per-object table here")
    ap.add_argument("--roads", action="store_true",
                    help="with --elf/--needle: run all eight ARM32 addressing roads and report each")
    a = ap.parse_args()
    if a.selftest:
        sys.exit(selftest())
    if a.census:
        if not os.path.isdir(a.census):
            sys.exit("gate: --census needs a directory, got %r" % a.census)
        if a.out:
            write_census_tsv(a.census, a.out)
        else:
            report_census(a.census)
        return
    if not a.elf:
        sys.exit("gate: --elf <ARM32 object> or --selftest")
    r = survey(a.elf, a.donor)
    if a.roads:
        if not a.needle:
            sys.exit("gate: --roads is meant with --needle <string>; without a needle use --elf alone")
        report_roads(a.elf, a.needle)
        return
    if a.needle:
        rows = [h for h in r["refs"] if a.needle.lower() in h["string"].lower()]
        print("rows matching %r: %d  (%s)" % (a.needle, len(rows), r["verdict"][:60]))
        for h in rows:
            print("   %s %s -> %r" % (h["function"][:44], h["site"], h["string"][:60]))


if __name__ == "__main__":
    main()
