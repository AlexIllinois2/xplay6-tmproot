#!/usr/bin/env python3
"""tools/so_xref.py -- "who references this string?" inside an ARM64 shared object.

pyelftools is not installed here, so the ELF is parsed by hand: section headers + their name
table give .text/.plt/.rodata/.data.rel.ro, program headers give the file-offset <-> vaddr map,
dynsym gives function names and sizes, RELA gives the PLT stub names and the load-time pointers.

Two reference shapes are reported, because a tool that only knows the first one prints false zeros:
  CODE   adrp xN, #page  followed (anywhere later) by  add xM, xN, #off  or  ldr xM, [xN, #off]
  TABLE  an 8-byte word in .data/.data.rel.ro/.got whose value is the string vaddr, i.e. a
         pointer baked into a static table (R_AARCH64_RELATIVE/ABS64 resolves it at load time)
The register model is a single linear pass, so a page value left in a register by an unrelated
block can still be matched -- each hit prints with its site address and containing function for
a human to judge. This tool locates candidates; it does not claim proven data flow.

Usage:
  tools/so_xref.py <so> --string "ro.vivo.product.platform" [--string ...] [--context 6]
  tools/so_xref.py <so> --find <file-offset> [--find ...]
  tools/so_xref.py <so> --list-strings <regex>
  tools/so_xref.py <so> --selftest [--selftest-string S ...]   # prove the ruler before trusting a 0
"""
import argparse
import os
import re
import struct
import sys

from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, CS_OP_IMM, CS_OP_MEM, CS_OP_REG, Cs

# AArch64 (LP64) ELF relocation types, 0x100-based -- NOT the x86-64 numbers. A wrong constant here
# silently yields "0 named PLT stubs" and every lookup downstream reads as absence.
R = {256: "NONE", 257: "ABS64", 258: "ABS32", 259: "PREL64", 260: "PREL32", 261: "CB28",
     262: "CALL26", 263: "JUMP26", 266: "RELATIVE", 267: "GLOB_DAT", 268: "JUMP_SLOT",
     275: "ADR_PREL_PG_HI21", 276: "ADR_PREL_PG_HI21_NC", 277: "ADD_ABS_LO12_NC",
     285: "MOVW_ABS12", 286: "MOVW_ABS12_L", 287: "MOVW_ABS12_H1",
     288: "TRY_BNTPLT26", 300: "GOT_OFF16", 301: "GOT_ABS64",
     309: "ADR_PREL_LO19", 310: "ADR_GOT_PAGE_OLD", 311: "ADR_GOT_PAGE",
     312: "LD64_GOT_LO12_NC", 313: "LD32_GOT_LO12_NC", 315: "LDST8_GOT_LO12_NC",
     1024: "TLS_DTPMOD64", 1025: "GLOB_DAT(android 0x401)",
     1026: "JUMP_SLOT(android 0x402)"}
R_ABS64, R_RELATIVE, R_GLOB_DAT, R_JUMP_SLOT = 257, 266, 267, 268
R_ADR_GOT_PAGE, R_LD64_GOT_LO12_NC = 311, 312


def sec_name(b, strtab_off, idx):
    end = b.index(b"\0", strtab_off + idx)
    return b[strtab_off + idx:end].decode("latin1")


def parse(path):
    b = open(path, "rb").read()
    if b[:4] != b"\x7fELF" or b[4] != 2 or b[5] != 1:
        sys.exit(f"gate: {path} is not a 64-bit little-endian ELF")
    e_phoff, e_shoff = struct.unpack_from("<QQ", b, 32)
    e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx, _e_flags = struct.unpack_from("<HHHHHH", b, 54)
    loads = []
    for i in range(e_phnum):
        o = e_phoff + i * e_phentsize
        p_type, _fl, p_offset, p_vaddr, _pa, p_filesz, _pm, _al = struct.unpack_from("<IIQQQQQQ", b, o)
        if p_type == 1:
            loads.append((p_offset, p_vaddr, p_filesz))
    raw = []
    for i in range(e_shnum):
        o = e_shoff + i * e_shentsize
        sh_name, sh_type, _fl, sh_addr, sh_offset, sh_size, sh_link, _info, _al, entsize = \
            struct.unpack_from("<IIQQQQIIQQ", b, o)
        raw.append((sh_name, sh_type, sh_addr, sh_offset, sh_size, sh_link, entsize))
    if not (0 < e_shstrndx < e_shnum):
        sys.exit("gate: no section name table -- cannot identify .text/.plt by name")
    shstrtab_off = raw[e_shstrndx][3]
    secs = []
    for sh_name, sh_type, sh_addr, sh_offset, sh_size, sh_link, entsize in raw:
        secs.append({"name": sec_name(b, shstrtab_off, sh_name), "type": sh_type, "addr": sh_addr,
                     "off": sh_offset, "size": sh_size, "link": sh_link, "entsize": entsize})
    byname = {s["name"]: s for s in secs}

    text = byname.get(".text")
    if not text or text["size"] < 0x100:
        cand = max((s for s in secs if s["type"] == 1 and s["size"] > 0x100),
                   key=lambda s: s["size"], default=None)
        text = cand
    if not text:
        sys.exit("gate: no .text-like section")

    syms = []
    for s in secs:
        if s["type"] not in (2, 11):                      # SHT_DYNSYM / SHT_SYMTAB
            continue
        strtab = secs[s["link"]]
        ent = s["entsize"] or 24
        for j in range(s["size"] // ent):
            st_name, st_info, _o, st_shndx, st_value, st_sz = struct.unpack_from(
                "<IBBHQQ", b, s["off"] + j * ent)
            if (st_info & 0xF) != 2 or st_sz == 0:        # STT_FUNC with a size
                continue
            syms.append((st_value, st_sz, sec_name(b, strtab["off"], st_name)))

    # PLT stub names: entry i of .plt lives at .plt + 0x10 + 16*i, and the JUMP_SLOT relocation
    # whose r_offset lands in .plt tells us which symbol that stub resolves to.
    plt = {}
    dynstr = next((s for s in secs if s["name"] == ".dynstr"), None)
    symtab_sec = next((s for s in secs if s["type"] in (2, 11)), None)
    plt_sec = byname.get(".plt")
    if dynstr and symtab_sec and plt_sec:
        for s in secs:
            if s["type"] != 4:                            # SHT_RELA
                continue
            ssym = secs[s["link"]]
            ent = s["entsize"] or 24
            for j in range(s["size"] // ent):
                r_off, r_info, _r_add = struct.unpack_from("<QQq", b, s["off"] + j * ent)
                if (r_info & 0xFFFFFFFF) != R_JUMP_SLOT:
                    continue
                sym = r_info >> 32
                if 24 * sym >= ssym["size"]:
                    continue
                st_name = struct.unpack_from("<I", b, ssym["off"] + 24 * sym)[0]
                idx = (r_off - plt_sec["addr"]) // 16
                if 0 <= idx:
                    plt[plt_sec["addr"] + 0x10 + 16 * idx] = sec_name(b, dynstr["off"], st_name)

    # load-time pointers: a table entry can hold the string's vaddr, which no instruction scan will
    # ever see. In a shared object the file bytes of such an entry are usually ZERO -- the value
    # lives in the relocation's r_addend -- so the authoritative source is .rela.dyn, not .data.
    ptrs = {}                                              # target vaddr -> [entry labels]
    rcount = {}
    for s in secs:
        if s["type"] != 4:                                   # SHT_RELA
            continue
        ent = s["entsize"] or 24
        for j in range(s["size"] // ent):
            r_off, r_info, r_add = struct.unpack_from("<QQq", b, s["off"] + j * ent)
            rtype = r_info & 0xFFFFFFFF
            rname = R.get(rtype, f"#{rtype}")
            rcount[rname] = rcount.get(rname, 0) + 1
            if rtype not in (R_RELATIVE, R_ABS64):
                continue
            where = next((f"{x['name']}[{(r_off - x['addr']) // 8}]" for x in secs
                          if x["addr"] and x["addr"] <= r_off < x["addr"] + x["size"]), f"@{r_off:#x}")
            ptrs.setdefault(r_add, []).append(where)
    return b, loads, sorted(syms), text, plt, secs, ptrs, rcount


def decode_all(md, code, start):
    """Every decodable word in a range, plus the count of words skipped. capstone's disasm() STOPS
    at the first undecodable word, so a naive pass read 7208 of this HAL's 36162 .text words and
    reported real references as absent -- that silent truncation is what this function exists to kill."""
    out, skipped = [], 0
    pc, end = 0, len(code) - (len(code) % 4)
    while pc < end:
        got = False
        try:
            for ins in md.disasm(code[pc:end], start + pc):
                out.append(ins)
                pc = ins.address - start + 4
                got = True
        except Exception:
            pass
        if pc >= end:
            break
        if not got:
            pc += 4
            skipped += 1
    return out, skipped


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("so")
    ap.add_argument("--find", action="append", default=[])
    ap.add_argument("--string", action="append", default=[])
    ap.add_argument("--context", type=int, default=6)
    ap.add_argument("--list-strings", default=None, help="regex: show matching string offsets and exit")
    ap.add_argument("--peek", action="append", default=[],
                    help="vaddr: print the NUL-terminated string there (objdump shows adrp+add "
                         "targets as bare numbers; without this I guess what the format string was)")
    ap.add_argument("--strings-in", default=None, metavar="LO-HI",
                    help="vaddr range inside .text: list every string that function materialises "
                         "(adrp+add pairs) -- reading a function means reading its messages")
    ap.add_argument("--call", action="append", default=[],
                    help="regex over PLT stub names: list bl sites (this is how a caller of an "
                         "imported acdb_loader_* function is found without scanning by string)")
    ap.add_argument("--selftest", action="store_true",
                    help="prove this reader CAN find a reference before any zero answer is trusted")
    ap.add_argument("--selftest-string", action="append", default=[])
    args = ap.parse_args()
    b, loads, syms, text, plt, secs, ptrs, rcount = parse(args.so)
    taddr, toff, tsize = text["addr"], text["off"], text["size"]

    def to_vaddr(fo):
        for p_off, p_va, p_sz in loads:
            if p_off <= fo < p_off + p_sz:
                return p_va + (fo - p_off)
        return None

    def func_of(addr):
        for sv, ss, nm in syms:
            if sv and sv <= addr < sv + ss:
                return f"{nm}+{addr - sv:#x}"
        return "?"

    code = b[toff:toff + tsize]
    md = Cs(CS_ARCH_ARM64, 0)
    md.detail = True

    # one decode pass feeds every arm below, and its census prints on the face of each answer,
    # so a coverage collapse cannot be mistaken for "this string is unreferenced"
    words = tsize // 4
    ins_list, skipped = decode_all(md, code, taddr)
    cov = 100.0 * (len(ins_list) + skipped) / max(words, 1)
    if cov < 99.5:
        print(f"  coverage warning: {cov:.1f}% of .text words visited ({len(ins_list)} instructions, "
              f"{skipped} undecodable words) -- a zero below may be a hole in the code, not an absence")

    targets = []
    for s in args.string:
        for m in re.finditer(re.escape(s.encode()), b):
            # snap back to the start of the enclosing C string: code references the string, not a
            # substring of it, and a miss here reads as "this message is never used" (false negative)
            start = b.rfind(b"\0", 0, m.start()) + 1
            targets.append((start, s))
    for f in args.find:
        targets.append((int(f, 0), f"offset {f}"))

    tv = {}
    for fo, lab in targets:
        va = to_vaddr(fo)
        if va is None:
            print(f"  {lab}: file offset {fo:#x} is not inside any PT_LOAD")
        else:
            tv.setdefault(va, lab)

    def scan(tvm):
        pages, hits, tab = {}, {}, {}
        stale = 0
        for ins in ins_list:
            ops = ins.operands
            cand = None
            if ins.mnemonic != "adrp":
                if ins.mnemonic in ("add", "sub") and len(ops) == 3 and ops[1].type == CS_OP_REG \
                        and ops[2].type == CS_OP_IMM:
                    base = pages.get(ops[1].reg)
                    if base is not None:
                        cand = base + (ops[2].imm if ins.mnemonic == "add" else -ops[2].imm)
                elif ins.mnemonic == "ldr" and len(ops) == 2 and ops[1].type == CS_OP_MEM and ops[1].mem.base:
                    base = pages.get(ops[1].mem.base)
                    if base is not None:
                        cand = base + ops[1].mem.disp
            # A page value stops being a page the moment the register is written again. Without this
            # invalidation the model reported 12 sites for a 4-byte global that no code reads -- every
            # `ldr x4,[x1,#8]` after an unrelated `adrp x1` in an earlier block matched.
            try:
                _rd, wr = ins.regs_access()
            except Exception:
                wr = ()
            for r in wr:
                if r in pages:
                    del pages[r]
                    stale += 1
            if ins.mnemonic == "adrp" and len(ops) == 2:
                pages[ops[0].reg] = ops[1].imm
            if cand in tvm:
                fo = toff + ins.address - taddr
                hits.setdefault(tvm[cand], []).append((ins.address, fo))
        for va, lab in tvm.items():
            for where in ptrs.get(va, []):
                tab.setdefault(lab, []).append(where)
        scan.invalidated = stale
        return hits, tab

    def to_foff(va):
        for p_off, p_va, p_sz in loads:
            if p_va <= va < p_va + p_sz:
                return p_off + (va - p_va)
        return None

    if args.peek:
        for spec in args.peek:
            lo, _, hi = spec.partition("-")
            a = int(lo, 0)
            fo = to_foff(a)
            if fo is None:
                print(f"  peek {spec}: vaddr is not inside any PT_LOAD")
                continue
            if not hi:
                end = b.index(b"\0", fo)
                print(f"  {a:#x}: {b[fo:end].decode('latin1')!r}")
                continue
            n = int(hi, 0) - a
            i = a
            while i < a + n:
                f2 = to_foff(i)
                if f2 is None:
                    break
                end = b.index(b"\0", f2)
                s = b[f2:end].decode("latin1")
                if len(s) >= 2:
                    print(f"  {i:#x}: {s!r}")
                i = end + 1
        return 0

    if args.strings_in:
        lo, hi = (int(x, 0) for x in args.strings_in.split("-", 1))
        pages2, seen = {}, {}
        for ins in ins_list:
            if not lo <= ins.address < hi:
                continue
            ops = ins.operands
            cand = None
            if ins.mnemonic != "adrp":
                if ins.mnemonic in ("add", "sub") and len(ops) == 3 and ops[1].type == CS_OP_REG \
                        and ops[2].type == CS_OP_IMM:
                    if pages2.get(ops[1].reg) is not None:
                        cand = pages2[ops[1].reg] + (ops[2].imm if ins.mnemonic == "add" else -ops[2].imm)
                elif ins.mnemonic == "ldr" and len(ops) == 2 and ops[1].type == CS_OP_MEM and ops[1].mem.base:
                    if pages2.get(ops[1].mem.base) is not None:
                        cand = pages2[ops[1].mem.base] + ops[1].mem.disp
            try:
                _rd, wr = ins.regs_access()
            except Exception:
                wr = ()
            for r in wr:
                pages2.pop(r, None)
            if ins.mnemonic == "adrp" and len(ops) == 2:
                pages2[ops[0].reg] = ops[1].imm
            if cand is None:
                continue
            fo = to_foff(cand)
            if fo is None:
                continue
            end = b.find(b"\0", fo)
            if end < 0 or end - fo > 200:
                continue
            s = b[fo:end]
            if len(s) >= 3 and all(32 <= c < 127 for c in s):
                seen.setdefault(cand, s.decode("latin1"))
        vis = sum(1 for i in ins_list if lo <= i.address < hi)
        print(f"strings materialised in {lo:#x}-{hi:#x}: {len(seen)} distinct, from {vis} instructions inside the range (of {len(ins_list)} decoded in .text)")
        for va, s in sorted(seen.items()):
            print(f"   {va:#x} {s!r}")
        return 0

    if args.list_strings:
        pat = re.compile(args.list_strings, re.I)
        for m in re.finditer(rb"[ -~]{5,}", b):
            s = m.group().decode("latin1")
            if pat.search(s):
                print(f"  {m.start():#07x} vaddr={to_vaddr(m.start()) or 0:#x} {s[:100]}")
        return 0

    if args.call:
        pats = [re.compile(p, re.I) for p in args.call]
        # GNU objdump resolves stub -> imported symbol for us. My own PLT map is NOT used here:
        # this Android numbers JUMP_SLOT as 0x402 and its r_offset points into .got, not .plt, so
        # indexing stubs from .plt gives 0 names -- a ruler that silently answers "nobody calls it".
        obj = next((t for t in ("aarch64-linux-gnu-objdump", "objdump")
                    if os.system("command -v " + t + " >/dev/null 2>&1") == 0), None)
        if not obj:
            sys.exit("--call needs objdump (none found) -- my own PLT naming cannot resolve Android "
                     "JUMP_SLOT numbering, so I refuse to answer instead of printing a false zero")
        sites, stubs = {}, {}
        import subprocess
        for ln in subprocess.run([obj, "-d", args.so], capture_output=True, text=True).stdout.splitlines():
            m = re.match(r"^\s+([0-9a-f]+):\t[0-9a-f]+\s+(bl|b)\s+([0-9a-f]+) <([^>]+)>", ln)
            if not m:
                continue
            nm = m.group(4)
            if any(p.search(nm) for p in pats):
                sites.setdefault(nm, []).append(int(m.group(1), 16))
                stubs[nm] = int(m.group(3), 16)
        print(f"{os.path.basename(args.so)}: {len(sites)} matching callee(s) for {args.call} "
              f"(via {obj}); my own PLT map held {len(plt)} names")
        if not sites:
            print("  no call site matched -- the imported-name list was searched, so this is a real "
                  "zero for direct bl/b targets (dispatch through a table or dlsym is out of scope)")
        for nm, lst in sorted(sites.items()):
            print(f"\n   {nm}: stub {stubs[nm]:#x}, {len(lst)} call site(s)")
            for s in lst[:12]:
                print(f"      {s:#x} inside {func_of(s)}")
        return 0

    if args.selftest:
        # A zero answer is only admissible after this ruler has HIT something in the very binary
        # being measured. Default candidates are sampled from .rodata (log formats and paths that
        # linked code almost certainly loads), so the check needs no outside knowledge to run.
        cands = list(args.selftest_string)
        if not cands:
            r = next((s for s in secs if s["name"] == ".rodata"), None)
            if r is None:
                sys.exit("selftest: no .rodata to sample from -- pass --selftest-string")
            cands = [m.group().decode("latin1")
                     for m in re.finditer(rb"[ -~]{8,}", b[r["off"]:r["off"] + r["size"]])][:60]
        want = {}
        for s in cands:
            for m in re.finditer(re.escape(s.encode()), b):
                start = b.rfind(b"\0", 0, m.start()) + 1
                va = to_vaddr(start)
                if va is not None:
                    want.setdefault(va, s)
        if not want:
            sys.exit("selftest: none of the candidate strings is inside a PT_LOAD -- nothing proven")
        hits, tab = scan(want)
        nref = sum(len(v) for v in hits.values()) + sum(len(v) for v in tab.values())
        print(f"selftest: {len(want)} candidate vaddr(s) from {len(cands)} string(s), "
              f"{nref} reference(s) found, coverage {cov:.1f}% of {words} .text words, "
              f"{len(plt)} named PLT stub(s)")
        for lab, lst in list(hits.items())[:5]:
            print(f"   CODE  {lab}: {len(lst)} site(s) e.g. {lst[0][0]:#x} in {func_of(lst[0][0])}")
        for lab, lst in list(tab.items())[:5]:
            print(f"   TABLE {lab}: {len(lst)} pointer(s) e.g. {lst[0]}")
        if nref == 0:
            print("FAIL: this reader sees no reference at all in this binary -- treat every 0 as UNKNOWN")
            return 1
        print("PASS: the ruler hits this binary; a per-target zero below is a real zero")
        return 0

    if not targets:
        sys.exit("nothing to look for: pass --string, --find, or --list-strings")
    hits, tab = scan(tv)
    if not plt:
        print("  note: PLT stub names unresolved here (no .plt/.dynstr) -- call targets print as bare "
              "addresses; read them with `aarch64-linux-gnu-objdump -d --start-address=...`")
    print(f"{os.path.basename(args.so)}: .text {taddr:#x}+{tsize:#x} ({words} words, "
          f"{len(ins_list)} instructions decoded), {len(syms)} sized functions, {len(tv)} target string(s)")
    for lab, lst in hits.items():
        print(f"\nCODE  {lab}: {len(lst)} candidate site(s)")
        for va, fo in lst[:8]:
            print(f"   at {va:#x} (file {fo:#x}) inside {func_of(va)}")
            w0 = max(0, (fo - toff) - 4 * args.context)
            for w in md.disasm(code[w0:(fo - toff) + 4 * (args.context + 1)], taddr + w0):
                note = ""
                if w.mnemonic.startswith("bl") and w.op_str.startswith("#"):
                    tgt = int(w.op_str[1:], 16)
                    if tgt in plt:
                        note = f"   ; -> {plt[tgt]}()"
                print(f"   {'  <<<' if w.address == va else '     '} {w.address:#x}\t{w.mnemonic}\t{w.op_str}{note}")
    for lab, lst in tab.items():
        print(f"\nTABLE {lab}: {len(lst)} static pointer(s): {', '.join(lst[:8])}")
    if not hits and not tab:
        print("no ADRP+ADD/LDR site and no static pointer to those addresses. "
              + (f"COVERAGE {cov:.1f}% < 99.5%, so this is a NO-ANSWER, not an absence."
                 if cov < 99.5 else
                 f"Coverage {cov:.1f}% of .text; this is a zero for the two shapes this ruler reads "
                 f"(code adrp+add/ldr, relocated pointer). Indirect reach -- a path built at runtime "
                 f"with strcpy/sprintf, or a page materialised by something other than adrp -- is out "
                 f"of scope, so pair it with `--list-strings` and objdump before drawing a conclusion."))
    return 0


if __name__ == "__main__":
    sys.exit(main())
