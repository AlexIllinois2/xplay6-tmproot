#!/usr/bin/env python3
"""tools/kssym_str.py -- disassemble a kernel symbol and resolve every string it references.

Replaces the old text-regex version, which could only pair an adrp with an add writing the
*same* register and therefore missed strings passed as x1/x2 while the page landed in x0.
Capstone details are used and a flat register-page map is kept across the whole symbol, so
all of these shapes resolve:
  adrp xN, #page            -> track xN = page
  add  xM, xN, #imm         -> VA = page + imm (string data)
  ldr  xM, [xN, #imm]       -> VA = page + imm (pointer table), dereferenced when it points into the Image
  adr  xM, #target          -> VA = target
  mov  xM, xN               -> value copy
Any other write to a tracked register drops it. Text VAs map to file offsets as
va - 0xffffffc000080000 in our stock arm64 Image.

Usage: tools/kssym_str.py <symbol> [--any] [--instr=N]
  --any    print every resolvable string, not only those containing '%'
"""
import bisect
import os
import re
import struct
import sys

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, CS_OP_REG, CS_OP_IMM, CS_OP_MEM
from capstone.arm64 import ARM64_REG_INVALID

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEXT_BASE = 0xFFFFFFC000080000
IMG = os.path.join(ROOT, "fw/Image")
KALL = os.path.join(ROOT, "art/kallsyms_real.txt")

# mnemonics whose first register operand is read, not written
NO_WRITE = {"bl", "b", "br", "blr", "ret", "cbz", "cbnz", "tbz", "tbnz", "cmp", "cmn", "tst",
            "teq", "fcmp", "str", "strb", "strh", "stur", "stnp", "stp", "dc", "ic", "msr",
            "svc", "hvc", "smc", "dsb", "dmb", "isb", "nop", "prfm"}

MASK64 = 0xFFFFFFFFFFFFFFFF


def rkey(md, reg):
    """w1 and x1 are the same storage -- capstone gives them different enum ids"""
    name = md.reg_name(reg) or ""
    if name in ("sp", "xzr", "wzr"):
        return "r" + name.lstrip("wxz")
    return "r" + name.lstrip("xw")


def load_syms():
    pairs = []
    by_va = {}
    for line in open(KALL, encoding="utf-8", errors="replace"):
        p = line.split()
        if len(p) != 3:
            continue
        try:
            va = int(p[0], 16)
        except ValueError:
            continue
        pairs.append((va, p[2]))
        by_va.setdefault(va, p[2])
    pairs.sort()
    return [a for a, _ in pairs], [n for _, n in pairs], by_va


def near(addrs, names, va):
    i = bisect.bisect_right(addrs, va) - 1
    if i < 0:
        return "?"
    return names[i] if va == addrs[i] else f"{names[i]}+{va - addrs[i]:#x}"


def span(addrs, start):
    """function length by next symbol -- a fixed span would run past the ret"""
    i = bisect.bisect_right(addrs, start)
    nxt = addrs[i] if i < len(addrs) else start + 0x400
    return max(4, min(nxt - start, 0x4000))


def cstr(blob, fo, maxlen=160):
    """kernel fmt strings end in a real newline -- rejecting \\n would drop most of them"""
    if fo < 0 or fo >= len(blob):
        return None
    end = blob.find(b"\0", fo)
    if end < 0 or end - fo > maxlen or end - fo < 2:
        return None
    s = blob[fo:end].decode("latin-1")
    if not all(32 <= ord(c) < 127 or c in "\n\t" for c in s):
        return None
    return s if sum(1 for c in s if 32 <= ord(c) < 127) >= 2 else None


def main():
    argv = sys.argv[1:]
    positional = [a for a in argv if not a.startswith("--")]
    if not positional:
        sys.exit(__doc__)
    sym = positional[0]
    show_any = "--any" in argv
    limit = None
    for a in argv:
        m = re.match(r"--instr=(\d+)$", a)
        if m:
            limit = int(m.group(1))
        elif a == "--instr" and positional.index(a) + 1 < len(positional):
            limit = int(positional[positional.index(a) + 1])

    addrs, names, by_va = load_syms()
    starts = [a for a, n in zip(addrs, names) if n == sym]
    if not starts:
        sys.exit(f"symbol {sym} not in {KALL}")
    blob = open(IMG, "rb").read()
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True

    for start in starts:
        nbytes = span(addrs, start)
        if limit:
            nbytes = min(nbytes, limit * 4)
        code = blob[start - TEXT_BASE:start - TEXT_BASE + nbytes]
        print(f"=== {sym} @ {start:#x} ({nbytes // 4} instrs) ===")
        regs = {}          # rkey -> ('page'|'addr', value); chained adds accumulate
        found = {}
        for ins in md.disasm(code, start):
            ops = ins.operands
            cands, dst, tracked = [], None, False
            if ins.mnemonic == "adrp" and len(ops) == 2 and ops[0].type == CS_OP_REG and ops[1].type == CS_OP_IMM:
                dst, tracked = ops[0].reg, True
                regs[rkey(md, dst)] = ("page", ops[1].imm & MASK64)
            elif ins.mnemonic == "adr" and len(ops) == 2 and ops[0].type == CS_OP_REG and ops[1].type == CS_OP_IMM:
                dst, cands = ops[0].reg, [ops[1].imm & MASK64]
                regs[rkey(md, dst)] = ("addr", ops[1].imm & MASK64)
                tracked = True
            elif ins.mnemonic in ("add", "sub") and len(ops) == 3 and ops[0].type == CS_OP_REG \
                    and ops[1].type == CS_OP_REG and ops[2].type == CS_OP_IMM \
                    and rkey(md, ops[1].reg) in regs:
                kind, base = regs[rkey(md, ops[1].reg)]
                dst = ops[0].reg
                va = base + ops[2].imm if ins.mnemonic == "add" else base - ops[2].imm
                cands = [va]
                regs[rkey(md, dst)], tracked = ("addr", va), True
            elif ins.mnemonic == "mov" and len(ops) == 2 and ops[0].type == CS_OP_REG \
                    and ops[1].type == CS_OP_REG and rkey(md, ops[1].reg) in regs:
                dst = ops[0].reg
                regs[rkey(md, dst)] = regs[rkey(md, ops[1].reg)]
                tracked = True
            elif ins.mnemonic.startswith("ldr") and len(ops) == 2 and ops[0].type == CS_OP_REG \
                    and ops[1].type == CS_OP_MEM and ops[1].mem.index == ARM64_REG_INVALID \
                    and regs.get(rkey(md, ops[1].mem.base), ("", 0))[0] == "page":
                base = regs[rkey(md, ops[1].mem.base)][1] + ops[1].mem.disp
                dst = ops[0].reg
                cands = [base]
                fo = base - TEXT_BASE
                if 0 <= fo < len(blob) - 7:
                    ptr = struct.unpack("<Q", blob[fo:fo + 8])[0]
                    if TEXT_BASE <= ptr < TEXT_BASE + len(blob):
                        cands.append(ptr)
                tracked = True
            elif ins.mnemonic not in NO_WRITE and ops and ops[0].type == CS_OP_REG:
                # untracked write: this register no longer holds a usable address
                dst = ops[0].reg
            if dst is not None and not tracked:
                regs.pop(rkey(md, dst), None)
            note = ""
            for va in cands:
                s = cstr(blob, va - TEXT_BASE)
                if s and (show_any or "%" in s):
                    found.setdefault((va, s), ins)
                    note += f"   <== str {s!r}"
            tgt = ""
            if ins.mnemonic in ("bl", "b") and ops and ops[0].type == CS_OP_IMM:
                t = ops[0].imm & MASK64
                tgt = "   ; -> " + (by_va.get(t) or near(addrs, names, t))
            print(f"{ins.address - start:08x}  {ins.mnemonic:<8} {ins.op_str:<44}{tgt}{note}")
        print("\n--- referenced strings ---")
        for (va, s), ins in found.items():
            print(f"  {va:#x} (file {va - TEXT_BASE:#x}) @{ins.address - start:#x} {ins.mnemonic} {ins.op_str}: {s!r}")
        if not found:
            print("  (none containing '%' -- rerun with --any to list all resolved strings)")
    return 0


def selftest():
    """the ruler carries its own scale: two positive arms, a structural negative arm, a dd witness"""
    import subprocess

    def run(args):
        return subprocess.run([sys.executable, __file__] + args, capture_output=True,
                              text=True, cwd=ROOT).stdout

    a = run(["tfa98xx_debug_reg_write"])
    b = run(["tfa98xx_debug_reg_write", "--any"])
    neg = run(["tfa98xx_convert_data2bytes", "--any"])
    pos = [x for x in ("'%x %x'", "; -> sscanf") if x not in a]
    chain = "'tfa98xx_debug_reg_write'" in b          # chained add: the old regex version missed this
    zero = "referenced strings" in neg and "  0x" not in neg.split("referenced strings")[-1]
    fo = 0xFFFFFFC0011AB7DA - TEXT_BASE
    dd = subprocess.run(["dd", "if=%s" % IMG, "bs=1", "skip=%d" % fo, "count=5"],
                        capture_output=True, text=True, cwd=ROOT).stdout
    print("POSITIVE fmt+sscanf resolved      : %s" % ("PASS" if not pos else "FAIL missing %r" % pos))
    print("POSITIVE chained-add accumulation : %s" % ("PASS" if chain else "FAIL"))
    print("NEGATIVE adrp-free function -> 0  : %s" % ("PASS" if zero else "FAIL"))
    print("WITNESS  dd at printed file offset: %s" % ("PASS" if dd == "%x %x" else "FAIL got %r" % (dd,)))
    return 0 if (not pos and chain and zero and dd == "%x %x") else 1


if __name__ == "__main__":
    sys.exit(selftest() if "--selftest" in sys.argv else main())
