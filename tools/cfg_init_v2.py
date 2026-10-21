#!/usr/bin/env python3
"""tools/cfg_init_v2.py -- branch-graph reachability over one function in an ELF, used to settle a
control-flow question a linear disassembly cannot: does the loader still scan the cal directory when
`persist.audio.calfile*` is set?  (ledger 377/378/379; port-target row `persist.audio.calfile0..19`)

Why a walker and not a read: in the ARM64 build the props loop exits by `cbnz` at 0x73f4 to a join at
0x6f38, while the directory cascade sits at 0x73f8 -- *above* the join in address order.  Reading
instructions top-down suggests "falls through", so only a successor walk over the join can say whether
the cascade is reachable at all.  It answers that and nothing more: branch edges plus fall-through,
`bl` recorded as a call target and never as control flow.

Both ELF classes are handled, because the copy mediaserver actually maps is the 32-bit one (§374) and
llvm-objdump decodes its .text as ARM (it ignores the $t/$a mapping symbols, so everything comes out as
svcmi/<unknown>): ELF64/AArch64 gets a linear pre-decode, ELF32/ARM decodes Thumb **on demand** -- only
at addresses control flow reaches -- so literal pools are not walked as if they were code.  The report
prints the block count and the number of addresses that failed to decode, and a "False" is always a
claim about the given window.  Pair every negative with a positive in the same window (walk the loop
head to its own exit): that pairing is what caught this tool classifying `ble`/`blt` as calls, which
dropped conditional edges and made every False meaningless.

Verdict reached with it on 6.0.1, in both copies: the props join does NOT reach the directory cascade
(replacement, not addition) and DOES reach send_meta_info.

Usage:
  python3 tools/cfg_init_v2.py <so> [--start 0x6e24] [--end 0x7800] [--from 0x6f38] [--to 0x73f8]
      # ELF32 example from §379: --start 0x517c --end 0x5dd9 --from 0x523a --to 0x5670
  python3 tools/cfg_init_v2.py --selftest        # synthetic windows + the mnemonic-classification table
"""
import argparse
import re
import struct
import subprocess
import sys

from capstone import CS_ARCH_ARM, CS_ARCH_ARM64, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN, CS_MODE_THUMB, Cs

TGT = re.compile(r"(0x[0-9a-f]+)\s*$")
COND = ("b", "cbz", "cbnz", "tbz", "tbnz")


def elf_arch(path):
    """(elf class, e_machine) -- the reason this file grew a Thumb mode: llvm-objdump decodes this
    library's .text as ARM (svcmi/<unknown> everywhere) because it ignores the $t mapping symbols, so
    the 32-bit copy cannot be read with the same tool that read the 64-bit one."""
    d = open(path, "rb").read(54)
    if d[:4] != b"\x7fELF":
        sys.exit(f"gate: {path} is not an ELF file")
    return d[4], struct.unpack_from("<H", d, 18)[0]


def edge_kind(mnemonic):
    """call | terminal | cond | uncond | plain -- the classification that was wrong once.  `ble`/`blt`/
    `bgt`/`bcc` are conditional branches that start with the letters bl, so startswith('bl') silently
    deleted their branch edges; only bl/blx are calls."""
    m = mnemonic.split(".")[0] if mnemonic.endswith(".w") else mnemonic
    if mnemonic in ("bl", "bl.w", "blx", "blx.w"):
        return "call"
    if mnemonic in ("bx", "bx.w", "ret", "ret.w") or mnemonic.startswith("pop"):
        return "terminal"
    if mnemonic in ("b", "b.w"):
        return "uncond"
    if mnemonic in ("cbz", "cbnz", "tbz", "tbnz"):
        return "cond"
    if mnemonic.startswith("b"):
        return "cond"
    return "plain"


def walk_thumb(data, lo, hi, entry, delta):
    """lazy Thumb successor walk: decode only at reached addresses.  A whole-window linear disassembly
    would walk literal pools as if they were code and invent branches, which is the failure mode that
    makes an unreachable-claim meaningless; on demand, pool words are only decoded if control flow
    actually arrives at them -- and a pool word that decodes to a branch out of range is dropped."""
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    seen, stack, junk, calls = set(), [entry], [], {}
    while stack:
        a = stack.pop()
        if a is None or a in seen or not (lo <= a < hi):
            continue
        seen.add(a)
        off = a - delta
        ins = None
        for n in (4, 2):
            got = list(md.disasm(data[off:off + n], a))
            if got and got[0].address == a:
                ins = got[0]
                break
        if ins is None:
            junk.append(a)
            continue
        line = f"{ins.mnemonic} {ins.op_str}".strip()
        m = TGT.search(ins.op_str or "")
        tgt = int(m.group(1), 16) if m and lo <= int(m.group(1), 16) < hi else None
        kind = edge_kind(ins.mnemonic)
        if kind == "call":
            if m:
                calls[int(m.group(1), 16)] = calls.get(int(m.group(1), 16), 0) + 1
            stack.append(a + ins.size)
        elif kind == "terminal":
            continue
        elif kind in ("uncond", "cond"):
            if tgt is not None:
                stack.append(tgt)
            if kind == "cond":
                stack.append(a + ins.size)               # a conditional branch also falls through
        else:
            stack.append(a + ins.size)
    return seen, calls, junk


def build(code, start, end):
    """successor edges within [start,end): branch targets plus linear fall-through"""
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    succ, ins = {}, {}
    for i in md.disasm(code, start):
        ins[i.address] = i
        mn = i.mnemonic
        if mn in COND or mn.startswith("b."):
            m = TGT.search(i.op_str or "")
            if m and start <= int(m.group(1), 16) < end:
                succ.setdefault(i.address, []).append((int(m.group(1), 16), mn))
        elif mn == "bl":
            succ.setdefault(i.address, []).append((None, "bl " + i.op_str))
    addrs = sorted(ins)
    for k, a in enumerate(addrs):
        i = ins[a]
        # only an UNCONDITIONAL transfer has no fall-through: cbz/cbnz/tbz/tbnz and b.<cond> take one
        # branch and also continue -- treating them as terminal is the bug the --selftest window caught
        # on 2026-10-17 (it under-connected the graph, 17 blocks instead of 188, and made every False
        # from the walker meaningless)
        if i.mnemonic in ("b", "br", "ret"):
            continue
        nxt = addrs[k + 1] if k + 1 < len(addrs) else None
        if nxt is not None:
            succ.setdefault(a, []).append((nxt, "fall"))
    return succ, ins


def walk(succ, start, start_lo, start_hi):
    seen, stack = set(), [start]
    while stack:
        a = stack.pop()
        if a is None or a in seen or not (start_lo <= a < start_hi):
            continue
        seen.add(a)
        for t, kind in succ.get(a, []):
            if t is not None:
                stack.append(t)
    return seen


def calls(succ, seen):
    out = {}
    for a in seen:
        for t, kind in succ.get(a, []):
            if t is None and kind.startswith("bl "):
                m = TGT.search(kind)
                if m:
                    out[int(m.group(1), 16)] = out.get(int(m.group(1), 16), 0) + 1
    return out


def selftest():
    """a synthetic function whose graph I chose, so a walker that silently connects nothing fails"""
    bad = []
    base = 0x1000
    # b 0x1008 | nop | nop | cbnz w0, 0x1010 (out of the window) | bl 0x2000 | ret
    words = [0x14000002, 0xD503201F, 0xD503201F, 0xB5000040, 0x97FFFC00 | 0x0, 0xD65F03C0]
    code = b"".join(w.to_bytes(4, "little") for w in words)
    lo, hi = base, base + len(words) * 4
    succ, ins = build(code, lo, hi)
    seen = walk(succ, base, lo, hi)
    if base + 8 not in seen:
        bad.append("the synthetic `b` was not followed -- the walker cannot connect branches")
    if base + 4 in seen:
        bad.append("a block the `b` skipped was still reached -- the walker treats every address as a "
                   "successor, so a False from it would mean nothing")
    for off, why in ((8, "the branch target"), (12, "fall-through after the target"),
                     (16, "the cbnz with an out-of-window target must still fall through"),
                     (20, "fall-through after the bl")):
        if base + off not in seen:
            bad.append(f"{why} at {base + off:#x} was not reached -- the graph is under-connected, and "
                       "every False this walker prints would be an artifact of that")
    c = calls(succ, seen)
    if not c:
        bad.append("no bl target recorded from a window that contains a bl -- call sets would always "
                   "come back empty")
    # the classification that was wrong (ble/blt are branches, not calls)
    want = {"bl": "call", "bl.w": "call", "blx": "call", "ble": "cond", "blt.w": "cond",
            "bgt": "cond", "bcc": "cond", "bne": "cond", "beq": "cond", "b": "uncond",
            "b.w": "uncond", "cbz": "cond", "cbnz": "cond", "bx": "terminal", "pop": "terminal",
            "mov": "plain", "ldr": "plain"}
    wrong = {k: (v, edge_kind(k)) for k, v in want.items() if edge_kind(k) != v}
    if wrong:
        bad.append(f"edge_kind misclassifies {wrong} -- a dropped branch edge turns every unreachable "
                   "answer into an artifact of the walker")
    print(f"selftest: {len(bad)} arm(s) failed" + ("" if not bad else " -- " + "; ".join(bad))
          + f"  (synthetic blocks seen: {sorted(hex(a) for a in seen)})")
    return 1 if bad else 0


def stub_names(path):
    """PLT stub address -> imported name.  Worth having inside the tool because the runbook's step 7k
    verdict is phrased in names (send_meta_info), and reading stub addresses by hand is how a 0x2168
    gets mistaken for 0x216c.  .plt is ARM/static-linker code even in a Thumb library, so llvm-objdump
    labels it correctly even where it mis-decodes .text."""
    out = {}
    p = subprocess.run(["llvm-objdump", "-d", "--section=.plt", path], capture_output=True, timeout=180)
    for line in p.stdout.decode("utf-8", "replace").split("\n"):
        m = re.match(r"^([0-9a-f]{8,16}) <([^>]+)>:", line)
        if m:
            out[int(m.group(1), 16)] = m.group(2)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("so", nargs="?")
    ap.add_argument("--start", default="0x6e24")
    ap.add_argument("--end", default="0x7800")
    ap.add_argument("--from", dest="frm", default="0x6f38")
    ap.add_argument("--to", default="0x73f8")
    ap.add_argument("--delta", default="0", help="vaddr minus file offset for the code section "
                    "(0 in these libraries; the first decoded line is printed so a wrong value is "
                    "visible rather than silent)")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        return selftest()
    if not a.so:
        sys.exit(__doc__)
    s, e = int(a.start, 16), int(a.end, 16)
    frm, to = int(a.frm, 16), int(a.to, 16)
    data = open(a.so, "rb").read()
    elfclass, machine = elf_arch(a.so)
    if elfclass == 2 and machine == 0xB7:                 # ELF64 / AArch64
        succ, ins = build(data[s:e], s, e)
        seen = walk(succ, frm, s, e)
        cs = calls(succ, seen)
        arch = "arm64"
    elif elfclass == 1 and machine == 0x28:               # ELF32 / ARM (Thumb here)
        seen, cs, junk = walk_thumb(data, s, e, frm, int(a.delta, 0))
        arch = "thumb"
        first = Cs(CS_ARCH_ARM, CS_MODE_THUMB).disasm(data[frm - int(a.delta, 0):frm - int(a.delta, 0) + 4], frm)
        print(f"  entry decodes as: {next(iter(first), None)}")
        print(f"  addresses that did not decode as instructions: {len(junk)}")
    else:
        sys.exit(f"gate: {a.so} is ELF class {elfclass} machine {machine:#x} -- this walker knows "
                 "ELF64/AArch64 and ELF32/ARM(Thumb); anything else must not be read with it")
    print(f"  {a.so} [{arch}]: window {s:#x}..{e:#x}, walk from {frm:#x}")
    print(f"  {len(seen)} blocks in-window; reaches {to:#x}? {to in seen}")
    names = stub_names(a.so)
    labelled = ", ".join(f"{t:#x}{'/' + names[t] if t in names else ''}(x{n})"
                         for t, n in sorted(cs.items()))
    print("  call targets: " + labelled)
    print(f"  stub names resolved for {sum(1 for t in cs if t in names)}/{len(cs)} call targets")
    return 0 if to not in seen else 1


if __name__ == "__main__":
    sys.exit(main())
