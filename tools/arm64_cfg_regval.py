#!/usr/bin/env python3
"""tools/arm64_cfg_regval.py -- §335: is the base register of a store REALLY single-valued there?

§333/§334 published a dominance check ("no branch target lands between the last definition in listing
order and the use") and used it to DEMOTE two sites in `hifi_codec_dac_event` to "not proven".  That
check is a listing-order approximation: a diamond where both arms define the register the same way
fails it even though the value is certain, and a block entered with a stale register passes it.  This
tool answers the question the right way: build the function's control-flow graph, compute dominators
and BACKWARD REACHING DEFINITIONS (walk predecessors until every path hits a writer), and resolve the
value each arm carries into the store -- a per-arm answer, not a union.  The earlier forward fixpoint
census is gone (§335 found it does not converge on a branch-heavy handler, §340 deleted the path: a
non-settled state is not an answer, and a mode that can only abort is not an entry point).

Model (deliberately narrow, everything else becomes UNKNOWN):
  adrp xD,#imm            -> imm
  add/sub xD,xS,#imm      -> S's value +- imm        (only if S is known)
  mov xD,#imm             -> imm
  mov xD,xS               -> S's value
  any load, any other op  -> UNKNOWN for the destination
  bl / blr                -> x0..x17 become UNKNOWN (caller-saved), other registers kept
Blocks end at a branch; edges follow the branch target and, when the branch is conditional or not a
branch at all, the fall-through.  A block with no incoming edge (other than the entry) is reported --
that is how a wrong function span shows up.

usage: tools/arm64_cfg_regval.py --func NAME|0xVA --at 0xVA[,0xVA...] (--dom SITES [--out TSV] |
                               --defs REGS | --graph [--sites SITES] | --selftest)
--out writes the per-arm table that --dom computes: which value each arm stores and WHICH BRANCH
ENTERS that arm (entry_compares) -- the machine-derived form of "arm == condition", published so a
second tool can compose the selection instead of my reading it off the printout.
CFG_NO_SELF_EXCLUDE=1 retires the "a site is not its own definition" rule; only --selftest sets it.
"""
import argparse
import collections
import csv
import hashlib
import os
import re
import struct
import subprocess
import sys

from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, Cs

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IMG = os.environ.get("DAC_IMG", os.path.join(ROOT, "fw", "Image"))
KALL = os.environ.get("DAC_KALL", os.path.join(ROOT, "art", "kallsyms_real.txt"))
TEXT_BASE = 0xFFFFFFC000080000
TEXT_END = TEXT_BASE + os.path.getsize(IMG)
MASK = 0xFFFFFFFFFFFFFFFF
ALIAS = {"fp": 29, "lr": 30, "sp": 31}
# CFG_NO_SELF_EXCLUDE=1 retires the "a site is not its own definition" rule so that --selftest can show
# the rule is load-bearing; nothing else should set it.
SELF_EXCLUDE = os.environ.get("CFG_NO_SELF_EXCLUDE") != "1"
BLOB = open(IMG, "rb").read()

ENTRIES = []
for line in open(KALL, encoding="utf-8", errors="replace"):
    p = line.split()
    if len(p) >= 3 and re.fullmatch(r"[0-9a-f]{16}", p[0]):
        ENTRIES.append((int(p[0], 16), p[1], p[2]))
NAME = {}
FOR_NAME = collections.defaultdict(list)
for a, t, n in ENTRIES:
    NAME.setdefault(a, n)
    FOR_NAME[n].append(a)
TEXT = sorted({(a, n) for a, t, n in ENTRIES if t in "tT" and TEXT_BASE <= a < TEXT_END})
TA = [a for a, _n in TEXT]
IDX = {a: i for i, a in enumerate(TA)}
MD = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
MD.detail = True
UNKNOWN = object()


def sha16(p):
    return hashlib.sha256(open(p, "rb").read()).hexdigest()[:16]


def rnum(reg):
    n = MD.reg_name(reg) or ""
    if n in ALIAS:
        return ALIAS[n]
    m = re.fullmatch(r"[wx](\d+)", n)
    return int(m.group(1)) if m else None


def decode_range(va, end):
    out, a, bad = [], va, 0
    while a < end:
        w = BLOB[a - TEXT_BASE:a - TEXT_BASE + 4]
        if len(w) < 4:
            break
        if struct.unpack("<I", w)[0] == 0:
            a += 4
            continue
        x = next(MD.disasm(w, a), None)
        if x is None:
            bad += 1
        else:
            out.append(x)
        a += 4
    return out, bad


def branch_targets(x, lo, hi):
    """where control leaves this instruction, restricted to addresses inside the function"""
    mn = x.mnemonic
    out = []
    if mn in ("bl", "blr", "ret", "br"):
        return ("call", [])
    if mn == "b" or mn.startswith("b."):
        for o in x.operands:
            if o.type == 2 and lo <= (o.imm & MASK) < hi:
                out.append(o.imm & MASK)
        return ("uncond" if mn == "b" else "cond", out)
    if mn.startswith(("cbz", "cbnz", "tbz", "tbnz")):
        for o in x.operands:
            if o.type == 2 and lo <= (o.imm & MASK) < hi:
                out.append(o.imm & MASK)
        return ("cond", out)
    return ("fall", [])


def build_blocks(ins, lo, hi):
    addrs = [x.address for x in ins]
    addr_set = set(addrs)
    pos = {a: i for i, a in enumerate(addrs)}
    leaders = {addrs[0]}
    for i, x in enumerate(ins):
        kind, tg = branch_targets(x, lo, hi)
        for t in tg:
            if t in addr_set:
                leaders.add(t)
        if kind in ("uncond", "cond", "call") and i + 1 < len(ins):
            leaders.add(ins[i + 1].address)
    leaders = sorted(leaders)
    blocks, bid = [], {}
    for n, l in enumerate(leaders):
        end = leaders[n + 1] if n + 1 < len(leaders) else addrs[-1] + 4
        body = [x for x in ins if l <= x.address < end]
        bid[l] = len(blocks)
        blocks.append({"start": l, "body": body, "succ": []})
    edges = collections.defaultdict(set)
    for b in blocks:
        last = b["body"][-1]
        kind, tg = branch_targets(last, lo, hi)
        i = pos[last.address]
        fall = addrs[i + 1] if i + 1 < len(addrs) else None
        if kind in ("fall", "cond") and fall is not None:
            edges[b["start"]].add(fall)
        if kind == "call" and fall is not None:      # a call returns to the next instruction
            edges[b["start"]].add(fall)
        for t in tg:
            if t in bid:
                edges[b["start"]].add(t)
    for b in blocks:
        b["succ"] = sorted(edges[b["start"]])
    incoming = collections.defaultdict(set)
    for s, ts in edges.items():
        for t in ts:
            incoming[t].add(s)
    return blocks, bid, incoming


def writes_reg(x, reg):
    """does this instruction assign `reg`? (branches, flag-only ops and stores do not)  A call counts
    for x0-x17: those are caller-saved, so the value the callee returns IS a definition of x0 -- without
    this the walk reaches past a `blr` and credits an older write with the compared value (a false
    data-flow claim, the same mistake the retired transfer function avoided)."""
    ops, mn = x.operands, x.mnemonic
    dst = rnum(ops[0].reg) if ops and ops[0].type == 1 else None
    mem = [o for o in ops if o.type == 3]
    if reg is not None and mn in ("bl", "blr", "braa", "brba") and reg <= 17:
        return True
    return (dst == reg and not mn.startswith(("cmp", "tst", "cbz", "cbnz", "tbz", "tbnz"))
            and not (mem and mn.startswith("st")) and mn not in ("bl", "blr", "br", "ret"))


def value_at(by_start, preds_of, blk, reg, before=None, seen=None):
    """the value `reg` holds at `blk` (optionally only up to instruction `before`), by resolving the
    definition that reaches there: inside the block if it defines the register, otherwise the union
    over predecessors.  Returns an int, or None when the value is not statically resolvable (a load,
    a call result, or a cycle).  Cycles return None rather than iterating to a fixpoint -- a value
    that a loop could change is not a value worth publishing."""
    seen = seen or set()
    key = (blk, reg, before)
    if key in seen:
        return None
    seen = seen | {key}
    body = by_start[blk]["body"]
    limit = before if before is not None else body[-1].address + 4
    defn = None
    for x in body:
        if x.address >= limit:
            break
        if writes_reg(x, reg):
            defn = x
    if defn is None:
        vals = set()
        for p in preds_of[blk]:
            v = value_at(by_start, preds_of, p, reg, None, seen)
            if v is None:
                return None
            vals.add(v)
        return vals.pop() if len(vals) == 1 else None
    ops, mn = defn.operands, defn.mnemonic
    if mn == "adrp" and len(ops) == 2 and ops[1].type == 2:
        return ops[1].imm & MASK
    if mn == "mov" and len(ops) == 2 and ops[1].type == 2:
        return ops[1].imm & MASK
    if mn == "mov" and len(ops) == 2 and ops[1].type == 1:
        return value_at(by_start, preds_of, blk, rnum(ops[1].reg), defn.address, seen)
    if mn in ("add", "sub") and len(ops) == 3 and ops[2].type == 2:
        src = value_at(by_start, preds_of, blk, rnum(ops[1].reg), defn.address, seen)
        if src is None:
            return None
        step = ops[2].imm & MASK
        return (src + step) if mn == "add" else (src - step) & MASK
    return None


def resolve_def(by_start, preds_of, blocks, blk, reg, before):
    """(definition address, value it assigns) pairs for every path reaching `before` in `blk`:
    resolving each arm separately is what lets a two-arm store report its two values."""
    pairs = []
    work, seen = [blk], {blk}
    while work:
        cb = work.pop()
        hit = None
        for y in reversed(by_start[cb]["body"]):
            if SELF_EXCLUDE and cb == blk and y.address >= before:
                continue
            if writes_reg(y, reg):
                hit = y
                break
        if hit is not None:
            val = None
            ops, mn = hit.operands, hit.mnemonic
            if mn == "adrp" and len(ops) == 2 and ops[1].type == 2:
                val = ops[1].imm & MASK
            elif mn == "mov" and len(ops) == 2 and ops[1].type == 2:
                val = ops[1].imm & MASK
            elif mn in ("add", "sub") and len(ops) == 3 and ops[2].type == 2:
                src = value_at(by_start, preds_of, cb, rnum(ops[1].reg), hit.address)
                if src is not None:
                    step = ops[2].imm & MASK
                    val = (src + step) if mn == "add" else (src - step) & MASK
            elif mn == "mov" and len(ops) == 2 and ops[1].type == 1:
                val = value_at(by_start, preds_of, cb, rnum(ops[1].reg), hit.address)
            pairs.append((hit.address, cb, val))
            continue
        for p in preds_of[cb]:
            if p not in seen:
                seen.add(p)
                work.append(p)
    return pairs


def block_fall(blocks):
    """where each block lands when it does NOT take its conditional branch"""
    starts = [b["start"] for b in blocks]
    return {b["start"]: (starts[i + 1] if i + 1 < len(starts) else None)
            for i, b in enumerate(blocks)}


def edges_in(by_start, fall, p, c):
    """the branch that moves control from block p to block c, with the compares sitting in p.
    Returns (taken, fall-through) for that one edge -- an arm is decided by the SIDE actually taken,
    which is why the caller must ask per edge instead of reading a union of all paths."""
    body = by_start[p]["body"]
    term = body[-1]
    mn = term.mnemonic
    # a plain b/bl/br/ret decides nothing; b.cond / cbz / cbnz / tbz / tbnz do -- and testing
    # mn.startswith("b") for the fall-through side silently dropped every b.ne's fall-through,
    # which is exactly the side that decides two of the four arms
    if not mn.startswith(("b.", "cbz", "cbnz", "tbz", "tbnz")):
        return None
    tg = [o.imm & MASK for o in term.operands if o.type == 2]
    taken = c in tg
    fell = fall.get(p) == c
    if not (taken or fell):
        return None
    cmps = [f"{y.mnemonic} {y.op_str}" for y in body if y.mnemonic in ("cmp", "cmn", "tst")]
    return {"at": p, "branch": f"{term.address:#x} {mn} {term.op_str}",
            "side": "taken" if taken else "fall-through",
            "cmp_ins": [y for y in body if y.mnemonic in ("cmp", "cmn", "tst")],
            "compares": cmps or ["(no compare in this block: the branch tests an earlier flag)"]}


def reachable(adj, entry, target, banned=None):
    seen, stack = {entry}, [entry]
    while stack:
        n = stack.pop()
        if n == target:
            return True
        for t in adj.get(n, []):
            if (n, t) == banned or t in seen:
                continue
            seen.add(t)
            stack.append(t)
    return target in seen


def necessary_edges(by_start, blocks, entry, target):
    """the edges EVERY path to `target` must cross, with the side taken: an edge u->v is necessary when
    deleting it makes the target unreachable from the entry.  This is the conjunction -- path_conditions
    gives the union, in which one instruction appears on both sides and which therefore cannot be read
    as "what decides this arm"."""
    adj = {b["start"]: b["succ"] for b in blocks}
    fall = block_fall(blocks)
    out = []
    for b in blocks:
        for t in b["succ"]:
            e = edges_in(by_start, fall, b["start"], t)
            if not e:
                continue
            if reachable(adj, entry, target) and not reachable(adj, entry, target, banned=(b["start"], t)):
                out.append(e)
    return out


def path_conditions(by_start, preds_of, blocks, blk):
    """the branches that decide whether control reaches `blk`, by walking predecessors back to the
    entry: for each edge p -> c, p's terminator tells which side was taken (target list = taken,
    the instruction after p's last instruction = fall-through).  A UNION over paths -- see
    necessary_edges for the conjunction."""
    fall = block_fall(blocks)
    conds, work, seen = [], [blk], {blk}
    guard = 0
    while work:
        guard += 1
        if guard > 5000:
            sys.exit("gate: the predecessor walk did not terminate -- the graph has an unexpected shape")
        c = work.pop()
        for p in preds_of[c]:
            e = edges_in(by_start, fall, p, c)
            if e:
                conds.append(e)
            if p not in seen:
                seen.add(p)
                work.append(p)
    return conds, seen


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--func", required=True)
    ap.add_argument("--at", required=True, help="absolute field addresses to test")
    ap.add_argument("--out", default="", help="with --dom: write the arm/entry-edge table to this TSV")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--graph", action="store_true",
                    help="print the blocks, their terminators and their successors, and mark the blocks "
                         "holding the requested sites -- the auditable form when the solver does not "
                         "settle: read the edges instead of trusting them")
    ap.add_argument("--sites", default="", help="addresses to mark in --graph output")
    ap.add_argument("--dom", default="",
                    help="comma-separated instruction addresses: compute the dominator sets and report, "
                         "for each, the dominating definitions of the access's base register -- the "
                         "question §333's listing-order check could only flag, not answer")
    ap.add_argument("--defs", default="",
                    help="comma-separated register NUMBERS: print every writer of each inside the "
                         "function, with the block it sits in -- the domination question answered by "
                         "counting writers instead by solving")
    a = ap.parse_args()
    out_path = a.out
    if a.func.startswith("0x"):
        start = int(a.func, 0)
        if start not in IDX:
            sys.exit(f"gate: {start:#x} is not a text symbol start in {KALL}")
        fn = NAME[start]
    else:
        hits = sorted(set(FOR_NAME.get(a.func, [])))
        if not hits:
            sys.exit(f"gate: {a.func} not in kallsyms")
        if len(hits) > 1:
            sys.exit(f"gate: {a.func} has {len(hits)} addresses {[hex(h) for h in hits]} -- pass the "
                     "exact one; name is not identity (ledger 283/287/332)")
        start = hits[0]
        fn = a.func
    i = IDX[start]
    end = TA[i + 1] if i + 1 < len(TA) else start + 4
    fields = {int(s, 0) for s in a.at.split(",") if s.strip()}
    ins, bad = decode_range(start, end)
    blocks, bid, incoming = build_blocks(ins, start, end)
    if a.defs and (a.dom or a.out):
        # --defs prints a list and stops; running it together with --dom used to swallow the domination
        # question while still exiting 0, which reads as a complete answer
        sys.exit("gate: --defs answers by itself and exits -- combine it with --dom/--out as two separate "
                 "commands, otherwise the second question is never asked and rc=0 still prints")
    if a.defs:
        regs = {int(s, 0) for s in a.defs.split(",") if s.strip()}
        block_of = {x.address: b["start"] for b in blocks for x in b["body"]}
        print(f"register writers inside {fn} (registers {sorted(regs)}), with the block each sits in; "
              f"entry block {blocks[0]['start']:#x}")
        for reg in sorted(regs):
            ws = []
            for x in ins:
                ops, mn = x.operands, x.mnemonic
                dst = rnum(ops[0].reg) if ops and ops[0].type == 1 else None
                mem = [o for o in ops if o.type == 3]
                writes = (dst == reg and not mn.startswith(("cmp", "tst", "cbz", "cbnz", "tbz", "tbnz"))
                          and not (mem and mn.startswith("st")) and mn not in ("bl", "blr", "br", "ret"))
                if writes:
                    ws.append(x)
            print(f"   x{reg}: {len(ws)} writer(s) " + "; ".join(
                f"{x.address:#x}@block{block_of[x.address]:#x} {x.mnemonic} {x.op_str}" for x in ws))
        sys.exit(0)
    if a.selftest:
        me = [sys.executable, os.path.abspath(__file__)]
        fnc = os.environ.get("CFG_TEST_FUNC", "0xffffffc000bb7450")
        dom = os.environ.get("CFG_TEST_DOM", "0xffffffc000bb759c,0xffffffc000bb75b0")
        fld = os.environ.get("CFG_TEST_FIELD", "0xffffffc001b24368")
        self_site = os.environ.get("CFG_TEST_SELF_SITE", "0xffffffc000bb7580")
        ctl = subprocess.run(me + ["--func", fnc, "--at", fld, "--dom", dom],
                             capture_output=True, text=True)
        if ctl.returncode != 0:
            sys.exit(f"gate: --selftest: the published call (--func {fnc} --dom {dom}) is no longer "
                     f"rc=0 ({ctl.returncode}): {ctl.stderr.strip()[:160]}")
        print(f"selftest: control arm rc=0, cross-witness line present={'cross-witness' in ctl.stdout}, "
              f"written-value line present={'written values' in ctl.stdout}")
        shift = hex(int(fld, 0) + 8)
        bad = subprocess.run(me + ["--func", fnc, "--at", shift, "--dom", dom],
                             capture_output=True, text=True)
        if bad.returncode == 0 or "confirmed NONE" not in bad.stderr:
            sys.exit(f"gate: --selftest: asking about field {shift} instead of {fld} still gives rc=0 "
                     f"(stderr {bad.stderr.strip()[:130]}) -- then the confirmed line is not a judgment "
                     "about the field address and must not be published as one")
        print("selftest: the shifted-field arm aborts on the confirmed-NONE gate -- the field address in "
              "--at is load-bearing")
        env = dict(os.environ, CFG_NO_SELF_EXCLUDE="1")
        kept = subprocess.run(me + ["--func", fnc, "--at", fld, "--dom", self_site],
                              capture_output=True, text=True)
        off = subprocess.run(me + ["--func", fnc, "--at", fld, "--dom", self_site],
                             capture_output=True, text=True, env=env)
        if kept.stdout == off.stdout:
            sys.exit(f"gate: --selftest: retiring the self-reference exclusion changes nothing at "
                     f"{self_site} -- either that site is not the self-writing shape the rule was made "
                     "for, or the switch does not reach the walk; the rule would be unproven either way")
        print(f"selftest: at {self_site} retiring the self-reference exclusion moves the reaching "
              f"definition to the site itself -- the §336 rule is load-bearing")
        sys.exit(0)
    if a.dom:
        sites = {int(s, 0) for s in a.dom.split(",") if s.strip()}
        block_of = {x.address: b["start"] for b in blocks for x in b["body"]}
        by_start = {b["start"]: b for b in blocks}
        starts = [b["start"] for b in blocks]
        entry = starts[0]
        doms = {s: set(starts) for s in starts}
        doms[entry] = {entry}
        for _ in range(len(starts) + 5):
            changed = False
            for s in starts:
                if s == entry:
                    continue
                ps = [b["start"] for b in blocks if s in b["succ"]]
                if not ps:
                    continue
                new = set(starts)
                for p in ps:
                    new &= doms[p] | {p}
                new |= {s}
                if new != doms[s]:
                    doms[s] = new
                    changed = True
            if not changed:
                break
        else:
            sys.exit("gate: dominators did not settle -- refusing to publish a domination answer")
        agree = []
        written = []
        arm_rows = []
        for site in sorted(sites):
            blk = block_of.get(site)
            if blk is None:
                print(f"   {site:#x} is not an instruction of this function -- cannot answer")
                continue
            strict = [d for d in doms[blk] if d != blk]
            # the immediate dominator is the strict dominator with the MOST dominators of its own,
            # not the one with the largest address (that mistake would have printed a wrong idom)
            idom = max(strict, key=lambda d: (len(doms[d]), d)) if strict else None
            print(f"   site {site:#x} in block {blk:#x}: {len(doms[blk])} dominators, "
                  f"idom {idom and hex(idom)}, entry dominates: {entry in doms[blk]}")
            for reg in sorted({rnum(o.reg) for x in ins if x.address == site
                               for o in x.operands if o.type == 3 and rnum(o.mem.base) is not None} or {None}):
                # backward reaching definition: walk predecessors until each path hits a writer.
                preds_of = {b["start"]: [p["start"] for p in blocks if b["start"] in p["succ"]]
                            for b in blocks}
                work, seen, found = [blk], {blk}, []
                while work:
                    cb = work.pop()
                    hit = None
                    for y in reversed(by_start[cb]["body"]):
                        if SELF_EXCLUDE and cb == blk and y.address >= site:
                            continue      # a site that WRITES its own base register (ldr x0,[x0,#..])
                                          # must be judged on the value coming IN, not on itself
                        if writes_reg(y, reg):
                            hit = y
                            break
                    if hit is not None:
                        found.append((cb, hit.address, f"{hit.mnemonic} {hit.op_str}"))
                        continue
                    for p in preds_of[cb]:
                        if p not in seen:
                            seen.add(p)
                            work.append(p)
                vals = sorted({f[2] for f in found})
                print(f"      base x{reg}: reaching definitions {[f'{f[1]:#x} in block {f[0]:#x}' for f in found]}"
                      + ("" if len(vals) > 1 else f" -- {len(found)} path(s), all the same instruction: "
                         f"{vals[0] if vals else 'no definition found (caller-supplied)'}"))
                x = next(y for y in ins if y.address == site)
                mem_ops = [o for o in x.operands if o.type == 3]
                if reg is None or not mem_ops:
                    print(f"      this site is not a bracketed memory access ({x.mnemonic} {x.op_str}) "
                          "-- there is no base register here to resolve; ask --defs for the writers "
                          "instead")
                    continue
                disp = mem_ops[0].mem.disp
                bv = value_at(by_start, preds_of, blk, reg, site)
                if bv is None:
                    print(f"      value: the chain does not resolve (a load, a call result, or a loop "
                          f"stands between) -- no address is claimed for x{reg}")
                else:
                    field = (bv + disp) & MASK
                    print(f"      value: x{reg} = {bv:#x} on every path -> this access addresses "
                          f"{field:#x} (displacement +{disp:#x})")
                    if fields and field not in fields:
                        print(f"      note: {field:#x} is not among the --at fields "
                              f"{sorted(hex(f) for f in fields)} -- this site is a different field")
                    if fields and field in fields:
                        agree.append((site, reg, bv, field))
                src_reg = rnum(x.operands[0].reg) if x.operands and x.operands[0].type == 1 else None
                if x.mnemonic.startswith("st") and src_reg is not None and src_reg != reg:
                    arms = resolve_def(by_start, preds_of, blocks, blk, src_reg, site)
                    got = sorted({(a, v) for a, _c, v in arms if v is not None})
                    print(f"      stored x{src_reg}: {len(arms)} arm(s), {len(got)} resolved -> "
                          + "; ".join(f"def {a:#x} = {v:#x} {NAME.get(v) or '(no symbol)'}"
                                     for a, v in got)
                          + ("" if len(got) == len(arms) else "   (some arms unresolved)"))
                    fall = block_fall(blocks)
                    for a, cb, v in arms:
                        imms = [e for e in (edges_in(by_start, fall, p, cb) for p in preds_of[cb]) if e]
                        conds, reach = path_conditions(by_start, preds_of, blocks, cb)
                        nec = necessary_edges(by_start, blocks, entry, cb)
                        sig = "; ".join(sorted(f"{c['branch'].split(' ')[1]} {c['side']} "
                                               f"[{'; '.join(c['compares'])}]" for c in nec))
                        src = []
                        for c in nec:
                            for ci in c["cmp_ins"]:
                                ops = ci.operands
                                if not ops or ops[0].type != 1:
                                    continue
                                rg = rnum(ops[0].reg)
                                ds = sorted({p[0] for p in resolve_def(by_start, preds_of, blocks,
                                                                       c["at"], rg, ci.address)})
                                if not ds:
                                    src.append(f"w{rg}<-no definition inside the function "
                                               f"(caller-supplied or a call result)")
                                for d in ds:
                                    di = next((y for y in ins if y.address == d), None)
                                    src.append(f"w{rg}<-{di.mnemonic} {di.op_str}@{d:#x}" if di
                                               else f"w{rg}<-{d:#x}")
                        arm_rows.append({
                            "kind": "arm", "fn": f"{fn}@{start:#x}", "site": f"{site:#x}",
                            "block": f"{cb:#x}", "def": f"{a:#x}", "stores": f"x{src_reg}",
                            "value": (f"{v:#x}" if v is not None else "UNRESOLVED"),
                            "value_name": (NAME.get(v) or "-") if v is not None else "-",
                            "enters": " / ".join(f"{c['branch']} {c['side']} [{'; '.join(c['compares'])}]"
                                                 for c in imms) or "-",
                            "entry_compares": "; ".join(sorted({x for c in imms for x in c["compares"]}))
                                              or "-",
                            "necessary": " / ".join(f"{c['branch']} {c['side']}" for c in nec) or "-",
                            "necessary_compares": sig or "-",
                            "necessary_reg_sources": "; ".join(sorted(set(src))) or "-",
                            "upstream_edges": str(len(conds))})
                        print(f"        arm def {a:#x} (block {cb:#x}) value "
                              f"{v and hex(v) or 'UNRESOLVED'}: enters via "
                              + (" / ".join(f"{c['branch']} {c['side']} [{'; '.join(c['compares'])}]"
                                            for c in imms)
                                 or "an unconditional jump (no branch decides this arm directly)"))
                        ups = sorted({(c["branch"], c["side"], "; ".join(c["compares"]))
                                      for c in conds} - {(c["branch"], c["side"], "; ".join(c["compares"]))
                                                          for c in imms})
                        if ups:
                            print("          upstream (union over every path reaching that edge, so one "
                                  "instruction can appear on both sides): "
                                  + " / ".join(f"{b} {s} [{c}]" for b, s, c in ups))
                        if not imms:
                            print("        note: this arm's entry edge is not a conditional branch -- the "
                                  "condition that selects it (if any) sits further upstream, so the union "
                                  "below must NOT be read as this arm's conjunction")
                        if not conds:
                            print("        (that arm is unconditional: it is taken on every path "
                                  "reaching the site)")
                    written += [v for _a, v in got]
        if written:
            uniq = sorted(set(written))
            print(f"written values    {len(written)} arm-resolved value(s), {len(uniq)} distinct: "
                  + ", ".join(f"{v:#x}={NAME.get(v) or '?'}" for v in uniq))
            alt = os.environ.get("DAC_ALT_TSV") or os.path.join(
                os.path.dirname(KALL), "audio-6.0.1", "dac-integration-params.PD1610.tsv")
            if os.path.exists(alt):
                named = {r["name"] for r in csv.DictReader(open(alt, encoding="utf-8"), delimiter="\t")
                         if r["kind"] == "alt-table"}
                miss = [f"{v:#x}={NAME.get(v)}" for v in uniq
                        if NAME.get(v) and not any(NAME.get(v) in n for n in named)]
                if miss:
                    sys.exit(f"gate: the values this CFG resolves were never seen by the other witness "
                             f"(dac_integration_params --rows-at knows {sorted(named)}): {miss} -- one of "
                             "the two readings is wrong")
                print(f"cross-witness     every resolved value is also a row in "
                      f"dac-integration-params.PD1610.tsv's alt-table arm ({len(named)} candidates) -- "
                      "two instruments, one set")
            else:
                print("cross-witness     no dac-integration-params artifact beside this tool; the values "
                      "are published on this instrument alone")
        if fields:
            print(f"confirmed         {len(agree)} of {len(sites)} requested site(s) resolve onto a "
                  f"--at field: " + ", ".join(f"{s:#x} x{r}={v:#x}->{f_:#x}" for s, r, v, f_ in agree))
            if not agree:
                sys.exit("gate: the CFG resolver confirmed NONE of the sites onto the requested fields -- "
                         "either the resolver is blind here or §333's listing-order census pointed at the "
                         "wrong sites; publish neither")
        vals = [r["value"] for r in arm_rows if r["value"] != "UNRESOLVED"]
        noedge = [r["def"] for r in arm_rows if r["enters"] == "-"]
        nonec = [r["def"] for r in arm_rows if r["necessary"] == "-"]
        sigs = {r["def"]: r["necessary_compares"] for r in arm_rows}
        print(f"binding         {len(arm_rows)} arm(s): " + "; ".join(
            f"{r['value_name']} <- {r['necessary_compares']} ({r['necessary_reg_sources']})"
            for r in arm_rows if r["necessary_compares"] != "-"))
        distinct = {s for s in sigs.values() if s != "-"}
        repeated = [s for s in distinct if [x for x in sigs.values() if x != "-"].count(s) > 1]
        if repeated:
            sys.exit(f"gate: two arms share the same necessary-condition signature {repeated} -- the "
                     "table cannot be bound to a condition, so neither the binding nor the arm values "
                     "may be published")
        if nonec:
            sys.exit(f"gate: arm(s) {nonec} have NO edge that every path must cross -- the CFG says a "
                     "value can reach the store from anywhere, so publishing a per-arm condition would "
                     "be my guess")
        if out_path:
            cols = ["kind", "fn", "site", "block", "def", "stores", "value", "value_name",
                    "enters", "entry_compares", "necessary", "necessary_compares",
                    "necessary_reg_sources", "upstream_edges"]
            lines = []
            for r in arm_rows:
                line = "\t".join(str(r.get(c, "-")) for c in cols)
                if "\t" in str(r.get("enters", "")):
                    sys.exit(f"gate: refusing to write a TSV field containing a tab: {r}")
                lines.append(line.replace("\n", " ").replace("\r", " "))
            lines.append("\t".join(["DENOM", f"{fn}@{start:#x}", str(len(sites)), str(len(blocks)),
                                    str(len(arm_rows)), str(len({v for v in vals})),
                                    f"{len(vals)} resolved", f"{len(distinct)} signature(s)",
                                    str(len(noedge)), "-", str(len(nonec)),
                                    "; ".join(f"{k}={v}" for k, v in sorted(sigs.items()))[:400],
                                    "; ".join(sorted({r["necessary_reg_sources"] for r in arm_rows}))[:400],
                                    "arms without a conditional entry edge: "
                                    f"{noedge or 'none'}"]))
            widths = {len(l.split("\t")) for l in lines}
            if widths != {len(cols)}:
                sys.exit(f"gate: {out_path} row widths {sorted(widths)} are not all {len(cols)} columns")
            with open(out_path, "w", encoding="utf-8") as fh:
                fh.write("\t".join(cols) + "\n")
                fh.write("\n".join(lines) + "\n")
            print(f"wrote           {out_path}: {len(lines)} rows x {len(cols)} columns, "
                  f"{len({v for v in vals})} distinct arm value(s), {len(noedge)} arm(s) with no "
                  "conditional entry edge")
        sys.exit(0)

    if a.graph:
        mark = {int(s, 0) for s in a.sites.split(",") if s.strip()}
        print(f"CFG of {fn}@{start:#x}: {len(blocks)} blocks, {len(ins)} instructions; "
              f"marked sites {sorted(hex(m) for m in mark)}")
        for b in blocks:
            last = b["body"][-1]
            hits = [f"{x.address:#x}<{x.mnemonic} {x.op_str}>" for x in b["body"] if x.address in mark]
            print(f"  {b['start']:#x}..{last.address:#x} ({len(b['body']):3}) term={last.mnemonic:6} "
                  f"-> {', '.join(f'{t:#x}' for t in b['succ']) or 'none'}"
                  + (f"   MARKED: {'; '.join(hits)}" if hits else ""))
        unreachable = [hex(b["start"]) for b in blocks
                       if b["start"] != start and not incoming[b["start"]]]
        print(f"  blocks with no incoming edge (entered from outside this span, or dead): "
              f"{unreachable or 'none'}")
        sys.exit(0)
    sys.exit("gate: no mode chosen -- this tool answers through --dom (reaching definitions and the "
             "values they carry), --defs (register writers per block) or --graph (the block listing); "
             "the old fixpoint census was retired in §335 and deleted in §340")


if __name__ == "__main__":
    main()
