#!/usr/bin/env python3
"""Data xref that survives multi-step address chains (adrp + add + add ...).

Why: `blsweep.dataxref` matches only `adrp page` followed by a *single* add/ldr/str whose
imm12 equals the page offset.  gcc emits
`adrp x26,#P; add x26,x26,#0xeb0; ...; add x0,x26,#0x418`, so a global reached through an
already-finalised base pointer is invisible -- that is what made the `--vas` arm report 0
sites for `es9038_data` (ledger 583), and, for the same reason, 0 for `wcd_hph_gain`.

How it works: one numeric pass finds every ADRP whose page is within --near of a target
(that pass needs no disassembler, so it covers the whole image), and only the 128-byte
window after each such site is decoded and run through the value model.  A per-word
disassembly of all 28 MB does not finish inside a round, and a ruler that never answers is
blind by construction.

Hits are candidates and print their chain: the model is over-approximate (a linear window
cannot tell paths apart, and choosing one silently is how the first version of this tool
lost `wcd_hph_gain` to an `ERR_PTR` on an error branch).

Every answer is qualified by its own arm: --must-hit <target>[:<function>] must be satisfied
or the run aborts, so "0 sites" can never be quoted as "no reader exists".

usage:
  tools/datarefs.py --img fw/7/Image --kallsyms art/kallsyms-7-real.txt \
      --target wcd_hph_gain --target wcd_imped_defs \
      --must-hit wcd_hph_gain:wcd_hph_gain_config
"""
import argparse
import bisect
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEXT = 0xFFFFFFC000080000
MASK = (1 << 64) - 1

from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs  # noqa: E402

READ_MN = ("ldr", "ldur", "ldrb", "ldurb", "ldrsb", "ldrsh", "ldrh", "ldurh", "ldar", "ldp")
WRITE_MN = ("str", "stur", "strb", "sturb", "stlr", "sttr", "stp")
RE_R = re.compile(r"\b([wx]sp|x\d{1,2}|w\d{1,2})\b")


def norm(r):
    return "x" + r[1:] if r.startswith("w") else r


def imm_of(text):
    m = re.search(r"#(-?0x[0-9a-f]+)", text)
    if not m:
        return None
    v = int(m.group(1), 16)
    s = re.search(r"lsl\s*#(\d+)", text)
    if s:
        v <<= int(s.group(1))
    return v & MASK


def adrp_sites(data, pages, text=TEXT):
    """Every ADRP in the image whose destination page is in `pages` (numeric, no decoder)."""
    hits = {}
    n = len(data) // 4
    for i in range(n):
        w = int.from_bytes(data[i * 4:i * 4 + 4], "little")
        if (w & 0x9F000000) != 0x90000000:
            continue
        va = text + i * 4
        imm = ((((w >> 5) & 0x7FFFF) << 2) | ((w >> 29) & 3))
        if imm & (1 << 20):
            imm -= 1 << 21
        page = (va & ~0xFFF) + (imm << 12)
        for t in pages:
            if page == t:
                hits.setdefault(t, []).append(va)
    return hits


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--img", required=True)
    ap.add_argument("--kallsyms", required=True)
    ap.add_argument("--target", action="append", default=[])
    ap.add_argument("--must-hit", action="append", default=[])
    ap.add_argument("--near", type=int, default=0x2000,
                    help="also try pages within this distance of a target (chained bases)")
    ap.add_argument("--window", type=int, default=128, help="bytes decoded after each adrp site")
    a = ap.parse_args()

    p = lambda x: x if x.startswith("/") else os.path.join(ROOT, x)  # noqa: E731
    vas, names, types = [], [], []
    byname = {}
    for ln in open(p(a.kallsyms), errors="replace"):
        m = re.match(r"^([0-9a-fA-F]{8,16}) ([a-zA-Z]) (\S+)$", ln.strip())
        if not m:
            continue
        v = int(m.group(1), 16)
        if v < TEXT or v in byname:
            continue
        vas.append(v)
        names.append(m.group(3))
        types.append(m.group(2))
        byname[m.group(3)] = v
    order = sorted(range(len(vas)), key=lambda i: vas[i])
    vas = [vas[i] for i in order]
    names = [names[i] for i in order]
    types = [types[i] for i in order]
    # text windows: [symbol, next symbol) -- so a data blob between functions is never decoded
    tv = sorted(v for v, t in zip(vas, types) if t in "tT")
    tnext = {tv[i]: tv[i + 1] for i in range(len(tv) - 1)}

    targets = {}
    for t in a.target:
        v = int(t, 16) if re.fullmatch(r"0x[0-9a-f]+", t) else byname.get(t)
        if v is None:
            sys.exit("target %s is not in kallsyms -- refusing to guess an address" % t)
        targets[v] = t

    data = open(p(a.img), "rb").read()
    pages = set()
    for t in targets:
        base = t & ~0xFFF
        for off in range(-(a.near // 0x1000), a.near // 0x1000 + 1):
            pages.add(base + off * 0x1000)
    sites = adrp_sites(data, pages)
    nsites = sum(len(v) for v in sites.values())
    print("# %s + %s: %d adrp site(s) across %d candidate page(s) for %d target(s)"
          % (a.img, a.kallsyms, nsites, len(pages), len(targets)))

    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True

    def own(x):
        i = bisect.bisect_right(vas, x) - 1
        return (names[i], x - vas[i]) if i >= 0 else ("?", x)

    hits = []
    for page, slist in sorted(sites.items()):
        for s in slist:
            end = min(s + a.window, tnext.get(s, s + a.window))
            if end <= s:
                end = s + a.window
            reg = {}
            src = {}
            for ins in md.disasm(data[s - TEXT:end - TEXT], s):
                w, ops = ins.mnemonic, ins.op_str

                def note(kind, val):
                    for t, tname in targets.items():
                        if val == t:
                            hits.append((ins.address, tname, kind, own(ins.address),
                                         " ".join("%x" % x for x in src.get((t, val), []))[-60:]))

                if w == "adrp":
                    rl = [norm(x) for x in RE_R.findall(ops)]
                    v = imm_of(ops.split(",", 1)[1]) if "," in ops else None
                    if rl and v is not None:
                        reg.setdefault(rl[0], set()).add(v)
                        src[(rl[0], v)] = [ins.address]
                    continue
                if w in ("add", "sub"):
                    rl = [norm(x) for x in RE_R.findall(ops)]
                    im = imm_of(ops)
                    if len(rl) >= 2 and reg.get(rl[1]) and im is not None:
                        delta = im if w == "add" else -im
                        for b in list(reg[rl[1]]):
                            v = (b + delta) & MASK
                            reg.setdefault(rl[0], set()).add(v)
                            src[(rl[0], v)] = src.get((rl[1], b), []) + [ins.address]
                            note("materialise", v)
                    elif len(rl) >= 3 and reg.get(rl[1]) and im is None:
                        # `add x2, x0, w2, sxtw`: register-scaled index, base preserved.
                        # Without this the chain dies exactly where 6.0.1 selects its column.
                        reg.setdefault(rl[0], set()).update(list(reg[rl[1]]))
                    elif rl:
                        reg.setdefault(rl[0], set())
                elif w == "mov":
                    rl = [norm(x) for x in RE_R.findall(ops)]
                    if len(rl) >= 2 and reg.get(rl[1]):
                        reg.setdefault(rl[0], set()).update(list(reg[rl[1]]))
                        for v in list(reg[rl[1]]):
                            src.setdefault((rl[0], v), [ins.address])
                            note("materialise", v)
                    else:
                        im = imm_of(ops)
                        if rl and im is not None:
                            reg.setdefault(rl[0], set()).add(im)
                        elif rl:
                            reg.setdefault(rl[0], set())
                elif w in READ_MN or w in WRITE_MN:
                    m = re.search(r"\[([^\]]*)\]", ops)
                    if m:
                        parts = [x.strip() for x in m.group(1).split(",")]
                        base = norm(parts[0].split()[0]) if parts and parts[0] else None
                        im = 0
                        extra = []
                        for q in parts[1:]:
                            if q.startswith("#"):
                                im = imm_of(q) or 0
                            elif re.fullmatch(r"[wx]sp|x\d{1,2}|w\d{1,2}", q.split()[0]):
                                extra.append(norm(q.split()[0]))
                        k = "read" if w in READ_MN else "write"
                        if reg.get(base):
                            for v in list(reg[base]):
                                if extra:
                                    for r2 in extra:
                                        for v2 in reg.get(r2, ()):
                                            note(k + "-indexed", v2)
                                    note(k + "-base", v)
                                else:
                                    note(k, (v + im) & MASK)
                if w not in ("add", "sub", "mov", "adrp") and ops:
                    d = [norm(x) for x in RE_R.findall(ops.split(",")[0])]
                    if d:
                        reg.setdefault(d[0], set())

    seen, per = set(), {}
    for va, tname, kind, (fn, off), chain in hits:
        if (va, tname, kind) in seen:
            continue
        seen.add((va, tname, kind))
        print("%016x  %-18s %-14s %-30s  chain %s" % (va, tname, kind, fn[:30], chain))
        per.setdefault(tname, set()).add(fn)
    for t in a.target:
        v = int(t, 16) if re.fullmatch(r"0x[0-9a-f]+", t) else byname.get(t)
        print("target %-24s sites=%-4d functions=%d" %
              (targets[v], sum(1 for h in seen if True and _n(h) == targets[v]), len(per.get(targets[v], ()))))
    for mh in a.must_hit:
        want, _, fn = mh.partition(":")
        got = [h for h in hits if h[1] == want and (not fn or h[3][0] == fn)]
        if not got:
            sys.exit("ARM FAILED: --must-hit %s.  Every 0-site line above is UNMEASURED, "
                     "not an absence." % mh)
        print("arm ok: %s -> %d site(s), first %016x/%s" % (mh, len(got), got[0][0], got[0][2]))
    print("# candidates are over-approximate: verify each quoted site by hand before citing it")
    print("# boundary: only adrp pages within 0x%x of a target are tried, within %d B after each site"
          % (a.near, a.window))


def _n(h):
    return h[1]


if __name__ == "__main__":
    main()
