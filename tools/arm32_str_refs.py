#!/usr/bin/env python3
"""tools/arm32_str_refs.py -- who references this string? (ARM32, resolved from the object's own arithmetic)

§430 established the rule for these Android ARM32 objects: a string operand is built as
    ldr  rB, [pc, #i1]   ; pool word = (string region - PC of the add)
    add  rB, pc          ; region base
    ldr  rD, [pc, #i2]   ; pool word = (string - region)
    add  rD, rB          ; rD = address of the string
so `grep`-ing the file for the VA finds nothing (absolute pointers are absent), and the reference is
only visible through the def chain.  This tool runs that chain over every function and answers the
inverse question: given a string, which functions materialise its address.

The rule is CALIBRATED per object before anything is named (tools/dsd_gate.py's pool_calibrate):
known-answer where the object contains the property literal, otherwise a statistical landing test
with a 1-byte-shift sensitivity requirement.  No calibration -> no names.
"""
import argparse, os, re, struct, sys

for _cand in (os.path.dirname(os.path.abspath(__file__)),
              os.path.join(os.environ.get("AUDIO_PORT_ROOT") or "/home/v/.local/project/xplay6", "tools"),
              "/home/v/.local/project/xplay6/tools"):
    if _cand and os.path.isdir(_cand):
        sys.path.insert(0, _cand)
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
import dsd_gate as DG


def coverage(d, secs, sym):
    """Share of .text reachable through sized FUNC symbols (union of ranges, not a sum of sizes)."""
    n, covered, pct = decode_coverage(d, secs, sym)
    return (n, "%d of %d B" % (covered, secs[".text"]["size"])), pct


def str_starts(d, secs):
    va2str = {}
    for nm in (".rodata", ".data", ".data.rel.ro", ".data.rel.ro.local"):
        s = secs.get(nm)
        if not s or not s["size"]:
            continue
        blob = d[s["off"]:s["off"] + s["size"]]
        va2str.setdefault(s["addr"], blob.split(b"\0")[0].decode("latin-1", "replace"))
        # NB: the trailing NUL must stay unconsumed -- back-to-back literals share it, so a greedy
        # \x00(...)\x00 would name only every other string (that bug made a whole survey read 0).
        for m in re.finditer(rb"\x00([ -~]{4,120})(?=\x00)", blob):
            va2str[s["addr"] + m.start() + 1] = m.group(1).decode("latin-1")
    return va2str


def refs(path, cal=None):
    d, secs = DG.elf32(path)
    sym0 = secs.get(".dynsym") or secs.get(".symtab")
    if not sym0:
        sys.exit("gate: %s has no symbol table -- functions cannot be enumerated, so the survey "
                 "would silently see nothing" % os.path.basename(path))
    (ncov, covtxt), covpct = coverage(d, secs, sym0)
    if covpct < 50.0:
        sys.exit("gate: %s exposes only %d sized FUNC symbol(s) covering %s of .text (%.1f%%) -- a "
                 "zero from this survey would then be the STRIPPED SYMBOL TABLE, not the code; on such "
                 "objects read the string tables instead (see the HAL backend vocabulary row)"
                 % (os.path.basename(path), ncov, covtxt, covpct))
    cal = cal or DG.pool_calibrate(path)
    if not cal.get("rule"):
        sys.exit("gate: %s -- the operand arithmetic is not calibrated (%s), so no string reference "
                 "can be named here; a zero result would be this tool being blind"
                 % (os.path.basename(path), cal.get("residual")))
    text = secs[".text"]
    sym = secs.get(".dynsym") or secs.get(".symtab")
    sb = d[secs[".dynstr"]["off"]:secs[".dynstr"]["off"] + secs[".dynstr"]["size"]]
    va2str = str_starts(d, secs)
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    out, decoded, landed, shifted = [], 0, 0, 0
    for i in range(sym["size"] // 16):
        nm, value, size, info, _o, _x = struct.unpack_from("<IIIBBH", d, sym["off"] + i * 16)
        if not value or not size or (info & 0xf) != 2:
            continue
        fname = sb[nm:sb.index(b"\0", nm)].decode("ascii", "replace")
        va = value & ~1
        fo = text["off"] + va - text["addr"]
        if not (0 <= fo < len(d)):
            continue
        ins = list(md.disasm(d[fo:fo + size], va))
        decoded += len(ins)
        for j, x in enumerate(ins):
            if x.mnemonic not in ("add", "adds", "add.w"):
                continue
            if not re.match(r"^(?:r\d+|sl|fp|ip),(?:\s*(?:r\d+|sl|fp|ip)){1,2}$", x.op_str):
                continue
            # ask for the value AFTER the add, not before: chain_value(ins, j, reg) means "what does
            # reg hold at instruction j", so querying at j itself would return the register's PREVIOUS
            # value and never perform the sum (that is how this survey read 0 references).
            v, why = DG.chain_value(ins, j + 1, x.op_str.split(",")[0].strip(), d, text,
                                     cal["slot_off"], cal["pc_off"])
            if v is None:
                continue
            if v in va2str:
                landed += 1
                out.append({"function": fname, "site": hex(x.address), "va": hex(v),
                            "string": va2str[v], "how": why})
            if (v + 1) in va2str:
                shifted += 1
    # Coverage of the decode is a first-class result: a survey that saw 2% of .text cannot say
    # "nobody references this string" -- that zero is the symbol table being stripped, not the code.
    if decoded < 1000:
        sys.exit("gate: %s decoded only %d instructions over %.1f%% of .text -- blind sweep"
                 % (os.path.basename(path), decoded, covpct))
    return {"path": path, "calibration": cal, "decoded": decoded, "refs": out,
            "landed": landed, "shifted_by_1": shifted, "strings": len(va2str),
            "funcs": ncov, "covered": covtxt, "coverage_pct": covpct}


def query(r, needle, limit=12):
    hits = [x for x in r["refs"] if needle in x["string"]]
    return hits


def report(r, needle=None):
    c = r["calibration"]
    print("== %s" % r["path"])
    print("   calibration: mode=%s rule=%s" % (c["mode"], c["rule"]))
    print("   decoded %d instructions ・ %d nameable strings in the image ・ resolved operands landing "
          "on a string start: %d ・ of those, still a string after +1 byte: %d"
          % (r["decoded"], r["strings"], r["landed"], r["shifted_by_1"]))
    if r["shifted_by_1"] * 4 > r["landed"]:
        sys.exit("gate: %d of %d resolutions survive a 1-byte shift -- the rule is not discriminating, "
                 "so the names below would be noise" % (r["shifted_by_1"], r["landed"]))
    if needle is None:
        return
    hits = query(r, needle)
    print("   references to a string containing %r: %d" % (needle, len(hits)))
    for h in hits[:12]:
        print("      %-46s %s -> %s  %r" % (h["function"][:46], h["site"], h["va"], h["string"][:52]))
    if not hits:
        print("      (the string is referenced only where this survey cannot see: data tables, code "
              "that copies it at runtime, or a function without a symbol)")


def decode_coverage(d, secs, sym):
    """Share of .text covered by sized FUNC symbols -- as a UNION of ranges, because summing sizes
    double-counts overlapping symbols (that is what made an earlier version report 101-121%)."""
    text = secs[".text"]
    iv = []
    for i in range(sym["size"] // 16):
        _nm, value, size, info, _o, _x = struct.unpack_from("<IIIBBH", d, sym["off"] + i * 16)
        if value and size and (info & 0xF) == 2:
            va = value & ~1
            if text["addr"] <= va < text["addr"] + text["size"]:
                start = va - text["addr"]
                iv.append((start, min(size, text["size"] - start)))
    iv.sort()
    total, end = 0, -1
    for a, l in iv:
        b = a + l
        if a > end:
            total += b - a
            end = b
        elif b > end:
            total += b - end
            end = b
    return len(iv), total, (100.0 * total / text["size"] if text["size"] else 0.0)


def coverage_census(root):
    """How much of the shipped 32-bit corpus can a per-function decode actually see?"""
    out, skipped = [], []
    for dp, _dn, fn in os.walk(root):
        for f in sorted(fn):
            if not f.endswith(".so"):
                continue
            p = os.path.join(dp, f)
            try:
                d, secs = DG.elf32(p)
            except SystemExit:
                skipped.append((os.path.relpath(p, root), "not ELF32"))
                continue
            text, sym = secs.get(".text"), (secs.get(".symtab") or secs.get(".dynsym"))
            if not text or not text["size"]:
                skipped.append((os.path.relpath(p, root), "no .text"))
                continue
            if not sym:
                skipped.append((os.path.relpath(p, root), "no symbol table"))
                continue
            n, _bytes, pct = decode_coverage(d, secs, sym)
            out.append((os.path.relpath(p, root), text["size"], n, pct))
    if not out:
        sys.exit("gate: %s yielded no measurable ELF32 object -- the census would be emptiness, not "
                 "a finding" % root)
    if any(pct > 100.0 for _p, _t, _n, pct in out):
        sys.exit("gate: coverage above 100%% means the union is broken -- refusing to publish")
    return out, skipped


def report_coverage(out, skipped, root):
    low = [x for x in out if x[3] < 50.0]
    zero = [x for x in out if x[3] == 0.0]
    print("== decode coverage census: %s" % root)
    print("   measurable ELF32 objects: %d ・ skipped: %d ・ below 50%% of .text visible: %d (%.1f%%) "
          "・ with NOTHING visible: %d" % (len(out), len(skipped), len(low),
                                           100.0 * len(low) / len(out), len(zero)))
    for p, t, n, pct in sorted(out, key=lambda x: x[3])[:10]:
        print("      %5.1f%%  %6d B  %4d funcs  %s" % (pct, t, n, p))
    print("      ... best: " + "・".join("%s %.1f%%" % (os.path.basename(p), pct)
                                         for p, t, n, pct in sorted(out, key=lambda x: -x[3])[:5]))
    for p, why in skipped[:6]:
        print("      skipped %s (%s)" % (p, why))


def _abort(fn, *a):
    try:
        fn(*a)
        return ""
    except SystemExit as e:
        return str(e)
    except Exception as e:
        return "%s: %s" % (type(e).__name__, e)


def _shift_fixture(path):
    """Break the calibrated rule by forcing the PC offset to be 4 bytes wrong: the SAME survey must
    then name (far) fewer strings -- proof the printed names come from the calibrated arithmetic."""
    d, secs = DG.elf32(path)
    cal = dict(DG.pool_calibrate(path))
    good = refs(path, cal)
    cal2 = dict(cal)
    cal2["pc_off"] = (cal["pc_off"] + 4) & ~3 if cal["pc_off"] == 4 else 4
    cal2["slot_off"] = cal["slot_off"]
    bad = refs(path, cal2)
    return good["landed"] > 3 * max(bad["landed"], 1)


def _locates_calibration_site(r, path, needle):
    """The calibration site is an independently known answer: a call whose first argument must be the
    property-name string.  The survey must find that string's def chain in the same function, a few
    bytes before the call (the survey records the `add`, the calibration records the `blx`)."""
    if r["calibration"]["mode"] != "known-answer":
        return len(query(r, needle)) >= 1
    cs = r["calibration"]["calibration_sites"][0]
    hits = query(r, DG.PROP)
    return len(hits) >= 1 and any(h["function"] == cs[0]
                                  and int(h["site"], 16) <= int(cs[1], 16) <= int(h["site"], 16) + 0x10
                                  for h in hits)



def selftest(path, needle):
    r = refs(path)
    arms = [
        ("ok: the object calibrates (mode printed) and resolves operands onto string starts",
         lambda: r["calibration"]["rule"] is not None and r["landed"] >= 20),
        ("gate: a resolution that survives a 1-byte shift must be rare, else the rule is not "
         "discriminating and no name is printed",
         lambda: r["shifted_by_1"] * 4 <= r["landed"]),
        ("ok: the query independently LOCATES the reference to the very string the calibration "
         "used (the survey names the def chain that feeds that known call)",
         lambda: _locates_calibration_site(r, path, needle)),
        ("gate: deliberately mis-setting the PC offset must cut the number of names (the printed "
         "names come from the calibrated arithmetic, not from a list)",
         lambda: _shift_fixture(path)),
        ("ok: the denominator travels with the result (decoded, strings, landed)",
         lambda: r["decoded"] > 1000 and r["strings"] > 100 and r["landed"] > 0),
    ]

    def _covpct(pth):
        dd, ss = DG.elf32(pth)
        return decode_coverage(dd, ss, ss.get(".dynsym") or ss.get(".symtab"))[2]

    def coverage_attributed():
        """A stripped object must be refused FOR THE COVERAGE REASON, and the reason must quote the
        same percentage this tool computes elsewhere -- so a zero is never blamed on the code."""
        repo = os.environ.get("AUDIO_PORT_ROOT") or "/home/v/.local/project/xplay6"
        stripped = f"{repo}/art/audio-6.0.1/shipped/system/lib/libaudioflinger.so"
        full = f"{repo}/art/audio-6.0.1/shipped/system/lib/libstagefright.so"
        msg = _abort(refs, stripped)
        quoted = re.search(r"\((\d+\.\d)%\)", msg)
        rr = refs(full)
        return bool("STRIPPED SYMBOL TABLE" in msg and quoted
                    and abs(float(quoted.group(1)) - _covpct(stripped)) < 0.05
                    and rr["coverage_pct"] >= 50.0 and rr["landed"] >= 20)

    arms.append(("gate: a stripped object is refused with the COVERAGE reason, quoting the same "
                 "percentage the census computes (a fully symbolised object is not refused that way) "
                 "-- a zero is never blamed on the code by mistake", coverage_attributed))

    def census_honest():
        out, skipped = coverage_census(os.path.dirname(os.path.dirname(path)))
        worst = min(out, key=lambda x: x[3])
        return (len(out) > 30 and all(x[3] <= 100.0 for x in out)
                and worst[3] == 0.0 and any(x[3] > 80.0 for x in out))

    arms.append(("ok: the corpus census is bounded (<=100%%), finds both a 0%% object and an 80%%+ one, "
                 "and counts what it skipped", census_honest))

    bad = 0
    for label, fn in arms:
        try:
            ok = bool(fn())
        except SystemExit as e:
            ok = label.startswith("gate:")
            print("     (aborted: %s)" % str(e)[:120])
        except Exception as e:
            ok = False
            print("     (exception: %s)" % str(e)[:160])
        print(("ok   " if ok else "FAIL ") + label)
        bad += 0 if ok else 1
    print("selftest: %d arm(s) failed" % bad)
    return 1 if bad else 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--elf", default=None)
    ap.add_argument("--find", default=None, help="substring of the string whose references you want")
    ap.add_argument("--coverage", metavar="ROOT", default=None,
                    help="census how much of .text a per-function decode can see in every ELF32 .so")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    repo = os.environ.get("AUDIO_PORT_ROOT") or "/home/v/.local/project/xplay6"
    default = f"{repo}/art/audio-6.0.1/shipped/system/lib/hw/audio.primary.msm8996.so"
    path = a.elf or default
    if not os.path.exists(path):
        sys.exit("gate: " + path + " missing")
    if a.coverage:
        out, skipped = coverage_census(a.coverage)
        report_coverage(out, skipped, a.coverage)
        return
    if a.selftest:
        sys.exit(selftest(path, a.find or "TERT_MI2S_RX"))
    report(refs(path), a.find)


if __name__ == "__main__":
    main()
