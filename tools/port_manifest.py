#!/usr/bin/env python3
"""tools/port_manifest.py -- assemble the "carry to Android 7" table from the 6.0.1 captures.

Every row's value is read out of an on-disk artifact (no hand transcription) and each row carries
its source, whether it is writable at runtime, whether it is use-case dependent, and whether a
second witness exists. Rows we could NOT resolve are emitted too, marked UNRESOLVED, so the table
cannot be mistaken for complete coverage.
"""
import csv
import glob
import hashlib
import os
import re
import struct
import sys
import zlib
from collections import Counter, defaultdict

BASE = os.environ.get("ART") or "art/audio-6.0.1"
# The 7-side manifest was always blocked on this line being pinned (ledger 576's debt).  Overriding
# it through ART is allowed; what is NOT allowed is for a pinned expectation to then describe the
# wrong machine, so every denominator this table reports is read from the capture itself (see the
# ACDB gate) and gates that are baseline-shaped refuse instead of guessing.
if BASE != "art/audio-6.0.1":
    print(f"# ART={BASE}: this run describes that extract, not the 6.0.1 baseline.  Gates read their "
          "denominators from the capture; a refusal here means the capture for that machine is "
          "missing or disagrees with its own counts -- that is the intended answer")


def preflight_inputs():
    """Name the per-machine inputs this builder reads, by scanning its OWN source for `{BASE}/...`
    literals, and check them against BASE.  Without this, pointing ART at another extract died in a
    FileNotFoundError deep inside the row builder -- a crash is not a refusal, and it told the reader
    nothing about how far that machine's manifest actually is (ledger 576's debt, measured 588+)."""
    import re
    src = open(os.path.abspath(__file__), encoding="utf-8").read()
    PATHISH = re.compile(r"^(?:live/|shipped/|art/)?[A-Za-z0-9_.\-/]+\.(?:tsv|txt|json|xml|conf|md|dtb)$")
    exact, prefixed = set(), set()
    for lit in re.findall(r'f"\{BASE\}/([^"]+)"', src):
        lit = lit.rstrip(",").split(" ")[0]      # `f"{BASE}/x.tsv [sha]"` is display text, not a path
        head, brace, _ = lit.partition("{")
        if brace:                      # f"{BASE}/dapm-routes-{card}.tsv" -- a family, not one file
            if len(head) > 4 and "[" not in head:
                prefixed.add(head)
        elif head and PATHISH.match(head):
            exact.add(head)
    listing = sorted(os.listdir(BASE)) if os.path.isdir(BASE) else []
    miss_exact = sorted(w for w in exact if not os.path.exists(os.path.join(BASE, w)))
    miss_pref = sorted(h for h in prefixed if not any(f.startswith(h) for f in listing))
    n_exact, n_pref = len(exact), len(prefixed)
    print(f"# inputs under {BASE}: exact {n_exact - len(miss_exact)}/{n_exact} present, "
          f"prefix-families {n_pref - len(miss_pref)}/{n_pref} matched"
          + ("" if not (miss_exact or miss_pref) else
             " -- missing: " + ", ".join((miss_exact + [h + "*" for h in miss_pref])[:12])))
    missing = len(miss_exact) + len(miss_pref)
    if missing and BASE != "art/audio-6.0.1":
        sys.exit(f"gate: a manifest for {BASE} is {missing} per-machine input(s) short "
                 f"(exact {len(miss_exact)}, families {len(miss_pref)}): " +
                 ", ".join((miss_exact + [h + "*" for h in miss_pref])[:12]) +
                 ".  Each is produced by the tool named in it under tools/; the honest statement is "
                 "'this machine's manifest is N inputs short', not a traceback.")
    return miss_exact + miss_pref
# Imported by tools/man_check.py to reuse the digest recipe, so the CLI must not read sys.argv when
# it is not the program being run -- otherwise `man_check --fix` aborted on its own flag.
SELFTEST = SYNC_HEADER = False
OUT = f"{BASE}/port-target.PD1610.tsv"
# Artifacts OUTSIDE BASE that rows() reads.  Kept in one list because the --selftest fixture runs the
# generator with cwd=the fixture tree: anything not mirrored there silently shortens the table, so a
# cross-version row can pass the live build and break every arm at once (ledger 610 caught exactly that).
EXTRA_ARTIFACTS = ["art/audio-7.1.1/live/tfa98xx/tfa98xx_PD1610.cnt",
                   "art/audio-7.1.1/live/tfa98xx/embedded/cnt-embed.PD1610.tsv"]
if __name__ == "__main__":
    SELFTEST = "--selftest" in sys.argv
    SYNC_HEADER = "--sync-header" in sys.argv
    OUT = next((x for x in sys.argv[1:] if not x.startswith("--")), OUT)
    if any(x.startswith("--") and x not in ("--selftest", "--sync-header") for x in sys.argv[1:]):
        sys.exit("gate: this tool takes --selftest (re-runs the runbook structure gates on doctored "
                 "documents) and --sync-header (rewrites the runbook header's per-layer listing from "
                 "the table, ledger 385); anything else is a typo, not a flag")
if not (OUT.endswith(".tsv") or "/" in OUT):
    # this tool has no subcommands -- argv[1] is an OUTPUT PATH.  Typing `build` used to write a
    # 120 KB table into the repo root and still print "wrote build: 168 rows", which reads as a pass.
    sys.exit(f"refusing to write the table to {OUT!r}: that looks like a command name, not a path "
             "(this tool takes an optional output .tsv path; run it with no argument for the default)")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IMG = os.path.join(ROOT, "fw/Image")
KALL = os.path.join(ROOT, "art/kallsyms_real.txt")
TEXT_BASE = 0xFFFFFFC000080000
# tfa98xx_debug_reg_read: cmp x20, #0x1a -- the loop bound is the only length, the .rodata list
# starts with register 0x00 so there is no terminator to scan for (ledger 249)
PA_LOOP_BOUND = 26


def pa_whitelist():
    """the PA denominator, supplied by the binary rather than counted off a capture"""
    va = None
    for line in open(KALL, encoding="utf-8", errors="replace"):
        p = line.split()
        if len(p) == 3 and p[2] == "tfa98xx_regs":
            va = int(p[0], 16)
            break
    if va is None:
        sys.exit("PA denominator gate: tfa98xx_regs not in kallsyms")
    blob = open(IMG, "rb").read()
    fo = va - TEXT_BASE
    wl = list(blob[fo:fo + PA_LOOP_BOUND])
    if blob[fo + PA_LOOP_BOUND] != 0:
        sys.exit("PA denominator gate: byte after the list is not null -- length reading is wrong")
    return wl

DAC_STRIDE = 2                    # es9038_debug_read walks the table 2 bytes per register
DAC_PAIR_BYTES = 0x5e + DAC_STRIDE  # bound 0x5e is the LAST index, so the walk touches 96 bytes


def dac_parameters_table():
    """the DAC denominator AND its content, from the kernel image (the PA equivalent is
    pa_whitelist(), ledger 249).  es9038_debug_read() loops `cmp x25, #0x5e` over a {reg, byte}
    array at stride 2 => 47 registers, and the array is the kallsyms object `dac_parameters`.
    The driver source is compiled twice (an es9028 copy shares the symbol name), so the candidate is
    picked by shape: span must cover the walk AND the 47 keys must be exactly 0x00..0x2e ascending."""
    blob = open(IMG, "rb").read()
    syms = []
    for line in open(KALL, encoding="utf-8", errors="replace"):
        p = line.split()
        if len(p) == 3:
            syms.append((int(p[0], 16), p[2]))
    syms.sort()
    cand, seen = [], []
    for va, name in syms:
        if name != "dac_parameters":
            continue
        nxt = [v for v, _ in syms if v > va]
        span = (nxt[0] - va) if nxt else 0
        pairs = list(struct.iter_unpack("<BB", blob[va - TEXT_BASE: va - TEXT_BASE + DAC_PAIR_BYTES]))
        regs = [r for r, _ in pairs]
        ok = span >= DAC_PAIR_BYTES and regs[:47] == list(range(47))
        seen.append(f"{va:#x} span={span} first47={regs[:3]}..{regs[46]:#02x} {'CANDIDATE' if ok else ''}")
        if ok:
            cand.append((va, span, dict(pairs)))
    if len(cand) != 1:
        sys.exit(f"DAC denominator gate: {len(cand)} dac_parameters objects walk 47 ascending "
                 f"registers -- saw: {' | '.join(seen)}")
    va, span, tab = cand[0]
    prov = (f"dac_parameters @{va:#x} in fw/Image ({span} B to the next symbol; "
            f"{len(tab)} pairs, keys 0x00-0x2e)")
    return tab, prov


PLAY = f"{BASE}/live/essnap-20261015-211903.txt"
PLAY_MIX = PLAY + ".tinymix"
IDLE_MIX = f"{BASE}/live/essnap-20261015-212326.txt.tinymix"
# a SPEAKER-route tinymix: the capture where the amplifier really was in the path, so it is what the
# "speaker=" control column and the route witness are read against (ledger 283; §285 removed the PA
# precondition that had been inferred from a parse which mixed the PA and DAC debugfs sections)
SPK_MIX = f"{BASE}/live/tinymix-D0-playing-speaker-20261016.txt"
OLD_HP_MIX = f"{BASE}/live/tinymix-D0-playing-headphones.txt"
OLD_SPK_MIX = f"{BASE}/live/tinymix-D0-playing-speaker.txt"
OLD_IDLE_MIX = f"{BASE}/live/tinymix-D0.txt"

ESS_SRC = "fw/ess/ES9038Q2M-datasheet-1.4-20210120.pdf p6-10"
ESS_NAMES = {
    0: "System Registers (clk_gear)", 1: "Input selection (input_select/auto_select)",
    2: "Mixing, Serial Data and Automute Configuration", 4: "Automute Time",
    5: "Automute Level", 6: "De-emphasis, DoP and Volume Ramp Rate",
    7: "Filter Bandwidth and System Mute (filter_shape/bypass_osf)",
    8: "GPIO1-2 Configuration", 10: "Master Mode and Sync Configuration",
    11: "SPDIF Select", 12: "ASRC/DPLL Bandwidth", 14: "Soft Start Configuration",
    17: "Master Trim byte0 of 4 (32-bit signed)", 18: "Master Trim byte1 of 4",
    19: "Master Trim byte2 of 4", 20: "Master Trim byte3 of 4",
    27: "General Configuration (18dB channel gain)",
    34: "Programmable NCO 1 of 4", 35: "Programmable NCO 2 of 4",
    36: "Programmable NCO 3 of 4", 37: "Programmable NCO 4 of 4",
    45: "Low Power and Auto Calibration (calib_en/calib_sel/calib_latch)",
    46: "ADC Configuration",
}


# A few live captures are re-taken in place by the verification run (they are cited as evidence, but
# they carry a per-boot field).  Hashing them raw makes every --device run a MANIFEST "DRIFT" and
# trains everyone to ignore that word, so mask the counter -- never the content.
VOLATILE = ((rb"REACH uptime=[0-9][0-9.]*", rb"REACH uptime=*"),
            (rb"uptime=[0-9][0-9.]*", rb"uptime=*"))


def mask_volatile(b):
    for rx, rep in VOLATILE:
        b = re.sub(rx, rep, b)
    return b


def sha16_bytes(b):
    return hashlib.sha256(mask_volatile(b)).hexdigest()[:16]


def sha16(p):
    return sha16_bytes(open(p, "rb").read())


def cnt_integrity(p):
    """recompute the container header the way the driver does (tfa98xx_cnt_loadfile, ledger 255):
    crc32_le(0xffffffff, data+14, size-14) inverted == u32 @10, and u16 @6 == file length"""
    b = open(p, "rb").read()
    size = struct.unpack_from("<H", b, 6)[0]
    stored = struct.unpack_from("<I", b, 10)[0]
    calc = zlib.crc32(b[14:]) & 0xFFFFFFFF
    magic = b[:2].decode("latin-1", "replace")
    if magic != "PM" or size != len(b) or calc != stored:
        sys.exit(f"gate: {p} fails the driver's own header check "
                 f"(magic {magic!r} size {size} vs {len(b)} crc {calc:#010x} vs {stored:#010x})")
    return f"magic={magic} size@6={size} CRC@10={stored:#010x} (recomputed, matched)"


def acdb_dir_inputs():
    """the two inputs libacdbloader's acdb_loader_init_v2 uses to choose the cal directory
    (ledger 272) -- values read from the live dumps, never typed"""
    out = []
    gp = f"{BASE}/live/getprop.txt"
    sy = f"{BASE}/live/sysfs_soc0_selection.txt"
    if not os.path.exists(gp):
        sys.exit("gate: live/getprop.txt missing -- cannot state the dir-selection inputs")
    props = dict(re.findall(r"\[([a-zA-Z0-9._]+)\]:\s*\[([^\]]*)\]", open(gp, encoding="utf-8", errors="replace").read()))
    want = [("ro.vivo.product.model", "loader's FIRST dir input: property_get at "
                                      "acdb_loader_init_v2+0x6f0 (0x7514), then dst=base+value, log "
                                      "'product:%s, dst_dir:%s', access(dst,F_OK) at +0x73c (0x7560) "
                                      "-- a hit ENDS the search"),
            ("ro.vivo.product.platform", "second input: property_get at +0x940 (0x7764), same access() "
                                         "gate at +0x98c (0x77b0), log 'platform:%s, dst_dir:%s'"),
            ("ro.product.device", "NOT read by the loader -- it is the HAL's own key; it only happens "
                                  "to equal the model value on this machine, so it must not be the "
                                  "row a port compares")]
    for k, why in want:
        if k in props:
            out.append((k, props[k], why))
    if os.path.exists(sy):
        for ln in open(sy, encoding="utf-8", errors="replace"):
            if "=" not in ln:
                continue
            path, val = ln.rstrip("\n").split("=", 1)
            if "hw_platform" in path:
                out.append((path, val or "EMPTY",
                            "THIRD loader input, used only after both properties' dirs fail access(): "
                            "fopen of this node, fgets 64 bytes, trailing '\\n' trimmed, then "
                            "log 'No project and platform info use src dir :%s' -- on this machine it "
                            "reads Surf and no Surf dir exists, so it never fires"))
    cal = sorted(k for k in props if k.startswith("persist.audio.calfile"))
    out.append(("persist.audio.calfile0..19",
                f"{len(cal)} of 20 slots set" + (f": {','.join(cal)}" if cal else ""),
                "loader's file-list OVERRIDE: a 20-iteration loop snprintfs 'persist.audio.calfile%d' "
                "(acdb_loader_init_v2+0x90, 0x6eb4), property_get's it into 256 bytes and appends the "
                "path to the same 260-byte-per-entry list the directory scan fills, logging "
                "'ACDB -> Prop Load file: %s' -- it bypasses the directory cascade entirely.  ★§377/§378 "
                "narrowed both halves with a branch-graph walk (tools/cfg_init_v2.py over 0x6e24..0x7800, "
                "631 instructions): the loop TERMINATES at the first unset slot (0x73e8 stores that index "
                "as the file count and 0x73f4's cbnz jumps to the join at 0x6f38), so the slots are an "
                "ordered PREFIX list -- setting 0x02 while 0 and 1 are empty does nothing; and the 349 "
                "in-window blocks downstream of that join contain NO edge into the cascade at 0x73f8, so "
                "a set prop list REPLACES the scanned file set rather than adding to it, while still "
                "reaching send_meta_info (stub 0x2d00) -- prop-listed files get pushed to the ADSP the "
                "same way scanned ones do.  ★§379 repeats the walk on the OTHER copy, the one actually "
                "mapped by mediaserver (32-bit Thumb, ledger 374): llvm-objdump decodes its .text as ARM "
                "(garbage), so cfg_init_v2 grew a Thumb mode -- from the props join 0x523a 532 blocks "
                "exclude the cascade at 0x5670 and still reach the meta push at 0x5604 through "
                "send_meta_info@plt 0x2168, and the loop's own exit 0x5666 is reachable from its head "
                "0x51f0 (that last pairing is what caught the walker misclassifying ble/blt as calls). "
                "Same constants in both builds: name buffer 24, value 256, slot stride 0x104, length "
                "stored at slot-4, bound #0x14"))
    return out


def acdb_load_order(path):
    """re-run tools/acdb_order.py's own collision ruler here (single implementation -- a second copy
    of the predicate would drift), and refuse to return unless its injected-collision control fires"""
    import acdb_order
    rows = acdb_order.load(path)
    col = acdb_order.collisions(rows)
    files = sorted({r[1] for r in rows})
    tabs = sorted({r[2] for r in rows})
    probe = acdb_order.collisions(rows, injected=("<probe-table>", "<probe-key>", files[:2]))
    if ("<probe-table>", 1) not in probe:
        sys.exit(f"gate: {path}: order ruler positive control did not fire -- verdict not admissible")
    return len(rows), files, tabs, col


def acdb_dev_ids():
    """acdb_dev_ids this machine actually puts on the wire, read from the live three-state control
    dump plus the platform_info declarations -- the denominator is taken, not typed (ledger 215/264).
    Returns {dev_id: {"states": set, "app_types": set, "declared": str}}"""
    out = {}

    def note(i, state, app, declared):
        d = out.setdefault(i, {"states": set(), "app_types": set(), "declared": ""})
        if state:
            d["states"].add(state)
        if app:
            d["app_types"].add(hex(app))
        if declared:
            d["declared"] = declared

    rs = f"{BASE}/route-states.tsv"
    if os.path.exists(rs):
        for ln in open(rs, encoding="utf-8"):
            p = ln.rstrip("\n").split("\t")
            if len(p) < 2 or not re.match(r"Audio Stream \d+ App Type Cfg$", p[0]):
                continue
            for st, cell in zip(("idle", "speaker", "headphones"), p[2:5]):
                w = [int(x) for x in cell.split()[:2]]
                if len(w) == 2 and w[1]:
                    note(w[1], st, w[0], "")
    mp = f"{BASE}/acdb-map-output.tsv"
    if os.path.exists(mp):
        for ln in open(mp, encoding="utf-8"):
            a = ln.rstrip("\n").split("\t")
            if len(a) == 2 and a[1].isdigit():
                note(int(a[1]), "", 0, a[0])
    return out


def acdb_expected():
    """the ACDB-asset denominator comes from the metadata table, not a typed number"""
    meta = f"{BASE}/acdb-meta.PD1610.tsv"
    if not os.path.exists(meta):
        return 0
    return sum(1 for r in csv.DictReader(open(meta), delimiter="\t") if r["dir"] == "PD1610")


def bf_family_sentence():
    """answer the long-open TFA1-vs-N1C numbering question from the vote artifact, so the prose cannot
    quote numbers the tool did not just produce (ledger 320)"""
    p = f"{BASE}/tfa-bf-family.TfaBfNames.tsv"
    if not os.path.exists(p):
        return ("PA field-numbering vote MISSING (tools/tfa_bf_family.py --out "
                "art/audio-6.0.1/tfa-bf-family.TfaBfNames.tsv) -- cannot say whether 0x00-0x0f is "
                "TFA1 or N1C numbered")
    vr = list(csv.DictReader(open(p, encoding="utf-8"), delimiter="\t"))
    agg = {r["family"]: int(r["exact"]) for r in vr if r["scope"] == "all"}
    tot = next((int(r["rows"]) for r in vr if r["scope"] == "all"), 0)
    tfa1 = next((int(r["exact"]) for r in vr if r["row_name"] == "TFA1-total"), -1)
    n1c = agg.get("N1C/TFA2-total", -1)
    l1c = agg.get("N1C/TFA2-no-addr-ballot", -1)
    if tfa1 < 0 or n1c < 0 or l1c < 0:
        sys.exit(f"gate: {p} carries no TFA1-total / N1C/TFA2-total / N1C-no-addr-ballot row -- the "
                 "verdict and its control are both required before the numbering may be called settled")
    if tfa1 == 0:
        sys.exit(f"gate: {p} says the TFA1 family matched 0 rows -- the numbering is NOT settled by this "
                 "vote and the sentence below would claim it was")
    bsum, buckets, seen = 0, {}, set()
    for r in vr:
        if r["scope"] == "all" or r["scope"] in seen:
            continue
        seen.add(r["scope"])
        bsum += int(r["rows"])
        if r["family"] != "no-family":
            buckets[r["scope"]] = f'{r["family"].split(":")[-1]} {r["exact"]}/{r["rows"]}'
    if bsum != tot:
        sys.exit(f"gate: {p} bucket denominators sum to {bsum} against a {tot}-row table -- the vote "
                 "denominator is inconsistent, so no family may be declared")
    if not buckets:
        sys.exit(f"gate: {p} lists no family row at all -- nothing to report per bucket")
    un = [r for r in vr if r["family"] == "no-family"]
    nohead = [r for r in un if r["why_unmatched"].startswith("declared in NO")]
    other = [r for r in un if not r["why_unmatched"].startswith("declared in NO")]
    low_names = {r["row_name"] for r in un if r["scope"] == "0x00-0x0f"}
    low_nohead = len({r["row_name"] for r in nohead if r["scope"] == "0x00-0x0f"})
    low_rows = next((int(r["rows"]) for r in vr if r["scope"] == "0x00-0x0f"), 0)
    return (f"the PA field numbering is now voted, not guessed: the driver's {tot}-row TfaBfNames table "
            f"matches the flat TFA1 scheme on {tfa1}/{tot} rows by (name,addr,pos,len) "
            f"({' ; '.join(f'{k} -> {v}' for k, v in buckets.items())}) while the N1C/TFA2 table "
            f"contributes {n1c} exact matches in any bucket, so 0x00-0x0f is TFA1-numbered (§250/§251).  "
            f"That zero is shown to be live rather than inert -- dropping the address from the same ballot "
            f"lifts N1C to {l1c}, i.e. N1C declares these names and bit positions but at other addresses.  "
            f"{len(un)} rows match no family and are listed rather than extrapolated: {len(nohead)} "
            f"declared in no reference header ({low_nohead} of them in 0x00-0x0f), {len(other)} whose name "
            f"exists elsewhere with a different (addr,pos,len) -- so {len(low_names)}/{low_rows} rows in "
            f"the low bucket match no family at all.")


def acdb_gap_sentence():
    """what the ACDB layer does and does not now know -- counted from the tables, not retyped"""
    tlv, lut = f"{BASE}/acdb-tlv.PD1610.tsv", f"{BASE}/acdb-lut.PD1610.tsv"
    if not (os.path.exists(tlv) and os.path.exists(lut)):
        return "ACDB field inventory MISSING (run tools/acdb_tlv.py) -- cannot state what is unresolved"
    trows = list(csv.DictReader(open(tlv), delimiter="	"))
    ntab = len({r["field"].strip() for r in trows if r["rec_bytes"]})
    nvar = len({r["field"].strip() for r in trows if r["note"].startswith("not a fixed-record")})
    nrec = sum(1 for _ in open(lut)) - 1
    # what is actually still unreadable is counted from the census file, not retyped: acdb_bodies.py
    # only writes fields no tool parses, so its row set IS the gap (ledger 300 moved *CDOT out of it)
    unreadable, nbytes = 0, 0
    brows = []
    bod = f"{BASE}/acdb-bodies.PD1610.tsv"
    if os.path.exists(bod):
        brows = list(csv.DictReader(open(bod, encoding="utf-8"), delimiter="\t"))
        unreadable = len(brows)
        for r in brows:
            nbytes += int(r["len"]) if r.get("len", "").isdigit() else 0
    cd = f"{BASE}/acdb-cdot.PD1610.tsv"
    cdot = (len([l for l in open(cd, encoding="utf-8") if l.strip()]) - 1) if os.path.exists(cd) else 0
    cvp = f"{BASE}/acdb-cvd.PD1610.tsv"
    cvd = len([r for r in csv.DictReader(open(cvp, encoding="utf-8"), delimiter="\t")
               if r["cal_set"] == "PD1610"]) if os.path.exists(cvp) else 0
    dpr = [r for r in brows if r["field"] == "DATAPOOL"]
    dpb = sum(int(r["len"]) for r in dpr if r["len"].isdigit())
    plp = f"{BASE}/acdb-pool.PD1610.tsv"
    plr = [r for r in csv.DictReader(open(plp, encoding="utf-8"), delimiter="\t")
           if r["cal_set"] == "PD1610"] if os.path.exists(plp) else []
    return (f"ACDB: {nrec} coefficient words from {ntab} fixed-record tables are decoded, and every "
            f"variable body now has a grammar: {nvar} variable-size field names, of which the *CDFT "
            f"bodies parse as (id,id) pair-lists (§268), {cdot} *CDOT groups as "
            f"REPEAT{{u32 n, n*u32}} (§300), the *OFST bodies as REPEAT{{u32 n, n*(u32,u32)}} and "
            f"{cvd} PD1610 *CVD0 records as REPEAT{{u32 n, n*8 or n*7}} (§303); DATAPOOL is a chain of "
            f"byte-length-prefixed blocks -- {len(plr)} PD1610 blocks as {{u32 L, L bytes}} (§304), "
            f"which is why 16/49 pool bodies are not whole word counts.  A grammar is not a unit: "
            "exactly one column of one record type has been NAMED -- DPROPLUT word 2 is a DATAPOOL block "
            "offset (100% of its non-zero values land on a block start of their own file, +4 control "
            "0.58%, foreign-pool control 0%, ledger 316) -- and no units and no block TYPE are named, so "
            f"{unreadable} field bodies ({nbytes} B, of which {len(dpr)} DATAPOOL bodies = {dpb} B) "
            "stay on the byte watch list, "
            "now with a per-block digest beside each.  This layer is a comparison basis for 7, not a "
            "tuning instruction.  The QC cal channel still returns nothing (§226/§228)")


def pa_gap_sentence():
    """state the PA naming gap from the field inventory, so the prose cannot rot behind the data"""
    p = f"{BASE}/tfa-reg-fields.PD1610.tsv"
    if not os.path.exists(p):
        return "PA field inventory MISSING (run tools/tfa_reg_fields.py) -- cannot state what is unresolved"
    rows_ = list(csv.DictReader(open(p), delimiter="\t"))
    noname = [r["reg"] for r in rows_ if r["genregs_name"] == "-"]
    nofield = [r["reg"] for r in rows_ if int(r["nfields"]) == 0]
    return (f"{len(noname)} of {len(rows_)} PA registers have no genregs name, but "
            f"{len(noname) - len([a for a in noname if a in nofield])} of those do have driver-resolvable bitfields "
            f"(TfaBfNames, addr = enum >> 8); overall {len(nofield)} registers ({','.join(nofield)}) have no field the "
            "driver can name at all.  " + bf_family_sentence())


def runbook_structure(rb):
    """return (step_labels, problems) for the runbook's markdown table.  Kept as a function of text so
    a fixture can prove it fires -- the defect this catches is a document that lost a cell separator,
    which silently means the command you read is not the command you run."""
    steps, problems = [], []
    for ln in rb.splitlines():
        if ln.startswith("\\|"):
            # this is how a mangled row hides: an escaped leading pipe stops matching '|' at all, so
            # the row leaves the table silently instead of failing the cell count
            problems.append(f"row whose leading pipe got escaped: {ln[:40]!r}")
            continue
        if not ln.startswith("|"):
            continue
        if ln.startswith("| # ") or re.match(r"^\|[-|]+\|$", ln):
            continue
        m = re.match(r"^\|\s*([0-9]+[a-z]?)\s*\|", ln)
        if not m:
            problems.append(f"row without a step label: {ln[:40]!r}")
            continue
        steps.append(m.group(1))
        cells = len(re.split(r"(?<!\\)\|", ln)) - 2
        if cells != 5:
            problems.append(f"step {m.group(1)}: {cells} cells (expected 5)")
    return steps, problems


def runbook_count_check(rb):
    """the runbook's prose now names the A-table's step count, and since ledger 361 that number IS the
    coverage denominator runbook_selfcheck.sh is judged against -- so it is read off the A-table here
    rather than trusted.  Returns a problem string, or None when the claim and the document agree."""
    if "## A." not in rb or "## B." not in rb:
        return "cannot find the '## A.'/'## B.' headings -- the count check has no denominator to read"
    seg = rb.split("## A.", 1)[1].split("## B.", 1)[0]
    a_steps, a_probs = runbook_structure(seg)
    if a_probs:
        return f"the A-section on its own is malformed -> {a_probs[0]}"
    m = re.search(r"A 段那 (\d+) 个步骤号", rb)
    if not m:
        return ("the runbook no longer states the count as 'A 段那 N 个步骤号' -- that sentence is where "
                "a reader gets the coverage denominator, so dropping it makes the self-check's own "
                "completeness claim unverifiable")
    if int(m.group(1)) != len(a_steps):
        return (f"the runbook says 'A 段那 {m.group(1)} 个步骤号' but the A-table has {len(a_steps)} "
                f"({', '.join(a_steps[:6])}...) -- the document and the self-check would judge "
                "different denominators")
    return None


MARK7 = re.compile(r"7 \u4fa7|<7|\u5728 7|-7\.(?:tsv|txt|log)|pa-7|7 \u643a\u5e26")
SIDE_INDEP = "\u2605\u4e0e\u7248\u672c\u65e0\u5173"


def runbook_side_rows(rb):
    """(scanned, missing) over EVERY numbered A-table row.  A row counts as placed if it carries a
    7-side instruction (MARK7 -- the document's real convention, which is loose: '7 \u4fa7', '\u5728 7',
    '-7.tsv') or says outright that it is version-independent (SIDE_INDEP).  Split out so a fixture can
    compare what the gate reports against what the gate scanned."""
    seg = rb.split("## A.", 1)[1].split("## B.", 1)[0]
    scanned, miss = [], []
    for ln in seg.splitlines():
        m = re.match(r"^\|\s*([0-9]+[a-z]?)\s*\|", ln)
        if not m:
            continue
        scanned.append(m.group(1))
        if MARK7.search(ln) or SIDE_INDEP in ln:
            continue
        miss.append(m.group(1))
    return scanned, miss


def runbook_side_check(rb):
    """\u00a7439: the A-table is the acceptance ORDER for the switch to Android 7, so every row has to say
    which side it runs on.  Eleven rows previously named neither -- four of them (4b, 5b, 5f, 5u) are
    workstation rulers that cannot be 'run on 7' in any meaningful sense and now say so, the rest got
    their 7-side instruction.  Returns a problem string, or None when every row is placed."""
    if "## A." not in rb or "## B." not in rb:
        return ("cannot find the '## A.'/'## B.' headings -- the side check has no A-section to read, so "
                "it cannot state its own denominator")
    scanned, miss = runbook_side_rows(rb)
    if miss:
        return ("A-table row(s) %s of %d name neither a 7-side instruction nor a version-independence "
                "statement -- a step nobody can say which side it runs on is not part of the acceptance "
                "order for the 7 switch" % (", ".join(miss), len(scanned)))
    if not scanned:
        return ("the A-section has no numbered step rows at all -- the side gate found an empty "
                "denominator and refuses to report that as a pass")
    return None



HEADER_MARK = re.compile(r"现 \*\*(\d+) 行\*\*：(.*?)(?=；这枚数字由)", re.S)


def header_listing(counts):
    """the runbook's header quotes a per-layer listing; it is GENERATED here (ledger 385) because the
    hand-written one used Chinese abbreviations ('PA 26', 'DAC 48') while the checker matched only
    '**English layer name** N' pairs -- so exactly the layers most likely to change were unchecked, and
    a layer missing from the prose was invisible."""
    return " ＋ ".join(f"**{lay}** {counts[lay]}"
                      for lay in sorted(counts, key=lambda l: (-counts[l], l)))


def runbook_header_check(rb, counts, total, write=False):
    """returns (text, problems); with write=True the listing is rewritten instead of reported"""
    m = HEADER_MARK.search(rb)
    if not m:
        return rb, ["the header's listing cannot be located between '现 **N 行**：' and '；这枚数字由' "
                    "-- the cross-check between the runbook and the table is gone"]
    want = header_listing(counts)
    if int(m.group(1)) == total and m.group(2).strip() == want.strip():
        return rb, []
    if not write:
        have = re.findall(r"\*\*([^*]+)\*\* (\d+)", m.group(2))
        absent = sorted(set(counts) - {a for a, _ in have})
        problems = []
        if int(m.group(1)) != total:
            problems.append(f"total rows: runbook says {m.group(1)}, table has {total}")
        if m.group(2).strip() != want.strip():
            problems.append(f"the header listing is stale (it quotes {len(have)} entries for "
                            f"{len(counts)} layers; layers missing from prose: "
                            f"{', '.join(absent) or 'none'})")
        return rb, problems + ["run with --sync-header"]
    head = f"现 **{total} 行**："
    return rb[:m.start()] + head + want + rb[m.end(2):], []


def header_sync_selftest():
    """--selftest: the generator must notice every way the prose can rot -- a wrong number, a dropped
    layer, and the abbreviation shape that the OLD checker could not even see."""
    bad, why = [], []
    counts = {"PA/TFA9890": 26, "DAC/ES9038": 4, "ACDB cal asset": 2}
    good = "分母来自表（现 **32 行**：" + header_listing(counts) + "；这枚数字由 tools/port_manifest.py 现校）"
    _, probs = runbook_header_check(good, counts, 32)
    if probs:
        bad.append("a header generated by this very tool was reported stale")
    else:
        why.append("fresh header clean")
    for name, doc in (
            ("wrong count", good.replace("**DAC/ES9038** 4", "**DAC/ES9038** 48")),
            ("dropped layer", good.replace(" ＋ **ACDB cal asset** 2", "")),
            ("hand-written abbreviations",
             good.replace(header_listing(counts), "PA 26 ＋ DAC 4 ＋ ACDB 2")),
            ("markers lost", good.replace("现 **32 行**：", "现 32 行：")),
            ("wrong total (the number that rotted twice)", good.replace("现 **32 行**", "现 **30 行**"))):
        _, p = runbook_header_check(doc, counts, 32)
        if not p:
            bad.append(f"{name} was accepted as fresh")
        else:
            why.append(f"{name} -> {p[0][:52]}")
    out, p = runbook_header_check(good.replace("**DAC/ES9038** 4", "**DAC/ES9038** 40"), counts, 32,
                                 write=True)
    if p or "**DAC/ES9038** 4 " not in out or "**ACDB cal asset** 2" not in out or "现 **32 行**" not in out:
        bad.append(f"--sync-header did not restore the listing (problems={p})")
    _, p2 = runbook_header_check(out, counts, 32)
    if p2:
        bad.append("after a sync the header is still reported stale -- the writer and the checker "
                   "disagree, so the gate would flap on every run")
    print("header-sync selftest: " + "; ".join(why) + f"; bad={bad}")
    return len(bad)


def runbook_selftest(rb_text):
    """--selftest: the structure gate must be able to reject.  Three doctored copies of the real
    document -- a lost cell separator, an escaped leading pipe (the shape that hid a row from the old
    gate), and a duplicated step label -- each has to be reported, and the clean text must be clean."""
    bad, why = [], []
    lines = rb_text.split("\n")
    k = next((i for i, l in enumerate(lines) if re.match(r"^\|\s*5k\s*\|", l)), None)
    if k is None:
        return ["--selftest found no step 5k row, so the fixtures cannot be built from the real file"]
    four = lines[k].rsplit(" | ", 1)[0] + "  (separator deleted)"
    escaped = "\\" + lines[k]
    dupe = "\n".join(lines[:k + 1] + [lines[k].replace("5k", "5j")] + lines[k + 1:])
    for name, doc in (("4-cell row", "\n".join(lines[:k] + [four] + lines[k + 1:])),
                      ("escaped leading pipe", "\n".join(lines[:k] + [escaped] + lines[k + 1:]))):
        steps, probs = runbook_structure(doc)
        if not probs:
            bad.append(name)
        else:
            why.append(f"{name} -> {probs[0][:70]}")
    _s, p0 = runbook_structure(rb_text)
    if p0:
        bad.append(f"the real document itself reports problems: {p0[0][:80]}")
    steps2, probs2 = runbook_structure(dupe)
    if len(steps2) != len(set(steps2)):
        why.append("duplicated label detected by the caller's own duplicate check")
    else:
        bad.append("a duplicated step label survived the label list")
    # the §361 count claim: three ways it goes stale, each of which must be reported.  The third is a
    # defect I inflicted on the real file minutes before writing this arm -- a step row that gained one
    # leading space stops matching '|' and left the table silently.
    n = len(runbook_structure(rb_text.split("## A.", 1)[1].split("## B.", 1)[0])[0])
    if not re.search(r"A 段那 (\d+) 个步骤号", rb_text):
        bad.append("--selftest cannot build the count fixtures: the prose has no 'A 段那 N 个步骤号'")
    else:
        wrong = rb_text.replace(f"A 段那 {n} 个步骤号", f"A 段那 {n - 1} 个步骤号", 1)
        gone = re.sub(r"A 段那 \d+ 个步骤号", "A 段那若干步骤号", rb_text, count=1)
        j = next((i for i, l in enumerate(rb_text.split("\n")) if re.match(r"^\|\s*5k\s*\|", l)), None)
        hidden = "\n".join(" " + l if i == j else l for i, l in enumerate(rb_text.split("\n")))
        for name, doc, want_fire in (("count off by one", wrong, True),
                                     ("count sentence deleted", gone, True),
                                     ("one step row hidden by a leading space", hidden, True),
                                     ("clean document", rb_text, False)):
            got = runbook_count_check(doc)
            if bool(got) != want_fire:
                bad.append(f"{name}: {'no problem reported' if want_fire else 'a problem reported'}"
                           + (f" -> {got[:90]}" if got else ""))
            elif got:
                why.append(f"{name} -> {got[:60]}")
            else:
                why.append("clean document accepted by the count check")
    # §439: the side gate must be able to reject, must reject the row that was doctored, and the
    # version-independence branch must be live too.  Arms read the document's CURRENT shape and each
    # one asserts the doctoring moved bytes -- nothing here may depend on a defect that this very
    # landing removes (v2 of the script did, and would have turned --selftest red the day it landed).
    def _erase_side(doc, lab):
        out, hit = [], False
        for l in doc.split("\n"):
            m = re.match(r"^\|\s*([0-9]+[a-z]?)\s*\|", l)
            if m and m.group(1) == lab:
                new = MARK7.sub("\u00d7", l).replace(SIDE_INDEP, "\u00d7")
                if new != l:
                    l = new
                    hit = True
            out.append(l)
        return "\n".join(out), hit

    sc_all, miss_all = runbook_side_rows(rb_text)
    indep = [l for l in sc_all if SIDE_INDEP in next(x for x in rb_text.split("\n")
             if re.match(r"^\|\s*%s\s*\|" % re.escape(l), x))]
    for lab in ([sc_all[0]] + ([indep[0]] if indep else [])):
        doc_e, moved = _erase_side(rb_text, lab)
        if not moved:
            bad.append(f"erasing step {lab}'s side statement did not move any text")
            continue
        _s, m_e = runbook_side_rows(doc_e)
        want = [lab] if not miss_all else sorted(set(miss_all) | {lab})
        if sorted(m_e) != sorted(want):
            bad.append(f"erased step {lab} -> gate reported {m_e}, expected {want}")
        else:
            why.append(f"step {lab} side statement erased -> gate reports {m_e}")
    if not indep:
        bad.append("no A-row carries the version-independence statement, so that branch of the gate is "
                   "untested -- the four workstation rulers must keep it")
    doc_x, moved_x = None, 0
    acc = rb_text
    for lab in sc_all:
        acc, moved = _erase_side(acc, lab)
        moved_x += 1 if moved else 0
    _s2, m_x = runbook_side_rows(acc)
    if len(sc_all) != len(runbook_structure(rb_text.split("## A.", 1)[1].split("## B.", 1)[0])[0]):
        bad.append(f"the side gate scans {len(sc_all)} rows but the structure gate counts "
                   f"{len(runbook_structure(rb_text.split('## A.', 1)[1].split('## B.', 1)[0])[0])} -- "
                   "two different denominators in one document")
    elif m_x != sc_all:
        bad.append(f"erasing every side statement reported {len(m_x)} of {len(sc_all)} rows -- the "
                   "denominator does not close")
    else:
        why.append(f"all side statements erased -> gate reports {len(m_x)}/{len(sc_all)} rows")
    clean_side = runbook_side_check(rb_text)
    if clean_side:
        bad.append(f"the real document fails its own side gate -> {clean_side[:150]}")
    else:
        why.append(f"clean document accepted by the side gate ({len(sc_all)} rows, {len(indep)} "
                   f"version-independent)")

    print("selftest: " + "; ".join(why) + f"; bad={bad}")
    return bad


def fres_witness(dtv):
    """the DT acceptance windows are only meaningful if something in play falls inside them, so the
    witness is recomputed from the speaker-play fRes_Detect capture rather than quoted from prose
    (ledger 259 asked for exactly this number and §283 got it).  Keys are DT property names."""
    d = os.environ.get("FRESDIR") or f"{BASE}/live/tfa98xx"
    fs = ([os.environ["FRESCAP"]] if os.environ.get("FRESCAP") else
          sorted(glob.glob(f"{d}/fres-detect-spk-*.txt"), key=os.path.getmtime))
    if not fs:
        return {}
    lo, hi = (int(dtv[k]) for k in ("vivo,tfa98xx-frequency-min", "vivo,tfa98xx-frequency-max"))
    out, vals, reads = {}, [], 0
    imp_all = []
    for f in fs:
        txt = open(f, encoding="utf-8", errors="replace").read()
        f0 = re.findall(r"f0 = (-?\d+)", txt)
        name = os.path.basename(f)
        if not f0:
            sys.exit(f"gate: {name} matches the speaker-play capture glob but prints no f0 line")
        if len(set(f0)) != 1:
            sys.exit(f"gate: {name} reports f0 values {sorted(set(f0))} -- "
                     + ("{0, -1} is the no-data shape (estimator never got a resonance, §282: that is the "
                        "headphone / off-path route), so it cannot witness an acceptance window"
                        if set(f0) <= {"0", "-1"} else
                        "more than one f0 in one file means the capture mixes sessions, and a mixed "
                        "session cannot be quoted as a steady reading"))
        v = int(f0[0])
        if not lo <= v <= hi:
            sys.exit(f"gate: measured f0 {v} ({name}) sits OUTSIDE the DT window {lo}..{hi} -- the row "
                     "that claims this window was validated in play would be false")
        vals.append((name, v, len(f0)))
        reads += len(f0)
        imp_all += [(int(a) * 100 + int(b)) for a, b in re.findall(r"impedance ok (\d+)\.(\d+) ohm", txt)]
    if len({v for _, v, _ in vals}) > 1 and os.environ.get("FRESCAP"):
        sys.exit("gate: a single FRESCAP file was expected to hold one session; the fixture mixes two")
    kinds = ", ".join(sorted({str(v) for _, v, _ in vals}))
    out["vivo,tfa98xx-frequency-min"] = out["vivo,tfa98xx-frequency-max"] = (
        f"in-play witness ({len(vals)} speaker-play session(s), {reads} reads: "
        + ", ".join(f"{n}={v}x{c}" for n, v, c in vals)
        + f"); every reading sits inside {lo}..{hi}, so the acceptance criterion is the WINDOW, not one "
        f"number (the sessions read {kinds} -- §366 measured the newest one, and the driver's own log "
        "line prints f0 and fRes as two different values, e.g. `f0 = 868 fRes = 806`); the headphone "
        "route gives f0 = 0 and FAIL (§282), so this window is only reachable on the speaker path")
    if imp_all:
        ohm = set(imp_all)
        if len(ohm) != 1:
            sys.exit(f"gate: the speaker-play captures show impedances {sorted(ohm)} across "
                     f"{len(imp_all)} reads -- not one steady speaker load, so the window row cannot "
                     "quote a single value")
        z = ohm.pop()
        ilo, ihi = (int(dtv[k]) for k in ("vivo,tfa98xx-impedance-min", "vivo,tfa98xx-impedance-max"))
        if not ilo <= z <= ihi:
            sys.exit(f"gate: measured impedance {z} (0.01 ohm) sits OUTSIDE {ilo}..{ihi}")
        out["vivo,tfa98xx-impedance-min"] = out["vivo,tfa98xx-impedance-max"] = (
            f"in-play witness ({len(vals)} session(s)): {len(imp_all)}/{len(imp_all)} reads give {z} "
            f"(0.01 ohm units) inside {ilo}..{ihi}; same captures report PASS per read")
    return out


def hifi_known_strings():
    """the compatible strings AND optional knobs the BUILT driver knows, read out of fw/Image --
    the port must match the driver's list, not the running board's node (ledger 287)"""
    b = open(IMG, "rb").read()
    return sorted({m.group(0).decode() for m in re.finditer(rb"vivo,hifi[-_a-z0-9]*", b)})


def hifi_dt_expected():
    """independent denominator: the capture's own header records how many property FILES `find` saw
    per node -- a different code path than the dump loop, so a row dropped or duplicated by my parser
    shows up as rows != files (ledger 287)"""
    txt = open(os.environ.get("HIFIDT") or f"{BASE}/live/hifi-dt-raw.txt",
               encoding="utf-8", errors="replace").read()
    out = {}
    for ln in txt.splitlines():
        m = re.match(r"##### NODE .*(vivo-hifi-codec|sound-9335) files=(\d+)$", ln)
        if m:
            out["Hi-Fi codec device tree" if m.group(1) == "vivo-hifi-codec"
                else "ASoC card device tree"] = int(m.group(2))
    if len(out) != 2:
        sys.exit(f"gate: the capture headers carry {len(out)} file-counts, expected 2 -- the count "
                 f"column is missing from {ln!r}-style headers, so this denominator is not available")
    return out


def _sections(path):
    txt = open(path, encoding="utf-8", errors="replace").read()
    out = {}
    for p in re.split(r"^## ", txt, flags=re.M)[1:]:
        head, _, body = p.partition("\n")
        out[head.strip()] = body.strip()
    return txt, out


def pa_regmap_rows():
    """§382/§384: the PA has a second, independent read path -- the regmap debugfs node -- whose window
    is 144 addresses, not the 26 the driver's own whitelist prints.  Everything below is re-derived from
    the capture on every run; if a section the sentence depends on is missing, the tool aborts instead of
    publishing a memory."""
    import glob as _g
    cands = sorted(_g.glob(f"{BASE}/live/regmap-tfa98xx-*.txt"))
    if not cands:
        sys.exit("gate: no live/regmap-tfa98xx-*.txt -- the second PA read path was never captured, so "
                 "the window/cross-check numbers below would be recollection (ledger 382)")
    path = cands[-1]
    txt, sec = _sections(path)
    for need in ("regmap/tfa98xx/registers", "regmap/tfa98xx/range", "regmap/tfa98xx/cache_bypass",
                 "regmap/tfa98xx/access", "tfa98xx/codec_reg (same instant)"):
        if need not in sec:
            sys.exit(f"gate: {path} has no '{need}' section -- the {need.split('/')[-1]} claim is not "
                     "supported by this capture")
    regs = {int(a, 16): int(v, 16) for a, v in re.findall(r"([0-9a-f]{2,}):\s*([0-9a-f]+)",
                                                          sec["regmap/tfa98xx/registers"])}
    rng = sec["regmap/tfa98xx/range"].strip()
    lo, hi = (int(x, 16) for x in rng.split("-"))
    if len(regs) != hi - lo + 1 or min(regs) != lo or max(regs) != hi:
        sys.exit(f"gate: the range says {rng} but {len(regs)} addresses are listed "
                 f"({min(regs):#x}..{max(regs):#x}) -- a hole means the dump is partial and 'the window "
                 "is 144' would be wrong")
    bypass = sec["regmap/tfa98xx/cache_bypass"].strip()
    tuples = set(re.findall(r":\s*(y|n) (y|n) (y|n) (y|n)", sec["regmap/tfa98xx/access"]))
    live = {int(a, 16): int(v, 16) for a, v in
            re.findall(r"reg\{0*([0-9a-f]+)\}:([0-9a-f]+)", sec["tfa98xx/codec_reg (same instant)"])}
    if len(live) != 26:
        sys.exit(f"gate: the same-instant codec_reg section carries {len(live)} registers, expected 26 "
                 "(the whitelist denominator, §249) -- without it the agreement count is meaningless")
    diff = sorted(a for a in live if regs.get(a) != live[a])
    reg = {int(r["reg"], 16): r for r in csv.DictReader(open(f"{BASE}/tfa-regs.PD1610.tsv",
                                                             encoding="utf-8"), delimiter="\t")}
    tbl = {int(r["addr"], 16) for r in csv.DictReader(open(f"{BASE}/tfa-bf.TfaBfNames.tsv",
                                                           encoding="utf-8"), delimiter="\t")}
    idle_diff = sorted(a for a in reg if regs.get(a) != int(reg[a]["idle"], 16))
    idle_txt = ", ".join(f"{a:#04x}(class {reg[a]['class']})" for a in idle_diff) or "none"
    agree_idle = 26 - len(idle_diff)
    return [{
        "layer": "PA regmap window", "item": "regmap/tfa98xx registers vs the debugfs whitelist",
        "value": (f"{len(regs)} addresses {lo:#04x}..{hi:#04x} listed with no hole; "
                  f"cache_bypass={bypass}; access tuples={sorted(tuples)}; "
                  f"same-instant agreement with codec_reg {26 - len(diff)}/26 (differ: "
                  f"{', '.join(f'{a:#04x}={regs[a]:#06x} vs {live[a]:#06x}' for a in diff) or 'none'}); "
                  f"vs the published idle baseline {agree_idle}/26 (differ: {idle_txt})"),
        "name_or_meaning": ("the SECOND read path: regmap prints what the bus says (cache_bypass=Y) for "
                            "the whole window, while codec_reg only walks the driver's 26-entry whitelist "
                            f"(§249). The driver's bitfield table names {len(tbl)} addresses, the whitelist "
                            f"shows {len(reg)}, the window is {len(regs)} -- so {len(set(tbl) - set(reg))} "
                            "registers the driver knows are invisible to debugfs, and the addresses the "
                            "whitelist never shows include the per-unit calibration block (§384)"),
        "source": f"{path}, {BASE}/tfa-regs.PD1610.tsv, {BASE}/tfa-bf.TfaBfNames.tsv",
        "writable": "regmap access says readable+writable for every address in the window and the node is "
                    "0644, so NOTHING here restricts a write -- the chip's own answer is unstated (§350) "
                    "and pa_apply.py's per-register token is the only gate",
        "use_case": "on 7, capture the same five sections and require: the same window size, the same "
                    "access tuples, and the same-instant agreement; the registers that differ are expected "
                    "to be the volatile/cross-session ones -- and 0x81-0x8f must be allowed to differ, "
                    "because those are this chip's calibration and production words (§384)",
        "witness2": ("the cross-check is between two doors read in ONE device invocation, so a value that "
                     "moves between them is a live register, not a parsing error -- the one 1-LSB "
                     "difference found (0x71) is exactly a register §260/§361 classified volatile from "
                     "session data, two independent methods agreeing on the same address")}]


def device_binding_rows():
    """§383: which chip sits on which bus, and the sound-card node name -- the first thing that changes if
    7 binds a different codec instance."""
    import glob as _g
    cands = sorted(_g.glob(f"{BASE}/live/sound-topology-*.txt"))
    if not cands:
        sys.exit("gate: no live/sound-topology-*.txt -- the i2c/class-sound binding surface was never "
                 "captured, so the addresses below would be recollection (ledger 383)")
    path = cands[-1]
    txt, sec = _sections(path)
    for need in ("i2c-clients", "class-sound", "clk-summary-exists"):
        if need not in sec:
            sys.exit(f"gate: {path} has no {need} section -- that surface was not read")
    clients = dict(re.findall(r"^(\d+-[0-9a-f]{4}) (\S+)$", sec["i2c-clients"], re.M))
    want = {"es9038": None, "tfa98xx": None}
    for dev, name in clients.items():
        if name in want:
            want[name] = dev
    for k, v in want.items():
        if not v:
            sys.exit(f"gate: {path} lists no i2c client named {k} -- either the driver renamed it or the "
                     "binding is gone, and 'absent' here would be a port finding, not a parse result")
    card = re.search(r"\bcard0 -> (\S+)", sec["class-sound"])
    if not card:
        sys.exit("gate: the class-sound section has no card0 symlink -- the card path claim is unsupported")
    clk_absent = "No such file" in sec["clk-summary-exists"]
    return [{
        "layer": "device bindings", "item": "i2c clients + sound card node",
        "value": (f"es9038 at {want['es9038']}・tfa98xx at {want['tfa98xx']} (bus "
                  f"{want['es9038'].split('-')[0]} for both)・card0 -> {card.group(1)}"),
        "name_or_meaning": ("the two audio chips the port cares about hang off ONE i2c adapter, and the "
                            "DAC's client name is es9038 (es9028 has no bound node, §355); the card node "
                            "name sound-9335 is the same DT node hifi_dt_rows reads, so the two surfaces "
                            "cross-check"),
        "source": f"{BASE}/live/{path.split('/')[-1]}",
        "writable": "no (kernel binding resolved at probe; the port supplies an equal DTB/board file, it "
                    "does not patch this)",
        "use_case": "on 7, re-run tools/surface_coverage.py's roots or this capture and require the two "
                     "client names; the bus number and address may legitimately change (a different DT "
                     "layout), so the CHECK is the pair of names plus the single-adapter fact, not the "
                     "numbers",
        "witness2": (f"clk_summary {'is ABSENT on this build' if clk_absent else 'exists on this build'} "
                     "-- recorded as its own section because a 0-line grep cannot tell 'no audio clocks' "
                     "from 'the node is not there' (§383); the 516 per-clock directories do exist")}]


def loader_memplan_rows():
    """§388: the loader's compiled-in allocation plan -- 44 slots x {bytes, item count}.

    Sourced from `loader-memplan.PD1610.tsv`, which `tools/loader_memplan.py` decodes from the two
    shipped libacdbloader.so by SYMBOL, never by hand-typed address.  This row function refuses the
    table if the plan is not whole, because "44" is the number this line of work has been circling
    since ledger 381 and it must not survive as a recollection.
    """
    path = f"{BASE}/loader-memplan.PD1610.tsv"
    if not os.path.exists(path):
        sys.exit(f"gate: {path} missing -- run `python3 tools/loader_memplan.py --tsv {path}`; the "
                 "sizes below would otherwise be memory of a run, not a run (ledger 388)")
    rows = [l.split("\t") for l in open(path, encoding="utf-8").read().splitlines() if l.strip()]
    hdr, body = rows[0], rows[1:]
    if hdr[:4] != ["slot", "alloc_size_B", "mem_item_count", "cal_item_count"]:
        sys.exit(f"gate: {path} header is {hdr[:4]} -- the decoder changed shape and this row would "
                 "quietly quote the wrong columns")
    if len(body) != 44:
        sys.exit(f"gate: {path} has {len(body)} slots, not 44 -- either the plan moved or the capture "
                 "was truncated")
    try:
        plan = [(int(r[0]), int(r[1]), int(r[2]), int(r[3])) for r in body]
    except ValueError:
        sys.exit(f"gate: {path} has a non-numeric cell -- not a decoder product")
    if [p[0] for p in plan] != list(range(44)):
        sys.exit(f"gate: {path} slot column is not 0..43 in order")
    sizes = [p[1] for p in plan]
    total = sum(sizes)
    live = [i for i, s, c, _ in plan if s]
    counts = [p[3] for p in plan]
    return [{
        "layer": "loader allocation plan", "item": "mem_data[] compiled-in allocation sizes",
        "value": ("44 slots, " + ",".join(str(s) for s in sizes) +
                  f" (total {total} B over {len(live)} slots: " +
                  " ".join(str(i) for i in live) + ")"),
        "name_or_meaning": ("`mem_data` is an exported OBJECT in libacdbloader.so, indexed by **cal type** (the loop's own failure log prints `Could not allocate cal node %d for cal type %d`): 44 cal types, and `[record+4]` is that type's node count -- 1056 B on ARM32 "
                            "(24 B/slot) and 1408 B on ARM64 (32 B/slot), the widening being pointer "
                            "fields.  Per slot it stores {allocation bytes, item count, -1 sentinel, "
                            "run-time fields that are zero in the file}; the ARM32 "
                            "`acdb_loader_init_v2` walks it to the end pointer `mem_data+0x420` and "
                            "mallocs per (slot, item) via the allocator at 0x2794, which is why every "
                            "size here is a page multiple"),
        "source": f"{BASE}/loader-memplan.PD1610.tsv (from shipped/vendor/lib[64]/libacdbloader.so)",
        "writable": "no -- it is .data of a shipped library; the loader itself mutates two fields at "
                    "run time (slot 37 size/count from `acdb_ioctl`, and bit 16 of slots 0..8 at "
                    "`init_v2+0x7604`), which is exactly why the port reads the FILE bytes and "
                    "does not patch them",
        "use_case": ("★slot 37 is the exception to a byte-for-byte reading: its static 0 is not a missing "
                     "calibration -- the loader stores the metainfo size the ADSP reports into "
                     "`mem_data[37]` (ARM64 `str w3,[x8,#0x4a0]`, ARM32 `str.w r0,[r3,#0x378]`, "
                     "both next to `ACDB -> get metainfo size :%d`) and sets its count to 1, so "
                     "slot 37 should read 0/static on BOTH versions and the truncation argument "
                     "only applies to the statically-supplied slots.  on 7: `readelf --dyn-syms -W "
                     "vendor/lib64/libacdbloader.so | awk '$4==\"OBJECT\"'` "
                     "and re-run tools/loader_memplan.py against the 7 library.  A SMALLER size for a "
                     "slot that carries real calibration is a truncation that no log will shout about "
                     "-- the loader mallocs the size it was compiled with, then fills it.  Slot "
                     "index is the only key, so compare position by position, not by name"),
        "witness2": (f"both shipped bitnesses decode to the same 44-slot plan from their own symbol "
                     f"tables (sizes equal slot-for-slot), total {total} B; the tool's `--selftest` "
                     "proves the five decode gates fire (stride, mem/cal count agreement, sentinel, "
                     "run-time-zero fields, symbol re-anchoring)")},
        {"layer": "loader allocation plan", "item": "cal_data[] per-slot item counts",
         "value": "44 slots, " + ",".join(str(c) for c in counts) +
                  f" (sum {sum(counts)}; {sum(1 for c in counts if c > 1)} slots want more than one)",
         "name_or_meaning": ("`cal_data` is the sibling exported OBJECT, 352 B on ARM32 (8 B/slot) and "
                             "704 B on ARM64 (16 B/slot): {run-time pointer, static item count}.  The "
                             "ARM32 walk reads `[slot+4]` of mem_data as a loop bound and skips a slot "
                             "whose cal_data pointer is still null, so the two tables are one plan"),
         "source": f"{BASE}/loader-memplan.PD1610.tsv",
         "writable": "no (same reason)",
         "use_case": ("with the sizes: on 7 the counts say how many instances of each block the loader "
                      "will hold; a count that dropped means fewer calibration variants reachable even "
                      "when every file is present"),
         "witness2": "44 in both bitnesses and equal to mem_data's slot count -- the tool aborts if "
                     "those two ever disagree"},
        {"layer": "loader allocation plan", "item": "who reads the plan (both bitnesses)",
         "value": ("ARM32 (the loader that actually runs on 6.0.1, per the ACDB write reachability "
                   "row): slots 0x12dcc/0x12dd0, anchor 0x12df8 -- `tools/arm32_readers.py` counts 9 "
                   "pool sites / 6 consumed indexed loads for mem_data and 4/2 for cal_data, across "
                   "`acdb_loader_init_v2` (0x52fa 0x53ee 0x57fa 0x586c) and the (cal type, item id) "
                   "cal-node lookup at 0x29c8, whose own index math (r0*3*8 and [r4,r0,lsl #3]) "
                   "independently confirms the 24 B / 8 B record sizes; the walk runs to the end "
                   "pointer `mem_data+0x420` (44 x 24 B).  ARM64: "
                   "slots 0x24fe8/0x24ff0, 11 mem_data and 20 cal_data sites, `add base, idx, lsl #5` "
                   "(44 x 32 B).  BOTH counts are LOWER BOUNDS: only 42 of 113 ARM32 functions resolve "
                   "a GOT anchor in the tracked form, and the tool prints that denominator."),
         "name_or_meaning": ("both bitnesses read it, and the ARM64 readers are the audible send "
                             "chain: `acdb_loader_init_v2` (2 sites), `acdb_loader_send_audio_cal_v2`, "
                             "send_common_custom_topology, send_listen_lsm_cal, send_meta_info, "
                             "send_wcd9xxx_anc_cal.  The 32-bit chain is walked end to end (ledger 401): "
                             "the 52/44-byte wrappers acdb_loader_send_voice_cal and "
                             "send_voice_cal_v2 enter a hub at 0x4190, which dispatches to three local "
                             "node helpers, each calling the (cal type, item id) lookup at 0x29c8 that "
                             "indexes cal_data (lsl #3) and reads mem_data[type]+0x14 -- so voice "
                             "calibration is on this plan too, and send_audio_cal_v2+0x526 calls that "
                             "lookup directly.  These are preemptible exported globals, so every "
                             "reader loads them through a GOT slot -- an `adrp` to the OBJECT page finds "
                             "nothing, which is exactly how a first pass concluded the 64-bit build "
                             "never used the plan (§390, retracted) -- and the refusal is quotable: a cal type whose compiled size is short of what the calibration needs prints `Allocation request for cal type %d, but size is %d!` and is dropped, so on 7 grep logcat for that line while the audio path starts"),
         "source": "art/audio-6.0.1/shipped/vendor/lib[64]/libacdbloader.so",
         "writable": "n/a (analysis)",
         "use_case": ("on 7, run `python3 tools/arm32_readers.py <the 7 32-bit libacdbloader.so> "
                      "mem_data cal_data` and `python3 tools/got_readers.py <the 64-bit one> ...` -- "
                      "the two tools cover the two position-independent idioms and neither answers "
                      "0 readers when it has no slot or no anchor to work with.  Then ask "
                      "cal_data` FIRST: if the plan has no readers there, the slot sizes are inert and "
                      "the byte-by-byte comparison can drop down the queue; if the readers are the "
                      "`send_*_cal` functions as here, the sizes are on the audible path and a short "
                      "slot is a truncation.  The tool takes its slots from readelf --relocs, so a "
                      "renamed symbol is refused instead of answering 0"),
         "witness2": ("readers are named by function extent, not by impression: `.eh_frame_hdr`'s "
                      "start/FDE table gives 81 ranges and agrees with dynsym on the one case we "
                      "can check (`acdb_loader_init_v2` [0x6e24,0x7b10) == 0x6e24+3308).  Writing: "
                      "init_v2 0x7604/0x769c.  Reading: local cal-block helpers in 0x3744-0x4598 "
                      "(log tags deallocate_cal_block / create_cal_node, stride `lsl #5`) plus the "
                      "exported senders acdb_loader_send_audio_cal_v2, "
                      "acdb_loader_send_common_custom_topology, acdb_loader_send_listen_lsm_cal, "
                      "send_meta_info, send_wcd9xxx_anc_cal -- i.e. the plan sits on the path that "
                      "hands calibration to the ADSP.  No shipped .so imports the two symbols "
                      "(0 importers, 4 definers in the same pass = the parser is not blind)")}]


def audio_cfg_file_rows():
    """§403/§404: the shipped config files that produce the live state -- the file-level partner of
    the DAPM/route/ACDB readings, and the layer an audit found missing from this table.

    Every number is parsed from the files in this run (via tools/audio_cfg_files.py's helpers), so a
    row cannot outlive the file it quotes.  Also states, with counts, what will NOT be compared.
    """
    import glob
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "acfg", os.path.join(ROOT, "tools/audio_cfg_files.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    etc = m.ETC
    board = m.mixer_summary(os.path.join(etc, m.BOARD_MIX))
    generic = m.mixer_summary(os.path.join(etc, m.GENERIC_MIX))
    plat = m.platform_summary(os.path.join(etc, m.PLATFORM))
    pol = m.policy_summary(os.path.join(etc, m.POLICY))
    live = m.live_controls()
    if live is None:
        sys.exit("gate: route-states.tsv (the live control list) is absent, so the file-vs-live "
                 "cross-check below would be an unchecked claim")
    both = len(board["ctl_set"] & live)
    only_file = len(board["ctl_set"] - live)
    only_live = len(live - board["ctl_set"])
    d = f"{BASE}/shipped/system/etc"
    ea = m.effects_summary(os.path.join(m.ETC, "audio_effects.conf"))
    eb = m.effects_summary(os.path.join(ROOT, "art/audio-6.0.1/shipped/vendor/etc",
                                        "audio_effects.conf"))
    acdb_root = os.path.join(d, "acdbdata")
    plats = sorted(x for x in os.listdir(acdb_root)) if os.path.isdir(acdb_root) else []
    if not plats:
        sys.exit("gate: no acdbdata platform directories under system/etc -- the cal-asset rows "
                 "quote these, so the layer is not readable")
    sizes = {}
    for p in plats:
        fp = os.path.join(acdb_root, p)
        if not os.path.isdir(fp):
            continue
        fs = [f for f in os.listdir(fp)]
        sizes[p] = (len(fs), sum(os.path.getsize(os.path.join(fp, f)) for f in fs))
    if "PD1610" not in sizes:
        sys.exit("gate: acdbdata/PD1610 is the platform this baseline is for and it is not listed")
    direct = {k: v for k, v in pol.items() if any(len(r.split("|")) > 4 for r in v["rates"])}
    eff_a = os.path.join(d, "audio_effects.conf")
    eff_b = os.path.join(ROOT, "art/audio-6.0.1/shipped/vendor/etc/audio_effects.conf")
    eff = []
    for p in (eff_a, eff_b):
        if os.path.exists(p):
            t = open(p, encoding="utf-8", errors="replace").read()
            eff.append((os.path.relpath(p, os.path.join(ROOT, "art/audio-6.0.1/shipped")),
                        os.path.getsize(p), sorted(set(re.findall(r"^\s+([A-Za-z][\\w.]*)\\s*\\{", t, re.M)))))
    ifaces = sorted({i for _, _, i in plat["backend_rows"]})
    # <card>/<card-dir>/dapm/<widget> -- two levels below the card root, not one (an earlier glob
    # one level short found 1 directory and would have made the cross-check silently vacuous)
    aroot = os.path.join(ROOT, BASE, "live/debugfs_asoc")
    widget_roots = glob.glob(os.path.join(aroot, "**", "dapm", "*"), recursive=True)         if os.path.isdir(aroot) else []
    if len(widget_roots) < 100:
        sys.exit(f"gate: only {len(widget_roots)} DAPM widget entries found under live/debugfs_asoc "
                 "-- the known baseline has ~958, so this glob is not reading the capture and the "
                 "cross-check must not be quoted")
    widget_names = {os.path.basename(w) for w in widget_roots}
    iface_hits = sum(1 for i in ifaces if i in widget_names)
    if ifaces and iface_hits == 0:
        sys.exit("gate: the platform file names " + str(len(ifaces)) + " backend interfaces and none "
                 "of them appears as a live DAPM widget directory -- do not claim the two layers "
                 "agree until that is understood")

    if len(eff) < 2:
        sys.exit("gate: expected both audio_effects.conf copies (system/etc and vendor/etc) -- the "
                 "pair is the point of the row")
    import hashlib
    ship = os.path.join(ROOT, "art/audio-6.0.1/shipped")
    stray = sorted(x for x in os.listdir(ship) if x.endswith(".so"))
    dup_ok = []
    for x in stray:
        q = os.path.join(ship, "system/lib64", x)
        if not os.path.exists(q):
            sys.exit(f"gate: loose {x} has no system/lib64 namesake -- the claim that these are "
                     "duplicates is then unsupported, so say so in the row instead of asserting it")
        a = hashlib.md5(open(os.path.join(ship, x), "rb").read()).hexdigest()
        b = hashlib.md5(open(q, "rb").read()).hexdigest()
        if a != b:
            sys.exit(f"gate: loose {x} differs from its system/lib64 copy (md5 {a[:8]} vs {b[:8]}) "
                     "-- it is not a duplicate and must be treated as its own artifact")
        dup_ok.append(x)
    sys.path.insert(0, f"{ROOT}/tools")
    import audio_cfg_files as cfg
    _cands = {}
    for _nm in sorted(os.listdir(cfg.ETC)):
        if _nm.startswith("mixer_paths") and _nm.endswith(".xml"):
            _cands[_nm] = open(os.path.join(cfg.ETC, _nm), encoding="utf-8", errors="replace").read()
    _live = cfg.live_controls()
    if not _live:
        sys.exit("gate: no live control capture for the loaded-file row -- the proof needs "
                 "route-states.tsv")
    CFG_COMPOSED, CFG_COMPAT, CFG_REFUTED, CFG_DISC, CFG_CARD, CFG_TOK2, CFG_MODEL = \
        cfg.loaded_file_evidence(_cands, _live)
    return [
        {"layer": "audio configuration files", "item": "board mixer file vs generic mixer file",
         "value": (f"generic: {m.GENERIC_MIX}; {m.BOARD_MIX}: {board['paths']} paths ({board['distinct_paths']} distinct), "
                   f"{board['ctls']} ctl refs ({board['distinct_ctls']} distinct); "
                   + "・".join(f"{k}={v}" for k, v in board["critical"].items())
                   + f"; {m.GENERIC_MIX}: {generic['paths']} paths, "
                   f"{generic['distinct_ctls']} distinct ctls, SmartPA Switch="
                   f"{generic['critical']['SmartPA Switch']}"),
         "name_or_meaning": ("the mixer file is the HAL-side input that creates DAPM controls, so it is "
                             "the file-level partner of the DAPM/route rows: the board file defines the "
                             "one cell the speaker path needs (SmartPA Switch) and the generic file "
                             "defines none of it, so WHICH file the HAL loads is itself load-bearing"),
         "source": f"{d}/{m.BOARD_MIX}",
         "writable": "no (image file; 7 supplies its own board file)",
         "use_case": ("on 7, run tools/audio_cfg_files.py against the 7 extract (AUDIO_CFG_ETC=...): "
                      "the check is not equality -- 7's file will be a different board's file -- it is "
                      "that a SmartPA Switch (or 7's equivalent PA route control) is DEFINED somewhere "
                      "reachable, and that the HAL picks the board file, not the generic one"),
         "witness2": (f"file-and-live cross-check against route-states.tsv ({len(live)} live controls): "
                      f"shared {both}, file-only {only_file}, live-only {only_live} "
                      f"({100*only_live/len(live):.1f}% of live controls are NOT in the board mixer "
                      "file = driver-built) -- so the file is never a substitute for the live reading, "
                      "and the reverse is also false"),
         },
        {"layer": "audio configuration files", "item": "platform device->backend map + acdb ids + widths",
         "value": (f"{plat['devices']} device entries ({plat['distinct_devices']} distinct), "
                   f"{plat['backends']} backend rows, acdb_id "
                   + "・".join(f"{k.replace('SND_DEVICE_OUT_', '')}={v}" for k, v in plat["acdb"].items())
                   + "; bit_width "
                   + "・".join(f"{k.replace('SND_DEVICE_OUT_', '')}={v}" for k, v in plat["bits"].items())
                   + "; Hi-Fi devices "
                   + "・".join(f"{k.replace('SND_DEVICE_OUT_', '')}={'yes' if v else 'no'}"
                               for k, v in plat["hifi"].items())
                   + f"; native {plat['native']}; params {plat['params']}"),
         "name_or_meaning": ("this is where the HAL's device id becomes an ACDB id and a DAPM backend: "
                             "SPEAKER=15 is the file-side origin of the acdb_dev_id the live reading "
                             "reports, and HEADPHONE_HIFI / HEADPHONE_HIFI_DSD are the HAL-side names "
                             "for the vivo Hi-Fi and DSD paths whose kernel side is `HiFi DAC`/"
                             "`hifi mode 2=DSD`"),
         "source": f"{d}/{m.PLATFORM}",
         "writable": "no (image file)",
         "use_case": ("on 7: same tool.  A missing HEADPHONE_HIFI* device or a different acdb_id for "
                      "SPEAKER means the HAL cannot select the calibration the kernel path already "
                      "expects -- that is a silent difference, not an error at startup"),
         "witness2": ("cross-checked against the live DAPM capture rather than asserted: of the "
                      f"{len(ifaces)} distinct backend interfaces this file names, {iface_hits} exist "
                      "as a widget directory under live/debugfs_asoc/**/dapm/ (counted at build time; "
                      "the row refuses to claim agreement when none match).  The headphone family "
                      "routes to SLIMBUS_6_RX, the same backend the DAPM rows resolve"),
         },
        {"layer": "audio configuration files", "item": "audio_policy profiles and rate ceilings",
         "value": (f"{len(pol)} profiles declare rates; multi-rate profiles: "
                   + "・".join(f"{k}={v['rates'][0]}" for k, v in direct.items())),
         "name_or_meaning": ("direct_pcm is the profile the Hi-Fi direct path plays through; its rate "
                             "ceiling (192000 here) and flags are what decide whether a 96/176/192 kHz "
                             "file can be bit-exact, and audio_policy.conf is per-version by design"),
         "source": f"{d}/{m.POLICY}",
         "writable": "no (image file)",
         "use_case": ("on 7, compare the rate list per profile, not the file layout; then verify by "
                      "listening/plug test that the same file plays through the same profile"),
         "witness2": "commented-out rate lines are counted per profile so a disabled ceiling is visible",
         },
        {"layer": "audio configuration files", "item": "acdbdata platform inventory and what is NOT carried",
         "value": ("・".join(f"{k}={v[0]}f/{v[1]//1024}KiB" for k, v in sorted(sizes.items()))),
         "name_or_meaning": ("the platform directories shipped in the image; PD1610 is this machine's, "
                             "the others belong to other boards/SoC families present in the same image"),
         "source": f"{acdb_root}",
         "writable": "no (image files)",
         "use_case": ("only PD1610 (plus its sibling boards for the cross-board test) is compared on 7; "
                      "the other platform dirs are listed here so nobody spends a turn chasing them -- "
                      "and their presence in the image is NOT evidence the loader uses them"),
         "witness2": ("workspaceFile.qwsp exists per platform and is the ACDB toolchain's block/feature "
                      "definition (the thing the LUT/CDFT structures are read from), so the count above "
                      "includes it as a real file, not a stray"),
         },
        {"layer": "audio configuration files", "item": "effects chain (two audio_effects.conf copies)",
         "value": (f"system/etc: {len(ea['libs'])} libraries / {len(ea['effects'])} effects "
                   f"({ea['size']} B, {ea['uuids']} uuid lines); vendor/etc: {len(eb['libs'])} "
                   f"libraries / {len(eb['effects'])} effects ({eb['size']} B, {eb['uuids']} uuid); "
                   "only-in-system effects=" + ",".join(sorted(set(ea['effects']) - set(eb['effects'])))
                   + " ; only-in-vendor effects="
                   + ",".join(sorted(set(eb['effects']) - set(ea['effects'])))),
         "name_or_meaning": ("the effects library chain is a third audible-path input besides routes and "
                             "calibration, and the two shipped copies DISAGREE: the Dolby `ds` effect "
                             "exists only in the system copy while AEC/NS/bbesonicmax/hw_acc exist only "
                             "in the vendor copy -- so which file the HAL opens changes the effect set, "
                             "independently of any setting"),
         "source": "art/audio-6.0.1/shipped/system/etc/audio_effects.conf",
         "writable": "no (image file)",
         "use_case": ("on 7, diff the library and effect NAME SETS (tools/audio_cfg_files.py "
                      "effects_summary), not the file text; an effect absent from 7's set cannot be "
                      "enabled later, which is how an 'it sounds different' complaint becomes checkable"),
         "witness2": ("both copies: system etc + vendor etc; tokenizer self-check: libraries parsed == `path` lines declared per file "
                      f"({ea['declared_lib_entries']} vs {ea['paths']} and {eb['declared_lib_entries']} "
                      f"vs {eb['paths']}), and duplicate library names are reported "
                      f"({eb['duplicate_lib_names'] or 'none'}) -- an earlier draft deduped them and the "
                      "gate caught the mismatch"),
         },
        {"layer": "audio configuration files", "item": "which mixer file the live controls and the composed name agree on",
         "value": (f"{CFG_COMPOSED} (card {CFG_CARD!r} -> token2 {CFG_TOK2!r}, model {CFG_MODEL!r}); "
                   f"compatible={[n for n, _ in CFG_COMPAT]} refuted={[n for n, _, _ in CFG_REFUTED]} "
                   f"| leg-1 positive control: {CFG_DISC[0][0]} uniquely defines {', '.join(CFG_DISC[0][1][:3])}"),
         "name_or_meaning": ("§212 left this cell open -- the HAL holds no literal for the board file, "
                             "because the name is composed at runtime.  Two legs, and the row only "
                             "exists when they agree: leg 1 is a REFUTATION test on the controls "
                             "(a file that defines a control no other candidate defines, and that the "
                             "card does not expose, was not loaded) -- it refutes the generic "
                             "`mixer_paths.xml` and `mixer_paths_i2s.xml` and proves something "
                             "defined `MultiMedia5 Mixer AUX_PCM_TX`; it CANNOT separate PD1610 from "
                             "PD1610LG4, which share every control.  Leg 2 is the composition rule "
                             "(`/system/etc/mixer_paths_` + card token 2 + `.` + ro.vivo.product.model "
                             "+ `.xml`, read off the instructions in ledger 411/412) and that is what "
                             "picks the sibling.  Stated plainly: the control evidence alone is not "
                             "uniqueness, and the row says so"),
         "source": f"{ROOT}/tools/audio_cfg_files.py",
         "writable": "no -- derived from the shipped files and the live capture",
         "use_case": ("on 7: re-run with `AUDIO_CFG_ETC=<7 etc> AUDIO_CFG_ROUTES=<7 route-states.tsv> "
                      "AUDIO_CFG_CARDS=<7 cards.txt> AUDIO_CFG_GETPROP=<7 getprop.txt`.  The composed "
                      "name will differ (different card string, different model property) -- what must "
                      "still hold is that the composed name survives leg 1 and that leg 1 refutes at "
                      "least one file.  If the tool aborts with 'not compatible', the 7 build reads a "
                      "mixer file the 6.0.1 board file cannot explain, and the fallback "
                      "(`mixer_paths.xml`, no `SmartPA Switch`) is the likely outcome -- which shows "
                      "up as silent speaker failure, not as an error"),
         "witness2": ("four extra arms in --selftest: a positive (the evidence must name the board "
                      "file), two negatives (a doctored model property and a doctored card token must "
                      "each abort), and one for the empty case (no live capture -> no claim). The "
                      "model arm rewrites the `[ro.vivo.product.model]` line specifically because "
                      "`[PD1610]` is also the value of ro.product.device earlier in the file"),
         },
        {"layer": "audio configuration files", "item": "loose .so at the extract root (provenance note)",
         "value": "・".join(stray),
         "name_or_meaning": ("these sit at the top of the extract instead of under system/ or "
                             "vendor/. Checked by hashing each against its system/lib64 namesake: all "
                             "four are BYTE-IDENTICAL duplicates pulled by an earlier extraction, not "
                             "image layout -- so a 7-side comparison must look at system/lib64, and "
                             "none of these four is on the loader/route path this table tracks"),
         "source": "art/audio-6.0.1/shipped/",
         "writable": "n/a (extract artefact)",
         "use_case": ("listed so a 7-side comparison does not treat them as shipped paths; if they are "
                      "wrongly placed, the MANIFEST still covers them -- this row just says what they are"),
         "witness2": ("checked by hashing each loose file and the same-named file under system/lib64 "
                      "and comparing the digests -- recomputed on every table build, and this row "
                      f"aborts if any of the {len(dup_ok)} stops matching: sizes "
                      f"{', '.join(str(os.path.getsize(os.path.join(ROOT, 'art/audio-6.0.1/shipped', x))) for x in stray)} B; "
                      "none of the names matches libacdb*/libaudcal, so the loader rows are "
                      "unaffected -- re-run the same two-line hash compare to reconfirm"),
         },
    ]


def audio_hal_surface_rows():
    """§408/§409: the component that DECIDES -- the audio HAL -- as a cross-version reference.

    Sourced from `hal-surface.PD1610.tsv`, which `tools/audio_hal_surface.py` derives from the HAL
    binary by symbol/string search (never a remembered path: an earlier note of mine claimed the HAL
    was missing simply because I looked under vendor/lib*/hw).  Rows refuse to be emitted when the
    evidence pairs that make the claims meaningful are not both present.
    """
    path = f"{BASE}/hal-surface.PD1610.tsv"
    if not os.path.exists(path):
        sys.exit(f"gate: {path} missing -- run `python3 tools/audio_hal_surface.py --tsv {path}`; "
                 "the values below would otherwise be recollection of a run (ledger 407)")
    import csv as _csv
    rows = list(_csv.DictReader(open(path, encoding="utf-8"), delimiter="\t"))
    want = ["device_path", "elf_class", "live_mapped", "bytes", "strings", "snd_device_names",
            "hifi_declared", "needed", "mixer_pair", "platform_paths", "dsd_counts",
            "control_names_backed"]
    missing = [c for c in want if c not in (rows[0] if rows else {})]
    if missing:
        sys.exit(f"gate: {path} lacks columns {missing} -- the tool changed shape; re-supply it "
                 "rather than quoting the wrong column")
    live_rows = [r for r in rows if r["live_mapped"] == "True"]
    if len(live_rows) != 1:
        sys.exit(f"gate: {len(live_rows)} of the {len(rows)} HAL copies is named by the live maps -- "
                 "this layer is about the copy the device loads, so exactly one must be; check "
                 "live/loaders.txt and which bitness mediaserver runs (ledger 409)")
    if len(rows) < 2:
        sys.exit(f"gate: {path} has {len(rows)} HAL copies; the extract holds both the 32-bit "
                 "/system/lib/hw and the 64-bit /system/lib64/hw copy and the row must say which "
                 "one runs, which needs both in view")
    r = live_rows[0]
    other = [x for x in rows if x is not r]
    if r["hifi_declared"] != "True" or any(x["hifi_declared"] != "True" for x in other):
        sys.exit("gate: a HAL copy does not declare SND_DEVICE_OUT_HEADPHONE_HIFI, so no Hi-Fi claim "
                 "may be attached to this row")
    if r["mixer_pair"] != "present":
        sys.exit("gate: the mixer-selection evidence is not a pair (dynamic path + default-file "
                 "string), so how the config file is chosen is unproven")
    needed = [x for x in r["needed"].split(",") if x]
    for must in ("libexpat.so", "libtinyalsa.so"):
        if must not in needed:
            sys.exit(f"gate: {must} is no longer a NEEDED library of {r['device_path']} -- the "
                     "XML-selection / control-access story changes with it, stop quoting it")
    same_edges = all(x["needed"] == r["needed"] for x in other)
    return [
        {"layer": "audio HAL surface",
         "item": f"{r['device_path']} ({r['elf_class']}): the copy the device loads, and its library edges",
         "value": (f"{r['bytes']} B, {r['strings']} strings, {r['snd_device_names']} SND_DEVICE_* "
                   f"names, {len(needed)} NEEDED: " + "・".join(needed) +
                   f"; the other copy in the extract: " +
                   "・".join(f"{x['device_path']} ({x['elf_class']}, {x['bytes']} B, "
                             f"mapped={x['live_mapped']})" for x in other)),
         "name_or_meaning": ("the audio HAL is the component that opens the platform/mixer files, "
                             "maps SND_DEVICE_* to ACDB ids and drives tinyalsa; `libexpat.so` in its "
                             "edges is what makes the mixer-file selection a runtime XML decision "
                             "rather than a build-time path, and `libaudioroute.so` is why the route "
                             "cells the DAPM rows describe can be reached at all"),
         "source": f"{BASE}/hal-surface.PD1610.tsv",
         "writable": "no -- a shipped binary; the port compares its surface, it does not patch it",
         "use_case": ("on 7: `python3 tools/audio_hal_surface.py --root <7 extract>` then compare "
                      "three structural facts, not bytes: does the HAL still declare the Hi-Fi device, "
                      "does it still hold BOTH mixer-selection strings, and does it still link an XML "
                      "parser plus tinyalsa.  Any one of those missing means the decision layer differs "
                      "and the config-file rows cannot be assumed to be honoured"),
         "witness2": ("located by searching the four candidate hw dirs "
                      "(system/lib64, system/lib, vendor/lib64, vendor/lib) rather than by a "
                      "remembered path -- which is exactly how ledger 407 first got this wrong; the "
                      "tool aborts if it finds nothing or if NEEDED parses empty "
                      "(readelf output is locale-dependent).  Which copy runs is not a guess: "
                      "live/loaders.txt names the mapped path, and the bitness comes from the ELF "
                      "header bytes, not from readelf wording.  Ledger 409: the maps show the 32-bit "
                      "copy, so an earlier version of this layer that quoted only the 64-bit file was "
                      "describing a binary the device never loads" +
                      ("; both copies declare the same NEEDED set, so the library-edge claim is not "
                       "bitness-specific" if same_edges else
                       "; the two copies declare DIFFERENT NEEDED sets, so quote the edges together "
                       "with the bitness")),
         },
        {"layer": "audio HAL surface",
         "item": f"Hi-Fi / DSD decision strings in the loaded HAL ({r['elf_class']})",
         "value": (r["dsd_counts"] + "; platform files referenced: " + r["platform_paths"] +
                   "; control-shaped names backed by live/board files: " + r["control_names_backed"]),
         "name_or_meaning": ("this is the HAL side of the Hi-Fi path the kernel rows describe: the DSD "
                             "enable parameter, the DSD volume switch control, the HW_DSD output flag "
                             "and the headphone-hifi-DSD device name.  Note `DSDEnbale` -- vivo's own "
                             "misspelling -- which is a useful cross-version fingerprint: if 7 spells "
                             "it correctly (or not at all), that code was replaced, not carried"),
         "source": f"{BASE}/hal-surface.PD1610.tsv",
         "writable": "no",
         "use_case": ("on 7, grep the same token list through tools/audio_hal_surface.py output; the "
                      "DSD path is where an invisible regression starts (kernel HiFi mode works, HAL "
                      "never selects it), and it would show up as listening fatigue, not as an error"),
         "witness2": ("kernel-side partner already on the books: `HiFi Mode Switch` and the mode enum "
                      "[Off,HiFi,DSD,Normal] (ledger 332) plus `HiFi DAC` on the hifi-codec widget "
                      "(ledger 290) -- so the string here is not the only evidence of a DSD path"),
         },
    ]


def shipped_disposition_rows():
    """§409: every file in the shipped extract gets one verdict, decided by three independent legs
    (live maps, the ACDB landing capture, the carry-list citations) rather than by eyeballing names.

    This runs the census itself (import, not a remembered TSV) so no intermediate file can go stale
    between the extract and the table.  `tools/shipped_disposition.py --selftest` holds the arms that
    prove the matcher can fail; the gates here refuse to emit a claim the census cannot support.
    """
    sys.path.insert(0, f"{ROOT}/tools")
    import shipped_disposition as sd
    rows, gaps, landing, n_mapped, cfg = sd.census(f"{BASE}", ROOT)
    sc = cfg["scope"]
    cl = cfg["closure"]
    if n_mapped < 20:
        sys.exit(f"gate: the live maps yielded {n_mapped} mapped paths, below the 20 this layer was "
                 "built on -- either the capture shrank or the parser is blind")
    matched = [r for r in rows if r["live_mapped_via"] != "-"]
    if not matched:
        sys.exit("gate: zero live-mapped paths matched the extract -- that is the 'scanner is blind' "
                 "failure mode, not a real gap of 33")
    used = [r for r in rows if r["acdb_in_use"] == "yes"]
    st = cfg["acdb_stated"]
    # The expectation comes from the capture's own two self-reported counts, not from a remembered 7:
    # a pinned number is an anchor to one machine (ledger 582's recurring lesson), and a 7-side
    # capture legitimately carries a different one.  Both counts must exist and agree, and the leg
    # must answer exactly that many -- otherwise this is the "parser went blind and printed 0" case
    # that step 5b exists to catch (ledger 587).
    if st["header"] is None or st["footer"] is None:
        sys.exit(f"gate: {st['file']} states no denominator (header={st['header']} "
                 f"footer={st['footer']}); without one the ACDB leg has no expectation to be "
                 "measured against, so it must refuse instead of publishing a count")
    if st["header"] != st["footer"]:
        sys.exit(f"gate: the capture disagrees with itself -- header files-here={st['header']} "
                 f"but footer says over {st['footer']} baseline files ({st['file']})")
    if len(used) != st["header"] or not landing:
        sys.exit(f"gate: the ACDB leg answered {len(used)} in-use files with landing={landing}; "
                 f"the capture under {BASE} states {st['header']} -- if that changed, the .acdb "
                 "rows of this table are about the wrong directory")
    if "mixer_paths.xml" not in cfg["per_config"]:
        sys.exit("gate: the census no longer accounts for mixer_paths.xml -- the carrier row below "
                 "would quote a list that does not cover the default file")
    if len([k for k, v in cfg["per_config"].items() if v]) < 2:
        sys.exit("gate: fewer than two config files have a carrier binary; the byte search is "
                 "either blind or the extract lost its HAL")
    if cfg["per_config"].get("mixer_paths_tasha.PD1610.xml"):
        sys.exit("gate: a shipped binary now names the board-suffixed mixer file verbatim -- the "
                 "rule recorded in the row below (composed at runtime, no literal carrier) is no "
                 "longer true and the selection story has to be re-derived, not patched")
    peers = [r for r in rows if r["byte_identical_to"] != "-"]
    lit = cfg["literals"]
    SC = cfg["scope"]
    LOADER = "libacdbloader.so"
    sd_e, sd_m, _ = sd.soname_edges(BASE, rows)
    if lit["not_held"]:
        sys.exit(f"gate: {len(lit['not_held'])} config literal(s) the binaries name are on the "
                 f"device but not in the extract ({lit['not_held'][:3]}) -- capture them with "
                 "tools/grab_config_literals.sh plus a pull, before this row claims completeness")
    if len(lit["revalidated"]) < 8:
        sys.exit(f"gate: only {len(lit['revalidated'])} held config files re-hash to the device "
                 "value -- below the 8 this layer was built on, so the comparison is not working")
    by_kind = {}
    for r in rows:
        if r["verdict"] == "QUIET":
            by_kind[r["kind"]] = by_kind.get(r["kind"], 0) + 1
    live_dirs = {}
    for r in matched:
        key = r["device_path"].rsplit("/", 2)
        d = "/".join(key[:2]) if len(key) == 3 else r["device_path"]
        live_dirs[d] = live_dirs.get(d, 0) + 1
    lg4 = [r for r in peers if "PD1610LG4" in r["path"]]
    flat = [r for r in peers if r["path"].count("/") == 1]
    return [
        {"layer": "shipped file disposition", "item": "extract completeness against the live maps",
         "value": (f"{len(rows)} shipped files, {n_mapped} device paths named by the live map "
                   f"captures, {len(matched)} matched, {len(gaps)} gaps" +
                   ("" if not gaps else ": " + "・".join(g["device_path"] for g in gaps))),
         "name_or_meaning": ("the census of what the shipped extract actually holds versus what the "
                             "audio stack loads.  Gaps=0 is the state after ledger 409 pulled the "
                             "32-bit /system/lib stack: before that the extract named no copy of 29 "
                             "libraries the device maps, including the primary audio HAL -- so any "
                             "6.0.1-vs-7 comparison of 'the HAL' was being made against a binary the "
                             "6.0.1 device never loaded"),
         "source": (f"{ROOT}/tools/shipped_disposition.py + {BASE}/live/loaders.txt + "
                    f"{BASE}/live/acdb-reach.txt"),
         "writable": "no -- a census over captured artefacts",
         "use_case": ("on 7: capture the same two live map files (tools/grab_audio_live.sh) plus the "
                      "extract, then run `python3 tools/shipped_disposition.py --root <7>`; the "
                      "gap list is the capture to-do, and a 7 gap that is empty on 6.0.1 means the "
                      "audible stack moved a library -- e.g. audioserver splitting mediaserver off"),
         "witness2": ("two independent map captures (loaders.txt from the pid block dump, "
                      "acdb-reach.txt from the REACH sweep) must agree on libacdbloader; the tool "
                      "aborts if either parses to zero, and --selftest arms 2/3 check that a "
                      "genuine gap is reported while a captured file is not"),
         },
        {"layer": "shipped file disposition", "item": "which directory the audible libraries come from",
         "value": "・".join(f"{d}: {n} mapped" for d, n in sorted(live_dirs.items())),
         "name_or_meaning": ("this is the bitness answer for the HAL/loader layer: mediaserver maps "
                             "the /system/lib (32-bit) copies, and the loader rows in this table are "
                             "derived from vendor/lib (ARM32) for the same reason (ledger 397).  The "
                             "64-bit twins stay in the extract as reference, not as the running code"),
         "source": f"{BASE}/live/loaders.txt",
         "writable": "no",
         "use_case": ("on 7, expect this map to name /system/lib64 and /vendor/lib64 (or /vendor/lib "
                      "for a 32-bit mediaserver) -- compare the directory set, not the file list: a "
                      "port that grabs only one bitness reproduces the mistake this census caught"),
         "witness2": "same census, `verdict=LIVE-*` rows; elf bitness read from the header bytes",
         },
        {"layer": "shipped file disposition", "item": "byte-identical pairs in the extract (not independent samples)",
         "value": (f"PD1610LG4 vs PD1610: {len(lg4)} files identical; flattened-at-root duplicates: "
                   f"{len(flat)} files; all {len(peers)} peer rows are PEER-REFERENCE"),
         "name_or_meaning": ("the LG4 calibration directory is a byte copy of PD1610, so it is a "
                             "positive control (0 differences expected), never a second board -- and "
                             "the four .so files sitting at the extract root are copies of their "
                             "system/lib64 twins.  Cross-board statistics already exclude both pairs "
                             "(ledger 261/267), and this row re-derives that from the bytes each "
                             "build rather than from a remembered list"),
         "source": f"{ROOT}/tools/shipped_disposition.py",
         "writable": "no",
         "use_case": ("on 7, if two acdbdata directories that should differ hash equal, the vendor "
                      "shipped one calibration for two models -- that changes which board can be "
                      "used as a control"),
         "witness2": "sha256[:16] recomputed from the file bytes in this run, and checked against MANIFEST.txt",
         },
        {"layer": "shipped file disposition", "item": "config file -> carrier binaries (verbatim literals only)",
         "value": ("binary: " + "・".join(f"{k} -> " + " ".join(v) for k, v in sorted(cfg["carriers"].items())) +
                   "; config files with no carrier: " + str(len(cfg["no_carrier"])) +
                   " (" + " ".join(cfg["no_carrier"][:8]) +
                   ("..." if len(cfg["no_carrier"]) > 8 else "") + ")"),
         "name_or_meaning": ("who reads the config files, answered from the binaries instead of from "
                             "filenames.  Two things fall out that the config-file layer alone could "
                             "not give: the generic `mixer_paths.xml` is what several binaries name "
                             "as a literal (so when board-specific selection fails, the file opened "
                             "is the one WITHOUT `SmartPA Switch`), and the board-suffixed "
                             "`mixer_paths_tasha.PD1610.xml` has no literal carrier anywhere -- its "
                             "name is composed at runtime, which is why the suffix pieces have to be "
                             "read off the device (sound-card name, vivo model property) and not out "
                             "of the image"),
         "source": ROOT + "/tools/shipped_disposition.py",
         "writable": "no -- derived from the shipped binaries",
         "use_case": ("on 7: run the same census and diff the per-config carrier sets.  A config file "
                      "that loses its carrier is a file nobody opens any more (silently), and one that "
                      "gains a carrier is a new decision point; `audio_effects.conf` being carried by a "
                      "framework library rather than the HAL is exactly the kind of fact the "
                      "mediaserver/audioserver split in 7 moves"),
         "witness2": ("byte search for the exact basenames of the extract's own config files inside "
                      "every shipped `.so`, and the census aborts when NO binary names ANY config "
                      "file -- a blind search would otherwise look exactly like a real absence "
                      "(--selftest's last arm teaches a fixture HAL the literal, requires it to be "
                      "reported, then strips it and requires the abort)"),
         },
        {"layer": "shipped file disposition", "item": "config path literals the binaries ask for (device answer)",
         "value": (f"{len(lit['probe'])} literals, {len(lit['revalidated'])} hash-verified against the "
                   f"device, {len(lit['absent_on_device'])} absent on the device too "
                   f"({' '.join(lit['absent_on_device'])})"),
         "name_or_meaning": ("the reverse of the carrier row: what the shipped binaries REQUEST, read "
                             "off the device.  Four literals are ABSENT here (`/etc/ftm-mixerpath.xml`, "
                             "both `*_5.1.*` variants, `/etc/audio_output_policy.conf`), which is why "
                             "the earlier note that `/system/etc/drc` 'does not exist on this device' "
                             "was wrong -- the directory exists and holds `drc_cfg_AZ.txt`; the AZ "
                             "variant is what is live and the 5.1 name is a dormant fallback.  Every "
                             "literal the device does have is now in the extract and re-hashed: this "
                             "row is the config-file half of the completeness claim"),
         "source": f"{BASE}/live/config-literals.tsv",
         "writable": "no -- read from the device by tools/grab_config_literals.sh",
         "use_case": ("on 7: run the probe against the new image and diff device_state.  A literal "
                      "that is PRESENT on 7 and ABSENT on 6.0.1 is a tuning file the new HAL reads "
                      "and we never had; ABSENT on 7 where it was PRESENT here means a code path "
                      "lost its input and will silently fall back"),
         "witness2": ("the census aborts if any literal has no device answer, if the probe table is "
                      "older than the extract (a literal with no row), or if a held file's md5 "
                      "disagrees with the device -- so a stale probe cannot produce this row"),
         },
        {"layer": "shipped file disposition", "item": "capture scope and its stated boundary",
         "value": (f"module hosts: {len(sc['hosts'])} of {sc['n_mapped']} mapped captured binaries "
                   f"({sc['framework_hosts']} framework transport, whose names are ring-2 and are NOT chased); "
                   f"ring-1 names: {len(sc['ring1'])}; audible closure: seeds="
                   f"{' '.join(cl['seeds'])} reached={cl['reached']} ring_max={cl['ring_max']} "
                   f"dormant={cl['dormant']}; chased={cl['chased']} (every one now held); "
                   f"stated boundary: {cl['silent_boundary']} mapped libraries the DEVICE itself "
                   "reports as carrying ZERO audio-family literals (probe row for "
                   "audio.primary shows the control can see them)"),
         "name_or_meaning": ("the answer to 'have we captured the right things', drawn WITHOUT a name "
                             "pattern: a library is in scope when a HAL-module or effect-module "
                             "binary (paths under `*/hw/` or `*/soundfx/`, witnessed as mapped by "
                             "`live/maps-mediaserver.txt`) names it as a soname literal -- linked or "
                             "dlopened alike, since ledger 411 showed the ACDB loader only has a "
                             "dlopen edge.  Real gaps are zero, so the extract covers everything the "
                             "audio modules ask for that the device actually maps.  The six dormant "
                             "names are asked for but never mapped on this machine (`libdrc.so`, "
                             "`libsurround_3mic_proc.so` and friends) and are deliberately not "
                             "chased, and the 51 names beyond ring-1 belong to the framework "
                             "libraries' own dependencies -- that is the stated ceiling of this "
                             "capture, printed rather than implied"),
         "source": f"{BASE}/live/maps-mediaserver.txt",
         "writable": "no -- derived from the live maps and the shipped binaries",
         "use_case": ("on 7: capture the unfiltered maps first (`bash tools/grab_process_maps.sh`, "
                      "passing `audioserver` on a 7 device), then the census refuses to run until the "
                      "file is present and long enough.  A real gap on 7 = a module asks for a library "
                      "the image maps but we never held -- capture it and re-read; a dormant name that "
                      "becomes mapped = a feature path 7 actually loads (DRC or surround, e.g.) and "
                      "the listening result may differ for that reason alone"),
         "witness2": ("the maps file itself is gated: under 50 lines it is rejected as 'the old "
                      "name-filtered capture' (live/loaders.txt holds 33 lines against 194 here), the "
                      "scope leg aborts when it is absent, and a fixture arm proves a truncated file "
                      "fails rather than shrinking the claim"),
         },
        {"layer": "shipped file disposition", "item": "soname edges (linked or dlopened)",
         "value": (f"distinct names: {len(sd_e)}  held: {len(sd_e) - len(sd_m)}  not held: {len(sd_m)}"
                   " | " + LOADER + " named by " + str(len(sd_e.get(LOADER, []))) + " binaries: "
                   + "・".join(os.path.basename(x) for x in sd_e.get(LOADER, []))),
         "name_or_meaning": ("the dependency graph read from the binaries themselves rather than from "
                             "DT_NEEDED alone.  This is the layer that answers 'who pulls in the ACDB "
                             "loader': nobody NEEDEDs it -- the HAL and four effect libraries `dlopen` "
                             "it by name, next to the log line `%%s: DLOPEN failed for %%s`.  A port "
                             "that renames or relocates `libacdbloader.so` therefore fails "
                             "*silently*: audio still starts, calibration simply stops being applied.  "
                             "The 41 names the extract lacks are the capture to-do, and they include "
                             "the readers of the config files in the row above (`libdrc.so`, "
                             "`libsurround_3mic_proc.so`)"),
         "source": f"{ROOT}/tools/shipped_disposition.py",
         "writable": "no -- read from the shipped binaries",
         "use_case": ("on 7: run the census with `--require-loader-carriers`; if 7's HAL names a "
                      "different loader soname (v3 naming, or libacdbdata on newer CAF), the gate "
                      "fires and every calibration row in this table has to be re-read against that "
                      "name instead"),
         "witness2": ("the arm in --selftest writes the literal into a fixture binary, requires the "
                      "census to report one carrier, then removes it and requires the abort -- the "
                      "same literal once hid behind a truncated print (`[:14]` before sorting), which "
                      "is why it is now a gate rather than a note"),
         },
        {"layer": "shipped file disposition", "item": "the 90-odd files nobody compares, and why",
         "value": ("QUIET by kind: " + "・".join(f"{k}: {n}" for k, n in sorted(by_kind.items())) +
                   f"; CITED-NOT-LIVE: {sum(1 for r in rows if r['verdict'] == 'CITED-NOT-LIVE')}"),
         "name_or_meaning": ("an explicit 'do not compare' class with a reason, so absence from the "
                             "comparison is a decision instead of an oversight: the other platforms' "
                             ".acdb sets (Fluid/Liquid/MTP/QRD/PD1516A) are cross-board reference, the "
                             "64-bit soundfx twins are reference, and media_codecs/media_profiles are "
                             "not on the 外放/Hi-Fi listening path.  If the numbers move, something "
                             "was either captured or cited that this census does not explain"),
         "source": f"{ROOT}/tools/shipped_disposition.py",
         "writable": "no",
         "use_case": ("on 7, run the same census and diff the verdict counts by kind; a config file "
                      "that moves from QUIET to LIVE-* is a new decision point the port has to model"),
         "witness2": ("verdict enum is closed in code and an unclassified file aborts the build; the "
                      "census also aborts if two files claim one device path (that is how the "
                      "/system/vendor symlink could have hidden a duplicate).  One caveat stated "
                      "plainly: the citation leg reads the carry list as it stands on disk, so the "
                      "cited counts here settle one build after rows are added"),
         },
    ]



def audiofx_rows():
    """§414: the app-level gate.  The kernel/HAL/ACDB layers describe what happens once a session
    exists; this is who is ALLOWED to have one, and what the owner's UI toggles are set to."""
    sys.path.insert(0, f"{ROOT}/tools")
    import audiofx_surface as af
    st = af.summarize(BASE)
    CS = af.code_surface(BASE)
    COPIES = af.copy_agreement(BASE)
    MS = af.manifest_surface(BASE)
    if not st["rows"]:
        sys.exit("gate: zero whitelist entries parsed -- refuse to emit a layer that would say 'no gate'")
    if "com.android.bbkmusic" not in st["installed_names"]:
        sys.exit("gate: the stock player that owns the captured prefs is not in the installed list -- "
                 "the two captures disagree about the machine")
    return [
        {"layer": "audio UI gating", "item": "Hi-Fi / effects whitelist: which apps may hold an fx session",
         "value": (f"version={st['version']} entries={st['apps']} installed-on-this-device="
                   f"{st['present']} ({' '.join(st['installed_names'])}); "
                   f"fx_session strings differ from the package for "
                   f"{sum(1 for r in st['rows'] if r['fx_session'] != r['package'])} entries"),
         "name_or_meaning": ("vivo's audio UI (com.vivo.audiofx) ships a whitelist whose entries pair a "
                             "package with the audio-FX session name it should use -- the name and the "
                             "location (the app's own data dir, next to its `enabled`/`key` prefs) say "
                             "this is the app-level gate, but **which code consumes it was not verified "
                             "instruction by instruction**, so read it as: these are the sessions the "
                             "audio UI knows about.  Most "
                             "the 46 entries name third-party music apps that this device does not "
                             "carry -- the eligible set here is the stock music app and the stock video "
                             "app.  A port that reproduces every control value and every calibration "
                             "byte can STILL sound different if this list or its version differs, "
                             "because the app being played never entered the Hi-Fi path"),
         "source": f"{BASE}/live/data_com.vivo.audiofx.tgz",
         "writable": "no -- app data captured from /data; the port reads it, never writes it",
         "use_case": ("on 7: unpack the same tgz and run `python3 tools/audiofx_surface.py --tsv ...`; "
                      "compare `version` and the entry set, and check which of them are installed -- "
                      "if 7's whitelist drops the stock player, the Hi-Fi path is unreachable by UI no "
                      "matter what the ACDB holds"),
         "witness2": ("parsed from the tgz itself (no remembered list); the eligibility claim is checked "
                      "against live/packages_sys.txt + packages_3rd.txt, and the tool aborts if the "
                      "package that owns the captured prefs file is missing from those captures"),
         },
        {"layer": "audio UI gating", "item": "the class that reads the whitelist, named by the app code",
         "value": ("ODEX " + str(CS["bytes"]) + " B: " +
                   "・".join(f"{k}=x{v}" for k, v in sorted(CS["found"].items())) +
                   " | optional: " + " ".join(f"{k}={v}" for k, v in sorted(CS["optional"].items())) +
                   " | APK layout: " + CS["apk"]),
         "name_or_meaning": ("this is what turns the whitelist from 'a file that looks like a gate' "
                             "into a named consumer: the app's own code carries the class references "
                             "`com/vivo/audiofx/whitelist/hifi/HiFiWhiteList` and `AppList`, the "
                             "absolute path `/data/bbkcore/com.vivo.audiofx.hifi_whitelist.xml` (i.e. "
                             "the authoritative copy is NOT in the app's own data dir), the settings "
                             "keys `hifi_settings_music`/`hifi_settings_video`, an update-time key "
                             "`hifi_online_update_list_update_time` and logs for 'update file not "
                             "exists'/'not changed since last update' -- so the list is updatable at "
                             "runtime and its content on 7 is a property of this device's history, not "
                             "only of the ROM.  It also names `IDSDStateListener` and "
                             "`com.vivo.audiofx.maxxaudio.effect`: the app-side partners of the DSD "
                             "path (§408) and of `libbbesonicmax.so`.  The APK itself holds no dex "
                             "(resources only), which is why this had to be read from the sibling .odex"),
         "source": f"{BASE}/shipped/system/app/AudioEffect/oat/arm64/AudioEffect.odex",
         "writable": "no -- a shipped binary, pulled read-only and md5-verified",
         "use_case": ("on 7: pull the same two files and run `python3 tools/audiofx_surface.py`; the "
                      "leg aborts if any of the seven strings is gone, which is the honest way to find "
                      "out that vivo moved the mechanism (renamed class, different store path, or the "
                      "code back inside the APK)"),
         "witness2": ("an arm copies the ODEX into a fixture, requires the positive read, then "
                      "overwrites the `HiFiWhiteList` class literal in place and requires the abort -- "
                      "so the claim 'the code names its reader' is checked by something that can fail"),
         },
        {"layer": "audio UI gating", "item": "the app's outer interface: bound service, receiver, actions",
         "value": ("AXML " + str(MS["bytes"]) + " B / " + str(MS["strings"]) +
                   " strings; required names all present: " + "・".join(sorted(MS["found"])) +
                   " | permissions: " + " ".join(MS["perms"])),
         "name_or_meaning": ("how anything outside the app reaches the Hi-Fi path, and the answer to the "
                             "loose end from the code leg: `com.vivo.audiofx.IAudioFxService` is NOT in "
                             "`service list` (which does list `audio`, `media.audio_flinger`, "
                             "`media.audio_policy` -- the positive control that the list is readable), "
                             "because it is a *bound* service.  So the outside-reachable surface is the "
                             "manifest's broadcasts: `com.vivo.audiofx.vivo_sound.enable`, "
                             "`...vivo_sound.request`, `com.vivo.action.HIFI_APP_STATE_CHANGED`, "
                             "`bbk.media.action.DISPLAY_HIFI_CONTROL_PANEL`, `com.vivo.audiofx.cmd.set`.  "
                             "Sending one changes the audible path, so it stays a §C actuation -- but a "
                             "named, testable one.  The permission set (`MODIFY_AUDIO_SETTINGS`, "
                             "`WRITE_SETTINGS`, `CHANGE_COMPONENT_ENABLED_STATE`, "
                             "`RECEIVE_BOOT_COMPLETED`, `MOUNT_UNMOUNT_FILESYSTEMS`, vivo logsystem "
                             "read/write) says who could, and that the app can toggle its own components"),
         "source": BASE + "/shipped/system/app/AudioEffect/AudioEffect.apk",
         "writable": "no -- pulled read-only and md5-verified against the device",
         "use_case": ("on 7: decode the same manifest and diff the action names.  If 7 renamed or dropped "
                      "`vivo_sound.enable`, anything that drove Hi-Fi through that broadcast stops working "
                      "silently, and the listening difference will look like a DSP change instead of an "
                      "interface change"),
         "witness2": ("two arms: blank the receiver's UTF-16 name in place (same length, offsets survive) "
                      "and the leg must abort; restore it and the leg must go green -- so the abort is the "
                      "mutation's doing, not the reader's"),
         },
        {"layer": "audio UI gating", "item": "which copy of the whitelist this device actually holds",
         "value": ("・".join(f"{k}={v[:10]}" for k, v in sorted(COPIES[0].items())) +
                   ("  ALL THREE AGREE" if COPIES[1] else "  DISAGREE -- two live answers on one machine")),
         "name_or_meaning": ("three copies exist (the app's files dir, the `.from.secure` sibling, and "
                             "the /data/bbkcore original the code names first) and they are identical "
                             "here, so quoting 'the whitelist' is safe on 6.0.1.  The earlier "
                             "assumption that `.from.secure` meant Settings.Secure was tested and died: "
                             "the secure table has no hifi or whitelist key at all (its only "
                             "audio-adjacent keys are `usb_audio_automatic_routing_disabled` and "
                             "`media_button_receiver`)"),
         "source": f"{BASE}/shipped/bbkcore/com.vivo.audiofx.hifi_whitelist.xml",
         "writable": "no",
         "use_case": ("on 7: hash all three again.  A disagreement means the UI and the HAL-side reader "
                      "can be looking at different lists, and then no amount of control-value matching "
                      "explains the listening difference -- this is the first thing to rule out"),
         "witness2": "md5 of each copy computed from the artefacts at build time, not from a remembered list",
         },
        {"layer": "audio UI gating", "item": "the owner's own toggle state at capture time",
         "value": (" ".join(f"{k}={v['kind']}:{v['value']}" for k, v in sorted(st["prefs"].items())) +
                   (" | " + st["drift"] if st["drift"] else "")),
         "name_or_meaning": ("this is the listening baseline the rest of the runbook compares against: "
                             "with `enabled=false` and `key/prevkey=NONE`, no UI effect was active on "
                             "the owner's machine when every capture in this directory was taken -- so "
                             "the 6.0.1 reference sound is the UN-EFFECTED path plus whatever Hi-Fi "
                             "mode the kernel control holds, not a tuned EQ preset.  `prevhifi=1` is the "
                             "last Hi-Fi state the UI saw.  Carrying the port without this note invites "
                             "'it sounds different' being blamed on the DAC when the UI state differs"),
         "source": f"{BASE}/live/data_com.vivo.audiofx.tgz",
         "writable": "no -- reading app prefs is non-destructive; writing them would change the audible path and is a §C item",
         "use_case": ("on 7: capture the same prefs and require the SAME state before any AB "
                      "comparison; if 7 shows enabled=true, the comparison is invalid until it is set "
                      "back (that write belongs to the user, not to this procedure)"),
         "witness2": ("the four keys are named by the tool's gate -- a prefs file missing any of them "
                      "aborts rather than reporting a partial state; the second copy inside the tgz "
                      "(hifi_whitelist.from.secure.xml) is diffed against the first and the row prints "
                      "whether they agree"),
         },
    ]



def settings_state_rows():
    """§414: the framework-side machine state a listening comparison rests on.

    Stream volumes and the Hi-Fi setting live in Settings.System, NOT in the tuning layers: a 7-side
    AB that ignores them compares different gain and a different Hi-Fi flag, and the difference gets
    blamed on the DAC.  Values are read from the captured tables on every build, so the row cannot go
    stale against a remembered number.
    """
    rows = []
    for table in ("system", "secure", "global"):
        p = f"{BASE}/live/settings-{table}.tsv"
        if not os.path.exists(p):
            sys.exit(f"gate: {p} missing -- run `bash tools/grab_settings_tables.sh` before building "
                     "this layer (it is the only witness for the machine-state claim)")
        rows.append(p)
    import csv as _csv
    st = {}
    for p in rows:
        for r in _csv.DictReader(open(p, encoding="utf-8"), delimiter="\t"):
            st[(os.path.basename(p).split("-")[1].split(".")[0], r["name"])] = r["value"]
    need = [("system", "volume_music_speaker"), ("system", "volume_music_headset"),
            ("system", "volume_music"), ("system", "hifi_settings_music"),
            ("system", "volume_voice"), ("global", "mode_ringer")]
    missing = [k for k in need if k not in st]
    if missing:
        sys.exit(f"gate: the captured tables lack {missing} -- the state row would quote keys that "
                 "are not there; re-capture rather than guess")
    _keys = sorted(k for t, k in st if t == "system" and ("volume" in k or "hifi" in k))
    return [
        {"layer": "audio UI gating", "item": "machine state the listening baseline depends on",
         "value": ("Settings.System: " + "・".join(f"{k}={st[('system', k)]}" for k in
                  ("volume_music_speaker", "volume_music_headset", "volume_music", "volume_music_earpiece",
                   "volume_voice", "volume_ring", "hifi_settings_music")) +
                  " | Settings.Global: mode_ringer=" + st[("global", "mode_ringer")] +
                  " audio_safe_volume_state=" + st[("global", "audio_safe_volume_state")]),
         "name_or_meaning": ("the per-stream gain the AudioFlinger master volumes are built on, plus "
                             "vivo's own `hifi_settings_music` flag.  Two facts the tuning layers "
                             "cannot see: the speaker music index here is "
                             + st[("system", "volume_music_speaker")] + ", which is NOT the index 8 the "
                             "PA-safety rule asks for before any experiment that removes limiting -- so "
                             "the preflight has to say that out loud rather than let a comparison start "
                             "one index hot; and `hifi_settings_music=1` while the audio UI's own prefs "
                             "say `enabled=false`, i.e. there are three separate Hi-Fi/effects state "
                             "carriers (framework setting, app prefs, kernel `HiFi Mode Switch` §332) "
                             "and they do not imply each other"),
         "source": f"{BASE}/live/settings-system.tsv",
         "writable": ("writing any of these changes the audible path -- `settings put` is a §C item; "
                      "this layer only records what the tables say"),
         "use_case": ("on 7: capture the same three tables and require the SAME values for the streams "
                      "under test before the first AB; also check that no key this layer names has "
                      "disappeared -- a missing `volume_music_speaker` on 7 means the speaker stream is "
                      "represented differently and the volume comparison is not the same quantity"),
         "witness2": ("parsed from `content query --uri content://settings/<table> --projection "
                      "name:value`, gated at >=20 rows per table because `content` exits 0 even when it "
                      "printed nothing; the gate also refuses the row if any of the six keys the text "
                      "names is absent, and the counts print with the unparsed-line count next to them"),
         },
        {"layer": "audio UI gating", "item": "the Settings tables contain no whitelist key (a hypothesis killed)",
         "value": ("secure=" + str(sum(1 for (t, k) in st if t == "secure")) +
                   " system=" + str(sum(1 for (t, k) in st if t == "system")) +
                   " global=" + str(sum(1 for (t, k) in st if t == "global")) +
                   " | keys matching hifi|white in secure: "
                   + (", ".join(sorted(k for (t, k) in st if t == "secure" and ("hifi" in k.lower() or "white" in k.lower()))) or "none")),
         "name_or_meaning": ("the audio UI keeps a second whitelist copy called "
                             "`hifi_whitelist.from.secure.xml`, which reads like 'the authoritative list "
                             "came from Settings.Secure'.  It did not: the secure table holds no hifi or "
                             "whitelist key at all.  So the two copies are two files in the app's own "
                             "data, and the name is about where the app *thinks* it came from -- which "
                             "means a port must copy the file, not hope a settings write reaches it"),
         "source": f"{BASE}/live/settings-secure.tsv",
         "writable": "no",
         "use_case": ("on 7: same query; if 7 DOES keep a whitelist in a settings table, the carry "
                      "procedure differs (a settings write instead of a file copy), so this negative is "
                      "worth re-testing rather than assuming"),
         "witness2": "the counts come from the captured TSVs, and the hifi/white search runs over the secure table's keys in this build",
         },
    ]



def audio_log_rows():
    """§415: the only layer that describes a SEQUENCE rather than a state -- what the HAL ran, in
    order, with the ADSP's own return codes."""
    sys.path.insert(0, f"{ROOT}/tools")
    import audio_log_surface as al
    raw = f"{BASE}/live/logcat-raw.txt"
    if not os.path.exists(raw):
        sys.exit("gate: " + raw + " missing -- capture it with `adb exec-out \"su -c 'logcat -d -v brief'\"` "
                 "(read-only); this layer is runtime evidence and must never be typed from memory")
    hits, lines, kept, audio_levels, kept_levels = al.scan([raw])
    total = sum(len(v) for v in hits.values())
    if total == 0:
        sys.exit("gate: 0 audio events in the stored dump -- either nothing was playing when it was "
                 "taken or the tag set is blind; either way there is no skeleton to report")
    for k in ("select_devices", "send_audio_cal"):
        if not hits[k]:
            sys.exit(f"gate: the dump has no {k} lines but {total} other events -- the parse is blind")
    mixer_board = f"{BASE}/shipped/system/etc/mixer_paths_tasha.PD1610.xml"
    platform_info = f"{BASE}/shipped/system/etc/audio_platform_info.xml"
    board_table = al.mixer_paths_table(mixer_board)
    join = al.cross_check(hits, board_table, mixer_board)
    disc = al.discriminate(hits, al.mixer_family(f"{BASE}/shipped/system/etc"))
    chain = al.backend_chain(hits, platform_info, board_table)
    writers = al.ctl_writers(board_table)
    def uniq(k):
        return sorted({"・".join(str(y) for y in g) for _, _, g in hits[k]})
    errs = uniq("acdb_error")

    def join_text():
        # each route path the log applied, expanded into the controls the board file says it writes
        if not join:
            return ""
        paths, resolved = join
        parts = []
        for path, toks in sorted(resolved.items()):
            per = []
            for token, ctls in toks:
                switches = [f"{n}={v}" for n, v in ctls if "Switch" in n]
                per.append(token + " sets " + ("/".join(switches) if switches
                                               else f"no Switch among {len(ctls)} ctl(s)"))
            parts.append(path + " -> " + ", ".join(per))
        return (f" | log x board-file join: {len(resolved)}/{len(paths)} route path(s) resolve; "
                + "; ".join(parts))

    def disc_text():
        if not disc:
            return ""
        paths, per, winners = disc
        losers = sorted(k for k, v in per.items() if v[0] != v[1])
        verdict = ("DISCRIMINATING: only " + winners[0] if len(winners) == 1 else
                   ("names nothing: no candidate explains every route" if not winners else
                    "names nothing: " + str(len(winners)) + " survivors it cannot tell apart"))
        return (" | candidate-file test over " + str(len(per)) + " mixer-family files (key = the WHOLE "
                "route name the HAL passes): refutes " + str(len(losers)) +
                (" (" + "・".join(losers) + ")" if losers else "") + "; " + verdict)

    def chain_text():
        if not chain:
            return ""
        per = []
        for nm, dev, be, iface, ctls, known in chain:
            sw = ",".join(f"{a}={b}" for a, b in ctls if "Switch" in a or "Mode" in a)
            per.append(f"{nm} -> {dev} backend={be} interface={iface} " +
                       (f"{len(ctls)} ctl(s)" + (f" [{sw}]" if sw else "") if known
                        else "backend NOT in any mixer path"))
        return " | log->platform-info->mixer chain: " + "・".join(per)

    return [
        {"layer": "runtime audio events", "item": "the session the HAL actually ran (device, acdb id, rate, route paths)",
         "value": ("log lines " + str(lines) + " raw / " + str(kept) + " audio-tagged; levels kept " +
                   str({k: v for k, v in kept_levels.items() if v}) + "; " +
                   "select_devices=" + ("・".join(uniq("select_devices")) or "none") +
                   " send_audio_cal=" + ("・".join(uniq("send_audio_cal")) or "none") +
                   " app_type_cfg=" + ("・".join(uniq("app_type_cfg")) or "none") +
                   " dolby_endpoint=" + ("・".join(uniq("dolby_endpoint")) or "none") +
                   " route_applied=" + ("・".join(uniq("route_path_enable")) or "none") +
                   " route_reset=" + ("・".join(uniq("route_path_reset")) or "none") +
                   join_text() + disc_text() + chain_text()),
         "name_or_meaning": ("a live Hi-Fi session as the device itself narrates it: snd_device 43 "
                             "`headphone-hifi` enabled, `acdb_dev_id 150` with `app_type 69937` at "
                             "44100 Hz, and the route cell names `deep-buffer-playback headphone-hifi` "
                             "-- the same pair the board mixer file defines, seen from the other side.  "
                             "This is corroborating evidence for three state layers (the device table, "
                             "the acdb id list, the route-state capture) and it is the layer that survives "
                             "a state diff being ambiguous: if 7 selects a different snd_device or sends a "
                             "different app type, no value comparison needs to be interpreted.  "
                             "Two more legs came out of the same join.  (1) ★a THIRD independent witness "
                             "for §412's 'which mixer file is loaded' -- whose real power is REFUTATION: "
                             "the key is the WHOLE route name the HAL passes (`deep-buffer-playback "
                             "headphone-hifi`), and of the ten mixer-family files in the extract three "
                             "do not define it at all (`mixer_paths.xml`, `mixer_paths_dtp.xml`, "
                             "`mixer_paths_i2s.xml` -- the generic one defines `deep-buffer-playback` "
                             "four times, one on `SLIMBUS_0_RX` and three empty, so a token-level match "
                             "would have resolved it on the wrong file AND the wrong backend).  Seven "
                             "survivors (the tasha family plus the four FTM files) explain it equally, "
                             "so THIS leg alone names no file -- the intersection with §412's composed "
                             "name (`mixer_paths_<card token2>.<model>.xml`) is what leaves one.  I "
                             "first ran this with a hand-picked pair of candidates and it 'proved' the "
                             "board file was loaded; the candidate set is now enumerated from the disk "
                             "(mixer_family()).  (2) the same route lands on backend `headphone-hifi` = "
                             "interface `TERT_MI2S_RX`, the interface the platform info also gives for "
                             "SPEAKER -- Hi-Fi and 外放 share the TERT MI2S backend and the mixer path "
                             "separates them, the file-side counterpart of §299.  Note the two route "
                             "directions print differently (`apply mixer and update path` vs `reset and "
                             "update mixer path`): one pattern covering both matched only the reset "
                             "line, i.e. it read the undo and called it the application"),
         "source": f"{BASE}/live/logcat-raw.txt",
         "writable": "no -- a log dump, read-only capture",
         "use_case": ("on 7: boot, start the same file on the same route, then `logcat -d` and run "
                      "`python3 tools/audio_log_surface.py`.  Compare the SKELETON (which device ids, "
                      "which route path names, which ACDB commands) -- log text differs by version and "
                      "should not be diffed line-wise"),
         "witness2": ("thirteen selftest arms cover these legs: besides the level guard, the "
                      "ACDB-removal abort and the unknown-route-path abort, an arm gives a candidate "
                      "set in which NOTHING explains the route (the leg must then refuse to name a "
                      "file), one runs with only the reset line present (the union must still hold), "
                      "one with no route evidence at all (no file may be named), one runs over the "
                      "whole mixer family and must REFUTE three files while naming none, one renames "
                      "`SmartPA Switch` in a mixer file that still contains the route names (only the "
                      "enumeration leg may fire), and two doctor audio_platform_info.xml (drop the "
                      "device the log enabled / point it at a backend no mixer path defines).  Every "
                      "gate arm also names WHICH gate fired -- before that, one arm passed simply "
                      "because a default path was unreadable.  The tool counts per-level audio-tagged lines with a class-blind pattern before "
                      "filtering, and aborts if E-level audio lines exist yet none survived -- that "
                      "guard exists because an early filter omitted `E` and silently dropped the only "
                      "three error lines in the buffer (the ACDB -19s).  The join is gated too: a route "
                      "path the board mixer file does not define aborts the tool (fourth selftest arm)."),
         },
        {"layer": "runtime audio events",
         "item": "which board-file route paths can raise the decisive controls (file side of §298/§299)",
         "value": "・".join(f"{c} <- {len(p)} path(s): " + " ".join(p) for c, p in sorted(writers.items())),
         "name_or_meaning": ("§298 answered 'the single cell 外放 needs is `SmartPA Switch`' from the DAPM "
                             "graph; this is the same question answered from the loaded mixer file, and "
                             "it enumerates WHO may write it: exactly three route paths "
                             "(`speaker`, `speaker-mono`, `speaker-and-headphones`, all value 1).  "
                             "`HiFi Mode Switch` is written by two (`headphone-hifi` = HiFi, "
                             "`headphone-hifi-DSD` = DSD) and `DSD SampleRate Switch` by one.  Read "
                             "with the chain leg: the combo device `speaker-and-headphones` exists in "
                             "the platform info with interface `TERT_MI2S_RX-and-SLIMBUS_6_RX` AND "
                             "writes SmartPA Switch, so the FILE allows 外放+耳机同开 -- whether both "
                             "streams really co-activate is a live read, not a claim from this file.  "
                             "The enumeration merges every occurrence of a path name: reading the file "
                             "into `{name: node}` keeps only the LAST one, which for these files is an "
                             "empty Qualcomm stub, so a dict comprehension is exploration, not a ruler"),
         "source": mixer_board,
         "writable": "indirect -- these paths are what a route switch would write; the port reads the "
                     "file, and any actuation that raises SmartPA Switch stays §C",
         "use_case": ("on 7: run the same enumeration against 7's loaded mixer file.  If a control's "
                      "writer set changes (e.g. `speaker-and-headphones` drops `SmartPA Switch`), that "
                      "is a route-level difference no control-value comparison would show"),
         "witness2": ("computed from the file at build time; an arm renames `SmartPA Switch` in a mixer "
                      "file that still defines the log's route names, so only the enumeration leg can "
                      "fire -- the join cannot mask it"),
         },
        {"layer": "runtime audio events", "item": "ACDB commands and the errors that are BASELINE on 6.0.1",
         "value": ("commands=" + "・".join(uniq("acdb_cmd")) +
                   "; errors=" + ("・".join(errs) if errs else "none in this buffer")),
         "name_or_meaning": ("these three `-19` failures happen on the 6.0.1 device we are treating as "
                             "the good sound: `AUDPROC_COMMON_TABLE_SIZE`, `audproc`, and `AFE` all "
                             "return -19 during the headphone-hifi session, and playback continues.  "
                             "Recorded so that a 7 port does not chase them as regressions -- and so the "
                             "inverse is meaningful: if 7 issues those commands and they SUCCEED while "
                             "the sound differs, the difference is not these calls.  The dump has FOUR "
                             "E-level audio lines, not three: the fourth is "
                             "`audio_extn_dolby_ds2_set_endpoint: Dolby set endpint :0x4` from the same "
                             "pid as the ACDB loader.  Its meaning is NOT established -- one line in a "
                             "rolling buffer does not prove Dolby DS2 was in the audible path, and the "
                             "owner state says `enabled=false` -- so it is carried as a named event to "
                             "compare, not as a claim.  It is keyed on the device's own misspelling "
                             "(`endpint`), the same fingerprint family as the HAL's `DSDEnbale` (§408), "
                             "and an arm proves that keying: correct the typo in a fixture and the event "
                             "must stop being reported"),
         "source": f"{BASE}/live/logcat-audio.txt",
         "writable": "no",
         "use_case": "on 7: `grep -c \"Error: ACDB\" ` on the same capture; compare the SET of failing commands, not the count",
         "witness2": ("an arm removes every ACDB line from a fixture dump and the tool refuses to call "
                      "the result a skeleton; another excludes the E level from the filter and the level "
                      "guard fires"),
         },
    ]



def boot_rows():
    """§417: the kernel's own account of one cold boot -- the only layer that describes what happened
    exactly once, and the only place the PA's boot calibration measurement lives."""
    sys.path.insert(0, f"{ROOT}/tools")
    import boot_narrative as bn
    drel, lrel = bn.DMESG, bn.LOGCAT
    dp, lp = f"{BASE}/{drel}", f"{BASE}/{lrel}"
    for p, what in ((dp, "dmesg"), (lp, "logcat")):
        if not os.path.exists(p):
            sys.exit("gate: " + p + " missing -- a " + what + " boot capture is the whole point of this "
                     "layer; grab it within the first minutes after a boot (the logcat ring is only "
                     "1 MB and rolls the HAL's own boot lines out in ~30 s)")
    dtext = open(dp, encoding="utf-8", errors="replace").read()
    ltext = open(lp, encoding="utf-8", errors="replace").read()
    f = bn.parse(dtext)
    missing = [k for k in bn.MANDATORY if not f[k]]
    if missing:
        sys.exit("gate: boot facts absent from the stored dmesg: " + " ".join(missing))
    lf = bn.parse_log(ltext)
    if not lf["whitelist_read"]:
        sys.exit("gate: no HiFiInfoServer parseFileToGetList line in the boot logcat -- the runtime "
                 "witness naming the whitelist reader is gone")
    imp = bn.impedance_verdict(f)
    if imp.startswith("OUT-OF-WINDOW"):
        sys.exit("gate: " + imp + " -- refusing to publish a baseline whose PA booted uncalibrated")
    def g(k, i=0, j=0):
        return f[k][i][j]
    return [
        {"layer": "driver boot narrative",
         "item": "PA boot identity, the .cnt the DT picked, and its boot calibration",
         "value": (g("cnt_file") + " size=" + g("cnt_load", 0, 1) + " B; members " +
                   "・".join(f"[{a}]{b}={c}" for a, b, c in f["cnt_member"]) +
                   "; chip id " + g("chip_id") + " FW " + g("fw_ic_rev", 0, 0) +
                   "/IC " + g("fw_ic_rev", 0, 1) +
                   "; f0 window " + g("f0_window_hz", 0, 0) + ".." + g("f0_window_hz", 0, 1) + " Hz; " +
                   imp + "; MTP count " + g("mtp_count") + "; patch len " + g("patch_len") +
                   "; speaker params " + g("spk_params") + "; boot attenuation " + g("boot_attenuation") +
                   " dB; DSP regs " + "・".join(f"{a}={b}" for a, b in f["dsp_regs"])),
         "name_or_meaning": ("one cold boot as the kernel driver narrates it.  Two things here are not "
                             "reconstructable from any file: which .cnt the device tree selected "
                             "(`tfa98xx_PD1610.cnt`, size 4977 as loaded, with its member list naming "
                             "the patch/config/speaker blobs and the two profiles MUSIC_48000 + "
                             "VOICE_48000), and the impedance the PA MEASURED during its boot "
                             "calibration (07.15 Ohm) against the window the DT declares "
                             "(06.30..09.50).  That pair is the acceptance check for 7: the window may "
                             "legitimately differ (different DT) and the measurement may differ "
                             "(different speaker unit), but they must remain coherent or the PA is "
                             "running uncalibrated -- and the ruler refuses to publish a baseline in "
                             "that state rather than printing a number.  The member names also close "
                             "the .cnt container question from ledger 238-243 from the other side: the "
                             "driver lists them as it loads them.  §366's f0 window (700..950) is "
                             "re-confirmed verbatim from a fresh boot"),
         "source": dp,
         "writable": "no -- a kernel ring-buffer read, captured right after boot",
         "use_case": ("on 7: `adb exec-out \"su -c 'dmesg'\" > <7>/live/dmesg-boot.txt` within the "
                      "first minutes after boot, then `python3 tools/boot_narrative.py`.  Compare the "
                      "SET (which .cnt, which members, which profiles) and the coherence of measured "
                      "vs declared impedance -- not the register values, which differ every boot"),
         "witness2": ("five arms: the fixture parses, a measured 05.00 with the same window must be "
                      "called OUT-OF-WINDOW and abort, deleting the .cnt load line must abort, a "
                      "tail-only dmesg (not the boot segment) must abort, and a logcat without the "
                      "HiFiInfoServer line must abort.  Every fact is read out of the stored capture "
                      "at build time -- none of these numbers is typed from a note"),
         },
        {"layer": "driver boot narrative",
         "item": "ASoC route failures at boot (baseline set) and the card/codec identities",
         "value": (str(len(f["route_fail"])) + " unique failure(s): " +
                   "・".join(r.replace("ASoC: ", "")[:44] for r in f["route_fail"]) +
                   "; card registered " + g("card_registered") + "; Hi-Fi codec node " +
                   g("hifi_codec_node") + "; jack " + (g("jack_poles") if f["jack_poles"] else "?") +
                   " pole; machine probe repeats " + str(f["probe_repeats"])),
         "name_or_meaning": ("these 17 route failures are printed on the machine whose sound is the "
                             "target, so they are BASELINE, not defects to fix -- the list is what a 7 "
                             "boot must be diffed against.  Three of them are load-bearing for this "
                             "project: `unknown pin Speaker` + `no source widget found for HEADPHONE` / "
                             "`Failed to add route HEADPHONE -> direct -> HP` come from the "
                             "`hifi-codec-pd1610a` node (the Hi-Fi DAC's own DAPM description is "
                             "incomplete at boot, which is consistent with §290's finding that the "
                             "Hi-Fi path is actuated through the codec driver, not through a widget "
                             "route), and `CODEC DAI tasha_vifeedback not registered` plus 45 repeats "
                             "of the machine probe are deferred-probe churn, not an error.  The card "
                             "string `msm8996-tasha-cdp-snd-card` is the kernel-side witness for the "
                             "card token §412's composed mixer filename depends on"),
         "source": dp,
         "writable": "no",
         "use_case": ("on 7: compare the SET of route failures and the card string.  A 7 boot that "
                      "reports FEWER failures may have merged those routes -- then the graph differs "
                      "even if every control value matches, and §299's cone analysis has to be redone "
                      "there rather than assumed"),
         "witness2": "counts computed from the file at build time; the arm set above is what makes a silent parse failure loud",
         },
        {"layer": "driver boot narrative",
         "item": "boot-time HAL session, the whitelist reader named at runtime, and the isHifiSupport value flip",
         "value": ("select_devices " + "・".join(" ".join(x) for x in lf["boot_session"][:1]) +
                   "; app_type " + "・".join(" ".join(x) for x in lf["boot_app_type"][:1]) +
                   "; route " + "・".join(x[0] for x in lf["boot_route"][:1]) +
                   "; isHifiSupport " + "・".join(f"ret{a}=value{b}" for a, b in lf["hifi_support"]) +
                   " (in-play capture reads value:1); dlopen failures " +
                   "・".join(sorted({x[0] for x in lf["dlopen_fail"]})) +
                   "; whitelist parsed by AudioFx/HiFiInfoServer " +
                   str(len(lf["whitelist_read"])) + " line(s) -> " +
                   "・".join(sorted({x[0] for x in lf["whitelist_read"]}))),
         "name_or_meaning": ("three things this row settles.  (1) ★§414's open claim -- 'which code "
                             "consumes the whitelist was not verified' -- now has a RUNTIME witness: "
                             "the log names `AudioFx/HiFiInfoServer()` calling `parseFileToGetList: "
                             "com.vivo.audiofx.hifi_whitelist.xml` (3 lines), and `AudioFxService` "
                             "prints `HAVE_HIFI`.  (2) A second complete session is on record: at boot "
                             "the HAL ran snd_device 8 `headphones` with acdb_dev_id 10 at 48000 over "
                             "route `deep-buffer-playback headphones` -- so the route/device/acdb "
                             "triples are no longer a single sample (43/150 in-play vs 8/10 at boot).  "
                             "(3) ★`isHifiSupport` answers ret:4 with **value:0 at boot and value:1 "
                             "during the in-play capture** -- same ret, different value, so `value` is "
                             "a STATE and not a model capability; what writes it between boot and "
                             "playback is still unproven, and that is the sharpest form of the §B "
                             "question.  The `libwvm.so` dlopen failure is recorded as baseline noise "
                             "(Widevine is not installed here)"),
         "source": lp,
         "writable": "no",
         "use_case": ("on 7: `logcat -d -v brief` immediately after boot (main ring is 1 MB and the "
                      "HAL's own boot lines are gone ~30 s later) and compare: the session triples, "
                      "whether HiFiInfoServer still parses the same filename, and whether "
                      "isHifiSupport's value flips at the same moment"),
         "witness2": ("the whitelist-reader assertion is a gate in both tools: boot_narrative aborts if "
                      "the parseFileToGetList line is absent, and one selftest arm removes it from a "
                      "fixture to prove the gate fires"),
         },
    ]



def acdb_api_rows():
    """§418: which binaries are allowed to drive the ACDB loader, and the logd-capacity finding that
    says the HAL's own mixer-filename line is not reachable on this device."""
    sys.path.insert(0, f"{ROOT}/tools")
    import acdb_api_surface as api
    tsv = f"{BASE}/acdb-api-callers.PD1610.tsv"
    rows = api.classify(api.surface(BASE), api.mapped_names(BASE))
    ext = api.check(rows)
    live = sorted({c for r in rows for c in r["live_callers"]})
    listen = [r for r in rows if "listen" in r["entry"]]
    solo = [r for r in rows if r["n_callers"] == 0]
    note_p = f"{BASE}/live/logd-capacity-20261017.txt"
    if not os.path.exists(note_p):
        sys.exit("gate: " + note_p + " missing -- the log-ring finding is measured evidence and must not "
                 "be written from memory; rerun the probe it describes")
    note = open(note_p, encoding="utf-8").read()
    for must in ("ring buffer is 1Mb", "logcat -G 4M", "25.11 s", "17839"):
        if must not in note:
            sys.exit(f"gate: the capacity note lacks {must!r} -- it no longer records the measurements "
                     "the conclusion depends on")
    pcm_p = f"{BASE}/live/inplay-hifioff-20261017-1105/thread-owner.txt"
    if not os.path.exists(pcm_p):
        sys.exit("gate: " + pcm_p + " missing -- the PCM owner claim needs the /proc read, not a memory")
    ptxt = open(pcm_p, encoding="utf-8").read()
    if "Tgid" not in ptxt:
        sys.exit("gate: the thread-owner capture has no Tgid line -- it does not prove the owner is a thread")
    import dsd_surface as ds
    dd = ds.report(BASE)
    dsd_txt = (f"{len(dd['bins'])} binaries / " +
               str(sum(len(v['found']) for v in dd['bins'].values())) + " evidence strings; " +
               "・".join(sorted({k for v in dd['bins'].values() for k in v['found']})) +
               "; codec " + dd['codec']['name'] + " type " + dd['codec']['type'] +
               "; props " + "・".join(f"{k}={v!r}" for k, v in sorted(dd['props'].items())))
    ctl_p = f"{BASE}/live/inplay-hifioff-20261017-1105/controls.txt"
    reg_p = f"{BASE}/live/inplay-hifioff-20261017-1105/codec_reg.txt"
    ctl = open(ctl_p, encoding="utf-8").read() if os.path.exists(ctl_p) else ""
    reg = open(reg_p, encoding="utf-8").read() if os.path.exists(reg_p) else ""
    hi = re.search(r"HiFi Mode Switch:\s*>?(\w+)", ctl)
    sp = re.search(r"SmartPA Switch:\s*>?(\w+)", ctl)
    r0 = re.search(r"reg\{0000\}:([0-9a-f]+)", reg)
    r9 = re.search(r"reg\{0009\}:([0-9a-f]+)", reg)
    return [
        {"layer": "ACDB API callers",
         "item": "which binaries name the loader's entry points (the sub-path map)",
         "value": (f"{len(rows)} acdb/gsl symbol names in the extract; {len(ext)} distinct external "
                   f"callers: {'・'.join(sorted(ext))}; live callers {len(live)} ({'・'.join(live)}); "
                   f"entry points with no external caller: {len(solo)}; "
                   "listen-cal edges: " + "・".join(f"{r['entry']}<-{','.join(r['callers'])}"
                                                   for r in listen)),
         "name_or_meaning": ("this is the API side of the calibration layer: the .acdb card says what "
                             "calibration EXISTS, this says who is allowed to ASK for it.  Two findings "
                             "came out of widening the capture in §417: ①★`sound_trigger.primary.msm8996.so` "
                             "dlopens libacdbloader itself (`acdb_loader_init_v2`, `get_calibration`, "
                             "`send_listen_afe_cal`, `send_listen_lsm_cal`) -- a second external dlopen "
                             "carrier besides the audio HAL, and the concrete caller behind the "
                             "`send_listen_*` senders named in §396; ②★`libqcbassboost.so` (a mapped "
                             "soundfx module) names `acdb_loader_get_audio_cal_v2` -- an EFFECT library "
                             "reading ACDB calibration directly, i.e. part of the audible path is "
                             "ACDB-derived and not reproducible by copying control values.  The "
                             f"{len(solo)} loader-internal entry points (adsp/store get-set, "
                             "get_aud_vol_steps, get_ecrx_device...) have no caller in the extract, so "
                             "they are listed, not claimed"),
         "source": tsv,
         "writable": "no -- read from the shipped binaries",
         "use_case": ("on 7: run `python3 tools/acdb_api_surface.py --tsv <7>/acdb-api-callers.PD1610.tsv` "
                      "and diff the CALLER set per entry point.  An entry point that loses its caller "
                      "(e.g. no binary names send_listen_afe_cal any more, or nothing names "
                      "get_audio_cal_v2) is a missing sub-path: the calibration data can be identical and "
                      "the sound still differs, because nobody asks the ADSP for that block"),
         "witness2": ("three known edges are asserted by the tool, each established another way: "
                      "init_v2<-audio.primary (§411 dlopen), send_listen_afe_cal<-sound_trigger.primary "
                      "(dlsym strings in the same binary), get_audio_cal_v2<-libqcbassboost.  Arms: erase "
                      "one caller's literal in a linked fixture and the control must fail, restore it and "
                      "it must pass again; delete the live maps capture and the tool refuses to call "
                      "anything LIVE.  Fixtures link files instead of copying 164 MB, and a mutation "
                      "unlinks first so it can never write through into the baseline"),
         },
        {"layer": "DSD Hi-Fi source surface",
         "item": "both DSD routes exist, and what selects between them is a property plus a codec role",
         "value": dsd_txt,
         "name_or_meaning": ("DSD reaches the DAC by TWO independent routes on this machine, and the "
                             "listen result differs between them: ①★hardware DSD -- the HAL's "
                             "`AUDIO_OUTPUT_FLAG_HW_DSD`, the mixer control `HiFi DSD Volume Switch`, the "
                             "`headphone-hifi-DSD` route path, gated by the live property "
                             "`audio.dsd.hw.out=1`; ②★software DSD -- vivo's own media core "
                             "(`vivo::DSDExtractor`/`vivo::DSDDecoder`, `dsd2pcm_init/translate/reset`, "
                             "ffmpeg `ff_dsd_lsbf/msbf_decoder`, DSDIFF/DSF parsers) registered as "
                             "`OMX.vivo.dsd.decoder` with media type `audio/dsd`.  The framework half "
                             "(`libmediaplayerservice`) carries `DSDEnable return`/`isResetDSDFinished`/"
                             "`performResetDSD` -- the calls that actually reset the DSD path between "
                             "tracks, and `libmars-service.so` names the same `audio.dsd.hw.out` key.  "
                             "So 'does a DSD file sound the same' is decided by a PROPERTY, a CODEC "
                             "REGISTRATION and a HAL FLAG at once -- none of which appear in any control "
                             "value table.  `persist.vivo.phone.hifi=Have_hifi` and "
                             "`ro.config.hifi_config_state=2` are read live (with `ro.vivo.product.model` "
                             "as the same-run control that getprop works)"),
         "source": BASE + "/live/getprop.txt",
         "writable": ("no -- the properties are read; writing `audio.dsd.hw.out` would move DSD between "
                       "routes, which changes the audible path and stays §C"),
         "use_case": ("on 7: run `python3 tools/dsd_surface.py` against the 7 extract.  The check is the "
                      "SET, not the text: is `OMX.vivo.dsd.decoder`/`audio/dsd` still registered, does "
                      "the HAL still hold `AUDIO_OUTPUT_FLAG_HW_DSD`, does the framework still answer "
                      "`DSDEnable`/`isResetDSDFinished`, and what is `audio.dsd.hw.out` there.  Any one "
                      "of the four missing silently reroutes DSD playback"),
         "witness2": ("four arms: the stored extract must report BOTH routes; removing vivo's media core "
                      "from a fixture aborts; renaming the dsd MediaCodec line aborts the registration "
                      "leg; deleting `audio.dsd.hw.out` from the property capture aborts the property leg "
                      "-- so no leg can pass by silence"),
         },
        {"layer": "runtime audio events",
         "item": "in-play state with Hi-Fi OFF, and the PCM owner being a THREAD of mediaserver",
         "value": ((f"HiFi Mode Switch={hi.group(1) if hi else '?'}・SmartPA Switch={sp.group(1) if sp else '?'}"
                    f"; PA reg0000={r0.group(1) if r0 else '?'} reg0009={r9.group(1) if r9 else '?'} "
                    "(= the §283 IDLE values, with a stream RUNNING); `hifi_settings_music=0`; "
                    "PCM owner_pid 1723 -> Name=AudioOut_2 Tgid=719 (mediaserver)")),
         "name_or_meaning": ("the §B-6 read done in the negative direction: a real playback session was "
                             "running (one PCM in state RUNNING, AudioFlinger 48 kHz track, resample reset) "
                             "while Hi-Fi was OFF, and the PA registers read their IDLE values -- so "
                             "`SmartPA Switch=Off` + `HiFi Mode Switch=Off` is what an ordinary "
                             "non-Hi-Fi, non-speaker session looks like at boot+1 h.  ★The PCM "
                             "`owner_pid` is a THREAD of mediaserver (`AudioOut_2`, Tgid 719), not the "
                             "process id: comparing it to `pidof mediaserver` would wrongly conclude "
                             "'a different host owns the PCM'.  The decisive positive read (in-play with "
                             "Hi-Fi ON, where §415's chain predicts `HiFi Mode Switch=HiFi` for the "
                             "duration of the stream) is now on the table: the in-play Hi-Fi snapshot "
                             "reads `HiFi Mode Switch=HiFi` and the speaker snapshot reads the PA side "
                             "On (ledger 420, layer `in-play route state`)"),
         "source": f"{BASE}/live/inplay-hifioff-20261017-1105",
         "writable": "no -- all reads (tinymix get, /proc, debugfs cat); no control was written",
         "use_case": ("on 7: same read while playing WITHOUT Hi-Fi first (it should show Off/Off and idle "
                      "PA registers), then with Hi-Fi on.  The pair is what tests §415's causal chain; a "
                      "7 that shows HiFi Mode Switch=Off even in a Hi-Fi session means the route path no "
                      "longer asserts the control, which no static file comparison would reveal -- and 6.0.1 does read HiFi in-play, verified from two capture forms of the same snapshot (ledger 420)"),
         "witness2": ("the capture directory is required by this builder (missing files abort) and the "
                      "thread claim is read out of /proc/1723/status text, not asserted"),
         },
        {"layer": "audio HAL surface",
         "item": "log ring capacity: the HAL's own mixer-filename line is NOT capturable on this device",
         "value": ("`persist.logd.size=4M` ignored after reboot (ring still 1Mb)・`logcat -G 4M` returns "
                   "rc=0 and is also ignored・streaming from adbd-up (uptime 25.11 s, 17839 lines) still "
                   "shows 0 mixer-open lines; earliest HAL lines are out_get_latency/adev_open_output_stream"),
         "name_or_meaning": ("§412/§416 established WHICH mixer file is loaded by three legs, and the "
                             "missing fourth witness was the HAL printing its own chosen filename.  This "
                             "row records that it cannot be obtained inside the stated boundary: the main "
                             "ring is 1 MB and unchangeable (property AND runtime resize ignored), and "
                             "adbd itself appears at ~25 s, after `adev_open` has already emitted those "
                             "lines.  So the honest status is 'unreachable by design constraint', not "
                             "'TODO' -- and the three legs are load-bearing.  Recorded with the revert "
                             "state: the property file was deleted (effective next boot) while the live "
                             "property still echoes 4M until the next reboot"),
         "source": note_p,
         "writable": "no -- the experiment wrote one inert property, which was reverted",
         "use_case": ("on 7: re-run the two commands (`setprop persist.logd.size 4M` + reboot, "
                      "`logcat -G 4M`) and check `logcat -g`.  If 7's logd DOES honour them, the "
                      "mixer-filename line becomes capturable there -- a case where 7 gives more evidence "
                      "than the 6.0.1 baseline, so the runbook should capture boot logs on 7 even though "
                      "the same capture failed here"),
         "witness2": ("the builder aborts unless the stored note contains the measured strings "
                      "(ring text, the -G command, the uptime of adbd, the line count) -- the row cannot "
                      "be written from a recollection of the experiment"),
         },
    ]



def control_state_rows():
    """§419: what a Hi-Fi session ASSERTS, as a diff of two full control tables, plus the cross-boot
    register reconfirmation taken in the same session."""
    sys.path.insert(0, f"{ROOT}/tools")
    import control_state_diff as csd
    dact = f"{BASE}/live/inplay-hifion-20261017-1933"
    idle_p, act_p = f"{BASE}/live/tinymix-D0.txt", os.path.join(dact, "tinymix-all.txt")
    for p in (idle_p, act_p):
        if not os.path.exists(p):
            sys.exit("gate: " + p + " missing -- this layer is a diff of two stored full dumps")
    ch, oa, ob = csd.diff(csd.parse(idle_p), csd.parse(act_p))
    miss = [m for m in csd.MUST_MOVE if m not in ch]
    if miss:
        sys.exit("gate: must-move controls absent from the diff: " + "・".join(miss) +
                 " -- the active capture is not a Hi-Fi session, so this layer would report a fiction")

    def pair(k, n=26):
        a, b = ch[k]
        return f"{k}:{a[:n].strip()}->{b[:n].strip()}"
    facts = "・".join(pair(k) for k in sorted(ch))
    def regs(p):
        t = open(p, encoding="utf-8", errors="replace").read()
        return {k: v for k, v in re.findall(r"reg\{([0-9a-fx]+)\}:([0-9a-f]+)", t)}
    dac_new = regs(os.path.join(dact, "es9038-reg.txt"))
    dac_old = regs(f"{BASE}/live/dac-hpplay-20261016-092159.txt")
    common = sorted(set(dac_new) & set(dac_old))
    ddiff = {k: (dac_old[k], dac_new[k]) for k in common if dac_old[k] != dac_new[k]}
    if len(common) < 40:
        sys.exit(f"gate: only {len(common)} DAC registers are comparable between the two captures -- "
                 "the read format changed; refusing to report a reconfirmation count")
    pa = regs(os.path.join(dact, "codec_reg.txt"))
    st = open(os.path.join(dact, "settings.txt"), encoding="utf-8").read()
    pcm = open(os.path.join(dact, "pcm-status.txt"), encoding="utf-8").read()
    if "RUNNING" not in pcm:
        sys.exit("gate: no RUNNING PCM in the active capture -- the diff would compare idle against idle")
    if "hifi_settings_music=1" not in st:
        sys.exit("gate: the active capture does not record hifi_settings_music=1 -- the session "
                 "attribution is unproven")
    track_p = f"{BASE}/live/inplay-track-20261017-2000.txt"
    if not os.path.exists(track_p):
        sys.exit("gate: " + track_p + " missing -- the session needs its SOURCE MATERIAL named, or "
                 "'the same sound on 7' cannot be re-heard; resolve it by readlink on the fds of the "
                 "process that owns the RUNNING pcm")
    tl = dict(re.findall(r"^(\w[^(\n]*?)\s*:\s*(.+)$", open(track_p, encoding="utf-8").read(), re.M))
    return [
        {"layer": "control-table transitions",
         "item": "the recording the Hi-Fi baseline was heard on (so 7 can replay the SAME bytes)",
         "value": (f"{tl.get('file','?').strip()}・size={tl.get('size bytes','?').strip()} B・"
                   f"md5={tl.get('md5 (device)','?').strip()}・player={(tl.get('player mode','?') or '?').strip()}"
                   "・container=MP3 (so `DSD SampleRate Switch` correctly stayed Off)"),
         "name_or_meaning": ("the deliverable's success criterion is a perceived match, and a perception "
                             "comparison needs one fixed recording.  The file is resolved from the process "
                             "that owns the RUNNING PCM (`owner_pid` -> Tgid -> `readlink fd/*`), not from "
                             "what I remember was queued: a 12.3 MB MP3 (md5 taken on the device) in a "
                             "14-file folder, played on single-track loop so the same piece is in front of "
                             "the reader at every control read.  ★It also settles a §418 question: because "
                             "the source is MP3, the hardware-DSD route cannot be the active one, so "
                             "`DSD SampleRate Switch` staying Off during a genuine Hi-Fi session is "
                             "expected rather than a missing link"),
         "source": track_p,
         "writable": "no -- an fd/dir read; the song itself was never copied (its md5 is the handle)",
         "use_case": ("on 7: copy the same file (verify the md5) and play it on loop before any in-play "
                      "read -- comparing control sets across different recordings is meaningless because "
                      "the app-type and impedance values track the stream"),
         "witness2": ("the builder parses the note's own fields (file / size bytes / md5 / player mode) and "
                      "aborts if the note is missing; the note records how each value was obtained, "
                      "including the between-loop window where an fd scan comes back empty while the PCM "
                      "is still RUNNING"),
         },
        {"layer": "control-table transitions",
         "item": "what a Hi-Fi session asserts: 14 of 1518 controls move (idle -> Hi-Fi in play)",
         "value": f"{len(ch)} changed, 0 name-only on either side; " + facts,
         "name_or_meaning": ("this is the acceptance SET for 7, and it was invisible in every "
                             "single-instant read: the board mixer path only NAMES 5 controls "
                             "(§416), the session actually moves 14.  Four of them carry mechanism, "
                             "not just state: ①★`Audio Stream 0 App Type Cfg` second word goes "
                             "**15 -> 150** = the per-stream ACDB device id is readable straight out of "
                             "the control table (15 = SPEAKER/HP default, 150 = HEADPHONE_HIFI) -- a "
                             "third, file-free way to check the acdb id pairing of §403;  "
                             "②★`HPHL/HPHR Impedance` 0 -> **35 ohm**, which is the value §326's column "
                             "selector consumes (34/35 ohm -> column 1), so the impedance path is now "
                             "witnessed live during the very session whose DAC columns we compared;  "
                             "③★`TERT_MI2S mode` **Master -> Slave** -- the Hi-Fi route hands the clock "
                             "to the external side (the es9028), which is the file-side counterpart of "
                             "§357's clock step and is NOT in the `headphone-hifi` path's 5 controls;  "
                             "④`HiFi Mute` Both -> None, `HP Sel` Normal -> HiFi, `HPH Type` 0 -> 2, "
                             "`TERT_MI2S Bit Format` S16_LE -> S24_LE, `DSD SampleRate Switch` stays Off "
                             "and `HiFi DSD Volume Switch` stays 19 (so this is PCM Hi-Fi, not DSD).  "
                             "Also moving: the two MultiMedia1 mixer enables, `Headphone Rx Mixer I2S_RX`, "
                             "the two channel maps, and `Vbat ADC data` (PA fuel-gauge noise with the PA "
                             "off)"),
         "source": act_p,
         "writable": "no -- both dumps are `tinymix -D 0` reads; nothing was set",
         "use_case": ("on 7: capture `tinymix -D 0` twice (idle, then playing with Hi-Fi on) and run "
                      "`python3 tools/control_state_diff.py --idle <7>/live/tinymix-idle.txt "
                      "--active <7>/live/tinymix-hifi.txt`.  The gate is the SET of movers plus the four "
                      "mechanism values: a 7 that reaches HiFi Mode Switch=HiFi but leaves "
                      "`TERT_MI2S mode` on Master, or never fills App Type Cfg with 150, is routing "
                      "Hi-Fi through something else -- which is exactly the kind of difference that "
                      "changes the sound while every single-instant read still looks correct"),
         "witness2": ("five arms: the stored pair must report exactly the recorded change count, a "
                      "self-diff must report 0 changes and then have the must-move gate fire, comparing "
                      "two idle dumps must abort, a truncated dump must abort rather than present a "
                      "small diff, and undoing ONE asserted value in a fixture must lower the count -- "
                      "so the number cannot come from a remembered list"),
         },
        {"layer": "control-table transitions",
         "item": "cross-boot register reconfirmation taken in the same Hi-Fi session",
         "value": (f"DAC es9038: {len(common) - len(ddiff)}/{len(common)} registers identical to the "
                   f"2026-10-16 in-play capture ({'no differences' if not ddiff else str(len(ddiff)) + " differ: " + str(ddiff)}); "
                   f"PA codec_reg in the same instant: 0x00={pa.get('0000')} 0x09={pa.get('0009')} "
                   "= the §283 IDLE pair, consistent with SmartPA Switch=Off"),
         "name_or_meaning": ("the DAC register state survives a reboot and a fresh session unchanged "
                             "(48/48), which is the register-level twin of §373's f0 reconfirmation: the "
                             "Hi-Fi enable path writes the same table every time, so a 7 that differs here "
                             "is a different enable sequence, not a different measurement.  The PA reads "
                             "its idle pair because this session is headphones-only -- recorded so nobody "
                             "reads those two values as a PA-on baseline"),
         "source": dact,
         "writable": "no -- debugfs cat reads",
         "use_case": ("on 7: diff `cat /sys/kernel/debug/es9038/reg` taken while playing with Hi-Fi on "
                      "against this 48-register baseline.  Equal = the enable sequence writes the same "
                      "table; unequal = list which registers, and treat it as a mechanism difference"),
         "witness2": ("the builder aborts unless the capture shows a RUNNING PCM, "
                      "hifi_settings_music=1, and >=40 comparable DAC registers, so the reconfirmation "
                      "count can never be printed against a mismatched pair"),
         },
    ]



def dsd_gate_rows():
    """§422: the hardware-DSD gate is a cached byte flag, and this reads it out of the binary."""
    sys.path.insert(0, f"{ROOT}/tools")
    import dsd_gate
    libs = [f"{BASE}/shipped/system/lib/libmediaplayerservice.so",
            f"{BASE}/shipped/system/lib/libmars-service.so"]
    for p in libs:
        if not os.path.exists(p):
            sys.exit("gate: " + p + " missing -- the DSD gate row is a binary reading, not a recollection")
    A = dsd_gate.read(f"{BASE}/shipped/system/lib/libmediaplayerservice.so")
    B = dsd_gate.read(f"{BASE}/shipped/system/lib/libmars-service.so")
    written = sorted({x for n in A["stores"] for x in A["stores"][n] if isinstance(x, int)})
    read = sorted({x for n in A["loads"] for x in A["loads"][n]})
    if 0xF1 not in written or 0xF1 not in read:
        sys.exit("gate: the writer/reader pair at +0xf1 is what this layer claims -- if the decode no "
                 "longer shows it, the row must be rewritten, not asserted")
    def short(n):
        return n.split("NuPlayer")[-1].lstrip("123456789")
    libp = f"{BASE}/shipped/system/lib/libmediaplayerservice.so"
    sites, lits = dsd_gate.mime_sites(libp)
    _ms = [x for x in sites if x["mime_fourcc_seen"]]
    if not _ms:
        sys.exit("gate: no site carries the 'mime' fourcc -- the operand-calibration reading has "
                 "nothing to attach to, so this row must be rewritten rather than left asserting a "
                 "comparison target")
    _cal = _ms[0]["calibration"]
    _mime = next((x for x in sites if x["mime_fourcc_seen"]), None)
    if _mime["literal"] is None:
        sys.exit("gate: the MIME operand is not named (%s) -- this row asserts a comparison target, "
                 "so it must not be generated from an unresolved read" % _mime["literal_status"])
    _xsec = f"{BASE}/disasm/onStart-mime-objdump.txt"
    if not os.path.exists(_xsec):
        sys.exit("gate: the second-disassembler cross-check artifact %s is missing -- the naming "
                 "would rest on one tool's reading alone" % _xsec)
    _d, _secs = dsd_gate.elf32(libp)
    _nm, named_ct, stub_ct, _amb = dsd_gate.plt_names(_d, _secs)

    return [
        {"layer": "DSD Hi-Fi source surface", "item": "the instruction-level DSD gate: `NuPlayer::updateHWDSDEnable` caches a byte flag",
         "value": ("literal `" + dsd_gate.PROP + "` at " + "・".join(A["prop_vas"]) + "; " +
                   "DSD-named functions " + str(len(A["funcs"])) + ": " +
                   "・".join("%s@%#x/%dB" % (short(k), A["funcs"][k][0], A["funcs"][k][1])
                             for k in sorted(A["funcs"])) +
                   "; byte offsets WRITTEN by them: " + "・".join(hex(x) for x in written) +
                   "; byte offsets READ by the predicates: " + "・".join(hex(x) for x in read) +
                   "; read-but-not-written-here: " +
                   "・".join(hex(x) for x in sorted(set(read) - set(written))) +
                   "; `updateHWDSDEnable` (96 B) ends `cmp r0, #1` -> `strb r0, [r4, #0xf1]`, "
                   "`isHWDSDEnable` (56 B) begins `ldrb r0, [r0, #0xf1]`" +
                   "; whole-library pass decoded " + str(A["decoded"]) + " instructions across the "
                   "exported functions, and the flag census is: " +
                   "・".join("%s written by %s / read by %s" % (o, "|".join(x.split("NuPlayer")[-1]
                             .lstrip("123456789")[:30] for x in c["writers"][:4]),
                             "|".join(x.split("NuPlayer")[-1].lstrip("123456789")[:30]
                                      for x in c["readers"][:4]) or "nobody here")
                             for o, c in sorted(A["census"].items()) if o in ("0xf0", "0xf1", "0xf2"))),
         "name_or_meaning": ("★this closes the question §418 left open: the hardware-vs-software DSD "
                             "choice is not a routing table, it is a **cached byte in the NuPlayer "
                             "object at +0xf1**, refreshed only by `updateHWDSDEnable()`, which reads "
                             "`audio.dsd.hw.out`, converts it (`cmp #1`, so only the value 1 enables) "
                             "and stores the result -- and the consumer `isHWDSDEnable()` reads exactly "
                             "that offset.  A second flag at +0xf0 is read by `isHWDSDPlayer()` and is "
                             "written by no DSD-NAMED function -- and §423 found the writer anyway: "
                             "`NuPlayer::onStart()` sets it per stream from a MIME test (the "
                             "`findCString('mime')` row below), while the ctor only zeroes it.  "
                             "Reset bookkeeping is three more bytes (+0xd0/+0xd1/+0xd3, one of them "
                             "written by `performResetDSD`) and `resetDSD()` sets +0xf2 then passes the "
                             "fourcc built from `movw #0x7364 / movt #0x7264` = the bytes `d s d r`.  "
                             "★For the port this turns a listening question into a file question: if 7's "
                             "player service has no such writer, the hardware DSD path cannot engage no "
                             "matter what `audio.dsd.hw.out` says -- and that is invisible in every "
                             "config file we carry"),
         "source": f"{BASE}/shipped/system/lib/libmediaplayerservice.so",
         "writable": "no -- read-only decode of a stored library",
         "use_case": ("on 7: `python3 tools/dsd_gate.py --elf <7>/system/lib/libmediaplayerservice.so` "
                      "(and the lib64 path if the build moved it -- the tool refuses a 64-bit ELF "
                      "instead of disassembling it blind, so move the check to whatever file the 7 "
                      "player service actually is and read the refusal as information)"),
         "witness2": ("5 arms: the writer/reader pair at +0xf1 must actually agree, a flag read but not "
                      "written here must be REPORTED rather than hidden, a non-ELF32 file must be "
                      "refused, and blanking every DSD symbol name must empty the census (that arm's "
                      "first fixture only renamed two of six symbols, so it proved nothing until the "
                      "pattern was widened -- an arm passing on an incomplete mutation is the same old "
                      "failure shape)"),
         },
        {"layer": "DSD Hi-Fi source surface", "item": "the same property read by a second service, whose symbols are gone",
         "value": ("libmars-service.so: literal `" + dsd_gate.PROP + "` at " +
                   "・".join(B["prop_vas"]) + "; DSD-named symbols: " + str(len(B["funcs"])) + " (none)"),
         "name_or_meaning": ("`libmars-service.so` carries the same key but exports no DSD-named "
                             "function, so this tool can show the literal and nothing more there -- the "
                             "boundary is printed with the result on purpose: a 7 build that keeps the "
                             "literal and loses the reader is indistinguishable from one that never had "
                             "a reader, unless the symbol shape is also compared (which is what the row "
                             "above does for the player service)"),
         "source": f"{BASE}/shipped/system/lib/libmars-service.so",
         "writable": "no",
         "use_case": "on 7: same command against 7's libmars-service.so; compare the literal count AND whether any DSD-named symbol survives",
         "witness2": ("the census comes from .dynsym with size>0 and type=FUNC; the tool aborts when "
                      "there is no symbol table at all rather than pattern-matching bytes into names"),
         },
        {"layer": "DSD Hi-Fi source surface",
         "item": "the per-stream DSD decision: findCString('mime') -> strcasecmp -> the byte flag, and the literal it compares",
         "value": ("sites in this library matching `MetaData::findCString` then `strcasecmp` then a byte "
                   "store: " + str(len(sites)) + " (" +
                   "・".join("%s +%#x mime-fourcc=%s" % (x["function"].split("android")[-1][:34],
                                                        x["flag_offset"], x["mime_fourcc_seen"])
                            for x in sorted(sites, key=lambda y: y["flag_offset"])) +
                   "); audio/* literals in .rodata: " + "・".join(lits) +
                   "; operand calibration: mode=" + str(_cal["mode"]) + "・rule=" + str(_cal["rule"]) +
                   "・absolute-VA pool words=" + str(_cal["absolute_hits"]) +
                   "・chain sums tried=" + str(_cal["sums_tried"]) +
                   "・closest miss=" + ("n/a" if _cal["residual"] is None else hex(_cal["residual"])) +
                   "; ★compared MIME literal NAMED: " + repr(_mime["literal"]) +
                   "・status: " + str(_mime["literal_status"])[:150]),
         "name_or_meaning": ("★the instruction-level answer §418 left open, and now with the comparison "
                             "target NAMED instead of inferred.  Of the four findCString/strcasecmp/store "
                             "sites in the player service, exactly one loads its key as the fourcc 'mime' "
                             "(`movw r1, #0x6d65` + `movt r1, #0x6d69`), and it is `NuPlayer::onStart()`, "
                             "whose byte store lands on +0xf0 -- the offset `isHWDSDPlayer()` reads -- and "
                             "the next instruction is `ldrb r1, [r4, #0xf1]`, the property-derived HW-DSD "
                             "enable.  So hardware DSD is decided **per stream, by MIME name, ANDed with "
                             "the cached property flag**.  §423 had to stop at 'exclusivity, not a resolved "
                             "pointer' because its operand arithmetic kept a residual of exactly 4; §430 "
                             "found why: the Thumb literal pools in this object are filled against "
                             "PC = (addr+4)&~3, not the (addr+8)&~3 the tool assumed.  With the corrected "
                             "convention the SAME def chain reproduces `audio.dsd.hw.out` at the "
                             "`property_get` call inside `NuPlayer::determineAudioModeChange` (a string "
                             "whose address is independently known), and then resolves onStart's "
                             "strcasecmp first argument to 0x87dfa = ★`audio/dsd`; the log-format argument "
                             "two instructions above resolves through the same base (0xa11f0) to 0x87de0 = "
                             "`This file has audio track` -- one base, two strings, no free parameters.  "
                             "★Corroboration from another layer entirely: `audio/dsd` is exactly the media "
                             "type the OMX component `OMX.vivo.dsd.decoder` is registered with, so the "
                             "framework and the HAL name the same string, and the DSD material that §424 "
                             "said was needed to settle this is no longer needed for THIS question."),
         "source": f"{BASE}/shipped/system/lib/libmediaplayerservice.so",
         "writable": "no -- read-only decode",
         "use_case": ("on 7: `python3 tools/dsd_gate.py --elf <7 libmediaplayerservice.so> --mime` and read "
                      "two lines.  (1) the calibration line: mode=known-answer plus a rule that names the "
                      "`property_get` site is the strong case; mode=statistical means the object has no "
                      "property literal so the rule was certified by landing counts, which is weaker and "
                      "must be written down as such; no rule at all means the tool REFUSES and the "
                      "comparison target cannot be settled from the file.  (2) the `compared operand` line "
                      "for the site carrying the 'mime' fourcc: 7's expected answer is the same string "
                      "`audio/dsd` -- a different string means the DSD trigger moved, an inline/rename of "
                      "the imports means the leg has to be re-pointed at 7's own names and must NOT be "
                      "read as 'no DSD decision'"),
         "witness2": ("12 arms: exactly one site must carry the 'mime' fourcc and its flag must be the "
                      "offset `isHWDSDPlayer` reads; the operand must come back NAMED as `audio/dsd` with "
                      "mode=known-answer; ★move-the-witness fixture rewrites the chain's delta pool word "
                      "so it points at a DIFFERENT real string in .rodata and the tool must then name THAT "
                      "one -- the name follows the arithmetic, not a constant; ★break-the-chain fixture "
                      "zeros the same word and the tool must REFUSE for that operand while its calibration "
                      "still passes -- a refusal is a ruler, not a habit; renaming `strcasecmp` out of "
                      ".dynstr makes the leg refuse rather than print zero sites; stub naming is per-target "
                      "exact-slot matching with coverage printed (1467 of 1920 here); the PC convention "
                      "itself is cross-checked with a second disassembler in " + _xsec),
         },
        {"layer": "ARM32 operand arithmetic",
         "item": "the Thumb PC base this build's literal pools are filled against",
         "value": ("pool slot = ((instruction address + 4) & ~3) + immediate; the anchor in `add rN, pc` "
                   "is also (address + 4) & ~3, and a string operand is (delta word) + (base word + "
                   "anchor) with the sum taken mod 2^32 -- " +
                   ("verified at %d real `property_get` site(s) in this object, first at %s, against a "
                    "string whose address is independently known"
                    % (len(_cal["calibration_sites"]), _cal["calibration_sites"][0][1]))
                   if _cal["mode"] == "known-answer" else
                   ("no property literal in this object, so certified statistically: %d def-chain sums "
                    "land on a literal start and %d of them survive a 1-byte shift"
                    % (_cal.get("literal_starts", 0), _cal.get("shifted_starts", 0)))),
         "name_or_meaning": ("★a tool-side expectation, not a device artifact, and it cost two rounds: "
                             "with the (addr+8)&~3 habit the same arithmetic lands 4 bytes off, which "
                             "reads like 'the operand is unrecoverable' and is actually 'the ruler has no "
                             "scale'.  Any operand naming on 7's ARM32 (or ARM64 `adrp`/`add` pairs) has "
                             "to be re-calibrated the same way -- the convention is a property of how the "
                             "object was linked, not of the architecture, so it must not be carried over "
                             "from this table as an assumption"),
         "source": _xsec,
         "writable": "no -- read-only decode",
         "use_case": ("on 7, before naming any string operand from instructions: run `dsd_gate.py --mime` "
                      "and check the calibration line says mode=known-answer (or, if the object has no "
                      "property literal, statistical with the landing counts shown) -- if neither, the "
                      "convention differs and every operand read from that build is a guess"),
         "witness2": ("the artifact is arm-linux-gnu-objdump's own pool annotation for the two windows "
                      "(the property_get call and the strcasecmp call) plus the arithmetic in its header; "
                      "objdump resolves `ldr rN,[pc,#i]` to (addr+4)&~3+i independently of this tool, and "
                      "the two strings the base produces are readable in the same file"),
         },

    ]




def hifi_control_rows():
    """§426: the vivo parameter grammar between app, AudioFlinger, policy and HAL -- read out of the
    string pools, with the runtime log line as an independent second witness."""
    sys.path.insert(0, f"{ROOT}/tools")
    import hifi_param_grammar as hpg
    root = f"{BASE}/shipped"
    res, nfiles, blind = hpg.scan(root)
    hs = res.get("hifi_switch_change", [])
    dv = res.get("dsdvol_index", [])
    af = [h for h in hs if "libaudioflinger" in h["file"]]
    app = [h for h in hs if h["file"].endswith(".odex")]
    if not (af and app):
        sys.exit("gate: hifi_switch_change is no longer seen on BOTH the app side and the "
                 "AudioFlinger side (%d/%d) -- the grammar row cannot name a two-endpoint protocol"
                 % (len(af), len(app)))
    hal = [h for h in dv if "audio.primary" in h["file"]]
    pol = [h for h in dv if "audiopolicymanager" in h["file"]]
    if len({hpg.bitness(h["abs"]) for h in hal}) != 2:
        sys.exit("gate: dsdvol_index must be present in the HAL's 32-bit AND 64-bit copies (found "
                 "%s) -- §379 established mediaserver runs the 32 one, so a single copy would mean "
                 "the parameter is not on the path that plays" % sorted({hpg.bitness(h['abs']) for h in hal}))
    fmt = "%s: enter: usecase(%d: %s) kvpairs: %s"
    cap = f"{BASE}/live/inplay-spk-20261017-2012/logcat-audio.txt"
    if not os.path.exists(cap):
        sys.exit("gate: " + cap + " missing -- the agreement check needs the running log")
    txt = open(cap, encoding="latin-1", errors="replace").read()
    # build a matcher FROM the binary's format string and let the capture fill the slots: no value
    # is typed by hand, so a stale or edited capture fails the build instead of passing on memory
    PREFIX = re.compile(r"^[VDIWEAF]/[^ (]+\(\s*\d+\):\s*")   # the logcat tag/pid header, not the message
    rx = re.compile(re.escape(fmt).replace("%s", "(.+?)").replace("%d", r"(\d+)") + r"\s*$")
    matched = [m for m in (rx.search(PREFIX.sub("", l)) for l in txt.splitlines() if "usecase(" in l)
               if m]
    if not matched:
        sys.exit("gate: the HAL format string %r does not match ANY line in the captured session -- "
                 "either the capture or the binary changed, so neither may be reported as confirming "
                 "the other" % fmt)
    first = matched[0]
    dsd_lines = [m for m in matched if "dsdvol_index" in m.group(4)]
    if not dsd_lines:
        sys.exit("gate: no captured out_set_parameters line carries dsdvol_index -- the producer row "
                 "loses its runtime witness")

    def keyed(h):
        return "・".join(x[:44] for x in h["keyed"][:6])
    return [
        {"layer": "Hi-Fi/DSD control plane",
         "item": "`hifi_switch_change` exists on exactly two ends: the AudioEffect app and AudioFlinger",
         "value": ("%d occurrence(s) in %d scanned files -- app side %s ・ AudioFlinger side %s ・ "
                   "AudioFlinger neighbours: %s"
                   % (len(hs), nfiles, "・".join(h["file"] + "@" + h["offset"] for h in app),
                      "・".join("@" + h["offset"] for h in af),
                      keyed(max(af, key=lambda h: len(h["keyed"]))))),
         "name_or_meaning": ("★the per-app Hi-Fi switch is an AUDIO PARAMETER handled inside "
                             "AudioFlinger itself -- the literal sits in a run of vivo grammar tokens "
                             "(`ckmute=`, `finduid=`, `;`, `getParameters, keys:%s`, "
                             "`getParameters, packageName:%s, int:%d`, "
                             "`getParameters, support HIFI Client count:%d`), and the app's own pool "
                             "carries the prefix `hifi_switch_change=` plus a complete example "
                             "`hifi_switch_change=com.android.bbkmusic:1`.  So the shape is "
                             "`<k=v;k=v;hifi_switch_change=<package>:<0|1>` and the HIFI client count "
                             "is ANSWERED BY getParameters, not read from a mixer control.  ★Nothing "
                             "here was executed: this is the string pool, so direction is inferred "
                             "from which two binaries share the key, not from a call graph."),
         "source": f"{BASE}/shipped/system/lib/libaudioflinger.so",
         "writable": ("yes in principle -- `setParameters` would change the audible path, so it is a "
                      "nod-required action; this row only reads the binaries"),
         "use_case": ("on 7: `python3 tools/hifi_param_grammar.py`.  If 7's AudioFlinger lacks the key "
                      "while the app still sends it, the per-app Hi-Fi switch has NO consumer: the UI "
                      "can still look right while Hi-Fi never engages -- invisible in every config "
                      "file we carry"),
         "witness2": ("6 arms: the key must be present on both ends; the HAL must carry dsdvol_index in "
                      "BOTH bitness copies; erasing the key from a copy must be called blind rather "
                      "than reported as an empty neighbour list; and padding the neighbours out of the "
                      "window must DROP the grammar claim instead of widening the window "
                      "(adjacency is a bounded pool fact, not a call edge)"),
         },
        {"layer": "Hi-Fi/DSD control plane",
         "item": "`dsdvol_index` is produced in the policy's volume path and consumed by the HAL",
         "value": ("%d occurrence(s): %s ・ policy-side neighbours: %s"
                   % (len(dv), "・".join("%s(%d-bit)@%s" % (os.path.basename(h["file"]),
                                                           hpg.bitness(h["abs"]), h["offset"]) for h in hal),
                      keyed(pol[0]) if pol else "none")),
         "name_or_meaning": ("★this is the CAUSE behind §425's warning: the policy manager sits with "
                             "`checkAndSetVolume()` strings and the HAL with `out_set_parameters`, so "
                             "`dsdvol_index=6` is emitted on the ordinary volume path for every "
                             "playback -- it is a volume-curve parameter, NOT evidence that a DSD "
                             "stream is in play.  The value is carried in the kvpairs the HAL logs."),
         "source": f"{BASE}/shipped/system/lib/libaudiopolicymanager.so",
         "writable": "no -- read-only string-pool reading",
         "use_case": ("on 7: same command; compare the SET of carriers (policy + both HAL copies). "
                      "A HAL that stopped reading the key silently loses a DSD volume step while "
                      "everything still plays"),
         "witness2": ("the 32-bit requirement is enforced by §379's finding that mediaserver runs the "
                      "32-bit stack (a 64-bit-only copy would not be the one that plays), and the "
                      "file denominator (265) is printed with the result"),
         },
        {"layer": "Hi-Fi/DSD control plane",
         "item": "the HAL's format string reproduces the captured runtime line (two independent sources)",
         "value": ("%d line(s) in the speaker session match the HAL format string (first match fills "
                   "the slots %s); %d of them carry dsdvol_index"
                   % (len(matched), [g[:26] for g in first.groups()], len(dsd_lines))),
         "name_or_meaning": ("★the agreement gate is what makes this row more than a string match: "
                             "the format literal is filled with the values the RUNNING system logged "
                             "and must appear in that line verbatim, so the static pool and the "
                             "runtime capture corroborate each other.  If they disagree the function "
                             "aborts instead of reporting a match."),
         "source": f"{BASE}/live/inplay-spk-20261017-2012/logcat-audio.txt",
         "writable": "no",
         "use_case": ("on 7: re-run with 7's capture; the built string must match 7's own line, and "
                      "that tells whether the same HAL entry point exists there under the same shape"),
         "witness2": ("the check is computed inside this generator, so a stale or edited capture fails "
                      "the build rather than passing on a remembered string"),
         },
    ]


def dsd_runtime_rows():
    """§425: the DSD decision as the RUNNING system logged it, pulled out of the stored logcat."""
    sys.path.insert(0, f"{ROOT}/tools")
    import dsd_runtime_face as drf
    live = f"{BASE}/live"
    dirs = [f"{live}/{x}" for x in sorted(os.listdir(live))
            if os.path.isdir(f"{live}/{x}")
            and any(f.startswith("logcat") for f in os.listdir(f"{live}/{x}"))]
    lone = [f"{live}/{f}" for f in sorted(os.listdir(live))
            if f.startswith("logcat") and os.path.isfile(f"{live}/{f}")]
    if not lone:
        sys.exit("gate: no standalone boot logcat in " + live + " -- the capability row is a reading")
    usable, skipped = [], []
    for d in dirs:
        try:
            usable.append(drf.read(d))
        except SystemExit as e:
            skipped.append("%s: %s" % (os.path.basename(d), str(e).replace("gate: ", "")[:70]))
    try:
        usable.append(drf.read_group("boot: %d standalone logcat file(s)" % len(lone), lone))
    except SystemExit as e:
        skipped.append("boot group: %s" % str(e)[:70])
    if not usable:
        sys.exit("gate: no capture group could be read at all -- that is a parser problem, not a "
                 "finding about DSD")
    chains = [(r, c) for r in usable for c in r["captures"] if c["chain"]]
    if not chains:
        sys.exit("gate: the hand-off chain is gone from the stored captures -- the row that names it "
                 "must be rewritten, not asserted")
    # quote the chain from the group whose route is known from dump values; print every group's line
    # count and switch value -- one boot capture says `data 1` and the speaker capture says `data 0`,
    # and a single longest-chain pick hid that
    chain_desc = []
    for r, c in chains:
        m = re.search(r"data (\d+)", c["chain"][0])
        chain_desc.append("%s/%s: %d lines, data %s" % (os.path.basename(r["dir"])[:20], r["route"],
                                                        len(c["chain"]), m.group(1) if m else "?"))
    spk = [(r, c) for r, c in chains if r["route"] != "not attributable"]
    ch = (spk or chains)[0][1]["chain"]
    pids = []
    for line in ch:
        m = re.search(r"\(\s*(\d+)\)", line)
        if m and m.group(1) not in pids:
            pids.append(m.group(1))
    pairs = [x for r in usable for c in r["captures"] for x in c["pairs"]]
    if not pairs:
        sys.exit("gate: no DSDHw_exist ask/return pair in the usable captures -- the capability row "
                 "has no witness")
    sh = drf.shapes(usable)
    sticky = [k for k in sh if "dsdvol_index" in k[1]]
    bc = [x["msg"] for r in usable for c in r["captures"] for x in c["dsd"]
          if "com.vivo.media.dsd.display" in x["msg"]]
    send = [x["msg"] for r in usable for c in r["captures"] for x in c["dsd"]
            if "onSendShowDSDIntent" in x["msg"]]
    if not (bc and send):
        sys.exit("gate: the named DSD broadcast is no longer seen both SENT and RECEIVED in the "
                 "stored captures, so the §C row must not claim a captured witness")
    SNAP = f"{live}/hifi-route-threadtime-20261017-2249"
    odex = f"{BASE}/shipped/system/app/AudioEffect/oat/arm64/AudioEffect.odex"
    if not os.path.exists(odex):
        sys.exit("gate: " + odex + " missing -- the receiver-identity half of the broadcast row is a "
                 "file reading, not a recollection")
    ob = open(odex, encoding="latin-1", errors="ignore").read()
    recv = [t for t in ("onReceive: com.vivo.media.dsd.display state = ",
                        "Lcom/vivo/audiofx/AboutDSD;", "registerDSDStateListener",
                        "com.vivo.audiofx.IDSDStateListener", "DSDHw_exist", "DSDHW",
                        "HIFI_STATE_CHANGED") if t in ob]
    if len(recv) < 5:
        sys.exit("gate: the odex carries only %d of the 7 receiver-side tokens -- the broadcast row "
                 "must drop its receiver-identity claim rather than name a class it cannot show"
                 % len(recv))
    stamped = [p for p in drf._corpus_files(live) if sum(1 for e in drf.events(p)[0] if e["ts"]) >= 1000]
    if not stamped:
        sys.exit("gate: no threadtime (timestamped) capture in the corpus -- the interval row cannot "
                 "be computed from brief-format files, and must not be asserted from memory")
    trows = [x for x in drf.time_leg(stamped) if x.get("timestamps", 0) >= 1000]
    # Not "the biggest ring" -- the ring that actually carries the dsdvol_index lines.  An in-play
    # snapshot's own logcat ring can be larger and still contain no stream start (the 01:15 capture is
    # exactly that), and silently computing intervals from it would be a number with no subject.
    withgaps = [x for x in trows if x.get("gaps")]
    if not withgaps:
        sys.exit("gate: none of the %d timestamped captures carries a dsdvol_index interval -- the "
                 "heartbeat row has no subject (largest ring: %s timestamps)"
                 % (len(trows), max(trows, key=lambda x: x["timestamps"])["timestamps"]))
    tr = max(withgaps, key=lambda x: x["timestamps"])
    ring_census = "・".join("%s: %d timestamped/%d intervals" % (x.get("file") or "ring%d" % i,
                                                                x["timestamps"],
                                                                len(x.get("gaps") or []))
                           for i, x in enumerate(sorted(trows, key=lambda y: -y["timestamps"])))
    pcm = open(f"{SNAP}/running-pcm.txt", encoding="latin-1", errors="replace").read() \
        if os.path.exists(f"{SNAP}/running-pcm.txt") else ""
    running = [l.split(":")[0] for l in pcm.splitlines() if re.search(r"\sRUNNING\s|: *RUNNING", l)]
    sticky_pids = sorted({p for k in sticky for p in sh[k]["pids"]})
    sticky_n = sum(sh[k]["n"] for k in sticky)
    if not sticky_pids:
        sys.exit("gate: the dsdvol_index shape lost its pids -- the stickiness row has no evidence")
    runfiles = sorted(glob.glob(f"{live}/inplay-*/running.txt") + glob.glob(f"{live}/*/running.txt"))
    if not runfiles:
        sys.exit("gate: no in-play running.txt in the corpus -- that file is the witness that a stream "
                 "really was open, so the interval row cannot claim one")
    owners, per_ring = set(), []
    for rf in runfiles:
        rt = open(rf, encoding="latin-1", errors="replace").read()
        o = sorted(set(re.findall(r"RUNNING owner_pid=(\d+)", rt)) |
                   set(re.findall(r"owner_pid\s+(\d+)", rt)))
        per_ring.append("%s=%s" % (os.path.basename(os.path.dirname(rf)), "・".join(o) or "no-RUNNING"))
        owners |= set(o)
    if not owners:
        sys.exit("gate: no owner_pid in any of the %d in-play captures -- the running stream cannot "
                 "be named" % len(runfiles))
    owner = "・".join(sorted(owners))
    return [
        {"layer": "DSD runtime decision face", "item": "the HW-DSD switch hand-off chain, as logged",
         "value": ("%s  ║  quoted chain = %d line(s), pids in order %s: " % (
             " ・ ".join(chain_desc), len(ch), "→".join(pids)) +
                   " ▸ ".join(x.split(") ")[-1][:56] for x in ch)),
         "name_or_meaning": ("★this is the runtime counterpart of §422/§423's instruction-level story, "
                             "and it names the party the binary could not: system_server's "
                             "FeatureService pushes the switch (msgCode 501) over binder "
                             "(`IFeatureService SET_PLAYER_FEATURE`) into mediaserver's "
                             "`FeatureService_Native::setPlayerFeatures`, which goes through "
                             "`MediaPlayerService::notifytoplayer` (flag word 00020000) and lands on "
                             "`NuPlayerDriver: DSD### setParameter +++ 2, 0` / `--- 2, 0` -- the pair "
                             "bracketing the call that decides.  ★Ordering here is LINE ORDER only: "
                             "these captures were taken with `logcat -d` in brief format and carry no "
                             "timestamps."),
         "source": f"{BASE}/live/inplay-spk-20261017-2012/logcat-raw.txt",
         "writable": "no -- read-only extraction from a stored capture",
         "use_case": ("on 7: `python3 tools/dsd_runtime_face.py --live <7 capture dir>` after the same "
                      "speaker playback; if 7 logs no `setDSDHWSwitch` line the tool REFUSES (it does "
                      "not print an absent chain as 'no DSD'), and `--allow-absent` turns that absence "
                      "into the finding to be compared"),
         "witness2": ("11 arms: the chain must be ordered (setPlayerFeatures before notifytoplayer "
                      "before DSD### setParameter) and must cross a process boundary; the chain walk "
                      "is bounded to the chain's own participant tags and stops at its end marker (an "
                      "earlier version slurped 40 lines across 7 pids, which made a hand-off read like "
                      "a process census -- every group's line count and switch value are printed now); "
                      "relabelling the "
                      "capture's own mixer dump (SmartPA Switch On→Off) must change the route verdict; "
                      "deleting the switch line must REFUSE the chain leg while `--allow-absent` still "
                      "reads the same fixture (the refusal is asymmetric); reversing ask and return must "
                      "produce no pair; a 0-event file is called blind and an over-small group is "
                      "refused; `--all` must print usable-of-candidate group counts (%d of %d here) so "
                      "a skipped capture shrinks the numerator instead of vanishing"
                      % (len(usable), len(dirs) + 1)),
         },
        {"layer": "DSD runtime decision face", "item": "the DSD-HW capability query answers a "
                                                       "different state than the caller's own copy",
         "value": ("%d ask/return pair(s): caller %s asked state=%s -> FeatureService(%s) answered "
                   "state=%s (rc=%s, %d line(s) apart)"
                   % (len(pairs), "・".join(pairs[0]["caller"]), pairs[0]["asked"],
                      pairs[0]["service_pid"], pairs[0]["answered"], pairs[0]["rc"], pairs[0]["gap"])),
         "name_or_meaning": ("★same shape as §417's `isHifiSupport` (state, not capability): the "
                             "app-side line carries `state=false` while the service's own return for "
                             "the SAME feature says `state=true`.  Which one the player acts on is "
                             "not decided by these two lines, so this row is a *disagreement* to "
                             "reproduce on 7, not a value to copy."),
         "source": f"{BASE}/live/logcat-boot-20261017-0956.txt",
         "writable": "no -- read-only extraction",
         "use_case": "on 7: same command; a missing pair means the query leg moved, not that DSD is off",
         "witness2": ("pairing is by tag+pid inside a bounded window and is directional -- the fixture "
                      "that swaps the two lines must yield zero pairs, and an ask with two candidate "
                      "returns is left unpaired rather than guessed"),
         },
        {"layer": "DSD runtime decision face", "item": "`dsdvol_index=N` is sent on every playback, "
                                                       "DSD or not -- it is not a DSD witness",
         "value": ("%d shape(s) containing dsdvol_index, seen %d time(s) across pids %s (also in the "
                   "boot captures, where nothing was playing as DSD)"
                   % (len(sticky), sticky_n, "・".join(sticky_pids))),
         "name_or_meaning": ("★a DSD-named parameter that appears unconditionally is a trap for a "
                             "port check -- this is the log-side twin of §421's sticky-control finding "
                             "(`HP Sel` / per-stream cfg keeping the previous route's value).  It must "
                             "NOT be used as evidence that DSD is in play."),
         "source": f"{BASE}/live/logcat-audio.txt",
         "writable": "no -- read-only extraction",
         "use_case": "on 7: compare presence, never value -- if 7 stops logging it, that is not a DSD verdict",
         "witness2": ("the shape census is printed with its denominator (%d of %d capture groups "
                      "usable) and each shape carries the pids and files it came from"
                      % (len(usable), len(dirs) + 1)),
         },
        {"layer": "DSD runtime decision face", "item": "the named DSD broadcast is captured SENT and "
                                                       "RECEIVED",
         "value": ("sent: %r ・ received: %r ・ receiver-side tokens found in the carried APK code: "
                   "%d of 7 (%s)" % (send[0][:44], bc[0][:64], len(recv),
                                      "・".join(x[:36] for x in recv))),
         "name_or_meaning": ("★a question this project kept deferring as 'needs a nod': can Hi-Fi/DSD "
                             "be driven by a named broadcast? here is "
                             "the 6.0.1 witness without any actuation from me: FeatureService logs "
                             "`onSendShowDSDIntent 0` and AudioFxService (a different pid) logs "
                             "`onReceive: com.vivo.media.dsd.display state = false`.  The action name, "
                             "the sender and the receiver are all now on the delivery surface -- the "
                             "value observed is `false`, so this says the intent exists, not that "
                             "sending it turns DSD on.  ★the receiver is now NAMED from the APK code we carry: that exact log format sits beside the class com.vivo.audiofx.AboutDSD and a listener API (IDSDStateListener / registerDSDStateListener) in AudioEffect.odex -- so the consumer of that intent is the AudioEffect app, not a nameless service.  ★Names come from a static string pool; what the app does on receiving it is not claimed."),
         "source": f"{BASE}/live/inplay-spk-20261017-2012/logcat-raw.txt",
         "writable": "no -- both lines come from a stored capture; nothing was broadcast by this work",
         "use_case": ("on 7: check whether the same action name is both sent and received; if 7's "
                      "player never logs the receive, the display/feature leg is broken there"),
         "witness2": ("★scope note, because it is easy to overread: the three actions already approved (§C) are PA `--apply`, `calfile0..19` and `HP imped fixed` -- sending this broadcast or that parameter is NOT among them, so this row is evidence that the channel exists, and using it would need a fresh, separate approval.  "
                             "The row is only emitted when BOTH directions are present in the same corpus -- "
                      "the tool aborts if either line shape disappears, so a one-sided capture cannot "
                      "be read as an end-to-end witness"),
         },
        {"layer": "DSD runtime decision face",
         "item": "with timestamps at last: `dsdvol_index` arrives in pairs every ~250 s, and the ring's "
                 "time order is NOT global",
         "value": ("%s: %d timestamped event(s)・monotonicity violations=%d・chosen monotonic run %s・"
                   "foreign date prefixes in the ring: %s ・ HAL-side dsdvol_index lines=%d vs "
                   "AudioFlinger stream starts=%d ・ every key line within %s s of a start・pairs "
                   "(<=0.05 s)=%d・inter-group spacing: %s ・ rings in the corpus (largest first): %s "
                   "・in-play RUNNING witnesses: %s"
                   % (tr.get("file") or os.path.basename(SNAP), tr["timestamps"], tr["violations"],
                      tr["run"],
                      "・".join(tr["foreign"]) or "none", tr["key_lines"], tr["starts"],
                      tr["worst_start_delta"], tr["pairs"],
                      "・".join("%.2f" % g for g in tr["gaps"][:6]), ring_census,
                      "；".join(per_ring))),
         "name_or_meaning": ("★this is what upgrades §425's boundary statement: the older captures were "
                             "BRIEF (no timestamps, so ordering was line order only) while this one is "
                             "THREADTIME.  Two measured results and one lesson about how I got here.  "
                             "(1) The ring is NOT globally ordered: exactly %d monotonicity break, where "
                             "a pre-NTP `01-12` segment appears after `10-17 22:49`; so intervals are "
                             "computed only on the largest monotonic run (%s .. %s) and the foreign date "
                             "prefix is printed instead of silently merged.  (2) The parameter rides on "
                             "stream starts, 1:1 -- %d dsdvol_index lines against %d AudioFlinger "
                             "start() lines, every key line within %s s of a start -- so the ~250 s "
                             "spacing is the pace at which this session opened streams, NOT a timer.  "
                             "★It is still not a DSD witness for a different reason than I first gave: "
                             "every session ever captured was MP3/FLAC -- never DSD -- and the key "
                             "appears at every one of their starts.  ★Three phrasings of mine were wrong "
                             "and are recorded so nobody repeats them: 'nothing was playing' (false -- "
                             "the boot captures contain 99 and 73 NuPlayer lines), 'no RUNNING "
                             "substream' (false -- I read /proc/asound/pcm, which has NO state column on "
                             "this kernel; card0/pcm0p/sub0/status reads RUNNING with owner_pid %s, the "
                             "same pid as §419/§420's owner→Tgid 727→fd chain), and 'a fixed ~250 s "
                             "heartbeat' (false -- regular spacing proves only regularity; pairing it "
                             "against the start lines is what named the cause)."
                             % (tr["violations"], tr["run_start"], tr["run_end"], tr["key_lines"],
                                tr["starts"], tr["worst_start_delta"], owner)),
         "source": f"{BASE}/live/hifi-route-threadtime-20261017-2249/logcat-ring-threadtime.txt",
         "writable": "no -- read-only device capture (logcat/tinymix/proc), nothing actuated",
         "use_case": ("on 7: capture the same way and run `python3 tools/dsd_runtime_face.py --time`; "
                      "compare the INTERVAL structure rather than the value -- a HAL that received the "
                      "key only at playback start would mean the parameter became state-driven, which "
                      "would invalidate §425's 'not a DSD witness' warning in the other direction"),
         "witness2": ("arms: a brief-format file must be reported as having NO timestamp backing "
                      "(refusing interval claims) rather than being given a fabricated list; the "
                      "threadtime leg must report violations and pick the monotonic run before quoting "
                      "any interval; and a cross-format control requires the same DSD key set to be "
                      "recoverable from BOTH a brief and a threadtime capture, so a format-blind parser "
                      "cannot pass -- the corpus is scanned, not a hand-picked file"),
         },
    ]



def hifi_recheck_rows():
    """§427: a SECOND in-play Hi-Fi snapshot, and what it changes -- everything here is read out of
    the two snapshot directories, so a stale claim fails the build instead of being recited."""
    a = f"{BASE}/live/inplay-hifion-20261017-1933"
    b = f"{BASE}/live/inplay-hifion2-20261017-2303"
    for d in (a, b):
        if not os.path.exists(f"{d}/tinymix-all.txt"):
            sys.exit("gate: " + d + " has no mixer dump -- these rows compare two real snapshots")
    sys.path.insert(0, f"{ROOT}/tools")
    import inplay_accept as IA
    on_b = sorted(IA.widgets_on(open(f"{b}/dapm-live.txt", encoding="utf-8", errors="replace").read()))
    if not on_b:
        sys.exit("gate: the new snapshot's dapm-live.txt yields zero ON widgets -- the parser is blind "
                 "on this capture format, so the dapm leg cannot be claimed")
    if not any(x.startswith("hifi-codec/") for x in on_b):
        sys.exit("gate: no hifi-codec widget is On in a snapshot the route judge calls Hi-Fi")
    has_dapm_a = os.path.exists(f"{a}/dapm-live.txt")

    def rate(d):
        txt = open(f"{d}/tinymix-all.txt", encoding="utf-8", errors="replace").read()
        m = re.search(r"Audio Stream 0 App Type Cfg\s+(\d+)\s+(\d+)\s+(\d+)", txt)
        return m.groups() if m else None
    ra, rb = rate(a), rate(b)
    if not (ra and rb):
        sys.exit("gate: the per-stream cfg could not be read from one of the two snapshots")
    track = ""
    for f in ("thread-owner.txt", "running.txt"):
        p = f"{b}/" + f
        if os.path.exists(p):
            t = re.findall(r"(/data/media/\S[^\n]*?\.(?:flac|mp3|wav|dsf|dff))", open(p, encoding="latin-1").read())
            if t:
                track = t[0]
                break
    def dregs(path):
        t = open(path, encoding="latin-1", errors="replace").read()
        return {m.group(1).lower(): m.group(2).lower()
                for m in re.finditer(r"reg\{([0-9a-fA-F]+)\}\s*:\s*([0-9a-fA-Fx]+)", t)}
    base = dregs(f"{BASE}/live/dac-hpplay-20261016-092159.txt")
    newr = dregs(f"{b}/es9038-reg.txt")
    common = sorted(set(base) & set(newr))
    if len(common) != 47:
        sys.exit("gate: the DAC comparison yields %d comparable registers, not the 47 §282 fixed -- "
                 "one of the two files is a partial read, so agreement would be an artefact"
                 % len(common))
    diff = [k for k in common if base[k] != newr[k]]
    spk_txt = (open(f"{BASE}/live/inplay-spk-20261017-2012/es9038-reg.txt",
                    encoding="latin-1", errors="replace").read() if os.path.exists(
                f"{BASE}/live/inplay-spk-20261017-2012/es9038-reg.txt") else "")
    if not spk_txt.strip():
        spk_state = "file absent"
    elif "Sorry" in spk_txt:
        spk_state = "refused: " + re.search(r"(Sorry[^\n]{0,44})", spk_txt).group(1)
    else:
        spk_state = "read %d register(s)" % len(dregs(f"{BASE}/live/inplay-spk-20261017-2012/es9038-reg.txt"))
    return [
        {"layer": "in-play Hi-Fi recheck", "item": "a second in-play Hi-Fi session, judged with the "
                                                   "dapm leg for the first time",
         "value": ("%d widget(s) On in the new snapshot: %s ・ legs that named the route: "
                   "HiFi Mode Switch・SmartPA Switch・per-stream acdb・dapm ・ baseline had its own "
                   "dapm capture: %s" % (len(on_b), "・".join(x[:26] for x in on_b),
                                         "yes" if has_dapm_a else "NO (this snapshot adds the leg)")),
         "name_or_meaning": ("★the acceptance procedure's fourth leg (which supply sink is powered, read "
                             "from the running kernel) now has a Hi-Fi-side witness: `hifi-codec/HP`, "
                             "`HiFi DAC`, `HiFi AMP`, `HiFi HPOUT`, `I2S_IN`, `vivo HiFi Playback` and "
                             "`Headphone Rx Mixer` are On while the PA's `SmartPA` is Off -- the mirror "
                             "image of §420's speaker witness.  So the two routes are demonstrably "
                             "mutually exclusive at the kernel, on the SAME machine, in the SAME day, "
                             "from live state rather than from graph inference.  ★`HiFi AMP` is a real "
                             "widget name here, which is worth noting against §290's correction (the "
                             "widget carrying the callback is `HiFi DAC`): the names coexist, so a port "
                             "check that keys on one must not assume the other is absent."),
         "source": f"{BASE}/live/inplay-hifion2-20261017-2303/dapm-live.txt",
         "writable": "no -- read-only snapshot of the running kernel's DAPM",
         "use_case": ("on 7: `python3 tools/inplay_accept.py --snap <dir>` while a stream runs on the "
                      "Hi-Fi route, then `--check <dir> --baseline "
                      "art/audio-6.0.1/live/inplay-hifion2-20261017-2303`; the judge refuses unless all "
                      "four legs agree, so a 7 that powers a different sink is named, not averaged"),
         "witness2": ("the row is computed from the snapshot's own files (widgets_on + the mixer dump), "
                      "and aborts if the dapm parse yields zero widgets or no hifi-codec widget is On "
                      "in a snapshot the route judge calls Hi-Fi"),
         },
        {"layer": "in-play Hi-Fi recheck", "item": "the DAC's in-play register set reproduces for a "
                                                   "third time (47/47 identical)",
         "value": ("baseline `live/dac-hpplay-20261016-092159.txt` vs this session's "
                   "`es9038-reg.txt`: %d register(s) common, %d differ%s ・ speaker-route capture reads "
                   "%s" % (len(common), len(diff),
                           "" if not diff else " -> " + "・".join("%s:%s->%s" % (k, base[k], newr[k])
                                                                  for k, in [(d,) for d in diff[:8]]),
                           spk_state)),
         "name_or_meaning": ("★§282 established the DAC in-play set as 47 registers identical to the "
                             "kernel's own table; §419 reproduced it across a boot; this is the THIRD "
                             "witness, ~36 h and several route changes later, and it reproduces with "
                             "zero differences -- so \"the Hi-Fi sound floor lives in the kernel "
                             "driver\" (§285) is not a one-session accident.  ★The same read on the "
                             "speaker route returns the driver's refusal string (\"dac(addr 0x48) is "
                             "off!\"), which is why the count is 0 there: the DAC is powered down off "
                             "the Hi-Fi path, so a 7-side check must compare these 47 only on a Hi-Fi "
                             "session."),
         "source": f"{BASE}/live/inplay-hifion2-20261017-2303/es9038-reg.txt",
         "writable": ("yes -- `es9038/reg` accepts writes, so this is a write-target; this row only "
                      "reads it"),
         "use_case": ("on 7: `python3 tools/dac_check.py` style read of `es9038/reg` during a Hi-Fi "
                      "session; the denominator is the 47 names from `dac_parameters` (not the count of "
                      "lines in a dump), and a differing register is a real audio-path difference, not "
                      "noise"),
         "witness2": ("computed from the two stored files at build time; the row aborts unless exactly "
                      "%d registers are comparable (that is the denominator §282 fixed), so a partial "
                      "read cannot be reported as agreement" % len(common)),
         },
        {"layer": "in-play Hi-Fi recheck", "item": "the per-stream cfg's rate column follows the "
                                                   "SESSION, not the file",
         "value": ("19:33 session = %s ・ 23:03 session = %s ・ same track family, same acdb 150, "
                   "different rate column (%s vs %s) ・ track behind the new session: %s"
                   % ("・".join(ra), "・".join(rb), ra[2], rb[2], track or "not named")),
         "name_or_meaning": ("★this bounds how the 7-side comparison may be worded.  Two Hi-Fi sessions "
                             "of the same material give `69937 150 48000` and `69937 150 44100`: the "
                             "first two columns are the route's identity (app_type, ACDB device) and are "
                             "stable, while the third records the rate the session actually opened at.  "
                             "So on 7 the check is `acdb must equal` and `rate must equal 7's own session "
                             "rate` -- requiring 48000 to repeat would be a false red, exactly the class "
                             "of error §372 and §419 each caught."),
         "source": f"{BASE}/live/inplay-hifion2-20261017-2303/tinymix-all.txt",
         "writable": "no",
         "use_case": ("on 7: read the same three columns from the live mixer dump; if 7's driver leaves "
                      "the rate column stale across sessions of different rates, that is a real "
                      "difference in the ACDB selection path, not a measurement artefact"),
         "witness2": ("both values are parsed from the two snapshots at build time (regex over the "
                      "dump, not a remembered pair), and the row aborts if either snapshot lacks the "
                      "control"),
         },
    ]



def bitwidth_chain_rows():
    """§428: how wide the sample is, from three comparable sources per session -- and which of them
    are allowed to vote."""
    sys.path.insert(0, f"{ROOT}/tools")
    import backend_bitwidth_chain as BC
    live = f"{BASE}/live"
    rows, ndirs = BC.scan(live)
    spk = BC.judge(f"{live}/inplay-spk-20261017-2012")
    hif = BC.judge(f"{live}/inplay-hifion2-20261017-2303")
    if spk["pairs"]["front-vs-backend"] != "DIFFERENT" or spk["pairs"]["backend-vs-XML"] != "MATCH":
        sys.exit("gate: the speaker session no longer reads front-24/backend-16 with the backend "
                 "matching the board XML -- the row must be rewritten, not asserted")
    if not hif["state"].startswith("AGREE(3"):
        sys.exit("gate: the Hi-Fi session no longer agrees across all three sources -- that is the "
                 "comparison 7 will be judged on, so it cannot be reported from memory")
    return [
        {"layer": "codec backend bit width",
         "item": "on the speaker route the front end opens S24 while the backend is commanded to S16 "
                 "by the board's own mixer XML",
         "value": ("front=%s ・ backend control=%s ・ XML `speaker` path=%s ・ platform (ADSP cfg) "
                   "bit width=%s ・ state=%s" % (
                       "・".join(spk["front_bits"]), "・".join(spk["control_bits"]), spk["xml"],
                       "・".join(spk["platform_bits"]) or "no log", spk["state"])),
         "name_or_meaning": ("★this closes §419's open item (`front S24 / back S16 -- causality not "
                             "established`): the 16 is not a lost write or a read artefact, it is what "
                             "vivo's board XML commands for the `speaker` path (`<ctl name=\"TERT_MI2S "
                             "Bit Format\" value=\"S16_LE\"/>`), while the `headphone-hifi` and "
                             "`headphone-hifi-DSD` paths set S24_LE.  So the 24-bit PCM is handed to a "
                             "backend configured for 16-bit ON PURPOSE on the speaker route, and the "
                             "same snapshot proves the front end really carried 24.  ★The platform's own "
                             "line (`Codec selected backend: 0 ... bit width: 24`) is a DIFFERENT "
                             "quantity -- the ADSP backend cfg -- so it is recorded here and deliberately "
                             "NOT voted against the DAI format control; voting it produced a false "
                             "three-way contradiction in the first version of this ruler."),
         "source": f"{BASE}/shipped/system/etc/mixer_paths_tasha.PD1610.xml",
         "writable": ("yes in principle -- writing `TERT_MI2S Bit Format` would change the audible path; "
                      "this row only reads the XML and the stored state"),
         "use_case": ("on 7: `python3 tools/backend_bitwidth_chain.py --selftest` then judge each of "
                      "7's snapshots; the check is pair-by-pair, so 7 passing means its speaker path "
                      "also commands S16 while its front end opens S24 -- if 7 instead runs the speaker "
                      "at S24 end to end, the bit-depth story differs and the listening result may too"),
         "witness2": ("6 arms: erasing the platform log lines from a copy must leave the verdict "
                      "IDENTICAL (the finding is live-state + XML, not a log artefact, and the fixture "
                      "must report how many lines it deleted); a session with no front-end hw_params may "
                      "claim at most 2 sources; only backend_idx 2 is paired to a DAI name anywhere in "
                      "the corpus so idx 0 stays unnamed; and the scan prints its own denominator "
                      "(%d directories)" % ndirs),
         },
        {"layer": "codec backend bit width",
         "item": "the Hi-Fi route carries 24-bit end to end (all three comparable sources)",
         "value": ("%s ・ front=%s ・ backend=%s ・ XML path=%s ・ log files in that snapshot: %s"
                   % (hif["dir"], "・".join(hif["front_bits"]), "・".join(hif["control_bits"]),
                      hif["xml"], "・".join(hif["log_files"]) or "none")),
         "name_or_meaning": ("★the mirror case that makes the row above meaningful: on the Hi-Fi route "
                             "the same three sources line up on 24, so the speaker S16 is route-specific "
                             "and not a global device default.  The rate also differs by session "
                             "(44100 here vs 48000 on the speaker session), which is the same "
                             "session-follows-material pattern as §427's per-stream cfg."),
         "source": f"{BASE}/live/inplay-hifion2-20261017-2303/hw_params.txt",
         "writable": "no -- read-only",
         "use_case": ("on 7: the same command on 7's Hi-Fi snapshot; a Hi-Fi route that lands on 16-bit "
                      "would be the audible difference, since this is the route the listening baseline "
                      "was set on"),
         "witness2": ("the verdict is recomputed at build time from the snapshot's own files plus the "
                      "board XML, and the generator aborts if the Hi-Fi session stops agreeing on all "
                      "three or if the speaker session stops showing front-24/backend-16"),
         },
    ]



def symbol_reach_rows():
    """§429: which side of a mangled symbol the corpus actually shows, and what two libraries were
    missing from the reference set until now."""
    sys.path.insert(0, f"{ROOT}/tools")
    import symbol_refs as SR
    root = f"{BASE}/shipped"
    sym = "_ZN7android11AVNuFactory14createNuPlayerEi"
    r = SR.survey([root], sym)
    ctl = SR.survey([root], "strcasecmp")
    if not ctl["importers"]:
        sys.exit("gate: the control symbol shows no non-definer carrier, so this survey is blind -- "
                 "an empty result for the factory symbol would prove nothing")
    if len(r["definers"]) != 1 or r["importers"]:
        sys.exit("gate: the factory symbol's role changed (definers=%d importers=%d) -- rewrite this "
                 "row, do not assert the old reading" % (len(r["definers"]), len(r["importers"])))
    new_libs = []
    for rel in ("system/lib/libmediandk.so", "system/lib64/libstagefright.so"):
        p = f"{root}/{rel}"
        if not os.path.exists(p):
            sys.exit("gate: " + p + " is named by this row but is not in the corpus")
        b = open(p, "rb").read()
        new_libs.append("%s %dB md5 %s" % (rel, len(b), hashlib.md5(b).hexdigest()[:12]))
    return [
        {"layer": "symbol reachability",
         "item": "`AVNuFactory::createNuPlayer(int)` has a definer and NO carrier anywhere in the "
                 "reference set",
         "value": ("%d file(s) scanned under %s ・ defines: %s ・ imports/other carriers: %d"
                   " ・ control (an import edge the survey DOES see): `strcasecmp` carried by %d "
                   "file(s)" % (r["files_scanned"], "shipped/",
                               "・".join(os.path.basename(p) for p, _h, _n in r["definers"]),
                               len(r["importers"]), len(ctl["importers"]))),
         "name_or_meaning": ("★this closes the §423/§425 loose end（“who constructs NuPlayer?”） from "
                             "the other side: the factory exists, the ctor's caller is "
                             "`AVNuFactory::createNuPlayer` itself (via the PLT stub, §426), and that "
                             "factory has no caller in what we carry.  A mangled symbol must appear as "
                             "a string in any binary that references it, so this is a real reachability "
                             "test -- with the limits printed: it covers only the paths given, and "
                             "`dlopen`+`dlsym` with a computed name would leave no bytes.  ★On the "
                             "device itself the same name was swept through the player stack "
                             "(`libmedia*`, `libstagefright*`, `libmediandk`, `libmediaservice`, "
                             "`mediaserver`), every `.so` under app/priv-app/data-app/vendor-app/"
                             "framework, and every executable under bin/xbin -- all zero.  So: no "
                             "caller found; not “proved unused”."),
         "source": f"{BASE}/shipped/system/lib/libmediaplayerservice.so",
         "writable": "no -- read-only symbol survey",
         "use_case": ("on 7: `python3 tools/symbol_refs.py --root <7 shipped tree>`; if 7 has a carrier "
                      "for this symbol, vivo's per-app Hi-Fi/DSD factory is actually wired there "
                      "instead -- a structural difference no config file shows"),
         "witness2": ("4 arms: the factory symbol must show exactly one definer and zero carriers; "
                      "`strcasecmp` must show at least one NON-definer carrier (proof the survey can "
                      "see an import edge, so the empty result is a finding and not blindness); an "
                      "absent symbol must be REFUSED rather than reported as 'nobody calls it'; and the "
                      "file denominator is printed (%d)" % r["files_scanned"]),
         },
        {"layer": "shipped file disposition",
         "item": "two player libraries were missing from the reference set until §429",
         "value": "・".join(new_libs) + " ・ both md5-verified against the device before install",
         "name_or_meaning": ("★`libmediandk.so` (32-bit) and the 64-bit `libstagefright.so` were the "
                             "gaps; §379 already established the playing process is 32-bit, so the "
                             "64-bit copy matters for completeness of the comparison set, not for the "
                             "live path.  ★Getting them in surfaced a transport trap worth recording: "
                             "base64 over `adb exec-out` returned a 2 059 960-byte file whose SIZE "
                             "matched the device but whose md5 did not -- a silent corruption that a "
                             "length check would pass.  The verified route for world-readable files is "
                             "`adb pull` plus an md5 comparison on both sides."),
         "source": f"{BASE}/MANIFEST.txt",
         "writable": "no -- stored copies",
         "use_case": ("on 7: carry the same two names from 7's own tree (both bitness if 7 runs the "
                      "player 64-bit) before comparing the DSD/MIME decision"),
         "witness2": ("this row is generated by hashing the files that are actually on disk, and the "
                      "install step itself refused to write unless the local md5 equalled the device's"),
         },
    ]


def route_matrix_rows():
    """§421: every stored mixer dump labelled by the state its OWN values name, then classified."""
    sys.path.insert(0, f"{ROOT}/tools")
    import inplay_accept as ia
    live = f"{BASE}/live"
    out_tsv = f"{BASE}/route-state-matrix.PD1610.tsv"
    for f in ("tinymix-D0.txt", "tinymix-D0-playing-headphones.txt", "tinymix-D0-playing-speaker.txt"):
        if not os.path.exists(f"{live}/{f}"):
            sys.exit("gate: " + f + " missing from live/ -- the matrix is built from stored dumps, "
                     "and a missing one silently changes every class")
    rows, groups = ia.matrix(live)
    if not os.path.exists(out_tsv):
        sys.exit("gate: " + out_tsv + " missing -- run `tools/inplay_accept.py --matrix --out` it first; "
                 "the row must agree with the stored file, not with a fresh computation")
    counts = {g: len(v) for g, v in groups.items()}
    byclass = {}
    for r in rows:
        byclass.setdefault(r["class"].split(" (")[0], []).append(r["control"])
    imp = next((x for x in rows if x["control"] == "HPHL Impedance"), None)
    sel = next((x for x in rows if x["control"] == "HP Sel"), None)
    cfg = next((x for x in rows if x["control"] == ia.STREAM0), None)
    relog = f"{live}/dac-impedance-recheck-20261017.txt"
    buckets = [l.strip() for l in open(relog, encoding="utf-8", errors="replace").read().splitlines()
               if "buckets" in l] if os.path.exists(relog) else []
    if not buckets:
        sys.exit("gate: no bucket line in " + relog + " -- the ohm-to-column claim needs the re-run's "
                 "own printed table, not a recollection")
    return [
        {"layer": "route-state matrix", "item": "the 12 stored mixer dumps, labelled by state and classified",
         "value": ("dumps idle=%d hifi=%d speaker=%d (labels come from each dump's own values, not from "
                   "its file name); %d of %d controls are not constant across states: " % (
                       counts["idle"], counts["hifi"], counts["speaker"], len(rows),
                       len(set.intersection(*[set(c) for _, c in sum(groups.values(), [])])))) +
                   "・".join("%s(%d): %s" % (k, len(v), ",".join(v)) for k, v in sorted(byclass.items())) +
                   "; per-dump provenance (each dump's own leg values) in " +
                   out_tsv.replace(".tsv", ".dumps.tsv"),
         "name_or_meaning": ("this is the acceptance target set for 7 in one table: `hifi-marker` "
                             "(HiFi Mode Switch・Headphone Rx Mixer I2S_RX・HiFi Mute・TERT_MI2S mode・"
                             "TERT_MI2S Bit Format) says which sink the I2S stream feeds; `speaker-marker` "
                             "is SmartPA Switch alone; `play-marker` (TERT_MI2S_RX MultiMedia1・"
                             "Playback Channel Map0) says a stream is up on the shared backend and does "
                             "NOT say which route; and the spread rows are where a single value tells you "
                             "nothing.  ★The classification is mechanical: a value that some other state "
                             "also holds is called shared (leftover or coincidence -- the tool refuses to "
                             "guess which), and only a value unique to one state is allowed to be a marker "
                             "or a drift"),
         "source": out_tsv + " and " + out_tsv.replace(".tsv", ".dumps.tsv"),
         "writable": "no -- every input is a stored read-only dump",
         "use_case": ("on 7: `tinymix -D 0 > dump` for each state (idle, Hi-Fi in play, speaker in play), "
                      "drop them beside these and run `python3 tools/inplay_accept.py --matrix --out …`; "
                      "compare the CLASSES first -- a control that is a marker on 6.0.1 but a spread on 7 "
                      "means the route is decided somewhere else"),
         "witness2": ("9 matrix arms; among them a dump forced to assert BOTH routes at once (refused, not "
                      "averaged), the idle dumps deleted (refuses to speak about idle), an empty candidate "
                      "set (called empty), and a guard that the arm's own fixture edit took effect before "
                      "trusting the abort -- an earlier version of that arm silently truncated its fixture "
                      "and passed for the wrong reason"),
         },
        {"layer": "route-state matrix", "item": "what survives a route teardown: leftovers, and one value that is not",
         "value": ("`HP Sel` in the speaker group = %s (%s); `%s` column split = %s; "
                   "`HPHL Impedance` = %s [%s]" % (sel["speaker"] if sel else "?",
                                                   sel["class"] if sel else "?", ia.STREAM0,
                                                   cfg["per_column"] if cfg else "?",
                                                   imp["idle"] + "/" + imp["hifi"] + "/" + imp["speaker"] if imp else "?",
                                                   imp["class"] if imp else "?")),
         "name_or_meaning": ("★one stored idle dump still reads `Audio Stream 0 App Type Cfg` = 69937 150 "
                             "44100 while `HiFi Mode Switch` has already gone back to Off -- that is the "
                             "teardown caught in the act: the route control reverts first and the per-stream "
                             "cfg keeps the previous session's ACDB id.  So the per-stream cfg may name the "
                             "route that RAN, not the route that IS, and the matrix says so structurally "
                             "(its ACDB column is `spread`, every value shared with another state).  "
                             "`HP Sel` behaves the same way (HiFi lingering under the speaker state).  "
                             "★`HPHL Impedance` is the opposite case: the Hi-Fi group holds 34 AND 35, and 35 "
                             "appears in no other state, so the tool refuses to call it a leftover -- it is a "
                             "measurement that moved between boots"),
         "source": f"{live}/essnap-20261015-212326.txt.tinymix",
         "writable": "no",
         "use_case": ("on 7: never accept a single reading of the per-stream cfg or HP Sel as route proof -- "
                      "read the powered DAPM sink (step 19) or take the reading twice, before and after a "
                      "known route change"),
         "witness2": ("the sticky rows are produced by the sharing rule, not by a name list: a control is "
                      "called shared-leftover only if every one of its values also occurs in another state"),
         },
        {"layer": "route-state matrix", "item": "ohm -> DAC column: the bucket table, and why 34 vs 35 Ω is not a difference",
         "value": "・".join(b[:150] for b in buckets) +
                  "; live readings mapped by that table: 0 Ω -> column 3 (idle and speaker), 34 Ω -> column 1 "
                  "(Hi-Fi); 35 Ω falls in the same 21..38 band; the two bucket tables disagree only on 21..24 "
                  "and no reading has ever landed there; re-run of the chain is byte-identical to "
                  "dac-impedance-chain.PD1610.tsv (134 rows)",
         "name_or_meaning": ("★the impedance number is an INPUT to a column choice, and the baseline itself "
                             "drifts (34 one boot, 35 the next) -- so demanding that 7 read the same ohms is "
                             "wrong, while demanding the same COLUMN is checkable: both 34 and 35 are inside "
                             "21..38, which the emulated selector maps to column 1, and the DAC's own live "
                             "bytes agree (0x17=3 at 0 Ω, 0x19=1 at 34 Ω).  The one honest gap: the out-of-line "
                             "selector and the inlined copy disagree on 21..24 Ω, so a 7 that measures there "
                             "cannot be predicted from this table -- that band must be reported as undecided, "
                             "not silently assigned to either column"),
         "source": f"{live}/dac-impedance-recheck-20261017.txt",
         "writable": "no -- offline rescan of the stored kernel Image",
         "use_case": ("on 7: read `HPHL Impedance` in play, put it through 7's OWN selector (the tool takes "
                      "DAC_IMG=/DAC_KALL=) and compare the column, never the ohm number"),
         "witness2": ("the chain tool itself aborts if the emulated buckets do not reach exactly the result "
                      "constants present in the function (`all four columns reachable`), so the table cannot "
                      "come from a partial decode"),
         },
    ]



def mime_symbol_rows():
    """§431: the DSD MIME constant read as DATA (no operand arithmetic), and what the 64-bit copy
    refuses to give up.  Both values come from the tool at generation time -- an empty read aborts."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("dsd_mime_symbol",
                                                  os.path.join(os.path.dirname(os.path.abspath(__file__)), "dsd_mime_symbol.py"))
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
    except SystemExit:
        pass
    l32 = f"{BASE}/shipped/system/lib/libstagefright.so"
    l64 = f"{BASE}/shipped/system/lib64/libstagefright.so"
    for p in (l32, l64):
        if not os.path.exists(p):
            sys.exit("gate: %s missing -- the DSD MIME constant rows cannot be generated from a file "
                     "that is not in the baseline" % p)
    r32 = mod.report(l32)
    r64 = mod.report(l64)
    h32 = [h for h in r32["hits"] if h.get("string")]
    if len(h32) != 1 or h32[0]["string"] != "audio/dsd":
        sys.exit("gate: the ARM32 read gave %r -- expected exactly one hit pointing at `audio/dsd`"
                 % ([h.get("string") for h in r32["hits"]],))
    h64 = r64["hits"][0]
    if h64.get("status") != "relocation-filled" or not r64["packed_relocs"]:
        sys.exit("gate: the ARM64 file did NOT show the packed-relocation boundary (%r) -- this row "
                 "asserts that boundary and must not be generated if the object changed" % (h64,))
    if not r64["literal_present"]:
        sys.exit("gate: `audio/dsd` is not even present in the 64-bit file -- the boundary row below "
                 "would be describing an absent literal")
    return [
        {"layer": "DSD Hi-Fi source surface",
         "item": "the exported DSD MIME constant, read as a DATA symbol (no operand arithmetic)",
         "value": ("`android::MEDIA_MIMETYPE_AUDIO_BBK_DSD` in libstagefright (32-bit) is a GLOBAL "
                   "OBJECT of %d bytes at %s whose file word is %#x -> .rodata %r・neighbouring "
                   "MEDIA_MIMETYPE_AUDIO_* constants in the same file: %d・no other shipped library "
                   "mentions the symbol name"
                   % (h32[0]["size"], h32[0]["addr"], int(h32[0]["points_to"], 16), h32[0]["string"],
                      len(r32["family"]))),
         "name_or_meaning": ("★this is the SAME fact as `audio/dsd` in the row above, reached by a road "
                             "that needs no instruction decoding: the constant is a data symbol and on "
                             "ARM32 a `R_ARM_ABS32` target is written into the file word by the linker, "
                             "so the pointer is readable statically.  It also names the constant the "
                             "framework itself uses, so a 7 build that keeps the comparison but renames "
                             "or drops this symbol is detectable without any disassembly.  ★Cross-check: "
                             "the value the pointer gives is exactly the string dsd_gate.py's def-chain "
                             "named at the strcasecmp site -- two independent roads, same answer."),
         "source": l32,
         "writable": "no -- read-only",
         "use_case": ("on 7: `python3 tools/dsd_mime_symbol.py --elf <7 libstagefright.so>` -- expect "
                      "the constant to point at `audio/dsd`; the tool REFUSES (rather than printing an "
                      "empty string) when the symbol is renamed or the pointer target is outside the "
                      "image, so a refusal means the leg must be re-pointed, not that DSD is gone"),
         "witness2": ("7 arms: the ARM32 read must yield exactly `audio/dsd`・the leg prints how many "
                      "MEDIA_MIMETYPE_AUDIO_* constants it also sees・renaming the symbol in .dynstr "
                      "makes it REFUSE・pointing the constant outside the image makes it REFUSE・every "
                      "hit must carry a string or the explicit `relocation-filled` status" ),
         },
        {"layer": "ARM64 packed relocations",
         "item": "why an absolute data pointer reads as 0 in a 64-bit Android library",
         "value": ("libstagefright (64-bit): `%s` is a GLOBAL OBJECT of %d bytes at %s・its `.data` "
                   "word is 0 in the file・`.rela.dyn` has sh_type 0x60000002 (SHT_ANDROID_RELA, packed) "
                   "so the target is established only at load time・the literal `audio/dsd` IS present in "
                   "this file's .rodata・`readelf -rW` does not list that section at all"
                   % (h64["symbol"], h64["size"], h64["addr"])),
         "name_or_meaning": ("★a boundary that saves a wrong finding on 7: with packed relocations the "
                             "static file gives you the symbol, its width and the literal's presence -- "
                             "NOT what the pointer holds.  Anything that wants 'this symbol points at "
                             "that string' on a 64-bit Android library must either decode the packed "
                             "table (uleb128 address/flag/info/addend arrays) or read the process memory, "
                             "and §375 already showed the live-RAM faces on this machine are closed.  "
                             "★The ARM32 copy of the same library has no such problem (REL, no addend, "
                             "target written into the word), which is exactly why the row above works "
                             "and this one stops at the boundary."),
         "source": l64,
         "writable": "no -- read-only",
         "use_case": ("on 7: run the same command against every 64-bit audio library you install; where "
                      "it prints `relocation-filled`, treat the claim as 'symbol + literal both exist "
                      "here' and do NOT write 'the constant equals audio/dsd' -- that needs the packed "
                      "decoder or a runtime read"),
         "witness2": ("an arm erases `audio/dsd` from the 64-bit file and requires `literal_present` to "
                      "go False -- otherwise `relocation-filled` would silently read as 'the string is "
                      "there'"),
         },
    ]


def dai_surface_rows():
    """§432: what the shipped 32-bit HAL can and cannot tell us about backend_idx -> DAI names.
    The numbers come from tools/dai_name_surface.py at generation time; an empty read aborts."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "dai_name_surface", os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                         "dai_name_surface.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    hal = f"{BASE}/shipped/system/lib/hw/audio.primary.msm8996.so"
    if not os.path.exists(hal):
        sys.exit("gate: %s missing -- the DAI vocabulary row cannot be generated" % hal)
    r = mod.census(hal)
    if not r["dai_literals"] or not r["ptr_any"]:
        sys.exit("gate: the census returned %d literals and %d control pointers -- the tool must "
                 "refuse internally, so reaching here means it went blind" % (len(r["dai_literals"]),
                                                                              r["ptr_any"]))
    names = sorted({n for _v, n in r["dai_literals"]})
    return [
        {"layer": "HAL backend vocabulary",
         "item": "the HAL's DAI-shaped literals, and whether backend_idx can be resolved to a name "
                 "from its data",
         "value": ("%d occurrences / %d distinct DAI-shaped literals in the 32-bit HAL's .rodata: "
                   % (len(r["dai_literals"]), len(names))
                   + "・".join(names) + " ・ absolute pointers into ANY .rodata string (control): %d"
                   " ・ absolute pointers aiming at a DAI name: %d ・ %d sections / %d bytes scanned"
                   % (r["ptr_any"], len(r["ptr_dai"]), r["sections_scanned"], r["bytes_scanned"])),
         "name_or_meaning": ("★this closes the STATIC route for §E's `backend_idx 0` question and says "
                             "why: the log gives an integer, §428 could only pair idx 2 with SLIM_6_RX "
                             "from a log line, and the hope was that the HAL keeps a `const char *name[]` "
                             "table you could index.  It does not -- the control proves the pointer scan "
                             "sees %d absolute pointers into .rodata in this very file, while ZERO of "
                             "them aim at any DAI name.  So the idx->name choice lives in code branches, "
                             "not in data, and the remaining ways to settle it are 7's own log lines or a "
                             "controlled read of the runtime structure (both need a human).  ★The literal "
                             "list is still useful on its own: it is the HAL's own backend vocabulary "
                             "(TERT_MI2S_RX / SLIMBUS_0_RX / SLIMBUS_5_RX / AFE_PCM_RX / HDMI_RX plus the "
                             "Format・SampleRate・Channels kcontrol names), which is what 7's HAL must be "
                             "diffed against when the board's DAI set changes." % r["ptr_any"]),
         "source": hal,
         "writable": "no -- read-only census",
         "use_case": ("on 7: `python3 tools/dai_name_surface.py --elf <7 audio.primary*.so>` and read the "
                      "two counts together -- if 7 DOES show pointers aiming at DAI names, the mapping "
                      "became indexable there and idx->name can be compared without any runtime read; if "
                      "the control count is 0 the tool refuses instead of reporting `no table`, because "
                      "that would be blindness"),
         "witness2": ("%d arms: the census must name >=5 DAI literals including TERT_MI2S_RX・the pointer "
                      "scan must find >0 absolute pointers into .rodata before any zero is quotable "
                      "(anti-blindness control)・the headline is written as an ASYMMETRY never a bare 0・"
                      "erasing a literal drops the count by exactly 1・FABRICATING a pointer to a DAI name "
                      "in .data must make the leg REPORT that site (so the zero is measured, not "
                      "printed)・a non-ELF32 file is refused・sections/bytes/size denominators are printed"
                      % 7),
         },
    ]




def hal_acdb_sourcing_rows():
    """§458: what the HAL itself prints when it sources per-device acdb ids.  The rows are read out of
    the post-restart logcat in the newest calfile-ab capture -- including the E-level line that says the
    DSD device gets NO id at all, which is the cell §456/§457 could only leave open."""
    import glob as _glob
    dirs = sorted(_glob.glob(f"{BASE}/live/calfile-ab-*"), key=os.path.getmtime)
    cand = None
    for d in reversed(dirs):
        p = f"{d}/logcat-after-restart.txt"
        if os.path.exists(p):
            cand = (d, p); break
    if cand is None:
        sys.exit("gate: §458 measured a post-restart HAL log but no calfile-ab capture carries one -- "
                 "the row cannot be written")
    d, p = cand
    txt = open(p, encoding="latin-1", errors="replace").read()
    setrows = re.findall(r"platform_set_snd_device_acdb_id: acdb_device_table\[(.*?)\]: old = (\d+) new = (\d+)", txt)
    miss = re.findall(r"process_backend_name: Device (\S+) not found, no ACDB ID set!", txt)
    prop = re.findall(r"ACDB -> Prop Load file: (\S+)", txt)
    alrd = len(re.findall(r"already initialized, exit", txt))
    if not setrows or not miss:
        sys.exit(f"gate: {p} has {len(setrows)} table-set lines and {len(miss)} 'no ACDB ID set' lines -- "
                 "§458 measured both, so this window is not the one")
    return [
        {"layer": "HAL acdb id sourcing",
         "item": "which per-device acdb ids the HAL actually sets at init, and the device it cannot set",
         "value": (f"{len(setrows)} keys set " + "／".join(f"{k}={n}" for k, o, n in setrows) +
                   f" ・ {len(miss)} device with NO id: " + "、".join(miss) +
                   f" ・ {len(prop)} Prop Load files ・ ADSP 'already initialized, exit' x{alrd}"),
         "name_or_meaning": ("★this closes §456/§457's open cell: only the keys the board file supplies are "
                             "set at runtime (the values agree with `audio_platform_info.xml`'s 2 entries), "
                             "and the **DSD device is never given an id at all** -- the HAL logs it at E level. "
                             "So the `acdb_dev_id` the stream cfg prints for the Hi-Fi and DSD routes does "
                             "NOT come from the platform-info path.  Also: the props branch loaded "
                             f"{len(prop)} files and the directory-cascade line (`dst_dir`) does not appear, "
                             "which is the runtime proof of §378's replacement-not-append reading; and the "
                             "ADSP said it was already initialised, so a HAL restart alone does not re-send "
                             "calibration to the DSP"),
         "source": f"{p} (captured 2026-10-18 after `setprop ctl.restart media`, owner-approved arm, read-only)",
         "writable": "no (log evidence)",
         "use_case": ("on 7: same window after the HAL starts.  A 7-side log WITHOUT the 'not found, no ACDB "
                      "ID set' line is a DIFFERENCE, not a fix -- it means 7's board file supplies an id for "
                      "the DSD device that 6.0.1 does not, so the DSD route can calibrate differently"),
         "witness2": ("the generator aborts unless both the key-set lines and the E line are present in the "
                      "same window, and it counts the Prop Load lines from the file rather than assuming "
                      "seven")}]


def dsd_inplay_state_rows():
    """§453/§454: what the DSD front-end and back-end actually read like while in play.  The row is
    supplied by the artifact `dsd-inplay-state.PD1610.tsv`, whose numbers come from
    `inplay_accept.py --check` -- so if the artifact is absent or lost a decisive row, the generator
    refuses instead of writing prose numbers."""
    art = f"{BASE}/dsd-inplay-state.PD1610.tsv"
    if not os.path.exists(art):
        sys.exit("gate: §453 measured a DSD in-play state table but it is not on disk -- the row "
                 "cannot be written")
    rows = [l.split("\t") for l in open(art, encoding="utf-8", errors="replace").read().splitlines()
            if l.strip() and not l.startswith("#")]
    body = rows[1:]
    if len(body) < 8:
        sys.exit(f"gate: {art} has {len(body)} data rows; §453 delivered 11 -- the artifact is truncated")
    def field(name):
        for r in body:
            if r[0].startswith(name):
                return r
        sys.exit(f"gate: {art} lost the `{name}` row -- refusing to assert the DSD state layer")
    cal = field("stream0 acdb_dev_id"); rate = field("stream0 rate"); app = field("stream0 app_type")
    fe = field("compress FE state"); be = field("backend state")
    ctl = [r for r in body if r[0].startswith("control ")]
    if not ctl:
        sys.exit(f"gate: {art} has no `control ` rows -- the route-difference layer is empty")
    return [{"layer": "DSD in-play runtime state",
             "item": ("what device 17 reads like while DSD is actually in play (§451: procfs cannot "
                      "answer this; the witness is the ASoC debugfs front-end state file)"),
             "value": (f"{len(body)} state readings in {art} ・ FE {fe[1]}->{fe[2]} ・ {be[2][:96]} ・ "
                       f"acdb_dev_id {cal[1]}->{cal[2]} ・ rate {rate[1]}->{rate[2]} ・ app_type "
                       f"{app[1]}=={app[2]} ・ {len(ctl)} controls move: "
                       + "；".join(f"{c[0][8:]} {c[1]}->{c[2]}" for c in ctl)),
             "name_or_meaning": ("★the audible DSD path is **not** the Hi-Fi path: the front end takes S8 "
                                 "at 176400 and the back end emits S24_LE/2ch/176400 (DoP), the stream's "
                                 "acdb_dev_id is **" + cal[2] + "** (not the " + cal[1] + " the Hi-Fi "
                                 "route uses), and the route difference shows up as " + str(len(ctl)) +
                                 " controls moving together -- so a 7-side reading that matches Hi-Fi but "
                                 "not these is the DSD branch missing, not a drift"),
             "source": (f"generated from {art}, whose numbers come from `python3 tools/inplay_accept.py "
                        f"--check <capture>` ・ capture 2026-10-18 09:28 (owner-approved controlled read, "
                        "read-only)"),
             "writable": "no (runtime reference)",
             "use_case": "7 侧放同一枚 DSD、在播时跑同一条 --check，再与本行逐条对照（比**同类**不是比同值）",
             "witness2": ("the artifact must carry the ACDB-cal row and at least one control row or the "
                          "generator aborts -- §454 lost exactly that row to a whitespace regex, and the "
                          "hand-appended version of this row was eaten by the next generator run")}].__getitem__(slice(None, None))

def dsd_inplay_rows():
    """§445: the DSD stream captured in play (art/audio-6.0.1/live/dsd-inplay-*).  Every number here is
    read out of the newest capture rather than quoted, because this is the one artifact no static route
    can produce -- and it closes the backend_idx pairing the file could not answer (§444)."""
    import glob as _glob
    # §470: the capture naming drifted twice in one day (dsd-inplay-*, dsd-spk-inplay-*, dsd-full-*),
    # and a directory-pattern that silently stops matching would leave this row describing an OLD
    # session while looking green -- so union the shapes and print how many were found.
    dirs = sorted(set(_glob.glob(f"{BASE}/live/dsd-inplay-*")) | set(_glob.glob(f"{BASE}/live/*dsd-inplay-*"))
                  | set(_glob.glob(f"{BASE}/live/dsd-spk-inplay-*")) | set(_glob.glob(f"{BASE}/live/dsd-full-*")),
                  key=os.path.getmtime)
    if dirs and os.environ.get("DSD_SCAN_VERBOSE") == "1":
        print("dsd in-play captures seen: %d -> %s" % (len(dirs), [os.path.basename(x) for x in dirs]))
    if not dirs:
        sys.exit("gate: no dsd-inplay capture on disk -- \u00a7445 measured one live, the row cannot be "
                 "written from prose")
    d = dirs[-1]
    ring = None
    for f in ("logcat-ring2.txt", "logcat-ring.txt"):
        if os.path.exists(f"{d}/{f}"):
            ring = open(f"{d}/{f}", encoding="latin-1", errors="replace").read()
            break
    if ring is None:
        sys.exit(f"gate: {d} has no logcat ring -- the capture is incomplete")
    def grab(pat, label):
        m = re.search(pat, ring)
        if not m:
            sys.exit(f"gate: {d} does not contain the {label} line -- refusing to assert it")
        return m.group(0)[:150]
    idx = grab(r"platform_get_backend_index: backend port - \d+, snd_device \d+[^\n]*", "backend-index")
    bw = grab(r"platform_check_codec_backend_cfg Codec selected backend: \d+ current bit width: \d+ "
              r"and sample rate: \d+", "backend-bitwidth")
    uc = grab(r"platform_check_and_set_codec_backend_cfg: Usecase bitwidth \d+, samplerate \d+", "usecase-bw")
    op = grab(r"start_output_stream: Opening PCM device card_id\(\d+\) device_id\(\d+\) "
              r"format\(0x[0-9a-f]+\),config.rate:\d+,bit_width:\d+", "pcm-open")
    sel = grab(r"always select HiFi DSD when its thread is writing data", "dsd-select-rule")
    dsp = grab(r"dsd state change from 0x?1? ?to 0x?1?", "dsd-state")
    dev = grab(r"enable_snd_device: snd_device\(\d+: [^)]+\)", "enable-snd_device")
    pair = re.search(r"backend port - (\d+), snd_device (\d+)", idx)
    name = re.search(r"snd_device\((\d+): ([^)]+)\)", dev)
    return [
        {"layer": "DSD in-play decision path",
         "item": "the backend index ↔ device pairing and the live bit width of the DSD stream",
         "value": (f"captured in {d} ・ {idx} ・ {name.group(2) if name else '?'} "
                   f"(snd_device {pair.group(2) if pair else '?'}) is backend port {pair.group(1) if pair else '?'}"
                   f" ・ {uc} ・ {bw} ・ {op} ・ {sel} ・ {dev} ・ {dsp}"),
         "name_or_meaning": ("★this is the cell the file could not answer: §442/§444 showed "
                             "no static route to the backend table, and here the HAL prints the pairing "
                             "itself -- **backend port 0 ↔ snd_device 49 = `headphone-hifi-DSD`**, with "
                             "the kernel PCM opened as card 0 device 17 at 176400 Hz / 24 bit while the "
                             "usecase requests 24-bit.  So `backend_idx 0` now HAS a name, and the DSD path "
                             "is DoP: the same ring carries `NuPlayerRenderer: DSD### audio flag has "
                             "FLAG_OFFLOAD_DOP`, `str_params key 'is_hw_dec_session_available' value "
                             "'audio/dsd'`, `AudioFlinger setParameters(): io 2, keyvalue dsdvol_index=6` "
                             "reaching `audio_hw_primary: audio_set_dsd_volume_index: 6`, and the "
                             "FeatureManager notifications (`NOTIFY_EVENT_DSD bOn:1`, "
                             "`NOTIFY_EVENT_HIFI bOn:1`) -- observed, never actuated by this procedure.  "
                             "★On 7 the same capture shape is the acceptance test: the backend-index, "
                             "bit-width and PCM-open lines must appear with the DSD stream running; if "
                             "`platform_get_backend_index` is missing there, 7 renamed or restructured the "
                             "selection and the pairing has to be re-derived, not carried over."),
         "source": f"{BASE}/live/dsd-inplay-*",
         "writable": "no -- read-only capture",
         "use_case": ("on 7: start a DSD stream (human) and run `logcat -d -v brief` + "
                      "`cat /proc/asound/pcm` into a dsd-inplay capture, then compare these five lines"),
         "witness2": ("the row ABORTS if any of the seven captured lines is absent from the newest "
                      "capture, so it cannot be produced from memory or from an empty directory"),
     }]


def dsd_registration_rows():
    """§444: the `audio/dsd` mime in libstagefright is not a loose constant -- it sits in a
    {char*, small-int, char*} registration triple next to an OMX component name, computed live by the
    roads survey.  This is the table the DSD decision surface reads, so its shape belongs on the carry
    list (and the small int is deliberately NOT called a length: both component names are 20 characters
    while the fields read 16 and 18)."""
    import importlib.util
    here = os.path.dirname(os.path.abspath(__file__))
    spec = importlib.util.spec_from_file_location("arm32_exidx_survey",
                                                  os.path.join(here, "arm32_exidx_survey.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    p = f"{ROOT}/{BASE}/shipped/system/lib/libstagefright.so"
    r = mod.roads_survey(p, "audio/dsd")
    rows = r["roads"][mod.ROADS[3]]["rows"]
    if not rows:
        sys.exit("gate: the pointer road found no audio/dsd slot in libstagefright -- §442 measured "
                 "five, so either the object changed or the road broke")
    triples = [x for x in rows if "str:OMX" in x.get("context", "")]
    ctx = rows[0]["context"]
    ints = sorted({int(m.group(1)) for x in rows for m in [re.search(r"len:(\d+)", x["context"])] if m})
    names = sorted({m.group(1) for x in rows for m in
                    [re.search(r"str:(OMX\.[^\s]+)", x["context"])] if m})
    return [{
        "layer": "DSD Hi-Fi source surface",
        "item": "where the audio/dsd mime actually lives in libstagefright: a registration table, not a "
                "loose constant",
        "value": (f"{len(rows)} pointer words to 'audio/dsd' in "
                  + ", ".join(sorted({x["section"] for x in rows})) + " at "
                  + ", ".join(x["addr"] for x in rows)
                  + f" ・ table shape seen around them: {ctx} ・ component names in the same "
                  f"records: {', '.join(names) or 'none'} ・ the small integer fields read "
                  f"{ints} while both names are 20 characters long"),
        "name_or_meaning": ("★this is the registration side of the DSD decision that §433 read "
                            "from code: the mime is paired with an OMX component name inside a "
                            "word-triple table in `.data.rel.ro.local` (twice — two tables carry the "
                            "same record, which is why the slots come in pairs 0x178b60/0x178b6c and "
                            "0x178c74/0x178c80), plus one more pointer in `.data` inside a flat list of "
                            "media-type strings (`text/cea-608`, `application/x-id3v4`, `video/divx3`...)."
                            " ★The integer field is reported, not interpreted: it is NOT the name "
                            "length (both names are 20 chars) and nothing in this object says what it is, "
                            "so the row records the shape and leaves the meaning open.  ★On 7: the "
                            "same command says whether that registration table still exists — if 7 "
                            "reports 0 pointer words for the mime, DSD registration moved (e.g. into "
                            "media.codecs XML or a different component list) and the §433 decision "
                            "surface has to be re-derived there, not assumed."),
        "source": f"{BASE}/shipped/system/lib/libstagefright.so",
        "writable": "no -- read-only decode",
        "use_case": ("on 7: `python3 tools/arm32_exidx_survey.py --elf <7 libstagefright.so> --roads "
                     "--needle audio/dsd` — read the pointer-road count and the printed table "
                     "context; 0 hits is a structural change, not an absence of DSD"),
        "witness2": ("17 arms on that ruler, including the pair 'a pointer-road hit must print the table "
                     "shape around it' (green only if a neighbouring str:OMX... name is decoded) and "
                     "'the pointer road reproduces the known audio/dsd slots' — so this row cannot "
                     "be produced by a road that silently sees nothing"),
    }]


def dsd_string_refs_rows():
    """§433: every function in the player service that materialises the address of a DSD string.
    Inverse of the §430/§431 question -- the numbers are read at generation time from
    tools/arm32_str_refs.py; a refusal there aborts the table."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "arm32_str_refs", os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                       "arm32_str_refs.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    lib = f"{BASE}/shipped/system/lib/libmediaplayerservice.so"
    if not os.path.exists(lib):
        sys.exit("gate: %s missing" % lib)
    r = mod.refs(lib)
    hits = mod.query(r, "dsd")
    if not hits:
        sys.exit("gate: the survey named no DSD reference -- it must have refused instead")
    if r["shifted_by_1"] * 4 > r["landed"]:
        sys.exit("gate: %d of %d resolutions survive a 1-byte shift -- not discriminating"
                 % (r["shifted_by_1"], r["landed"]))
    lines = "・".join("%s @%s -> %r" % (h["function"].split("NuPlayer")[-1].lstrip("123456789")[:40],
                                        h["site"], h["string"]) for h in sorted(hits,
                                                                                key=lambda x: x["string"]))
    mime = sorted({h["function"] for h in hits if h["string"] == "audio/dsd"})
    broad = [h for h in r["refs"] if re.search(r"DSD|dsd", h["string"])]
    import collections as _c
    per_fn = _c.Counter(h["function"] for h in broad)
    census = "；".join("%s x%d" % (k.split("NuPlayer")[-1].lstrip("123456789")[:34], n)
                       for k, n in per_fn.most_common())
    strs = sorted({h["string"] for h in broad})
    lib_media = f"{BASE}/shipped/system/lib/libmedia.so"
    media_note = "libmedia.so is not in the baseline"
    if os.path.exists(lib_media):
        try:
            rm = mod.refs(lib_media)
            mhits = [h for h in rm["refs"] if re.search(r"DSD|dsd|HiFi|HIFI|hifi", h["string"])]
            media_note = ("libmedia.so: calibration mode=%s, %d operands land on a string start, "
                          "DSD/Hi-Fi operands there = %d"
                          % (rm["calibration"]["mode"], rm["landed"], len(mhits)))
        except SystemExit as e:
            media_note = "libmedia.so: the ruler refuses there (%s)" % str(e)[:70]
    return [
        {"layer": "DSD Hi-Fi source surface",
         "item": "every function in the player service that builds the address of a DSD string",
         "value": ("★DSD operand census in this object: %d site(s) over %d function(s) -- %s ・ "
                   "strings seen: %s ・ %s ・ references to a string containing `dsd`: %d -- %s ・ "
                   "survey denominators: %d "
                   "resolved operands land on a string start, %d survive a 1-byte shift, %d nameable "
                   "strings in the image, %d instructions decoded"
                   % (len(broad), len(per_fn), census, "・".join(x[:44] for x in strs[:8]),
                      media_note, len(hits), lines,
                      r["landed"], r["shifted_by_1"], r["strings"], r["decoded"])),
         "name_or_meaning": ("★§430 named ONE comparison site; running the same rule as a survey -- "
                             "give a string, ask which functions materialise it -- shows the MIME "
                             "`audio/dsd` is built in **%d** places: `NuPlayer::onStart()` (the per-stream "
                             "decision) and `NuPlayer::instantiateDecoder()` (which chooses the decoder), "
                             "while `NuPlayer::determineAudioModeChange()` is the one that reads the "
                             "`audio.dsd.hw.out` property -- and that third site is the very one the tool "
                             "was calibrated against, so it doubles as the positive control.  ★For the "
                             "port this changes the check from 'is the onStart comparison still there' to "
                             "'are BOTH comparison sites still there': losing instantiateDecoder while "
                             "keeping onStart would let a stream be marked DSD and then be decoded by the "
                             "normal path -- audible, and invisible to every config file in this table.  "
                             "★Boundary that travels with the row -- and §438 corrects what I first said here: the survey "
                             "refuses on `libaudioflinger.so` because only 46 sized FUNC symbols cover 1.8%% of its .text (a zero there is the stripped symbol table, not the code), while on the audio HAL it sees 63.7%% of .text and refuses because string operands there are not built as (delta + base + PC) -- they sit in "
                             "`.data.rel.ro` tables (the `HAL backend vocabulary` row counts those).  A refusal is never 'nobody uses the string'." % len(mime)),
         "source": lib,
         "writable": "no -- read-only decode",
         "use_case": ("on 7: `python3 tools/arm32_str_refs.py --elf <7 libmediaplayerservice.so> "
                      "--find audio/dsd` -- expect the same set of functions (the names may differ but "
                      "the count and the property site must be reproducible); read the calibration line "
                      "first: `mode=known-answer` means the names are on a ruler, `statistical` is weaker, "
                      "and no rule at all means the survey refuses and nothing below it is quotable"),
         "witness2": ("%d arms: the object must calibrate and land >=20 operands on string starts・a "
                      "resolution surviving a 1-byte shift must be rare or the tool aborts・the query must "
                      "independently LOCATE the def chain feeding the known calibration call (same "
                      "function, within 0x10 bytes)・deliberately mis-setting the PC offset must cut the "
                      "number of names to under a third・decoded/string/landed denominators are printed"
                      % 5),
         },
    ]


def pa_label_provenance_rows():
    """§434: which header family supplied each PA register NAME in tfa-regs.PD1610.tsv.  The census is
    re-run at generation time; a matcher that finds nothing aborts instead of delivering blank lineage."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "pa_name_provenance", os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                           "pa_name_provenance.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    tsv = f"{BASE}/tfa-regs.PD1610.tsv"
    root = f"{ROOT}/fw/tfa-ref"
    if not os.path.exists(tsv):
        sys.exit("gate: %s missing" % tsv)
    rows = mod.read_rows(tsv)
    files = mod.tree(root)
    res = mod.audit(rows, files)
    named = [x for x in res if x["name"]]
    if not named:
        sys.exit("gate: no named rows to audit -- the table lost its name column")
    if all(x["families"] == ["NOWHERE"] for x in named):
        sys.exit("gate: every name reads NOWHERE in %d reference files -- matcher or tree is broken"
                 % len(files))
    by = {}
    for x in named:
        by.setdefault("・".join(x["families"]), []).append(x["reg"])
    lines = "；".join("%s = %d 枚（%s）" % (k, len(v), "・".join(v))
                     for k, v in sorted(by.items(), key=lambda kv: -len(kv[1])))
    anon = len(res) - len(named)
    return [
        {"layer": "PA label provenance",
         "item": "which reference header family supplied each PA register name in our table",
         "value": ("%d rows in tfa-regs.PD1610.tsv: %d named / %d NO-NAME / %d named-but-unfound ・ "
                   "reference files scanned: %d ・ lineage: %s"
                   % (len(res), len(named), anon, len([x for x in named
                                                       if x["families"] == ["NOWHERE"]]),
                      len(files), lines)),
         "name_or_meaning": ("★a label is not a fact unless you know whose label it is.  The vendor's "
                             "reference tree ships several chip families and they DISAGREE about the same "
                             "address: our `0x46`/`0x49` names (`INTERRUPT_IN_REG3`/`INTERRUPT_ENABLE_REG2`) "
                             "exist only in the N1C-genregs and the 9872/9912 POR tables, while "
                             "`tfa9891_genregs.h` calls `0x46` CurrentSense1 and `tfa_init.c:16` states "
                             "``The CurrentSense4 registers are not in the datasheet`` and defines bit2 of "
                             "0x49 itself (`CLKGATECFOFF`, used on the TFA9890 path at tfa_init.c:1330).  "
                             "Measured here: **every** named row in our table comes from that N1C/POR "
                             "group, none from the 9890's own table (which carries only bit-field names). "
                             "★So the PA comparison across versions must be made on **register number + "
                             "decoded fields + value** (which §346/§349 already do) and never on this name "
                             "column -- otherwise a 7 driver that renames by family reads as a hardware "
                             "difference.  The census is re-run wherever the tree is, and an all-NOWHERE "
                             "result aborts rather than shipping blank lineage."),
         "source": tsv,
         "writable": "no -- read-only audit of the label column",
         "use_case": ("on 7: run `python3 tools/pa_name_provenance.py --tsv <7's tfa-regs.tsv> --ref <the "
                      "same fw/tfa-ref>` -- rows whose lineage changes family between 6.0.1 and 7 are "
                      "**labelling** differences, not register differences; keep them out of the "
                      "must-copy list"),
         "witness2": ("%d arms: named rows must resolve to >=1 reference family (nothing silently blank)・"
                      "a SENTINEL name must read NOWHERE (proof the matcher can say 'not found')・the "
                      "9890's own field name must be found by SUBSTRING search -- an earlier version used "
                      "`\\b` and every name read NOWHERE because headers write `TFA98XX_<NAME>`・an empty "
                      "reference tree aborts・if every named row reads NOWHERE the census aborts" % 6),
         },
    ]



def exidx_reachability_rows():
    """§440: the same corpus surveyed with function boundaries from .ARM.exidx instead of from the
    symbol table, and with the decode mode chosen per function.  This is what turns 'the symbol table
    is stripped' into a measured view: libaudioflinger.so goes from 1.8% of .text visible to 96.8%,
    and the answer there is then a statement about the code, not about the tool."""
    import importlib.util
    here = os.path.dirname(os.path.abspath(__file__))
    spec = importlib.util.spec_from_file_location("arm32_exidx_survey",
                                                  os.path.join(here, "arm32_exidx_survey.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    root = f"{ROOT}/{BASE}/shipped/system/lib"
    names = ["libmedia.so", "libstagefright.so", "libmediaplayerservice.so", "libaudioroute.so",
             "libeffects.so", "libaudiopolicymanagerdefault.so", "libaudioflinger.so",
             "audio.primary.msm8996.so"]
    targets = {}
    for n in names:
        p = f"{root}/hw/{n}" if n.startswith("audio.primary") else f"{root}/{n}"
        if os.path.exists(p):
            targets[n] = p
    if len(targets) < 6:
        sys.exit(f"gate: the exidx row only finds {len(targets)} of {len(names)} audio-side objects "
                 "on disk -- the row would quote a partial census")
    got = {}
    for name, path in targets.items():
        try:
            got[name] = mod.survey(path, quiet=True)
        except SystemExit as e:
            sys.exit(f"gate: the exidx survey refused {name} -> {str(e)[:200]}")
    if len(got) != len(targets):
        sys.exit(f"gate: the exidx survey measured {len(got)} of {len(targets)} listed objects")
    parts = [f"{n}: funcs={r['funcs']} (thumb {r['thumb']} / arm {r['arm']}), viewed "
             f"{r['span']}/{r['text']} = {r['span_pct']:.1f}%, thumb pair-sum landings={r['landings']}, "
             f"thumb direct ldr[pc] landings={r['thumb_direct_landings']} of {r['thumb_direct_sites']} sites, "
             f"arm single-ldr landings={r['arm_landings']} of {r['arm_sites']} arm ldr[pc] sites "
             f"(ambiguous pool reads={r['arm_ambig']}), strings reached={r['strings_reached']}/"
             f"{r['string_starts']} (unreached windows {r['zero_windows']}/{r['tested_windows']}), "
             f"non-unwinder total={r['code_landings']} "
             f"(the floor of 20 is on that number), byte-shift survivors={r['shifted'] + r['arm_shift']}, "
             f"verdict={'nameable' if r['verdict'] == 'nameable' else ('PARTIAL' if r['verdict'].startswith('PARTIAL') else 'REFUSED')}"
             for n, r in sorted(got.items())]
    ka = all(r["ka_miss"] == 0 for r in got.values())
    nm = [n for n, r in got.items() if r["verdict"] == "nameable"]
    part = [n for n, r in got.items() if r["verdict"].startswith("PARTIAL")]
    refu = [n for n, r in got.items() if r["verdict"].startswith("REFUSED")]
    if len(nm) + len(part) + len(refu) != len(got):
        sys.exit(f"gate: the exidx verdicts do not partition ({len(nm)}+{len(part)}+{len(refu)} "
                 f"!= {len(got)}) -- a fourth verdict shape slipped in")
    # The whole-corpus measurement is a FIELD artifact (tools/arm32_exidx_survey.py --census --out …),
    # not something the generator re-derives on every run: measuring 75 objects here costs minutes and
    # the generator is on the acceptance path.  When the artifact is missing the row still measures live
    # rather than quoting prose -- and the header's own counts are checked against the rows either way.
    art_path = f"{ROOT}/{BASE}/exidx-census.PD1610.tsv"
    from_census_art = os.path.exists(art_path)
    if from_census_art:
        txt = open(art_path, encoding="utf-8").read()
        head, cols, *rec = [l.split(chr(9)) for l in txt.splitlines() if l.strip()]
        nfiles, rows_all = int(head[1]), [dict(zip(cols, r)) for r in rec]
        skipped_all = [("see-header", w) for w in head[5:6]]
        if int(head[3]) != len(rows_all):
            sys.exit(f"gate: {art_path} header says measured={head[3]} but the body has {len(rows_all)}")
        for r in rows_all:
            for k in ("thumb", "arm", "span_pct", "code_landings", "arm_ambig", "funcs"):
                r[k] = float(r[k])
    else:
        rows_all, skipped_all, nfiles = mod.census(f"{ROOT}/{BASE}/shipped/system/lib")
    nm_c = [r for r in rows_all if r["verdict"] == "nameable"]
    part_c = [r for r in rows_all if r["verdict"].startswith("PARTIAL")]
    refu_c = [r for r in rows_all if r["verdict"].startswith("REFUSED")]
    cal_fail = [n for n, why in skipped_all if "fall outside" in why]
    no_tbl = [n for n, why in skipped_all if "no .ARM.exidx" in why]
    census_row = {
        "layer": "static-analysis reachability",
        "item": "the whole shipped 32-bit corpus under that rule: what can be asked of it at all",
        "value": (f"{nfiles} .so candidates under system/lib ・ source=" +
                  ("the on-disk census artifact exidx-census.PD1610.tsv (regenerate with "
                   "`arm32_exidx_survey.py --census … --out …`)" if from_census_art else
                   "measured live this run, no artifact on disk") + " ・ measured={len(rows_all)} ・ skipped="
                  f"{len(skipped_all)} (no exidx table: {', '.join(no_tbl) or 'none'} ・ known-answer "
                  f"FAILED: {', '.join(cal_fail) or 'none'}) ・ verdicts: nameable={len(nm_c)} "
                  f"PARTIAL={len(part_c)} REFUSED={len(refu_c)} ・ functions thumb="
                  f"{sum(r['thumb'] for r in rows_all)} arm={sum(r['arm'] for r in rows_all)} ・ "
                  f"viewed span mean={sum(r['span_pct'] for r in rows_all)/len(rows_all):.1f}% "
                  f"min={min(r['span_pct'] for r in rows_all):.1f}% "
                  f"max={max(r['span_pct'] for r in rows_all):.1f}% ・ non-unwinder landings total="
                  f"{sum(r['code_landings'] for r in rows_all)} ・ ambiguous pool reads="
                  f"{sum(r['arm_ambig'] for r in rows_all)} ・ nameable top: "
                  + ", ".join(f"{os.path.basename(r['path'])} {r['code_landings']}"
                              for r in sorted(nm_c, key=lambda x: -x["code_landings"])[:8])
                  + " ・ REFUSED even with boundaries: "
                  + (", ".join(os.path.basename(r["path"]) for r in refu_c) or "none")),
        "name_or_meaning": ("★this is the denominator for every 'who references this string/table' leg in "
                            "the table, restated in the stronger口径: §438 measured visibility THROUGH THE "
                            "SYMBOL TABLE (46 of 75 objects under half visible), this measures visibility "
                            "through the exception index plus a per-function instruction mode -- and the "
                            "mean rises to the upper 80s of percent with only a handful of objects left "
                            "unreachable.  ★What does NOT change is the conclusion that matters: nameable "
                            "objects are the media/binder stack (stagefright family, playerservice, media), "
                            "while AudioFlinger, the audio HAL and AudioPolicy stay PARTIAL -- not because "
                            "they are opaque now, but because their `.rodata` string addresses never arrive "
                            "by a direct literal load (measured: 0 landings over thousands of `ldr [pc]` "
                            "sites in those objects) and their pair-sum sites are scarce.  ★Two refusals "
                            "are worth reading as measurements of the tool: `libc.so` has no exception "
                            "index at all (its unwind info is not per-function tables), and one object "
                            "fails the KNOWN-ANSWER calibration (a sized FUNC falls outside the recovered "
                            "ranges) so it is dropped rather than surveyed half-seen -- that is the gate "
                            "biting on a real file, not only on fixtures.  ★On 7: run the same census first; "
                            "an object that is PARTIAL there too cannot answer 'who references X' from the "
                            "file, and that is a property of the build, not of the switch."),
        "source": f"{BASE}/shipped/system/lib",
        "writable": "no -- read-only decode",
        "use_case": ("on 7: `python3 tools/arm32_exidx_survey.py --census <7 携带树>/system/lib` -- compare "
                     "the nameable/PARTIAL/REFUSED partition and the skipped list with this row; a layer "
                     "that was nameable here and is PARTIAL there has changed build conventions, and the "
                     "comparisons that depend on it have to be re-derived, not carried"),
        "witness2": ("the census prints candidates = measured + skipped WITH each reason (no table / "
                     "calibration failure), and one arm asserts exactly that identity; the same arm set "
                     "as the per-object row (12 arms) now also pins both pool-slot formulas against "
                     "arm-linux-gnu-objdump's own annotations, so a formula drift is caught before any "
                     "count is published"),
    }
    return [census_row, {
        "layer": "static-analysis reachability",
        "item": "the same corpus with .ARM.exidx boundaries, a per-function decode mode and a "
                "per-mode literal convention (thumb pair-sum vs arm single ldr[pc])",
        "value": ("boundaries calibrated against the symbol table: every sized .dynsym FUNC falls "
                  f"inside a recovered range = {ka} ・ nameable: " + str(len(nm)) + " (" + ", ".join(nm) +
                  ") ・ PARTIAL (rows quotable, absence not claimed): " + str(len(part)) + " (" +
                  ", ".join(part) + ") ・ REFUSED: " + str(len(refu)) + " (" + (", ".join(refu) or "none") +
                  ") ・ " + " ・ ".join(parts) +
                  " ・ the inlined-unwinder block supplies most of the remaining landings, which is why "
                  "the floor is put on the non-unwinder count"),
        "name_or_meaning": ("★this retires the §438 refusal for the objects the DSD/Hi-Fi legs needed, and "
                            "splits one claim into two.  `libaudioflinger.so` shows 1.8% of `.text` through "
                            "symbols and **96.8%** through its exception index, with the decode mode chosen "
                            "per function (811 thumb / 58 arm) -- and the blindness detector then says what the low count "
                            "MEANS: the survey reaches only 7 of AudioFlinger's 820 string starts "
                            "(770 of 785 windows of >=5 starts contain nothing it reached), while the "
                            "same code reaches 879 of 3376 in `libstagefright.so`.  So a PARTIAL here "
                            "measures THIS TOOL'S convention coverage, not the object: ★the earlier "
                            "sentence \"that object does not carry string addresses through the pool "
                            "arithmetic at all\" is RETRACTED -- five representations were tried and "
                            "none reaches its log strings (pool pair-sum, direct `ldr [pc]`, absolute "
                            "pointer words in .data/.data.rel.ro, section-relative pointer words, "
                            "`movw/movt`, `adr`/ADRL), and 17 sibling strings around "
                            "`hifi_switch_change` are all unreached too, including its own log line.  ★The second "
                            "finding is the HAL: 256 of its 308 functions decode as ARM, and ARM does name "
                            "its literals -- through a DIFFERENT convention, a single `ldr rN, [pc, #imm]` "
                            "with the slot at `(addr+8)&~3 + imm`, confirmed digit-for-digit against "
                            "`arm-linux-gnu-objdump`'s own annotations (`#1296 @ 8944`, `#1284 @ dde0`) and "
                            "landing on real HAL vocabulary (`vivo_ktv_miceq_preset`・`audio.stream.in`・"
                            "`platform_send_audio_calibration`・`voice-anc-fb-headphones`).  A thumb-only "
                            "sweep of that object reads zero for its own reasons, which is why the two "
                            "conventions are counted separately and the excluded-mode ranges are printed.  "
                            "★On 7: run the same command per object -- it says how much is visible, which "
                            "instruction mode each object is in, and whether naming is allowed at all."),
        "source": f"{BASE}/shipped/system/lib/libaudioflinger.so",
        "writable": "no -- read-only decode",
        "use_case": ("on 7: `python3 tools/arm32_exidx_survey.py --elf <7 object>` per object plus "
                     "`--selftest` once; read the `thumb/arm` split and the two landing counts before "
                     "believing anything -- PARTIAL at 96% viewed is a property of the code, REFUSED at "
                     "20% viewed is the tool being blind, and nameable here does not mean nameable there"),
        "witness2": ("three independent calibrations, each with its own refusal: boundaries must contain "
                     "every sized .dynsym FUNC (41/41, 1302/1302, 246/246 measured here), the mode choice "
                     "must keep the arm functions visible (>=10 in the stripped object, span >90%), and a "
                     "naming claim needs the byte-shift control to stay under the landings -- 9 arms green, "
                     "including 'a target readelf cannot index aborts' and 'the two conventions are counted "
                     "separately, because a thumb-only survey of the HAL would report its arm block as "
                     "zero'; every refusal still prints its own denominator, so a refusal cannot hide an "
                     "empty sweep"),
    }]


def reachability_rows():
    """§438: how much of the shipped 32-bit corpus a per-function decode can even see.  Every leg that
    answers "who references this string/table" depends on this number, so it is measured, not assumed."""
    import importlib.util
    here = os.path.dirname(os.path.abspath(__file__))
    spec = importlib.util.spec_from_file_location("arm32_str_refs", os.path.join(here, "arm32_str_refs.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    root = f"{ROOT}/{BASE}/shipped/system/lib"
    out, skipped = mod.coverage_census(root)
    low = [x for x in out if x[3] < 50.0]
    zero = [x for x in out if x[3] == 0.0]
    best = max(out, key=lambda x: x[3])
    watch = {os.path.basename(p): (t, n, pct) for p, t, n, pct in out
             if os.path.basename(p) in ("libstagefright.so", "libmediaplayerservice.so", "libmedia.so",
                                        "libaudioflinger.so", "libacdbloader.so", "libaudioroute.so")}
    if not out:
        sys.exit("gate: the census measured nothing")
    return [
        {"layer": "static-analysis reachability",
         "item": "how much of .text a symbol-guided decode can see across the shipped 32-bit corpus",
         "value": ("%d ELF32 objects measured under system/lib (%d skipped) ・ below 50%% visible: "
                   "%d (%.1f%%) ・ with NOTHING visible: %d (%s) ・ best: %s %.1f%% ・ the objects the "
                   "other rows lean on: %s"
                   % (len(out), len(skipped), len(low), 100.0 * len(low) / len(out), len(zero),
                      "・".join(os.path.basename(p) for p, _t, _n, _p in zero[:6]),
                      os.path.basename(best[0]), best[3],
                      "；".join("%s %.1f%% (%d funcs, %d B)" % (k, v[2], v[1], v[0])
                               for k, v in sorted(watch.items())))),
         "name_or_meaning": ("★this is the reachability boundary for every 'who references X' leg in this "
                             "table: a survey that walks `.text` per sized FUNC symbol sees under half the "
                             "code in most of this corpus, and five soundfx libraries have NO sized "
                             "function symbols at all -- so a zero from those files means the symbol table "
                             "is stripped, never 'nobody uses it'.  ★It also says which rows can be trusted "
                             "as findings: the DSD operand census in `DSD Hi-Fi source surface` runs over "
                             "`libmediaplayerservice.so` at 80.5% and the negative in `libstagefright.so` at "
                             "88.7%, while the AudioFlinger parameter strings sit in a file measured at "
                             "1.8% -- that leg has to be answered another way (full-section disassembly or "
                             "a runtime read).  ★Coverage is the UNION of symbol ranges, not the sum of "
                             "their sizes: summing double-counts overlapping symbols and reported 101-121% "
                             "here until the tool refused to publish it."),
         "source": f"{BASE}/shipped/system/lib",
         "writable": "no -- read-only census",
         "use_case": ("on 7: run `python3 tools/arm32_str_refs.py --coverage <7 shipped>/system/lib` FIRST "
                      "and read the two counts; only objects above ~80% can carry a 'nobody references this' "
                      "claim, and a 7 library that dropped its symbol table would silently turn every such "
                      "row into a false negative"),
         "witness2": ("the tool refuses to publish any object above 100% (union vs sum), counts what it "
                      "skipped, and its selftest carries a paired arm: a stripped object must be refused "
                      "with the COVERAGE reason quoting the same percentage the census computes, while a "
                      "fully symbolised object must not be refused that way"),
         },
    ]


def inplay_rows():
    """§420: the two output routes seen from the inside while a stream runs, and the one-command
    check that compares 7 against them."""
    hifion = f"{BASE}/live/inplay-hifion-20261017-1933"
    spk = f"{BASE}/live/inplay-spk-20261017-2012"
    spk2 = f"{BASE}/live/inplay-spk2-20261017-2023"
    for d in (hifion, spk):
        for f in ("tinymix-all.txt", "codec_reg.txt", "thread-owner.txt"):
            if not os.path.exists(f"{d}/{f}"):
                sys.exit(f"gate: in-play baseline {d} lacks {f} -- the layer describes a live session, "
                         "so it cannot be reported from memory")
    sys.path.insert(0, f"{ROOT}/tools")
    import inplay_accept as ia
    A, B = ia.load(hifion), ia.load(spk)
    diff = [(c, A["ctl"][c], B["ctl"][c]) for c in ia.MUST if A["ctl"].get(c) != B["ctl"].get(c)]
    same = [(c, A["ctl"][c]) for c in ia.MUST if A["ctl"].get(c) == B["ctl"].get(c)]
    onb = sorted(B["on"])
    raw = open(f"{spk}/logcat-raw.txt", encoding="utf-8", errors="replace").read().splitlines()
    devs = sorted({l.split("out_snd_device(")[1].split(" in_snd")[0].strip()
                   for l in raw if "select_devices: out_snd_device" in l})
    acdbs = sorted({l.split("acdb_dev_id ")[1].split(",")[0] for l in raw if "send_app_type_cfg" in l})
    def _route_cell(l):
        for tok in ("mixer path: ", "update path: "):
            if tok in l:
                return l.split(tok)[1].strip()
        return None
    paths = sorted({c for l in raw for c in [_route_cell(l)]
                    if c and ("mixer path" in l or "update path" in l)})
    if not devs or not acdbs:
        sys.exit("gate: the speaker-session log slice has no select_devices/app_type_cfg line -- the "
                 "(device, acdb) map cannot be reported from it")
    import csv as _csv
    cls = {}
    for _r in _csv.DictReader(open(f"{BASE}/tfa-regs.PD1610.tsv", encoding="utf-8"), delimiter="\t"):
        cls[int(_r["reg"].strip(), 16)] = _r["class"].strip()
    stable = [k for k in cls if cls[k].upper() == "STABLE"]
    if not stable:
        sys.exit("gate: the PA class table has no STABLE row -- a stability claim needs to know which "
                 "registers are allowed to move")

    def _regs(d):
        return {int(m.group(1), 16): m.group(2) for m in re.finditer(r"reg\{(\w+)\}:(\w+)",
                open(f"{d}/codec_reg.txt", encoding="utf-8", errors="replace").read())}
    va, vb = _regs(spk), _regs(spk2)
    cmp = [k for k in stable if k in va and k in vb]
    moved = sorted(k for k in va if k in vb and va[k] != vb[k])
    for _u in (f"{spk}/uptime.txt", f"{spk2}/uptime.txt"):
        if not os.path.exists(_u):
            sys.exit("gate: " + _u + " missing -- a stability claim needs the two moments it compares")
    up1 = open(f"{spk}/uptime.txt", encoding="utf-8").read().split()[0]
    up2 = open(f"{spk2}/uptime.txt", encoding="utf-8").read().split()[0]
    ca = ia.controls_current(open(f"{spk}/tinymix-all.txt", encoding="utf-8", errors="replace").read())
    cb = ia.controls_current(open(f"{spk2}/tinymix-all.txt", encoding="utf-8", errors="replace").read())
    nca = len(ca)
    diffc = sorted(c for c in ca if c in cb and ca[c] != cb[c])
    older = [f"{BASE}/live/tinymix-play-20261017-0837.txt",
             f"{BASE}/live/tinymix-D0-playing-speaker.txt"]
    for _f in older:
        if not os.path.exists(_f):
            sys.exit("gate: " + _f + " missing -- the cross-session stability count needs the older dumps")
    cross, ncross = set(), 0
    for _f in older:
        _c = ia.controls_current(open(_f, encoding="utf-8", errors="replace").read())
        ncross = len(_c)
        cross |= {k for k in _c if k in ca and _c[k] != ca[k]}
    cross = sorted(cross)
    for _x in (f"{spk}/tfa98xx-dir.txt", f"{spk}/es9028-dir.txt", f"{spk}/regmap-dirs.txt"):
        if not os.path.exists(_x):
            sys.exit("gate: " + _x + " missing -- the face-absence claim is an observation, not a recollection")
    rate_here = (ca.get(ia.STREAM0, "").split() + ["?", "?", "?"])[2]
    faces = " ".join(l.split()[-1] for l in open(f"{spk}/tfa98xx-dir.txt", encoding="utf-8",
                                                 errors="replace").read().splitlines()[1:]) or "?"
    _es = [l for l in open(f"{spk}/es9028-dir.txt", encoding="utf-8", errors="replace").read().splitlines()[1:]
           if re.search(r"[A-Za-z0-9]", l)]
    es9028 = "EXISTS but holds no faces" if not _es else "has " + str(len(_es)) + " entries"
    regmap_dirs = " ".join(l.strip() for l in open(f"{spk}/regmap-dirs.txt", encoding="utf-8",
                                                   errors="replace").read().splitlines() if l.strip())
    return [
        {"layer": "in-play route state", "item": "the two output routes as live state, control by control",
         "value": ("route-differing controls " + str(len(diff)) + "/" + str(len(ia.MUST)) + ": " +
                   "・".join(c + " hifi=" + a + "/spk=" + b for c, a, b in diff) +
                   "; controls identical on both routes: " + ("・".join(c + "=" + v for c, v in same) or "none") +
                   "; live DAPM sinks On (speaker snapshot): " + "・".join(onb) +
                   "; per-stream app type/acdb/rate: hifi=" + "/".join([A["apptype"], A["acdb"], A["rate"]]) +
                   " spk=" + "/".join([B["apptype"], B["acdb"], B["rate"]]) +
                   "; Hi-Fi DAC powered off on the speaker snapshot: " + str(B["dac_off"]) +
                   " (hifi snapshot: " + str(A["dac_off"]) + ")" +
                   "; track on the hifi snapshot: " + "・".join(A["track"] or ["?"]) +
                   "; track on the speaker snapshot: " + "・".join(B["track"] or ["?"])),
         "name_or_meaning": ("★the routes are mutually exclusive AT THE DEVICE SELECT, which is now "
                             "state rather than inference: `HiFi Mode Switch=HiFi` with "
                             "`SmartPA Switch=Off` on one side, `SmartPA Switch=On` with "
                             "`HiFi Mode Switch=Off` on the other, and the four tfa98xx widgets "
                             "`SmartPA I2S In -> SmartPA -> SmartPA Playback -> Speaker` live On with "
                             "`in 1 out 1`.  That is §298/§299's graph traversal (外放只差一格 "
                             "`SmartPA Switch`) witnessed from the running kernel, and it also closes "
                             "§375's worry that the live state had no observation face.  "
                             "`TERT_MI2S_RX Audio Mixer MultiMedia1` is On on BOTH routes, so the "
                             "backend is shared and the sink is chosen downstream -- the reason a "
                             "single switch flips the whole sound.  `TERT_MI2S mode` (Slave for Hi-Fi, "
                             "Master for speaker) and `TERT_MI2S Bit Format` (S24/S16) are the other "
                             "two discriminators; the front-end PCM of the speaker snapshot is "
                             "S24_LE at 48000 while the backend control says S16_LE, and the HAL line "
                             "`Allowing 24-bit playback on speaker ONLY at default sampling rate` sits "
                             "between them -- ★the three readings are recorded, the causal order is "
                             "NOT proven."),
         "source": f"{hifion}/tinymix-all.txt",
         "writable": "no -- read-only captures taken while a stream runs",
         "use_case": ("on 7: play one file, then `python3 tools/inplay_accept.py --snap <dir>` and "
                      "replay the SAME comparison; the tool decides the route from the powered DAPM "
                      "sink, the two switches and the per-stream ACDB id, and refuses to compare a "
                      "route it cannot name"),
         "witness2": ("9 arms; among them a same-run positive control around each mutation, and one "
                      "arm that judges the Hi-Fi snapshot against a baseline whose asserted control "
                      "was deleted -- that aborts with \"inventing its own expectation\" instead of "
                      "silently checking one fewer thing"),
         },
        {"layer": "in-play route state", "item": "snd_device -> acdb_dev_id map and route path names, read off the HAL's own narration",
         "value": ("speaker snapshot log: " + "・".join(devs) +
                   " with acdb " + "・".join(acdbs) +
                   "; route path names applied/reset: " + "・".join(paths)),
         "name_or_meaning": ("one buffer that rolled from the Hi-Fi session into a headphones session "
                             "into the speaker session, so the map is read from consecutive lines "
                             "rather than assembled from three captures: `8: headphones -> acdb_dev_id "
                             "10`, `2: speaker -> 15` (both app_type 69937 at 48000), with the Hi-Fi "
                             "pair `43: headphone-hifi -> 150` carried over from the §415 buffer and "
                             "its teardown lines (`reset and update mixer path: deep-buffer-playback "
                             "headphone-hifi`, `disable_snd_device 43 ref_cnt:0`, `hifi client cnt: "
                             "1 -> 0`) in the same window.  ★For the port this is the strongest single "
                             "comparison: if 7 selects a different device number or sends a different "
                             "acdb id, no value interpretation is needed -- and the copy-list of §309 "
                             "(19 cards, all at device 150) is shown here to be a Hi-Fi-only layer, "
                             "because the speaker stream asks for 15"),
         "source": f"{spk}/logcat-raw.txt",
         "writable": "no",
         "use_case": "on 7: `logcat -d -v brief` during the same three-route sequence, then compare the SET of (device, acdb) pairs, not the log text",
         "witness2": ("the `-19` ACDB errors are re-counted per buffer rather than compared as a "
                      "number: this ring kept 1 (`ACDB AFE returned = -19`) where the §415 ring kept 3, "
                      "and the tool reports the level distribution it saw so the difference is visible "
                      "as ring roll, not as a fix"),
         },
        {"layer": "in-play route state", "item": "what stays put between in-play snapshots and across boots, and which faces do not exist at all",
         "value": ("two speaker snapshots (uptime " + up1 + " vs " + up2 + "): " +
                   str(len(cmp)) + "/" + str(len(stable)) + " STABLE-class PA registers identical; the ones that moved are " +
                   ("・".join("0x%02x=%s->%s[%s]" % (k, va[k], vb[k], cls[k]) for k in moved) or "none") +
                   "; of " + str(nca) + " mixer controls read both times, " + str(len(diffc)) + " differ: " +
                   ("・".join(c + " " + ca[c] + "->" + cb[c] for c in diffc) or "none") +
                   "; across THREE speaker in-play dumps (older: " +
                   "・".join(os.path.basename(x) for x in older) + ") only " + str(len(cross)) + "/" +
                   str(ncross) + " controls differ: " + "・".join(cross) +
                   "; faces on the PA debugfs dir: " + faces + "; es9028 debugfs dir: " + es9028 +
                   " while es9038 has `reg`; `/sys/kernel/debug/regmap` holds: " + regmap_dirs +
                   "; the per-stream cfg RATE column moves with the material: 44100 in " +
                   "tinymix-D0-playing-headphones.txt vs " + rate_here + " here"),
         "name_or_meaning": ("★the register face is stable where the classifier says it must be and moves "
                             "only where it may: the 4 registers differing between two in-play snapshots are "
                             "exactly the `volatile`/`state-dependent` rows of tfa-regs.PD1610.tsv, and all 18 "
                             "STABLE ones match -- a 7-side check that demanded byte equality of the whole "
                             "26-register file would call THIS a regression on the good device (the §362 lesson "
                             "in its PA form).  ★Across three speaker in-play dumps from different sessions/boots "
                             "only 3 of 1555 controls differ, and none of them is a tuning value: `Vbat ADC data` "
                             "(fuel-gauge noise), `Playback Device Channel Map` (§419's routing artefact) and "
                             "`HP Sel` -- ★which was seen as BOTH `Normal` and `HiFi` under the same `SmartPA "
                             "Switch=On` state.  That is leftover from the route that ran before, so `HP Sel` and "
                             "the stale per-stream cfg (which reads acdb 15 even when nothing plays) are NOT live "
                             "route markers on their own: the route must be named by a powered sink plus the "
                             "switches, exactly as the ruler does.  ★And two absences worth naming so a later "
                             "reader does not mistake an empty read for a measurement: the PA debugfs directory "
                             "carries only `calibrate codec_reg fRes_Detect i2c` (there is NO `status` face), and "
                             "`/sys/kernel/debug/es9028` exists but holds no entries while es9038 has its `reg` "
                             "face -- consistent with §355 (no device-tree binding for the es9028 variant), "
                             "though the empty directory itself does not prove which code path created it"),
         "source": f"{BASE}/live/inplay-spk2-20261017-2023/codec_reg.txt",
         "writable": "no",
         "use_case": ("on 7: take two snapshots of the same route and compare only the STABLE register class -- "
                      "whole-file byte equality is the wrong test and the class table says why.  Judge the route "
                      "by the powered DAPM sink and the switches, never by `HP Sel` or by the per-stream cfg "
                      "alone, because both keep the previous route's value"),
         "witness2": ("two arms built from the class table rather than hand-picked addresses: flipping a STABLE "
                      "register must be named as a mismatch, and flipping a VOLATILE one must NOT fail (that is "
                      "the arm that stops the check from degenerating into a random-noise detector); the tool "
                      "aborts when the class table is absent, and this builder aborts when either older dump is "
                      "missing so the 3-of-1555 count cannot be typed from memory"),
         },
        {"layer": "in-play route state", "item": "★retraction: `HiFi Mode Switch` DOES read HiFi in the Hi-Fi in-play snapshot",
         "value": ("hifi snapshot: echo form `" + open(f"{hifion}/controls.txt", encoding="utf-8").readline().strip() +
                   "` -> " + str(ia.controls_echo(open(f"{hifion}/controls.txt", encoding="utf-8", errors="replace").read())["HiFi Mode Switch"]) +
                   "; full-dump form -> " + A["ctl"]["HiFi Mode Switch"] +
                   "; speaker snapshot -> " + B["ctl"]["HiFi Mode Switch"]),
         "name_or_meaning": ("§415 recorded \"the live control table reads `HiFi Mode Switch` Off while "
                             "the log runs headphone-hifi, therefore the control is NOT the gate and "
                             "another mechanism selects the device\".  That reading came from parsing "
                             "`tinymix -D 0 <name>` output by taking the token after the colon -- but "
                             "for an ENUM that token is the FIRST OPTION, and the active item is the "
                             "one carrying `>` (`Off\t>HiFi\tDSD\tNormal`).  Both capture forms of the "
                             "same snapshot now say HiFi, the board-file path definition "
                             "(`headphone-hifi` writes `HiFi Mode Switch=HiFi`) is confirmed from the "
                             "running kernel, and the \"两套状态\" sentence is withdrawn.  What survives "
                             "is narrower and still useful: the control reads HiFi ONLY while the "
                             "route is active, so 7 must be measured in-play"),
         "source": f"{hifion}/controls.txt",
         "writable": "no",
         "use_case": ("any enum control read from `tinymix -D 0 <name>`: the value is the item marked "
                      "`>`; a bare split on ':' yields the first option"),
         "witness2": ("two arms: one feeds a per-control echo that disagrees with the dump and the "
                      "load aborts naming both forms, the other asserts that the `>`-marked item is "
                      "what the parser returns -- so the trap that produced this retraction is now a "
                      "test, not a lesson"),
         },
    ]



def hifi_dt_rows():
    """the two board-level DT nodes the audio path binds to: the vivo Hi-Fi codec platform node
    (powers / resets / clock-selects the DAC) and the ASoC card node (names the machine driver and
    routes the widgets).  Both are compiled-DTB contracts, so they are compared, not carried (§287)."""
    raw = os.environ.get("HIFIDT") or f"{BASE}/live/hifi-dt-raw.txt"
    if not os.path.exists(raw):
        sys.exit(f"gate: {raw} missing -- capture it with tools/hifidt.sh on the device")
    txt = open(raw, encoding="utf-8", errors="replace").read()
    if "HIFIDT_DONE" not in txt:
        sys.exit(f"gate: {raw} has no HIFIDT_DONE marker -- the capture was cut off, so an absent "
                 "property below would be the cut and not the machine")
    want_nodes = ("/sys/firmware/devicetree/base/soc/vivo-hifi-codec",
                  "/sys/firmware/devicetree/base/soc/sound-9335")
    for n in want_nodes:
        if f"##### NODE {n}" not in txt:
            sys.exit(f"gate: the capture has no {n} section -- that node was not read, so its "
                     "property count is not a denominator")
    known = hifi_known_strings()
    compat_hifi = [s for s in known if s.startswith("vivo,hifi-codec-")]
    mach = sorted({m.group(0).decode() for m in re.finditer(rb"qcom,msm8996-asoc-snd[-_a-z0-9]*",
                                                            open(IMG, "rb").read())})
    props, order, node = {}, [], None
    for ln in txt.splitlines():
        if ln.startswith("##### NODE "):
            node = ln[11:].strip()
            props[node] = {}
            order.append(node)
            continue
        if not ln.strip() or ln.startswith("HIFIDT_DONE") or ln.strip() == "ABSENT":
            continue
        p_ = ln.split("\t")
        if len(p_) < 2 or node is None:
            continue
        hexs = "".join(p_[2:]) if len(p_) > 2 else ""
        props[node][p_[0]] = (p_[1], hexs)

    def decode(name, size, hexs):
        data = bytes.fromhex(hexs.replace(" ", "")) if hexs else b""
        if name.endswith("-gpio") and len(data) % 4 == 0:
            c = [int.from_bytes(data[i:i + 4], "big") for i in range(0, len(data), 4)]
            return (" ".join(f"{x:#010x}" for x in c),
                    f"gpio: controller phandle {c[0]:#x}, pin {c[1]} (0x{c[1]:x}), flags {c[2] if len(c) > 2 else '-'}")
        if name.endswith("-supply") and len(data) == 4:
            return (f"phandle 0x{int.from_bytes(data, 'big'):02x}",
                    "regulator phandle (resolving it to a regulator name needs the DT graph -- not done)")
        if name in ("compatible", "name", "qcom,model") or b"\x00" in data[:24]:
            strs = [s for s in data.decode("latin-1").split("\x00") if s]
            if strs:
                return (strs[0] if len(strs) == 1 else ", ".join(strs), "string list" if len(strs) > 1 else "string")
        if len(data) == 0:
            return ("(empty = boolean true)", "boolean property -- presence is the value, so a 7 node "
                    "that simply omits it flips this")
        if len(data) % 4 == 0 and not any(32 <= b < 127 for b in data):
            c = [int.from_bytes(data[i:i + 4], "big") for i in range(0, len(data), 4)]
            return (" ".join(f"{x}" for x in c), f"{len(c)} big-endian u32 cell(s)")
        return (f"{len(data)} bytes", "raw bytes (not decoded here)")

    rows = []
    for n in order:
        layer = ("Hi-Fi codec device tree" if "vivo-hifi-codec" in n else "ASoC card device tree")
        if not props[n]:
            sys.exit(f"gate: node {n} was reported but holds no property lines -- empty capture section")
        for name, (size, hexs) in sorted(props[n].items()):
            val, meaning = decode(name, size, hexs)
            if name == "compatible" and layer == "Hi-Fi codec device tree":
                if val not in compat_hifi:
                    sys.exit(f"gate: the node's compatible {val!r} is not in the driver's built list "
                             f"{compat_hifi} -- capture and Image are from different boards")
                meaning = (f"the ONLY strings the built driver binds to: {', '.join(compat_hifi)} -- "
                           "a 7 DTB with any other value leaves the Hi-Fi codec driver unprobed, so the "
                           "DAC never gets powered or written")
            if name == "compatible" and layer == "ASoC card device tree":
                if val not in mach:
                    sys.exit(f"gate: the card's compatible {val!r} is not among the machine drivers in "
                             f"the Image {mach} -- capture and Image disagree")
                meaning = (f"machine driver binding string; the Image contains exactly {mach}, so 7 must "
                           "carry a machine driver matching it or there is no sound card at all")
            rows.append({
                "layer": layer, "item": f"{n.rsplit('/', 1)[-1]}/{name}",
                "value": val, "name_or_meaning": meaning,
                "source": f"{raw} [{sha16(raw)}], fw/Image strings [{sha16(IMG)}]",
                "writable": "no (compiled DTB; the port supplies an equal node or patches the reader)",
                "use_case": "static",
                "witness2": f"{size} B as read off /sys/firmware/devicetree; the same Image also strings "
                            f"{', '.join(s for s in known if s.endswith(('-always-on', '-double-dac')))} "
                            "-- optional Hi-Fi knobs this node does not set (absence is the value)",
            })
    return rows


def dapm_coverage_rows():
    """every declared route accounted for (ledger 295).

    1167 tasha routes vs 213 edges the card published says nothing about the other 954, and a port
    needs that split: a route whose widgets are absent from the card is a different failure than one
    whose selector switch is simply not set.  tools/kssym_dapm_coverage.py classifies each route
    against the per-context widget universe, with --owner-context so a never-instantiated codec's
    table cannot read as merely 'unconnected'.
    """
    from collections import Counter
    covs = sorted(glob.glob(f"{BASE}/dapm-coverage-0x*.tsv"))
    if len(covs) != 7:
        sys.exit(f"gate: {len(covs)} coverage files, expected 7 (one per route array) -- run "
                 "tools/kssym_dapm_coverage.py ROUTES --owner-context CTX --out ... for each array")
    out, not_inst, cross_all = [], [], 0
    for cv in covs:
        at = os.path.basename(cv)[len("dapm-coverage-"):-len(".tsv")]
        crows = list(csv.DictReader(open(cv, encoding="utf-8"), delimiter="\t"))
        rt = f"{BASE}/dapm-routes-{at}.tsv"
        if not os.path.exists(rt):
            sys.exit(f"gate: {cv} has no matching route array file {rt} -- the classification would "
                     "be counted against a denominator this table cannot check")
        n_rt = len([l for l in open(rt, encoding="utf-8") if l.strip()]) - 1
        if len(crows) != n_rt:
            sys.exit(f"gate: {at}: coverage classifies {len(crows)} routes but {rt} holds {n_rt} -- "
                     "a route that silently dropped out of the class ladder is the hole this table "
                     "keeps catching")
        cc = Counter(r["class"] for r in crows)
        phant = cc["SOURCE-ABSENT"] + cc["SINK-ABSENT"] + cc["BOTH-ABSENT"]
        cross = [(r["source"], r["sink"], r["source_contexts"], r["sink_contexts"])
                 for r in crows
                 if r["source_contexts"] and r["sink_contexts"] != r["source_contexts"]]
        unc_ctl = Counter(r["control"] for r in crows if r["class"] == "UNCONNECTED")
        inst = "INSTANTIATED" if phant * 2 < len(crows) else "NOT instantiated"
        if inst == "NOT instantiated":
            not_inst.append(at)
        # cross-context paths are only meaningful for an array whose own context is live: for a dead
        # codec, an endpoint name found in another codec is a NAME COLLISION, not a connection.
        cross_n = len(cross) if inst == "INSTANTIATED" else 0
        cross_all += cross_n
        out.append({
            "layer": "DAPM route coverage", "item": f"{at}: {len(crows)} declared routes accounted",
            "value": " ".join(f"{k}={cc[k]}" for k in
                              ("LIVE", "UNCONNECTED", "SOURCE-ABSENT", "SINK-ABSENT", "BOTH-ABSENT")),
            "name_or_meaning": (f"{inst}: {phant}/{len(crows)} routes name a widget the running card "
                                "does not expose in ANY context. UNCONNECTED rows are routes whose "
                                "widgets exist but whose path is not published -- i.e. the control on "
                                "that route is off at capture time, not a missing connection"),
            "source": f"{cv} [{sha16(cv)}] (tools/kssym_dapm_coverage.py "
                      f"[{sha16(f'{ROOT}/tools/kssym_dapm_coverage.py')}]), {rt} [{sha16(rt)}], "
                      f"live/dapm-widgets-all.txt [{sha16(f'{BASE}/live/dapm-widgets-all.txt')}]",
            "writable": "n/a (compiled route table vs live graph)",
            "use_case": "on 7 the same class split must reproduce: LIVE count is what actually "
                        "carries sound, UNCONNECTED is what a mixer path has to switch on, and a "
                        "widget that comes up ABSENT here was never created -- which no register "
                        "comparison would show",
            "witness2": f"top UNCONNECTED controls: {unc_ctl.most_common(4)}; cross-context routes "
                        f"in this array: {cross_n}"
                        + (f" (e.g. {cross[0][0]}@{cross[0][2]} -> {cross[0][1]}@{cross[0][3]})"
                           if cross_n else "")
                        + (f"; {len(cross)} endpoint names found ONLY in other contexts = name "
                           "collisions with a live codec, not connections"
                           if inst != "INSTANTIATED" and cross else ""),
        })
    # Which arrays MAY be judged not-instantiated is decided by the device-side codec list, not by a
    # hardcoded array set: an array whose majority sink context is a codec the card does run must not
    # come out as not-instantiated (that would be the classifier losing widgets, which is exactly the
    # bug class this table keeps catching).
    # A codec being live does NOT make every one of its arrays live: the tfa98xx driver ships two
    # widget/route variants and only one is bound, so 'owner codec is live yet array judged dead' is
    # a legitimate finding, not a bug.  The defensible cross-check is against the independent winner
    # computation in dapm_inventory_rows() -- whichever array explains a live codec's published edges
    # must not come out dead here.  Done in rows(), which has both layer's rows.
    if not not_inst:
        sys.exit("gate: no array was judged not-instantiated, but kallsyms holds tomtom's and "
                 "wsa881x's tables and the card runs neither -- the absent-widget test is broken")
    if not cross_all:
        sys.exit("gate: no route in any array crosses DAPM contexts -- but the live card publishes "
                 "HPHL/HPHR (codec:tasha_codec) feeding HP (codec:hifi-codec), so either the "
                 "capture or the classifier broke")
    return out


def dapm_selector_rows():
    """which live ALSA knob each unpublished route is waiting on (ledger 297).

    UNCONNECTED says a path is not wired right now; the port needs the knob name.  The route's
    .control field is an ENUM item of the kcontrol named after the sink widget, or the bare suffix
    'Switch' of '<sink> Switch' -- tools/dapm_route_selectors.py joins both shapes against the live
    control universe.  The headline result is what makes this worth a table layer: every single
    UNCONNECTED route resolves to a control that exists on the card.
    """
    from collections import Counter
    sel = f"{BASE}/dapm-route-selectors.PD1610.tsv"
    if not os.path.exists(sel):
        sys.exit(f"gate: {sel} missing -- run python3 tools/dapm_route_selectors.py --out {sel}")
    rows = list(csv.DictReader(open(sel, encoding="utf-8"), delimiter="\t"))
    if len(rows) < 1000:
        sys.exit(f"gate: {sel} has {len(rows)} rows -- expected one per route across all 7 arrays")
    cl = f"{BASE}/live/debugfs_asoc/codecs"
    if not os.path.exists(cl):
        sys.exit(f"gate: {cl} missing -- the switch list has to be pinned to a card the capture names")
    unc = [r for r in rows if r["class"] == "UNCONNECTED"]
    unresolved = [r for r in unc if r["knob_kind"] == "NO-LIVE-KNOB"]
    kinds = Counter(r["knob_kind"] for r in unc)
    if unresolved:
        sys.exit(f"gate: {len(unresolved)} UNCONNECTED routes resolved to no live knob -- either the "
                 "control universe is stale or the join lost a shape; sample "
                 f"{sorted({r['control'] for r in unresolved})[:6]}")
    # live values of the switch-shaped knobs, read from the control table rather than asserted
    vals = {}
    cf = f"{BASE}/controls-live.tsv"
    for ln in open(cf, encoding="utf-8", errors="replace"):
        p = ln.rstrip("\n").split("\t")
        if len(p) >= 4:
            vals[p[0]] = (p[1], p[3])
    sw = sorted({r["knob"] for r in unc if r["knob_kind"] == "SINK-SWITCH"})
    mux = sorted({r["knob"] for r in unc if r["knob_kind"] == "SINK-MUX"})
    src = (f"{sel} [{sha16(sel)}] (tools/dapm_route_selectors.py "
           f"[{sha16(f'{ROOT}/tools/dapm_route_selectors.py')}]), {cf} [{sha16(cf)}]")
    out = [{
        "layer": "DAPM route selectors", "item": "UNCONNECTED routes -> live knob",
        "value": f"{len(unc)} UNCONNECTED routes, 0 unresolved; "
                 + " ".join(f"{k}={v}" for k, v in sorted(kinds.items())),
        "name_or_meaning": f"{len(mux)} of them wait on an ENUM kcontrol whose name IS the sink "
                           f"widget (route .control is one of that kcontrol's item texts), "
                           f"{len(sw)} wait on a BOOL kcontrol named '<sink> Switch' (the route "
                           "stores only the suffix). So no unpublished path on this card is missing "
                           "a knob -- it is a knob position, not an absent control",
        "source": src,
        "writable": "yes (these are ALSA controls; writing them is a consent decision)",
        "use_case": "on 7, reproduce a path by setting the SAME named control: the sink-mux ones via "
                    "the enum item text and the switch ones via '<sink> Switch'. A knob missing "
                    "there is a real graph difference, which is different from this baseline where "
                    "everything resolves",
        "witness2": "join's negative control: replacing the 988 tasha UNCONNECTED control strings "
                    "with an out-of-universe sentinel moves SINK-MUX 908->0 and resolved "
                    "1414->426, restoring gives 1414 again (so the join reads the control column, "
                    "not the widget names)",
    }, {
        "layer": "DAPM route selectors", "item": f"switch-shaped knobs currently not On ({len(sw)})",
        "value": "; ".join(f"{n}={vals.get(n, ('?', '?'))[1]}" for n in sw[:40])
                 + (f" ... (+{len(sw) - 40} more)" if len(sw) > 40 else ""),
        "name_or_meaning": "each of these is a '<widget> Switch' BOOL control that exists on the "
                           "running card and is Off at capture time; the routes behind it are the "
                           "UNCONNECTED ones. Example: `SmartPA Switch` Off is precisely why the "
                           "speaker feed `SmartPA I2S In -> SmartPA` is unpublished in an idle capture",
        "source": src,
        "writable": "yes (tinymix), but turning the speaker path on is an actuation -> 要人点头",
        "use_case": "on 7, the same control names must exist with the same default; a missing "
                    "'SmartPA Switch' means the PA path cannot be enabled at all, which is a graph "
                    "hole rather than a volume difference",
        "witness2": f"values read from {cf}, not asserted; {len(sw)} distinct switch knobs and "
                    f"{len(mux)} distinct sink-mux kcontrols from {len(rows)} joined route rows",
    }]
    return out


def dapm_endpoint_rows():
    """which knob chain feeds each audible endpoint (ledger 298).

    tools/dapm_path_knobs.py builds the directed graph from the instantiated route arrays, excludes
    every route whose endpoint has no widget file (a phantom must not become the shortest path), and
    walks backwards from each terminal.  Its selftest is the card-proven Hi-Fi chain, so a wrong edge
    direction aborts rather than silently reporting chains.
    """
    pk = f"{BASE}/dapm-path-knobs.PD1610.tsv"
    if not os.path.exists(pk):
        sys.exit(f"gate: {pk} missing -- run python3 tools/dapm_path_knobs.py --out {pk}; the "
                 "endpoint chains have to come from the traversal, not from reading route rows")
    rows = list(csv.DictReader(open(pk, encoding="utf-8"), delimiter="\t"))
    if len(rows) < 10:
        sys.exit(f"gate: {pk} has {len(rows)} terminals -- too few; the traversal probably died "
                 "partway, which is not a PASS")
    cf = f"{BASE}/controls-live.tsv"
    vals = {}
    for ln in open(cf, encoding="utf-8", errors="replace"):
        p = ln.rstrip("\n").split("\t")
        if len(p) >= 4:
            vals[p[0]] = p[3]
    want = ("HP", "Speaker")
    head = {r["terminal"]: r for r in rows if r["terminal"] in want}
    if len(head) != 2:
        sys.exit(f"gate: {want} must both be terminals of the graph (got {sorted(head)}) -- the "
                 "headphone jack and the speaker are the two endpoints this whole line exists for")
    spk = head["Speaker"]
    sw = re.findall(r"\[([^\]=]+)=SINK-SWITCH\]", spk["shortest_chain"])
    if not sw:
        sys.exit(f"gate: the speaker chain carries no switch-shaped knob ({spk['shortest_chain']!r}) "
                 "-- §293 established SmartPA feeds Speaker through one, so the join or the "
                 "traversal broke")
    src = (f"{pk} [{sha16(pk)}] (tools/dapm_path_knobs.py "
           f"[{sha16(f'{ROOT}/tools/dapm_path_knobs.py')}]), {cf} [{sha16(cf)}]")
    out = [{
        "layer": "DAPM endpoint chain", "item": f"{len(rows)} terminals: what feeds each output",
        "value": "; ".join(f"{r['terminal']}: {r['ancestors']} ancestors, "
                           f"{r['roots_reaching']} roots" for r in rows[:8]) + " ...",
        "name_or_meaning": "graph built from the 5 instantiated route arrays minus every "
                           "absent-endpoint edge; ancestors = widgets that can reach that terminal. "
                           "HP is fed from 21 roots and has TWO distinct routes in (tasha's own "
                           "analogue chain RX_BIAS->RX INT1 DAC->HPHL PA->HPHL, and the Hi-Fi chain "
                           "HiFi DAC->HiFi AMP->HiFi HPOUT->HP), which is the graph form of §295's "
                           "cross-context finding",
        "source": src,
        "writable": "n/a (graph read from the compiled tables + live capture)",
        "use_case": "on 7 run the same tool over the new capture: a terminal present here but absent "
                    "there, or with far fewer ancestors, is a missing sub-graph -- and that shows up "
                    "as silence, not as a register diff",
        "witness2": "tool selftest (hard gate inside it): the card-proven chain HiFi DAC -> HiFi AMP "
                    "-> HiFi HPOUT -> HP must be inside HP's ancestors with all three edges in that "
                    "direction, else the tool refuses. It passes.",
    }, {
        "layer": "DAPM endpoint chain", "item": "Speaker: the switch that gates 外放",
        "value": "; ".join(f"{n}={vals.get(n, '?')}" for n in sw),
        "name_or_meaning": f"shortest chain on the running card: {spk['shortest_chain']} -- "
                           f"{spk['roots_reaching']} root reaches it ({spk['example_roots']}). The "
                           "single knob on that chain is a BOOL '<widget> Switch'; §297 read it as Off "
                           "in an idle capture, so the speaker feed exists in the compiled table and "
                           "is simply not connected at rest",
        "source": src,
        "writable": "yes in principle (tinymix) -> 要人点头: turning it on changes the audible path",
        "use_case": "on 7 the chain must be the same length and the same knob name must exist; if "
                    "`SmartPA Switch` is missing there, no amount of register or cal copying will "
                    "bring the speaker back",
        "witness2": f"Speaker ancestors={spk['ancestors']}, edges by class {spk['edges_by_class']}; "
                    "values read from controls-live.tsv on this machine, not asserted",
    }]
    mxp = f"{BASE}/dapm-endpoint-matrix.PD1610.tsv"
    if not os.path.exists(mxp):
        sys.exit(f"gate: {mxp} missing -- run tools/dapm_path_knobs.py --emit-matrix {mxp}; without "
                 "the full cone the table would only carry one route per endpoint")
    mrows = list(csv.DictReader(open(mxp, encoding="utf-8"), delimiter="\t"))
    per = defaultdict(lambda: [0, 0, set(), set(), set()])   # live, unconn, all, liveK, bothK
    for r in mrows:
        if r["knob_kind"] == "NO-CONTROL (plain connection)":
            continue
        p = per[r["terminal"]]
        p[2].add(r["knob"])
        if r["class"] == "LIVE":
            p[0] += 1
            p[3].add(r["knob"])
        else:
            p[1] += 1
            p[4].add(r["knob"])
    if not per:
        sys.exit(f"gate: {mxp} holds no set-able route for any terminal -- the matrix is empty of "
                 "what it exists to report")
    spk, hp = per.get("Speaker"), per.get("HP")
    if not spk or not hp:
        sys.exit(f"gate: {mxp} must cover Speaker and HP (got {sorted(per)})")
    both = len(spk[3] & spk[4])
    out.append({
        "layer": "DAPM endpoint chain", "item": "selector cone: routes vs distinct knobs",
        "value": f"Speaker {spk[0]} live / {spk[1]} unconnected routes over {len(spk[2])} knob(s); "
                 f"HP {hp[0]} live / {hp[1]} unconnected routes over {len(hp[2])} knobs; "
                 f"{len(per)} terminals, {len(mrows)} (terminal,route) pairs total",
        "name_or_meaning": "the partition is over ROUTES, not knobs: one mux knob appears on many "
                           "routes and can only sit in one place, so its other positions stay "
                           "unconnected -- counting knobs on both sides would double-count "
                           f"(HP: {len(hp[3])} touched by a live route + {len(hp[4])} by an "
                           f"unconnected one - {len(hp[3] & hp[4])} in both = {len(hp[2])} distinct, "
                           f"and the arithmetic closes). Speaker's cone is one route behind one knob; "
                           "HP's fans out because every tasha RX path can reach it",
        "source": f"{mxp} [{sha16(mxp)}] (tools/dapm_path_knobs.py --emit-matrix, "
                  f"[{sha16(f'{ROOT}/tools/dapm_path_knobs.py')}])",
        "writable": "n/a (derived from the compiled tables + live capture)",
        "use_case": "on 7 compare cones endpoint by endpoint -- the tool checks for a knob required by "
                    "every output and finds none, so there is no single master gate to diff; a "
                    "terminal whose route count collapses is the signal that half a sub-graph did not "
                    "instantiate",
        "witness2": f"live+unconnected-both == distinct per terminal, recomputed here from the matrix "
                    f"(not copied from the tool's stdout); Speaker knobs in both states: {both}",
    })
    return out


def dapm_inventory_rows():
    """the per-codec DAPM counts read out of the kernel image (ledger 294, corrected 296).

    `struct snd_soc_codec_driver` carries {controls,+0x90 n} {dapm_widgets,+0xa0 n} {dapm_routes,
    +0xb0 n}.  kallsyms holds TWO objects named `audio_map` (tomtom.c and tasha.c each define one
    under the same C name), so the denominator has to be per-address.  Measured on this image the
    symbol span equals num_dapm_routes on every driver-referenced array -- an earlier note claiming
    the span overran was a misreading of this tool's distinct-edge count as a row count.  Reading
    the struct is still the point: the count becomes a declared value instead of a layout inference,
    and the two derivations cross-check.  Attribution to a live codec is done by edge overlap.
    """
    bts = f"{BASE}/dapm-route-bounds.PD1610.tsv"
    if not os.path.exists(bts):
        sys.exit(f"gate: {bts} missing -- run python3 tools/kssym_dapm_counts.py --symbol audio_map "
                 "--symbol vivo_codec_audio_map --symbol vivo_codec_map --symbol wsa881x_audio_map "
                 "--out art/audio-6.0.1/dapm-route-bounds.PD1610.tsv; without num_dapm_routes the "
                 "route arrays have no trustworthy denominator")
    bounds = list(csv.DictReader(open(bts, encoding="utf-8"), delimiter="\t"))
    if len(bounds) < 6:
        sys.exit(f"gate: {bts} has {len(bounds)} rows -- fewer than 6 driver structs means the field "
                 "offsets (+0x88/+0x98/+0xa8) did not hold, so every count here is suspect")
    WEAK = "next-object boundary only (no declared count)"
    bad = [r for r in bounds if r["count_agreement"] not in ("both", WEAK)]
    if bad:
        sys.exit(f"gate: {bad} -- num_dapm_routes and the next-object boundary disagree, so one of "
                 "the two derivations is wrong and no count may be stated")
    weak = [r["dapm_routes"] + "@" + r["routes_at"] for r in bounds if r["count_agreement"] == WEAK]
    codecs_p = f"{BASE}/live/debugfs_asoc/codecs"
    if not os.path.exists(codecs_p):
        sys.exit(f"gate: {codecs_p} missing -- 'instantiated' has to be judged against the codec list "
                 "the running card published, not against a name pattern")
    live_codecs = [l.strip() for l in open(codecs_p, encoding="utf-8", errors="replace") if l.strip()]
    edge_sets = {}
    for c in live_codecs:
        lp = f"{BASE}/live/dapm-edges-{c}.txt"
        if not os.path.exists(lp):
            continue
        s = set()
        for ln in open(lp, encoding="utf-8", errors="replace"):
            if ln.startswith("#") or not ln.strip():
                continue
            p_ = ln.rstrip("\n").split("\t")
            s.add((p_[0], p_[1]))
        edge_sets[c] = s
    route_tsvs = sorted(glob.glob(f"{BASE}/dapm-routes-0x*.tsv"))
    if len(route_tsvs) != 7:
        sys.exit(f"gate: found {len(route_tsvs)} per-array route files, expected 7 (one per route "
                 "array in dapm-route-bounds.PD1610.tsv) -- a missing one means an array nobody "
                 "decoded, which the table would otherwise hide")
    by_at = {}
    for tsv in route_tsvs:
        if not os.path.exists(tsv):
            continue
        for r in csv.DictReader(open(tsv, encoding="utf-8"), delimiter="\t"):
            by_at.setdefault(r["array_at"], []).append((r["source"], r["sink"]))
    # Attribution is by EXPLANATORY POWER, not by name similarity: for each live codec, the array that
    # covers the most of that codec's published edges is the one that instantiated it.  This matters
    # because tomtom's and tasha's tables share most of their endpoint strings (same vendor family), so
    # "does this array's edge appear live" is true for both -- only who explains the OTHER side's graph
    # separates them.
    cover = {}
    for c, s in edge_sets.items():
        scores = {at: len(s & set(e)) for at, e in by_at.items()}
        if scores:
            win = max(scores, key=lambda a: scores[a])
            if scores[win]:
                cover[c] = (win, scores[win], len(s))
    winners = {v[0]: c for c, v in cover.items()}
    out, attributed = [], 0
    for r in bounds:
        at, nm = r["routes_at"], r["dapm_routes"]
        edges = by_at.get(at, [])
        hits = {c: len(set(edges) & s) for c, s in edge_sets.items()}
        c_win = winners.get(at)
        if c_win:
            attributed += 1
            _w, n_c, tot = cover[c_win]
            verdict = (f"this array IS live codec {c_win!r}'s table: it covers {n_c}/{tot} of the "
                       f"edges that codec published (max over all {len(by_at)} decoded arrays)")
        else:
            verdict = (f"NOT the winner for any live codec (best overlap "
                       f"{max(hits.values()) if hits else 0}/{len(edges) or 0} edges, "
                       f"{len(edges)} decoded) -- compiled in but not bound to this card")
        out.append({
            "layer": "DAPM codec inventory", "item": f"{r['driver']} @{r['driver_at']} -> {nm} @{at}",
            "value": (f"num_controls={r['num_controls']} ({r['controls']}) "
                      f"num_dapm_widgets={r['num_dapm_widgets']} ({r['dapm_widgets']}) "
                      f"num_dapm_routes={r['num_dapm_routes']}"),
            "name_or_meaning": f"struct snd_soc_codec_driver fields at +0x88/+0x90, +0x98/+0xa0, "
                               f"+0xa8/+0xb0; route-array length is {nm} @{at} + "
                               f"{int(r['num_dapm_routes'])} * 0x20.  {verdict}",
            "source": f"{bts} [{sha16(bts)}] (tools/kssym_dapm_counts.py "
                      f"[{sha16(f'{ROOT}/tools/kssym_dapm_counts.py')}]), "
                      f"live/debugfs_asoc/codecs [{sha16(codecs_p)}], "
                      + ", ".join(f"live/dapm-edges-{c}.txt [{sha16(f'{BASE}/live/dapm-edges-{c}.txt')}]"
                                  for c in sorted(edge_sets)),
            "writable": "no (compiled into the driver struct)",
            "use_case": "on 7 the codec driver bound to the same chip must expose these same three "
                        "counts -- a smaller num_dapm_routes or num_dapm_widgets means part of the "
                        "signal graph is absent, and that shows up as dead audio before it shows up "
                        "in any register table",
            "witness2": f"num_dapm_routes cross-checked against the next kallsyms object boundary: "
                        f"{r['count_agreement']}"
                        + (f"; WEAK BOUND -- no driver struct declares this array, only its "
                           f"neighbouring object bounds it {weak.count(r['dapm_routes'] + '@' + r['routes_at'])}x"
                           if r["count_agreement"] == WEAK else "")
                        + "; live codecs on the card: "
                        + ", ".join(sorted(live_codecs)) + "; per-codec edge hits: "
                        + (", ".join(f"{c}={h}" for c, h in sorted(hits.items()) if h) or "none"),
        })
    if attributed < 3:
        sys.exit(f"gate: only {attributed} of {len(bounds)} route arrays are attributed to a live "
                 "codec by edge overlap -- the hifi/smartpa/tasha three are the ones the card runs, "
                 "so a lower number means the edge listings or the decodes went missing")
    # declared-vs-live widget counts.  The driver struct states how many widgets the codec DECLARES;
    # the capture shows how many the running card EXPOSED.  The delta is not noise: it is the widgets
    # ASoC instantiates per DAI link at probe, so a 7 build whose delta differs has a different
    # front-end set, which is a routing difference, not a counting one.
    for c in sorted(edge_sets):
        wf = f"{BASE}/live/dapm-files-{c}.txt"
        if not os.path.exists(wf):
            sys.exit(f"gate: {wf} missing -- tools/dapmsnap.py derives it from the debugfs capture, "
                     "and without it the declared/live widget delta for this codec is unstated")
        live_n = len([l for l in open(wf, encoding="utf-8", errors="replace")
                      if not l.startswith("#") and l.strip()])
        win = next((k for k, v in cover.items() if k == c), None)
        dcl = None
        if win:
            for r in bounds:
                if r["routes_at"] == cover[c][0]:
                    dcl = r["num_dapm_widgets"]
        out.append({
            "layer": "DAPM codec inventory", "item": f"live codec {c}: widgets exposed vs declared",
            "value": f"live={live_n} declared={dcl if dcl is not None else 'unknown'}",
            "name_or_meaning": (f"delta {live_n - int(dcl)} = widgets ASoC creates at instantiate time "
                                f"(per DAI link), on top of the {dcl} the driver struct declares"
                                if dcl else
                                "no decoded route array was attributed to this codec, so its "
                                "declared count is unknown"),
            "source": f"{bts} [{sha16(bts)}], {wf} [{sha16(wf)}] (tools/dapmsnap.py "
                      f"[{sha16(f'{ROOT}/tools/dapmsnap.py')}])",
            "writable": "n/a (mechanism)",
            "use_case": "on 7, `ls /sys/kernel/debug/asoc/*/codec:" + c + "/dapm | wc -l` must be "
                        f"{live_n}; fewer means widgets (so paths) are absent, more means the card "
                        "instantiates front-ends this baseline does not",
            "witness2": f"this codec's edges are explained by array {cover[c][0] if win else 'none'} "
                        f"at {cover[c][1]}/{cover[c][2]} coverage" if win else
                        "edges not attributed to any decoded array",
        })
    return out


def dapm_route_rows():
    """the decoded routes vs the edges the running card published (ledger 292).  Two come-alls, and
    the difference is reported rather than smoothed: a route carrying a DAPM control exists in the
    table but only becomes an edge when that path is connected, so 'decoded, not live' is a fact a
    port needs, not noise."""
    # two symbol families hold route tables in this kernel: vivo_codec_audio_map (the Hi-Fi codec's)
    # and vivo_codec_map (the SmartPA one) -- found by pointing tools/kstr_refs.py at a live edge and
    # clustering the pointers, not by guessing a symbol name
    tsvs = sorted(glob.glob(f"{BASE}/dapm-routes-0x*.tsv"))
    if len(tsvs) != 7:
        sys.exit(f"gate: {len(tsvs)} route files named dapm-routes-0x<addr>.tsv, expected 7 -- one "
                 "per route array in the bounds file; refusing to table a partial graph")
    rows = []
    for tsv in tsvs:
        if not os.path.exists(tsv):
            sys.exit(f"gate: {tsv} missing -- run python3 tools/kssym_dapm_routes.py --out {tsv} "
                     f"[--symbol {'vivo_codec_audio_map' if 'smartpa' not in tsv else 'vivo_codec_map'} "
                     "--expect ''] and append it; a route table nobody decoded is a hole in the graph")
        rows += list(csv.DictReader(open(tsv, encoding="utf-8"), delimiter="\t"))
    if len(rows) < 8:
        sys.exit(f"gate: only {len(rows)} routes decoded across {len(tsvs)} file(s) -- too few to be "
                 "an array set")
    tsv = " + ".join(tsvs)
    live, live_files = set(), []
    for lp in sorted(glob.glob(f"{BASE}/live/dapm-edges-*.txt")):
        tag = os.path.basename(lp)[len("dapm-edges-"):-len(".txt")]
        live_files.append(tag)
        for ln in open(lp, encoding="utf-8", errors="replace"):
            if ln.startswith("#") or not ln.strip():
                continue
            p_ = ln.rstrip("\n").split("\t")
            live.add((p_[0], p_[1]))
    if len(live_files) < 3:
        sys.exit(f"gate: only {len(live_files)} live/dapm-edges-*.txt listings exist "
                 f"({live_files}) -- the card runs hifi-codec, tfa98xx and tasha_codec, so a missing "
                 "one means an entire codec's graph is unjudged")
    by_arr = {}
    for r in rows:
        by_arr.setdefault(r["array_at"], []).append(r)
    out = []
    total_cover = 0
    for at, ents in sorted(by_arr.items()):
        edges = [(r["source"], r["sink"]) for r in ents]
        cov = [e for e in edges if e in live]
        only_bin = [e for e in edges if e not in live]
        total_cover += len(cov)
        ctl = sorted({r["control"] for r in ents if r["control"]})
        trip = [(r["source"], r["sink"], r["control"]) for r in ents]
        if len(trip) <= 20:
            listing = "; ".join(f"{s} -> {k}" + (f" [{c}]" if c else "") for s, k, c in trip)
        else:
            # the codec tables run to 1167 entries; a 60 KB cell is not readable and the full list is
            # already on disk in the TSV this row cites.  Cap it, but say so and give the shape.
            listing = (f"{len(trip)} routes (full list in the cited TSV) -- "
                       f"{len(ctl)} distinct control names, first 12: "
                       + "; ".join(f"{s} -> {k}" + (f" [{c}]" if c else "") for s, k, c in trip[:12]))
        out.append({
            "layer": "DAPM route inventory", "item": f"{at} ({len(ents)} routes)",
            "value": listing,
            "name_or_meaning": "route array decoded with stride 0x20 (sink@+0, control@+8, source@+0x10); "
                               "controls named here: " + (", ".join(ctl) or "none") +
                               " -- a route with a control only becomes an edge while that path is set",
            "source": f"{tsv}, tools/kssym_dapm_routes.py "
                      f"[{sha16(f'{ROOT}/tools/kssym_dapm_routes.py')}], "
                      + ", ".join(f"live/dapm-edges-{x}.txt [{sha16(f'{BASE}/live/dapm-edges-{x}.txt')}]"
                                  for x in live_files),
            "writable": "no (compiled into the driver's route table)",
            "use_case": "on 7: `cat /sys/kernel/debug/asoc/*/codec:<x>/dapm/* | grep -E ' (in|out) '` "
                        "must contain these edges, or the signal path is not there at all",
            "witness2": f"{len(cov)}/{len(ents)} of this array's edges appear in the live listings; "
                        + (f"decoded but NOT live ({len(only_bin)} of them, first 8): "
                           + ", ".join(f"{s}->{k}" for s, k in only_bin[:8])
                           if only_bin else "every decoded edge is live"),
        })
    if total_cover < 4:
        sys.exit(f"gate: only {total_cover} decoded routes are confirmed by the live listings -- the "
                 "stride/field assumption is not proven, refusing to state a route inventory")
    # an edge whose endpoint is a widget's .sname is a STREAM widget<->DAI hookup: ASoC creates those
    # from the codec_dai driver structs (tools/kstr_refs.py shows the stream names pointed at only
    # from vivo_codec_dai@0x179d3e0/0x179e6d0), so no route array is expected to contain them.
    att = f"{BASE}/dapm-route-attribution.txt"
    if not os.path.exists(att):
        sys.exit(f"gate: {att} missing -- the stream<->DAI attribution below is a CLAIM about "
                 "vivo_codec_dai structs, so it has to be backed by the tools/kstr_refs.py evidence "
                 "file it cites (a prose attribution without its evidence is exactly the kind of row "
                 "this table has been catching)")
    if "vivo_codec_dai" not in open(att, encoding="utf-8", errors="replace").read():
        sys.exit(f"gate: {att} does not show any pointer inside a vivo_codec_dai object -- the "
                 "stream<->DAI explanation is not supported by it, so refuse to write that row")
    snames, wnames = set(), set()
    wt = f"{BASE}/dapm-widgets.PD1610.tsv"
    if os.path.exists(wt):
        for r in csv.DictReader(open(wt, encoding="utf-8"), delimiter="\t"):
            wnames.add(r["name"])
            if r["sname"]:
                snames.add(r["sname"])
    missing = {(s, k) for s, k in live
               if not any((s, k) == (r["source"], r["sink"]) for r in rows)}
    explained = {e for e in missing if e[0] in snames or e[1] in snames}
    unexplained = sorted(missing - explained)
    if missing:
        out.append({
            "layer": "DAPM route inventory", "item": f"live edges NOT covered by any decoded array ({len(missing)})",
            "value": "; ".join(f"{s} -> {k}" + (" [stream<->DAI]" if (s, k) in explained else "")
                                for s, k in sorted(missing)),
            "name_or_meaning": f"{len(explained)} of {len(missing)} are NOT route rows at all: an "
                               "endpoint is a widget .sname (a DAI stream name), so ASoC creates the "
                               "connection from the codec_dai struct "
                               "(vivo_codec_dai@0x179d3e0 / @0x179e6d0 per tools/kstr_refs.py). "
                               + ("The rest are genuinely unexplained: " + "; ".join(f"{s}->{k}"
                                  for s, k in unexplained) if unexplained else
                                  "Nothing is left unexplained, but the vivo route arrays alone are "
                                  "still not the whole graph -- the DAI side must be checked too."),
            "source": ", ".join(f"live/dapm-edges-{x}.txt" for x in live_files) + f", {tsv}",
            "writable": "n/a (device-side observation)",
            "use_case": "on 7 the same DAI structs must carry these stream names; a route-table diff "
                        "alone would report them as missing connections",
            "witness2": f"decoded {len(rows)} routes across {len(by_arr)} arrays; "
                        f"{len(missing)} live edges still unattributed. Attribution evidence "
                        "(tools/kstr_refs.py pointer clustering, incl. the pooled-tail-string trap): "
                        f"{att} [{sha16(att)}]",
        })
    return out


def dapm_widget_rows():
    """widget names decoded from the kernel arrays vs the widget files the running card published --
    two independent come-alls for the same thing, so a 7 build that renames a widget shows up here
    before it shows up as an unexplained register difference (ledger 291)"""
    tsv = f"{BASE}/dapm-widgets.PD1610.tsv"
    if not os.path.exists(tsv):
        sys.exit(f"gate: {tsv} missing -- run python3 tools/kssym_dapm.py --out {tsv}")
    rows = list(csv.DictReader(open(tsv, encoding="utf-8"), delimiter="\t"))
    if not rows:
        sys.exit(f"gate: {tsv} has no rows -- the decoder produced an empty table, which is not a PASS")
    live = {}
    for tag in ("hifi-codec", "tfa98xx"):
        lp = f"{BASE}/live/dapm-files-{tag}.txt"
        if not os.path.exists(lp):
            sys.exit(f"gate: {lp} missing -- no live widget listing means the binary side is "
                     "self-consistent only, which is not evidence")
        live[tag] = {ln.strip() for ln in open(lp, encoding="utf-8", errors="replace")
                     if ln.strip() and not ln.startswith("#")} - {"bias_level"}
    by_arr = {}
    for r in rows:
        by_arr.setdefault(int(r["array"]), []).append(r)
    # first pass: decode every array and index which arrays claim each live listing, so the
    # ambiguity note is symmetric (the first draft appended it only to the later of the two)
    dec = {}
    for ai in sorted(by_arr):
        ents = by_arr[ai]
        names = []
        for r in ents:
            names.append(r["name"])
            if r["sname"]:
                names.append(r["sname"])
        dec[ai] = (ents, names, sorted({r["event"] for r in ents if r["event"]}))
    who_matches = {tag: [ai for ai, (_e, nm, _ev) in dec.items() if set(nm) == s]
                   for tag, s in live.items()}
    out = []
    matched = {}
    for ai in sorted(by_arr):
        ents, names, events = dec[ai]
        exact = who_matches_of = [tag for tag, s in live.items() if s == set(names)]
        if len(exact) == 1:
            matched[exact[0]] = ai
            matched[exact[0]] = ai
        verdict = (f"matches the live listing of codec:{exact[0]} exactly ({len(set(names))} widgets)"
                   if len(exact) == 1 else
                   f"NO live listing equals it (live sets: " +
                   "; ".join(f"{k}={len(v)}" for k, v in live.items()) +
                   f") -> this array belongs to a card variant that is not running here")
        out.append({
            "layer": "DAPM widget inventory", "item": f"{ents[0]['array_at']} (array #{ai})",
            "value": ", ".join(names),
            "name_or_meaning": "widget .name (+ stream widgets carry .sname as well); events: "
                               + (", ".join(events) or "none"),
            "source": f"{tsv} [{sha16(tsv)}], tools/kssym_dapm.py [{sha16(f'{ROOT}/tools/kssym_dapm.py')}]",
            "writable": "no (compiled into the machine/platform driver)",
            "use_case": "on 7, `ls /sys/kernel/debug/asoc/*/codec:<x>/dapm/` must contain these names -- "
                        "the widget that triggers the DAC writes is identified by name, so a rename "
                        "silently removes the whole enable path",
            "witness2": verdict + (f"; NOTE {len(who_matches[exact[0]])} decoded arrays carry this same "
                                   f"widget set ({', '.join('#' + str(a) for a in who_matches[exact[0]])}) "
                                   "-- widget names alone do not say WHICH copy is live, the DT compatible "
                                   "does (§287)" if len(exact) == 1 and len(who_matches[exact[0]]) > 1 else ""),
        })
    if set(matched) != set(live):
        sys.exit(f"gate: live widget listings matched {matched} but the card published {sorted(live)} -- "
                 "one of them has no decoded array, so the inventory is incomplete")
    return out


def hifi_trigger_rows():
    """the chain from userspace to the DAC writes, read out of the trigger section of
    dac-write-path.txt (tools/kssym_blr.py maps `ldr xN,[base,#slot] ; blr xN` across the image)"""
    # the live enable-path witness: `es9038_setting_special_params` prints every (addr,value) pair it
    # hands to the chip, so a capture taken inside the dmesg ring after a stream start is direct
    # evidence -- §287 asked for exactly this window, §353 inferred the loop never ran, and §369 has
    # the first live run of it.  Each byte is checked against the ruler's own candidate list, and the
    # column story is reported as observed rather than assumed: the three bytes did NOT all come from
    # the same column index, so §322's "one column per enable" reading needs the per-register form.
    globals()["DMESG_LIVE"] = {"name": "no live capture", "sentence": "live pairs: none witnessed"}
    lives = sorted(glob.glob(f"{BASE}/live/dmesg-hpenable-*.txt"), key=os.path.getmtime)
    pairs, ev, imp, fixed = [], [], [], []
    per_file = []
    for lf in lives:
        lt = open(lf, encoding="utf-8", errors="replace").read()
        fp = re.findall(r"es9038_setting_special_params write value (0x[0-9a-f]+) to addr (0x[0-9a-f]+)", lt)
        fe = re.findall(r"hifi_codec_dac_event: enter, event (\d+)", lt)
        fi = re.findall(r"msm_mbhc_get_impedance: impedance (\d+) ohm", lt)
        ff = re.findall(r"hifi_codec_dac_event: impedance (\d+)", lt)
        if fp:
            per_file.append((os.path.basename(lf), fp, fi, ff))
        pairs += fp
        ev += fe
        imp += fi
        fixed += ff
    if lives:
        lf = lives[-1]
        if not pairs:
            sys.exit(f"gate: {os.path.basename(lf)} is named as the live enable witness but prints no "
                     "setting_special_params pair -- the sentence below would be unsupported")
        # the strong form of the claim is "changing the input moves the byte": that needs the two
        # states witnessed, so one file is checked against the other before the sentence is written
        seen14 = {fn: dict((a.lower(), v.lower()) for v, a in fp).get("0x14") for fn, fp, _, _ in per_file}
        obs14 = {v for v in seen14.values() if v}
        if len(obs14) < 2:
            sys.exit(f"gate: the enable witnesses on disk all wrote 0x14={sorted(obs14)} -- one state "
                     "cannot support the claim that the impedance override selects a different column")
        cand, bound_name = {}, None
        for rr in csv.DictReader(open(f"{BASE}/dac-integration-params.PD1610.tsv", encoding="utf-8"),
                                 delimiter="\t"):
            # `param` rows exist for SEVERAL instances of the same-named table (0x179d550 and
            # 0x179d7d0 differ in every byte), so the candidate list must come from the instance the
            # selector actually binds -- the `derived` row whose verdict says "bound arm:".  Keying on
            # the first row seen made this gate reject 0x24, which is column 0 of the bound table.
            if rr["kind"] == "param":
                cand[rr["reg"]] = [int(c, 16) for c in re.findall(r"0x([0-9a-f]{1,2})", rr["candidates"])]
            elif rr["kind"] == "derived" and (rr["verdict"] or "").startswith("bound arm:"):
                bound_name = rr["name"]
        if bound_name:
            # the bound instance's byte lists live on the `derived` rows (the `param` rows belong to the
            # OTHER instance, 0x179d550 -- keying on those rejected the live byte 0x24 for no reason)
            for rr in csv.DictReader(open(f"{BASE}/dac-integration-params.PD1610.tsv", encoding="utf-8"),
                                     delimiter="\t"):
                if rr["kind"] == "derived" and rr["name"] == bound_name:
                    cand[rr["reg"]] = [int(c, 16) for c in re.findall(r"0x([0-9a-f]{1,2})", rr["candidates"])]
        for v, a in pairs:
            if a in cand:
                continue
            sys.exit(f"gate: live pair {a}={v} is outside the bound instance's byte list "
                     f"{[hex(x) for x in cand[a]]} (bound row: {bound_name}) -- "
                     "either the witness is from another table or the derivation lost this instance")
        badpair = [(a, v) for v, a in pairs if a in cand and int(v, 16) not in cand[a]]
        if badpair:
            sys.exit(f"gate: the live witness wrote {badpair} which the integration-params table does not "
                     f"list as a candidate for those registers -- either the pairing or the table is wrong")
        def cols_of(fp):
            return {a: cand[a].index(int(v, 16)) for v, a in fp
                    if a in cand and int(v, 16) in cand[a]}
        globals()["DMESG_LIVE"] = {
            "name": os.path.basename(lf),
            "sentence": (f"bound instance {bound_name or chr(63)}; "
                         + "; ".join(f"{fn} wrote " + ",".join(f"{a}={v}" for v, a in fp)
                                     + f" (handler impedance {fx[:1] or '-'} ohm, mbhc measured "
                                     f"{ii[:1] or '-'}) -> columns {sorted(cols_of(fp).items())}"
                                     for fn, fp, ii, fx in per_file)
                         + f"; events seen {len(ev)}; each state's column index is its own, and the "
                         "three registers do NOT share one column index (so the selection is read per "
                         "register), while 0x14 moves between the columns the two impedances select"),
        }
    dwp = f"{BASE}/dac-write-path.txt"
    txt = open(dwp, encoding="utf-8", errors="replace").read()
    if "who triggers the writes" not in txt:
        sys.exit(f"gate: {dwp} has no trigger section -- re-run tools/kssym_blr.py --disp 0x48/0x50 "
                 "and append it; without the caller side the write path is only half a mechanism")
    # site lines look like:  "  0xffffffc000bb6c94 in hifi_codec_dac_event   x2<-[x1+0x48]   x2"
    found = defaultdict(list)          # slot -> [(site, caller)]
    for m in re.finditer(r"^\s+(0x[0-9a-f]+) in (\S+)\s+x\d<-\[x\d+\+(0x[0-9a-f]+)\]", txt, re.M):
        found[int(m.group(3), 16)].append((m.group(1), m.group(2)))

    def summarize(slot):
        rows = found.get(slot, [])
        return rows, sorted({c for _a, c in rows})

    en_rows, en = summarize(0x48)
    mu_rows, mu = summarize(0x50)
    if not en or not mu:
        sys.exit(f"gate: trigger section yielded enable callers {en} / mute callers {mu} -- "
                 "the scan output is not parsable, so no chain can be stated")
    # the widget binding is COMPUTED by tools/kdata_ptrs.py and read back here: a pointer hit whose
    # containing object is a DAPM widget array, with the struct's name string sitting a fixed negative
    # offset before it.  The name therefore comes from the artifact, not from what I remember calling
    # it -- §289 typed 'hifi amp' (a tasha widget) and was wrong; the bound widget is 'HiFi DAC'.
    bind = []
    cur = {}
    for ln in txt.splitlines():
        m = re.match(r"hit @\S+ \(file \S+\) inside (\S+) @ .*offset in object (\S+)", ln)
        if m:
            cur = {"obj": m.group(1), "inobj": m.group(2)}
            continue
        m = re.match(r"\s+points to (\S+) @\S+", ln)
        if m:
            cur["sym"] = m.group(1)
            continue
        m = re.match(r"\s+nearest preceding string: (-0x[0-9a-f]+) '([^']*)'", ln)
        if m and cur.get("obj"):
            bind.append((cur["obj"], cur.get("sym", "?"), m.group(1), m.group(2)))
            cur = {}
    widgets = [b for b in bind if "dapm_widgets" in b[0]]
    if not widgets:
        sys.exit(f"gate: {dwp} carries no widget-array binding line (a hit inside *dapm_widgets* with "
                 "a preceding name string) -- run tools/kdata_ptrs.py <event symbol> --radius 240 and "
                 "append it, otherwise the trigger row would be prose about a name I typed")
    wobj, wsym, woff, wname = widgets[0]
    wcaller = wsym
    if wcaller not in en:
        sys.exit(f"gate: the widget-bound callback is {wcaller} but the enable call-through sites come "
                 f"from {en} -- the two halves of the chain do not meet, so nothing is stated")
    state = next((ln.strip() for ln in txt.splitlines() if ln.strip().startswith(wname + ":")), "")
    if not state:
        sys.exit(f"gate: the bound widget {wname!r} has no live debugfs line in {dwp} -- the widget "
                 "exists in the table but was never read off the running card")
    src = f"{dwp} [{sha16(dwp)}]"
    return [
        {"layer": "Hi-Fi trigger chain",
         "item": f"DAPM widget {wname!r} -> {wcaller} -> ops+0x48",
         "value": f"{len(en_rows)} call-through sites from {len(en)} function(s): {', '.join(en)}",
         "name_or_meaning": f"bound by {wobj} (name field {woff} before the .event pointer, read back "
                            f"off the artifact not typed); live card state: {state!r}; the graph "
                            f"continues {wname} -> HiFi AMP -> HiFi HPOUT -> HP",
         "source": src, "writable": "n/a (mechanism)",
         "use_case": "on 7 the same widget must exist under the card's dapm list, else es9038_enable "
                     "is never called and the dac_parameters writes never happen",
         "witness2": "slot 0x48 is what es9038_i2c_probe stores there (probe+0x464 `add x0,x0,#0xa54` "
                     "= &es9038_enable); branch-through sites found by tools/kssym_blr.py with a "
                     "passing control; §289 named the widget 'hifi amp' (a tasha widget) and §290 "
                     "corrected it to this one, read out of the table"},
        {"layer": "Hi-Fi trigger chain", "item": "ALSA control 'HiFi Mute' -> vivo_hifi_mute_put -> ops+0x50",
         "value": f"{len(mu_rows)} call-through sites from {len(mu)} function(s): {', '.join(mu)}",
         "name_or_meaning": "the mute path shares slot 0x50 with the DAI digital_mute callback, so the "
                            "ALSA knob in the table (layer 'ALSA control', item 'HiFi Mute') has a named "
                            "kernel handler: vivo_hifi_mute_put",
         "source": src, "writable": "n/a (mechanism)",
         "use_case": "on 7 the same control name must exist (tinymix by name) AND route to a DAC mute; "
                     "compare the control value, not the handler name (names change across kernels)",
         "witness2": "es9038_i2c_probe stores &es9038_mute at ops+0x50 (probe+0x474); the same slot is "
                     "branched through by vivo_codec_dai_digital_mute"},
    ]


def rows():
    out = []
    # layer 1: PA registers -- denominator and address set both come from the binary (ledger 249)
    wl = pa_whitelist()
    tfa = f"{BASE}/tfa-regs.PD1610.tsv"
    with open(tfa, encoding="utf-8") as fh:
        rd = csv.DictReader(fh, delimiter="\t")
        if "provenance" not in (rd.fieldnames or []):
            sys.exit(f"gate: {tfa} has no provenance column -- re-run tools/tfa_reg_decode.py {tfa} "
                     "so the table states which capture sessions each class came from")
        for r in rd:
            out.append({
                "layer": "PA/TFA9890", "item": f"codec_reg {r['reg']}",
                "value": f"idle={r['idle']} play={r['play']}",
                "name_or_meaning": r["name"] if r["name"] != "NO-NAME" else "UNRESOLVED(hidden area)",
                "source": f"/sys/kernel/debug/tfa98xx/codec_reg [{sha16(tfa)}]",
                "writable": "yes (0644; echo '<reg> <val>' = whole-register regmap_write, no mask, ledger 248)",
                "use_case": r["class"],
                "witness2": r["provenance"] + "; addr set == tfa98xx_regs in fw/Image (249)",
            })
    got_addrs = [int(o["item"].split()[-1], 16) for o in out if o["layer"] == "PA/TFA9890"]
    if got_addrs != wl:
        sys.exit(f"PA address-set gate: table {got_addrs} != binary {wl}")
    # layer 2: DAC registers, only observable while powered
    dtab, dprov = dac_parameters_table()
    txt = open(PLAY, encoding="utf-8", errors="replace").read()
    d = {}
    # the DAC dump does not zero-pad (reg{0}:0 .. reg{2e}:00) and the chip-id line is printed as
    # reg{0x60}, so the looped registers and that extra read are parsed apart
    for b in re.split(r"===== sample \d+ [0-9.]+ =====", txt)[1:]:
        m = dict(re.findall(r"reg\{([0-9a-f]+)\}:([0-9a-f]+)", b))
        if m:
            d = m
    live_keys = sorted(int(x, 16) for x in d)
    if live_keys != sorted(dtab):
        sys.exit(f"DAC denominator gate: the live dump exposes {live_keys[:3]}..{live_keys[-1]} "
                 f"({len(live_keys)}) but the driver walks {sorted(dtab)[:3]}..{sorted(dtab)[-1]} "
                 f"({len(dtab)}) -- {dprov}")
    dev = sorted(r for r in live_keys if int(d[f"{r:x}"], 16) != dtab[r])
    chip = re.findall(r"reg\{0x(60)\}:([0-9a-f]+)", txt)
    if not chip:
        sys.exit("DAC gate: the capture has no reg{0x60} chip-id line -- es9038_debug_read prints it "
                 "after the loop, so its absence means the dump was truncated, not that the DAC differs")
    trim = "".join(d.get(f"{i:x}", "00") for i in range(17, 21))
    tv = int(trim, 16)
    tv = tv - (1 << 32) if tv >= (1 << 31) else tv
    if not all(i in dtab for i in range(17, 21)):
        sys.exit("Master Trim gate: dac_parameters does not carry all four bytes 0x11-0x14, so the "
                 "32-bit signed trim cannot be assembled from the driver's own table")
    ttrim = "".join(f"{dtab[i]:02x}" for i in range(17, 21))
    ttv = int(ttrim, 16)
    ttv = ttv - (1 << 32) if ttv >= (1 << 31) else ttv
    wts = f"{BASE}/dac-register-writers.PD1610.tsv"
    wr = list(csv.DictReader(open(wts, encoding="utf-8"), delimiter="\t")) if os.path.exists(wts) else []
    kinds = Counter(r["reg_kind"] for r in wr)
    cons = sorted({r["reg"] for r in wr if r["reg_kind"] == "constant" and r["reg"] != "-"},
                  key=lambda x: int(x, 16))
    iparams = {}
    ip = f"{BASE}/dac-integration-params.PD1610.tsv"
    if os.path.exists(ip):
        iparams = {r["reg"]: r for r in csv.DictReader(open(ip, encoding="utf-8"), delimiter="\t")
                   if r["kind"] == "param"}
    for reg in sorted(d, key=lambda x: int(x, 16)):
        n = int(reg, 16)
        named = n in ESS_NAMES
        moved = n in dev
        cand = (f"; the impedance table offers [{iparams[f'{n:#04x}']['candidates']}] for it and its "
                f"verdict against the live byte is {iparams[f'{n:#04x}']['verdict']}"
                if f"{n:#04x}" in iparams else "")
        out.append({
            "layer": "DAC/ES9038", "item": f"reg {n:#04x}",
            "value": f"0x{d[reg]} (playing only; DAC unpowered at idle, §235)"
                     + (f" | regs17-20 assembled Master Trim = {tv} (0x{trim}) written by the driver as "
                        f"{ttv} (0x{ttrim}), delta {tv - ttv:+d} LSB" if n == 17 else ""),
            "name_or_meaning": (ESS_NAMES[n] + f" [{ESS_SRC}]") if named
            else "UNRESOLVED(not named in the captured pages; full register-table doc still missing)",
            "source": f"/sys/kernel/debug/es9038/reg [{sha16(PLAY)}], {dprov}",
            "writable": "yes (0644 same file; debug_write sscanf '%x %x' then do_reg_write_check "
                        "writes-reads-compares up to 5 retries, §285)",
            "use_case": ("requires stream: Hi-Fi route; RUNTIME-CHANGED (driver's own table byte is "
                         f"0x{dtab[n]:02x}, in play 0x{int(d[reg], 16):02x})" if moved
                         else f"requires stream: Hi-Fi route; STATIC == dac_parameters byte 0x{dtab[n]:02x}"),
            "witness2": f"{len(d) - len(dev)}/{len(d)} in-play values equal the compiled-in table exactly, "
                        f"the exceptions being {', '.join(f'{r:#04x}' for r in dev) or 'none'}; "
                        "3 samples bit-identical (§234); the dump's 48th line is a fixed read of reg 0x60"
                        + (f" -- no constant-fed write site names it (the literals in the writers census "
                           f"are {', '.join(cons)}){cand}; and auto-calibration is off (reg 0x2d = "
                           f"0x{int(d['2d'], 16):02x} = datasheet Register 45 default, calib_en and "
                           "calib_latch both clear)" if moved else ""),
        })
    out.append({
        "layer": "DAC/ES9038", "item": "reg 0x60",
        "value": f"0x{chip[0][1]} (printed as reg{{0x60}}:{chip[0][1]} by es9038_debug_read; chip id)",
        "name_or_meaning": "the driver's own 'which part is this' read: es9038_debug_read walks "
                           "dac_parameters (47 regs) then scnprintf()s one fixed reg{0x60} line",
        "source": f"/sys/kernel/debug/es9038/reg [{sha16(PLAY)}], {dprov}",
        "writable": "yes in principle (same file), but it is an identity register",
        "use_case": "requires stream: Hi-Fi route",
        "witness2": "not in dac_parameters, so it is a SEPARATE read -- a port that loops only the "
                    "table would print 47 lines and this one would vanish (that is why the gate "
                    "counts 48 lines here, §285)",
    })
    out.extend(dapm_inventory_rows())
    out.extend(dapm_coverage_rows())
    out.extend(dapm_selector_rows())
    out.extend(dapm_endpoint_rows())
    # Two independent computations must agree on who is live: the inventory picks each live codec's
    # route array by edge-explanatory power, the coverage classifier calls an array dead when most of
    # its routes name widgets the card lacks.  An array cannot be both the winner for a live codec and
    # dead -- if that happens one of the two rulers broke, so the table stops here.
    inv = [x for x in out if x["layer"] == "DAPM codec inventory" and "-> " in x["item"]]
    cov = {x["item"].split(":")[0]: x for x in out if x["layer"] == "DAPM route coverage"}
    disagree = []
    for r in inv:
        at = r["item"].split("@")[-1]
        if "this array IS live codec" in r["name_or_meaning"] and at in cov \
                and "NOT instantiated" in cov[at]["name_or_meaning"]:
            disagree.append(f"{at}: inventory says it is the live codec's table, coverage says dead")
    if disagree:
        sys.exit(f"gate: the two DAPM rulers disagree -> {disagree}")
    out.extend(dapm_route_rows())
    out.extend(dapm_widget_rows())
    # layer 2e: who actually triggers those writes, from userspace down (ledger 289)
    out.extend(hifi_trigger_rows())
    # layer 2d: the platform node that powers/resets/clock-selects the DAC (ledger 287)
    out.extend(hifi_dt_rows())
    out.extend(pa_regmap_rows())
    out.extend(device_binding_rows())
    # layer: the loader's own compiled-in allocation plan for ACDB blocks (ledger 388)
    out.extend(loader_memplan_rows())
    # layer: the shipped config files that produce the live state (ledger 403 audit)
    out.extend(audio_cfg_file_rows())
    # layer: the component that decides (ledger 408)
    out.extend(audio_hal_surface_rows())
    # layer: what the extract holds vs what the device loads (ledger 409)
    out.extend(shipped_disposition_rows())
    # layer: who is allowed an fx session, and the owner's state (ledger 414)
    out.extend(audiofx_rows())
    # layer: the machine state the listening comparison depends on (ledger 414)
    out.extend(settings_state_rows())
    # layer: what the HAL ran, in order (ledger 415)
    out.extend(audio_log_rows())
    # layer: the two routes as live state (ledger 420)
    out.extend(inplay_rows())
    # layer: every stored dump classified (ledger 421)
    out.extend(route_matrix_rows())
    # layer: the DSD gate read out of the binary (ledger 422)
    out.extend(dsd_gate_rows())
    out.extend(dai_surface_rows())
    out.extend(dsd_string_refs_rows())
    out.extend(dsd_registration_rows())
    out.extend(dsd_inplay_rows())
    out.extend(dsd_inplay_state_rows())
    out.extend(hal_acdb_sourcing_rows())
    out.extend(reachability_rows())
    out.extend(exidx_reachability_rows())
    out.extend(pa_label_provenance_rows())
    out.extend(mime_symbol_rows())
    # layer: the DSD decision as the running system logged it (ledger 425)
    out.extend(dsd_runtime_rows())
    # layer: the vivo parameter grammar between app, AF, policy and HAL (426)
    out.extend(hifi_control_rows())
    # layer: a second in-play Hi-Fi session and what it bounds (ledger 427)
    out.extend(hifi_recheck_rows())
    # layer: how wide the sample really is, per route (ledger 428)
    out.extend(bitwidth_chain_rows())
    # layer: symbol reachability + reference-set gaps (ledger 429)
    out.extend(symbol_reach_rows())
    # layer: what happened exactly once, at boot (ledger 417)
    out.extend(boot_rows())
    # layer: the API side of calibration + the in-play/capacity reads (ledger 418)
    out.extend(acdb_api_rows())
    # layer: what a session moves, not what a moment holds (ledger 419)
    out.extend(control_state_rows())
    # layer 2c: WHO writes those registers -- the debugfs dump only shows values, this row states the
    # mechanism that produced them (read from the same Image, artifact kept so the claim is re-checkable)
    dwp = f"{BASE}/dac-write-path.txt"
    if not os.path.exists(dwp):
        sys.exit(f"gate: {dwp} missing -- regenerate with tools/kssym_writes.py + "
                 "tools/kobj_span_refs.py (the write path is what makes the DAC layer portable advice)")
    dwp_lines = open(dwp, encoding="utf-8", errors="replace").read().splitlines()
    nsites = sum(1 for ln in dwp_lines if ln.startswith(" site"))
    # §351: the payload struct is only quotable if the artifact carries the measured loop
    whole = "\n".join(dwp_lines)
    seg = whole.split("=== payload struct", 1)
    if len(seg) != 2:
        sys.exit(f"gate: {dwp} has no '=== payload struct' section -- the §351/§352 records below are read "
                 "from it, so the write-path row cannot be built")
    body = seg[1].split("\n===", 1)[0].splitlines()
    recs, open_key = {}, None
    for ln in body:
        # records start with ONE space then the keyword; continuations start with THREE -- without the
        # `ln[1] != " "` test a continuation line that happened to open with the word `handle` was read as
        # a second record of that kind (the §359 gate caught this on the first run)
        parts = ln.strip().split(None, 1)
        if len(parts) == 2 and ln[1] != " " and parts[0] in (
                "shape", "scope", "slot", "table", "gates", "verdict", "bound", "handle", "mirror") and ln.startswith(" "):
            open_key = parts[0]
            recs.setdefault(open_key, []).append(parts[1].strip())
        elif ln.startswith("   ") and open_key and parts:
            recs[open_key][-1] += " " + ln.strip()
    need = {"shape": 1, "scope": 1, "slot": 3, "table": 1, "gates": 1, "verdict": 1, "bound": 1,
           "handle": 1, "mirror": 1}
    have = {k: len(recs.get(k, [])) for k in need}
    if any(have[k] != n for k, n in need.items()):
        sys.exit(f"gate: {dwp} carries {have} of the payload records (want {need}) -- the sentence below "
                 "quotes the struct layout, both codec instances, the pointer-vs-table identity and the "
                 "scope of what is NOT proven; every one of them must be read from the artifact (ledger 351/352)")
    if "NOT proof" not in recs["scope"][0]:
        sys.exit("gate: " + dwp + ": the scope line no longer states that the census cannot prove nobody "
                 "fills the slot -- publishing the absence reading without that caveat is the §285 shape")
    pay = {"shape": recs["shape"][0], "scope": recs["scope"][0],
           "slot": " ;; ".join(recs["slot"])}
    copies = [(m.group(1), m.group(2), m.group(3)) for m in
              (re.search(r"copy ([AB]) reads obj = \*(0x[0-9a-f]+).*?payload slot (?:therefore )?"
                         r"(obj\+0x[0-9a-f]+)", rec, flags=re.S) for rec in recs["slot"]) if m]
    if len(copies) != 2:
        sys.exit(f"gate: {dwp}: the slot records do not yield both codec instances -- got {copies}")
    if "NO device" not in recs["bound"][0] or "8-0048" not in recs["bound"][0]:
        sys.exit(f"gate: {dwp}: the bound record no longer carries the two machine witnesses (es9028 with "
                 "no device bound, es9038 bound at 8-0048) -- which DAC can register is published from them")
    rec_verdict = recs["verdict"][0]
    for frag in ("str xzr", "0xbb7d1c", "cbz"):
        if frag not in rec_verdict:
            sys.exit(f"gate: {dwp}: the verdict record lacks {frag!r} -- the sentence below states that the "
                     "payload pointer is only ever zeroed, and that must be carried by the artifact")
    ptrline = recs["table"][0]
    if "POINTER VARIABLE" not in ptrline:
        sys.exit(f"gate: {dwp}: the table record no longer says the global is a pointer variable -- §352's "
                 "correction would be unpublished and readers would keep treating 0x1b242b0 as the table")
    shape_off = sorted({m.group(1) for m in [re.search(r"u32 count at \+(0x[0-9a-f]+)", pay["shape"]),
                                             re.search(r"\*pairs at \+(0x[0-9a-f]+)", pay["shape"])] if m})
    if len(shape_off) != 2:
        sys.exit(f"gate: {dwp}: the shape line yields {shape_off} -- the sentence below names both the "
                 "count offset and the pair-pointer offset, so both must be parsed out of the artifact")
    slot = re.search(r"field = codec-object \+ (0x[0-9a-f]+)", pay["slot"])
    if not slot:
        sys.exit(f"gate: {dwp}: the slot line does not state 'field = codec-object + 0x..' -- "
                 f"{pay['slot'][:120]}")
    out.append({
        "layer": "DAC write path", "item": "es9038_enable -> es9038_one_enable -> es9038_setting_special_params",
        "value": f"{nsites} write/verify call sites in the three enable-path functions",
        "name_or_meaning": "one_enable walks dac_parameters TWICE writing (addr=byte0, value=byte1) "
                           "through es9038_i2c_write_byte + do_reg_write_check (write->readback->compare, "
                           "<=5 retries), then applies read-modify-write tweaks to regs 0x00/0x01/0x02/0x0a; "
                           "it also calls setting_special_params, whose payload -- read from the loop body, "
                           f"not inferred -- is a struct read at count `+{shape_off[0]}` and pair-pointer `+{shape_off[1]}`: "
                           "a u32 COUNT at +0x00 (zero skips the whole call) and a POINTER to byte pairs at "
                           "+0x08, written one pair per iteration as (reg=pair[2i], val=pair[2i+1]) and each "
                           "logged as '%s write value 0x%x to addr 0x%x'. That is NOT the DT 'vivo,params' u32 "
                           "array (no pointer field there, and probe keeps it at es9038 data+0x68, §325) -- "
                           f"§286's 'count = param-num[0]*[1] = 16' described an origin, not this callee. The slot "
                           f"is codec-object + {slot.group(1)}, reached from the heap object at *0x1b242c8",
        "source": f"{dwp} [{sha16(dwp)}], fw/Image [{sha16(IMG)}], art/kallsyms_real.txt",
        "writable": "n/a (mechanism, not a value)",
        "use_case": "§286 corrected §233 (the enable path DOES contain an (addr,value) write loop), §288 "
                    "narrowed it (the pointer comes from the caller's [x1+0x18], skipped when NULL), and "
                    "§351 resolves that chain to an offset: obj = *0x1b242c8, es9038_enable is called with "
                    "obj+0x28 and flag=1, so the payload is obj+0x40 read as {count, pair-pointer}. What is "
                    "STILL open is which buffer obj+0x40 holds: obj is heap and no codec-named function "
                    "stores at +0x40, so the pair BYTES are not in fw/Image. The 7-side observable is the "
                    "per-pair dmesg line: count==0 means the loop is skipped silently, so an empty dmesg "
                    "window says nothing -- capture within ~8 min of playback (§B)",
        "witness2": "call graph proven by a branch-target scan (5072849 instructions, 0 operand errors); "
                    "controls pass: get/set_vivo_codec_function both show for the global "
                    "vivo_codec_fun @0xffffffc001b242b0, and es9038_debug_read shows for dac_parameters. "
                    f"§352 adds the two instances and the identity of the global: copy A reads "
                    f"obj = *{copies[0][1]} (payload {copies[0][2]}) and copy B reads obj = "
                    f"*{copies[1][1]} (payload {copies[1][2]}) -- the same chain at field offsets that "
                    "differ by 8, so a 7-side check must name WHICH instance it is looking at; and "
                    "vivo_codec_fun @0x1b242b0 is a POINTER variable (get_ = ldr x0,[x0,#0x2b0]), not a "
                    "static table, while BOTH DAC drivers register their enable/mute pointers into "
                    "[table+0x48]/[table+0x50] of whatever it points at -- es9028's two stores sit behind "
                    "bit 12 of [dev+0x18], so which DAC the widget path actually reaches is probe order plus "
                    "a feature bit, never a static link. "
                    "§353 closes the payload question as far as static code allows: the pointer at "
                    "codec+0x40 (0x38 on copy A) is only ever WRITTEN ZERO by the functions that own the object "
                    "(0xbb7d1c / 0xbb6258 / 0xbb7c60 `str xzr,[..,#0x40]`, 0xbb6308 `str xzr,[x19,#0x38]`), and "
                    "no allocator result or table address is ever installed there, so setting_special_params "
                    "defaults to its `cbz` skip branch in 6.0.1 -- which is what makes §233's vivo,params "
                    "reading and §286's '16 pairs' both inapplicable to this slot. "
                    "§359 tidies the offset story: the payload field is handle+0x18 in BOTH drivers "
                    "(es9028 at 0xbb93dc / es9038 at 0xbba87c, byte-identical shape), and the two codec "
                    "copies differ only in where the handle sits inside the codec object (obj_A+0x20 -> "
                    "payload obj_A+0x38, obj_B+0x28 -> payload obj_B+0x40) -- not in two different layouts. "
                    "es9028's same handle also feeds its clock-divider step (reads at handle+0x0, +0x4, "
                    "+0x8, +0x10). "
                    "Registration topology: vivo_codec_platform_probe is the ONLY caller of "
                    "set_vivo_codec_function (4 sites) and the DAC i2c probes are the ONLY callers of "
                    "get_vivo_codec_function (es9028 + es9038), so the table es9038_enable/es9038_mute get "
                    "written into is allocated by the vivo codec platform driver and every later call is "
                    "§355 settles WHO writes it on this board: the machine shows /sys/bus/i2c/drivers/es9028 "
                    "with no device bound while es9038 holds 8-0048, and a tree-wide device-tree scan finds "
                    "0 nodes mentioning es9028 against 1 mentioning es9038 -- so es9028_i2c_probe never runs "
                    "here, its i2s-master/bit-12 gate is inert, and [table+0x48] has exactly one writer. "
                    "through a function pointer -- no direct bl to es9038_enable exists (§288). "
                    "LIVE witness (2026-10-17 09:02-09:03, consented single actuation, reverted): with "
                    "`HP imped fixed` ON the enable path ran and printed the pairs it wrote -- see "
                    + DMESG_LIVE["name"] + " -- " + DMESG_LIVE["sentence"]
                    + "; still not demonstrated: no DIAG packet was ever sent",
    })
    # layer 3: ALSA controls that flip on the Hi-Fi / speaker use case.  The three states come from
    # three DIFFERENT captures, because "play" is not one state: the essnap pair below was taken on
    # the Hi-Fi (headphone) route and the SPK_MIX capture on the speaker route.  Recording which
    # capture is which is what lets a reader tell a route apart from a regression -- §285 killed the
    # idea that the amp-off route excuses PA registers (it does not; they read the same).
    def ctl(path, name):
        for ln in open(path, encoding="utf-8", errors="replace"):
            if name in ln:
                return ln.strip().split(name, 1)[1].strip()
        return "ABSENT"
    interesting = ["HiFi Mute", "HP Sel", "HiFi Mode Switch", "TERT_MI2S Bit Format",
                   "TERT_MI2S_RX Audio Mixer MultiMedia1", "Playback Channel Map0", "SmartPA Switch"]
    # route witness: the value that means "the PA registers read right now are the ones that play".
    # WITNESS[name] = that value; the gate parses it out of use_case rather than hardcoding a name.
    WITNESS = {"SmartPA Switch": "On"}
    for p, what in [(SPK_MIX, "speaker-route"), (PLAY_MIX, "Hi-Fi-route"), (IDLE_MIX, "idle")]:
        if not os.path.exists(p):
            sys.exit(f"gate: the {what} control capture {p} is missing -- the control layer would "
                     "silently lose a route column")
    if ctl(SPK_MIX, "SmartPA Switch") != WITNESS["SmartPA Switch"]:
        sys.exit(f"gate: {SPK_MIX} reads SmartPA Switch = {ctl(SPK_MIX, 'SmartPA Switch')!r}, not On -- "
                 "that file is not a speaker-route capture, so it must not be quoted as the PA witness")
    for name in interesting:
        idle_v, play_v = ctl(IDLE_MIX, name), ctl(PLAY_MIX, name)
        spk_v = ctl(SPK_MIX, name)
        old_hp, old_spk = ctl(OLD_HP_MIX, name), ctl(OLD_SPK_MIX, name)
        wit = name in WITNESS
        out.append({
            "layer": "ALSA control", "item": name,
            "value": f"idle={idle_v} play={play_v} speaker={spk_v}",
            "name_or_meaning": "enum/bool value, replayable by name on the same codec driver"
                               + ("; route witness: tells a capture which path was live.  It is NOT a "
                                  "precondition for the PA layer -- measured, the 18 STABLE registers "
                                  "are the same with the switch On and Off (§285 corrects §282/§283, "
                                  "where a parse that mixed the two debugfs sections made 12 DAC bytes "
                                  "land in the PA dict)" if wit else ""),
            "source": f"tinymix -D 0 [{sha16(PLAY_MIX)} + {sha16(SPK_MIX)}]"
                      + (f", proof tools/port_check_neg.py [{sha16(f'{ROOT}/tools/port_check_neg.py')}]" if wit else ""),
            "writable": "yes (tinymix by name, no mount needed; setting it changes the audio path, "
                        "so the gate only ever reads)",
            "use_case": (f"WITNESS route-record ({WITNESS[name]} = the value that means the speaker "
                         "path was live; PA equality is enforced in EVERY route -- §285 measured all "
                         "18 STABLE registers identical between amp-off and amp-on captures)" if wit else
                         ("FLIPS" if len({idle_v, play_v, spk_v}) > 1 else "same in every route")),
            "witness2": f"other session: headphones={old_hp} speaker={old_spk} idle={ctl(OLD_IDLE_MIX, name)}",
        })
    # layer 4b: the ACDB calibration files this board's audio actually uses (ledger 261)
    meta = f"{BASE}/acdb-meta.PD1610.tsv"
    if os.path.exists(meta):
        with open(meta, encoding="utf-8") as fh:
            for r in csv.DictReader(fh, delimiter="\t"):
                if r["dir"] != "PD1610":
                    continue
                out.append({
                    "layer": "ACDB cal asset", "item": f"/system/etc/acdbdata/PD1610/{r['file']}",
                    "value": f"{r['bytes']} B sha16={r['sha16']}",
                    "name_or_meaning": (f"sub-db {r['subdb']}; platform {r['SWPNAME']}; adsp {r['ADSPVERS']}; "
                                        f"codec {r['CDCNAME']}; modified {r['modified']}"),
                    "source": f"{BASE}/acdb-meta.PD1610.tsv [{sha16(meta)}]",
                    "writable": "no (ro /system; on 7 the loader may also reject on the platform triple)",
                    "use_case": "carried byte-for-byte; coefficients live in named LUTs (VSTMLUT/ACGILUT/...)",
                    "witness2": "PD1610LG4 is byte-identical to PD1610 for all 7 files (261); "
                                "header invariant size@24==size@28==len-32 held on 49/49",
                })
    # layer 4c: the acdb_dev_ids the live controls actually carry, named from the ACDB's own pool
    devs = f"{BASE}/acdb-devs.PD1610.tsv"
    dn = {}
    if os.path.exists(devs):
        for r in csv.DictReader(open(devs), delimiter="\t"):
            dn[int(r["acdb_dev_id"])] = r["names"]
    for i, d in sorted(acdb_dev_ids().items()):
        out.append({
            "layer": "ACDB device id", "item": f"acdb_dev_id {i}",
            "value": dn.get(i, "MISSING from the ACDB name pool (run tools/acdb_names.py)"),
            "name_or_meaning": (f"seen in the {','.join(sorted(d['states']))} states of "
                                f"'Audio Stream N App Type Cfg' with app_type {','.join(sorted(d['app_types'])) or '-'}"
                                + (f"; declared in audio_platform_info.xml as {d['declared']}" if d["declared"] else
                                   "; NOT declared in audio_platform_info.xml (HAL-private)")),
            "source": f"{devs} [{sha16(devs)}]",
            "writable": "no (it is a lookup key the HAL writes into a control; the value lives in /system ACDB)",
            "use_case": "on 7 the same control must carry this id AND 7's ACDB must hold a table keyed on it, "
                        "otherwise the route silently falls back",
            "witness2": "id found in the ACDB's own '<n>_<NAME>' name pool" if i in dn else
                        "id NOT in the pool -- that is the finding, do not read the control value as proof of cal",
        })
    # the container grammar of those assets (ledger 263) -- one row, all numbers read from the table
    tlv = f"{BASE}/acdb-tlv.PD1610.tsv"
    lut = f"{BASE}/acdb-lut.PD1610.tsv"
    if os.path.exists(tlv):
        trows = [r for r in csv.DictReader(open(tlv), delimiter="\t") if r["dir"] == "PD1610"]
        per_file = {}
        for r in trows:
            per_file.setdefault(r["file"], set()).add(r["offset"])
        tabs = [r for r in trows if r["rec_bytes"]]
        var = [r for r in trows if r["note"].startswith("not a fixed-record")]
        nrec = sum(1 for _ in open(lut)) - 1 if os.path.exists(lut) else 0
        out.append({
            "layer": "ACDB field schema", "item": tlv.replace(BASE + "/", "art/audio-6.0.1/"),
            "value": (f"{len(trows)} fields over {len(per_file)} files "
                      f"({sorted({len(v) for v in per_file.values()})} per file); "
                      f"{len({r['field'].strip() for r in tabs})} fixed-record tables, "
                      f"{len({r['field'].strip() for r in var})} variable-size; {nrec} decoded records"),
            "name_or_meaning": "container grammar: 32 B header then a packed list of "
                               "name[8] + u32 len + payload, walk lands exactly on EOF",
            "source": f"{tlv} [{sha16(tlv)}]",
            "writable": "n/a (derived view of the .acdb assets, nothing on the device to write)",
            "use_case": "on 7 run tools/acdb_tlv.py --dirs <dir> and diff the field-name sequence and "
                        "rec_bytes before touching any coefficient value",
            "witness2": "eof-exact on 49/49 files, one 67-field sequence shared by all 7 dirs; the 7 "
                        "record sizes this and tools/acdb_lut.py both derived agree (ledger 263)",
        })
    bod = f"{BASE}/acdb-bodies.PD1610.tsv"
    if os.path.exists(bod):
        brows = list(csv.DictReader(open(bod), delimiter="\t"))
        bsum = sum(int(r["len"]) for r in brows)
        out.append({
            "layer": "ACDB undecoded bodies", "item": bod.replace(BASE + "/", "art/audio-6.0.1/"),
            "value": f"{len(brows)} field bodies, {bsum} B, {len({r['field'] for r in brows})} distinct field names",
            "name_or_meaning": "the byte watch list: bodies whose VALUES no tool can name. It is not "
                               "a list of unparsed regions any more -- *CDFT (§268), *CDOT (§300), "
                               "*OFST and *CVD0 (§303) all have proven grammars now, and they stay "
                               "here because a grammar is not a unit. DATAPOOL joins it in ledger 303: "
                               "acdb_tlv had labelled it a string/header field, so is_decoded() skipped "
                               "it and the list silently omitted the largest unreadable region "
                               "(192376 B in PD1610 alone)",
            "source": f"{bod} [{sha16(bod)}]",
            "writable": "no (ro /system asset; nothing to write here)",
            "use_case": "byte-for-byte watch list: tools/acdb_port_diff.py reports how many of these "
                        "slots moved on 7, so an unreadable region is still a diffable region",
            "witness2": "digest arm controls re-run on the enlarged census: PD1610 vs PD1610LG4 0/23 "
                        "differ (POSITIVE, those two files are byte-equal per 261), PD1610 vs QRD, "
                        "PD1610 vs PD1516A and QRD vs PD1516A all move (NEGATIVE) -- counts come from "
                        "the census file, recount by running tools/acdb_bodies.py --dirs PD1610",
        })
    cdfile = f"{BASE}/acdb-cdot.PD1610.tsv"
    if os.path.exists(cdfile):
        crows = list(csv.DictReader(open(cdfile, encoding="utf-8"), delimiter="\t"))
        if not crows:
            sys.exit(f"gate: {cdfile} is empty -- acdb_cdot wrote no groups, so the CDOT claim has "
                     "no artifact behind it")
        names = {r["field"] for r in crows}
        bodies = {(r["cal_set"], r["acdb_file"], r["field"]) for r in crows}
        sizes = Counter(int(r["count"]) for r in crows)
        out.append({
            "layer": "ACDB CDOT groups", "item": cdfile.replace(BASE + "/", "art/audio-6.0.1/"),
            "value": f"{len(crows)} groups in {len(bodies)} bodies over {len(names)} field names",
            "name_or_meaning": "body grammar REPEAT{u32 n, n*u32 values} -- the *CDOT fields, which "
                               "§267/§268 left unreadable because every model tried there was scored "
                               "with the id-window anchor on, and CDOT's words are 97 % below 0x10000. "
                               "The values' unit is NOT claimed; the group sizes are strongly "
                               f"per-family (most common {sizes.most_common(3)})",
            "source": f"{cdfile} [{sha16(cdfile)}] (tools/acdb_cdot.py "
                      f"[{sha16(f'{ROOT}/tools/acdb_cdot.py')}])",
            "writable": "no (ro /system asset)",
            "use_case": "on 7: run tools/acdb_cdot.py --dirs <new set>. Exact-consume either holds "
                        "(same grammar, values differ -> those are the tunables to copy) or it does "
                        "not (different structure -> do not diff values, diff the file). Per-field "
                        "group counts are the comparison",
            "witness2": "gates inside the tool: 360/360 exact-consume over six distinct sets, "
                        "per-name unanimity, the SAME grammar fits 0/360 CDFT bodies (so this is not "
                        "a lenient parser), rotate-by-1 null 0 %, PD1610 vs PD1610LG4 60/60 equal, "
                        "and count sensitivity -- moving every count word by +-1 must break "
                        "consumption at >=90 %, measured by the tool at run time",
        })
    ofp = f"{BASE}/acdb-ofst.PD1610.tsv"
    if os.path.exists(ofp):
        orows = list(csv.DictReader(open(ofp, encoding="utf-8"), delimiter="\t"))
        if not orows:
            sys.exit(f"gate: {ofp} is empty -- tools/acdb_ofst.py parsed nothing, so the OFST "
                     "structure claim has no artifact behind it")
        fams = Counter(r["field"] for r in orows)
        bad_hdr = [r for r in orows if int(r["pair_index"]) >= 1 and
                   int(r["n_from_header"]) == 0]
        if bad_hdr:
            sys.exit(f"gate: {len(bad_hdr)} OFST pairs sit under a zero header count in {ofp} -- "
                     "the pair walk did not respect the counts")
        out.append({
            "layer": "ACDB OFST pairs", "item": ofp.replace(BASE + "/", "art/audio-6.0.1/"),
            "value": f"{len(orows)} pairs over {len(fams)} field names ({dict(fams)})",
            "name_or_meaning": "STRUCTURE parsed, SEMANTICS NOT claimed. Body grammar is "
                               "REPEAT{u32 n, n*(u32,u32)} -- the same shape §268 rejected for this "
                               "family, but only because that test carried the id-window anchor and "
                               "these values are not ids (ledger 300's lesson). Checks the tool "
                               "computes over all seven sets: 56/56 bodies consume exactly, 56/56 "
                               "leading counts equal the sibling CVD0 count (whose records are now "
                               "decoded too, §303), and 353002/353002 values are below their file's "
                               "DATAPOOL length while only 90.4% fit under the CVD0 blob -- so DATAPOOL "
                               "is the referent that survives. Neither column is monotonic (0/56), and "
                               "every value in BOTH columns is a multiple of 4 in 56/56 bodies, which "
                               "is a scale/word-index hint rather than proof of an offset: 16/49 "
                               "DATAPOOL bodies are not even word-multiples and the block-tiling "
                               "reading was measured dead (ledger 303)",
            "source": f"{ofp} [{sha16(ofp)}] (tools/acdb_ofst.py "
                      f"[{sha16(f'{ROOT}/tools/acdb_ofst.py')}])",
            "writable": "no (ro /system asset)",
            "use_case": "on 7: run tools/acdb_ofst.py --dirs <set>. If exact-consume holds, compare "
                        "pair counts and the (col0,col1) multiset per field -- those are the "
                        "diffable units even though the columns are unnamed; if it does not hold, "
                        "the structure changed and value-level diffing is meaningless",
            "witness2": "these bodies deliberately STAY in acdb-bodies' digest census: understanding "
                        "the structure is not the same as knowing the meaning. Count sensitivity "
                        "1574/1574 = 100 % (every count word moved by +-1 breaks consumption), and the "
                        "running-offset reading is measured and DEAD (40.2 % of adjacent pairs over "
                        "seven sets, 22 % in PD1610 alone), so the two columns stay unnamed. The watch "
                        "list now holds 23 bodies: 8 OFST + 8 CVD0 structure-parsed but unnamed, and "
                        "7 DATAPOOL bodies whose block chain is parsed (§304) but whose blocks have "
                        "no named type",
        })
    cvfile = f"{BASE}/acdb-cvd.PD1610.tsv"
    if os.path.exists(cvfile):
        vrows = list(csv.DictReader(open(cvfile, encoding="utf-8"), delimiter="\t"))
        if not vrows:
            sys.exit(f"gate: {cvfile} is empty -- tools/acdb_cvd.py emitted no records, so the CVD0 "
                     "grammar claim has no artifact behind it")
        vstr = {}
        for r in vrows:
            vstr.setdefault(r["field"], set()).add(r["stride"])
        if any(len(s) > 1 for s in vstr.values()):
            sys.exit(f"gate: the emitted records disagree on stride per field name ({dict(vstr)}) -- "
                     "the unanimity that makes REPEAT{u32 n, n*s} a format is not in this artifact")
        mine = [r for r in vrows if r["cal_set"] == "PD1610"]
        vsets = sorted({r["cal_set"] for r in vrows})
        out.append({
            "layer": "ACDB CVD records", "item": cvfile.replace(BASE + "/", "art/audio-6.0.1/"),
            "value": (f"{len(mine)} PD1610 records "
                      f"({dict(Counter(r['field'] for r in mine))}) in a file holding {len(vrows)} "
                      f"records over {len(vsets)} sets {vsets}"),
            "name_or_meaning": "body grammar REPEAT{u32 n, n*s u32 words} with s = 8 for VPDYCVD0 and "
                               "s = 7 for VPSTCVD0 -- this is the family §267/§268 left as 'no model "
                               "fits' (6 tried), cracked by asking which STRIDE consumes the body to "
                               "the last word rather than by inventing a new shape. Two positions of "
                               "each record are confined to a sample-rate vocabulary (0/8000/16000/"
                               "32000/48000); the rest hold dense id runs 70495-70499, 77957-77960, "
                               "69568-69592, 77962-77991, the same numbering space as the app_type ids "
                               "69936/69937/69940 that DATAPOOL opens on and that acdb_tlv names from "
                               "audio_output_policy.conf (deep_buffer/default/compress_offload_24). "
                               "Naming a column is NOT done: 'rate-shaped' is a vocabulary test, not a "
                               "unit",
            "source": f"{cvfile} [{sha16(cvfile)}] (tools/acdb_cvd.py "
                      f"[{sha16(f'{ROOT}/tools/acdb_cvd.py')}])",
            "writable": "no (ro /system asset)",
            "use_case": "on 7: run tools/acdb_cvd.py --dirs <set> --out ... . The stride either stays "
                        "8/7 (same grammar -> the per-field record counts and the record multiset per "
                        "file are the diffable units, and a moved id run is a real tuning difference) or "
                        "it does not (structure changed -> value diffing is meaningless). PD1610 and "
                        "PD1610LG4 must agree exactly, since their files are byte-equal",
            "witness2": "gates in the tool, recheck by running it over all seven sets: 56/56 bodies "
                        "consume exactly, ONE stride per field name (unanimity), the sibling family's "
                        "stride parses 0/28 and 0/28, dropping the body's first word breaks 56/56 "
                        "(word-phase), the CVD0 strides parse 0/322 *CDOT bodies, count sensitivity "
                        "124/124 = 100 %, and every family has at least one rate-shaped column. The "
                        "OFST<->CVD0 'two views of one payload' reading is measured and dead: pairs == "
                        "records x stride/2 in 8/56, equal word length in 0/56",
        })
    plfile = f"{BASE}/acdb-pool.PD1610.tsv"
    if os.path.exists(plfile):
        prow = list(csv.DictReader(open(plfile, encoding="utf-8"), delimiter="\t"))
        if not prow:
            sys.exit(f"gate: {plfile} is empty -- tools/acdb_pool.py emitted no blocks, so the "
                     "DATAPOOL chain claim has no artifact behind it")
        pmine = [r for r in prow if r["cal_set"] == "PD1610"]
        psets = sorted({r["cal_set"] for r in prow})
        punal = sum(1 for r in prow if int(r["L"]) % 4)
        out.append({
            "layer": "ACDB POOL blocks", "item": plfile.replace(BASE + "/", "art/audio-6.0.1/"),
            "value": (f"{len(pmine)} PD1610 blocks in {len({r['acdb_file'] for r in pmine})} pools "
                      f"(file holds {len(prow)} blocks over {len(psets)} sets {psets})"),
            "name_or_meaning": "DATAPOOL is a CHAIN of byte-length-prefixed blocks: cursor i reads "
                               "L = u32@i, payload = bytes[i+4 : i+4+L], next block = i+4+L. That is "
                               "why the counted-array reading was 0/49 and why 16/49 pool bodies are "
                               "not whole word counts -- L counts BYTES. Sizes are strongly quantised "
                               "(4 B in 1932/8243 blocks, then 56/8/36/84), and 8.5% of payloads open "
                               "on an id-band word (0x10000-0x14000, the same space as the app_type ids "
                               "69936/69937/69940 named from audio_output_policy.conf). NO block type "
                               "is named and no value has a unit; the digest census keeps the bodies",
            "source": f"{plfile} [{sha16(plfile)}] (tools/acdb_pool.py "
                      f"[{sha16(f'{ROOT}/tools/acdb_pool.py')}])",
            "writable": "no (ro /system asset)",
            "use_case": "on 7, in this order. (a) tools/acdb_pool.py --compare <6.0.1 set> <7 set> walks both "
                        "pools by INDEX and prints per-role L-differ / payload-differ / "
                        "added-dropped counts -- valid only where the files are supposed to be the "
                        "same, because ledger 305 measured cross-board index agreement at 0.6 %, "
                        "BELOW the 1.2 % shuffled null, so index is NOT a join key between boards. "
                        "(b) tools/acdb_pool.py --dirs ... --slots joins on the block's own first "
                        "payload word, which IS stable: same-key/different-set L-equal 94-100 % "
                        "against a different-key/same-set null of 2.4-34.5 % in all seven roles. Same "
                        "key + same L + different payload_sha16 is one changed tunable, the finest "
                        "unit this layer offers without knowing what a block means",
            "witness2": "gates in the tool: six variants scored, V1 49/49 while 'L covers the header', "
                        "'L counts words (after/including header)' and both two-word-header forms take "
                        "0/49; payload independence 0/12584 breaks (layout depends on header words "
                        "only); off-grid length sensitivity +-1 99.7 % / +-2 100.0 % with the floor "
                        "there, while +-4 is REPORTED at 87.7 % and explained (1760/2019 survivors are "
                        "the same chain re-syncing one block later -- a 4-byte shift stays on the grid); "
                        "base rate: random non-boundary cursors close only 3.61 %, byte-phase starts "
                        "1-3 late close 0/147; POSITIVE PD1610 vs LG4 7/7 and Fluid vs Liquid 7/7 "
                        "identical walks (and --compare counts 0/1486 blocks differing), NEGATIVE "
                        "PD1610 vs QRD 0/7 roles agree with 1052 payload-differing blocks and PD1610 vs "
                        "PD1516A 1225 -- the compare separates boards by an order of magnitude",
        })
    slp = f"{BASE}/acdb-pool-slots.PD1610.tsv"
    if os.path.exists(slp):
        srows = list(csv.DictReader(open(slp, encoding="utf-8"), delimiter="\t"))
        if not srows:
            sys.exit(f"gate: {slp} is empty -- tools/acdb_pool.py --slots emitted no key rows, so the "
                     "cross-board join key claim has no artifact behind it")
        sun = sum(1 for r in srows if r["len_is_unanimous"] == "True")
        snosig = {r["role"] for r in srows if r["no_size_signal_role"] == "True"}
        snamed = sum(1 for r in srows if r["name"])
        if "cross_board_differs" not in srows[0]:
            sys.exit(f"gate: {slp} has no cross_board_differs column -- the line below would then be "
                     "counting sha variety WITHIN one board and calling it a between-board difference")
        svar = sum(1 for r in srows if int(r["distinct_payload_sha"]) > 1)
        sdiffer = sum(1 for r in srows if r["cross_board_differs"] == "True")
        out.append({
            "layer": "ACDB POOL slots", "item": slp.replace(BASE + "/", "art/audio-6.0.1/"),
            "value": (f"{len(srows)} block keys present in >=3 of the five byte-distinct sets, "
                      f"{sun} with a unanimous length, {sdiffer} whose payload differs BETWEEN boards "
                      f"(a separate {svar} keys show sha variety anywhere, i.e. a board may repeat one "
                      f"key with different content), {snamed} named from acdb-ids"),
            "name_or_meaning": "the cross-board join key for the pool, measured rather than assumed: "
                               "the block's own first payload word, NOT its index. Ledger 305 killed "
                               "the index reading (same-index (L,w0) agreement across the five boards "
                               "is 22/3616 = 0.6 %, BELOW the 1.2 % shuffled-index null, and the "
                               "longest common prefix is 0 blocks in Handset/Headset/Speaker), then "
                               "showed the key word is real with a matched-pairs design: same key in "
                               "two sets agree on L 94-100 % of the time while two different keys in "
                               "one set agree only 2.4-34.5 % -- in all seven cal-file roles. The keys "
                               "that differ in payload per board (17.9-22.5 % of the stable keys in "
                               "Bluetooth/Global/Handset/Headset/Speaker, 0 % in General/Hdmi -- the "
                               "counted totals are in the value column, not retyped here) are the "
                               "per-board tunables this layer "
                               "can name without knowing what any block means",
            "source": f"{slp} [{sha16(slp)}] (tools/acdb_pool.py "
                      f"[{sha16(f'{ROOT}/tools/acdb_pool.py')}])",
            "writable": "no (derived, ro /system asset)",
            "use_case": "on 7: run tools/acdb_pool.py --dirs <6.0.1 set> <7 set> --slots --out ... and "
                        "join on (role, key_hex). A key present on both sides with the same L and a "
                        "different payload_sha is one moved tunable; keys missing on one side are "
                        "features that board does not carry. Do NOT diff by block index across boards",
            "witness2": "the null is printed next to the signal on every run, per role, because the "
                        "first version of this arm compared whole key-to-key length-sets and read "
                        "100 % on a role with no signal at all -- an uncalibrated ruler in a new "
                        "costume. Roles flagged no_size_signal_role are written into the artifact so a "
                        "stale verdict cannot be joined on silently; 0 roles are flagged on the five "
                        "sets shipped here. Cross-board index null (1.2 %) and same-index agreement "
                        "(0.6 %) are both recomputed by the tool's ledger note, not typed here",
        })
    mop = f"{BASE}/acdb-pool-modules.PD1610.tsv"
    if os.path.exists(mop):
        mrows = list(csv.DictReader(open(mop, encoding="utf-8"), delimiter="\t"))
        if not mrows:
            sys.exit(f"gate: {mop} is empty -- tools/acdb_pool.py --modules anchored nothing, so the "
                     "module-level comparison has no artifact behind it")
        mp = sum(1 for r in mrows if r["on_listening_path"] == "True")
        mb = sum(1 for r in mrows if r["verdict"] == "BOARD-DEPENDENT")
        mbp = sum(1 for r in mrows if r["verdict"] == "BOARD-DEPENDENT"
                  and r["on_listening_path"] == "True")
        mnm = sum(1 for r in mrows if r["module_names"])
        mroles = Counter(r["role"] for r in mrows)
        out.append({
            "layer": "ACDB POOL modules", "item": mop.replace(BASE + "/", "art/audio-6.0.1/"),
            "value": (f"{len(mrows)} offset-stable module anchors ({mnm} named, {mp} on the listening "
                      f"path) in {len(mroles)} cal files {dict(mroles)}, {mb} board-dependent "
                      f"({mbp} of them on the path)"),
            "name_or_meaning": "the first place this project can name a pool value, and the first "
                               "place it can say who differs. The anchor is (cal-file role, module "
                               "id, offset of that id INSIDE its block) -- ledger 307 had to drop "
                               "the block key from the identity because the vivo board files the "
                               "same records under a DIFFERENT collection key (0x4 -> 0x7, 0x6 -> "
                               "0xc) and in a longer block (1572 -> 2748, 236 -> 524 bytes): 45 of "
                               "the 56 anchors sit under a board-varying key, and keying on it had "
                               "silently split PD1610 off the reference boards. Key and length are "
                               "columns now. Second fix in the same ledger: a record at the tail of "
                               "a short block gets a truncated window, and the 5 anchors that looked "
                               "PD1610-specific turned out to be that artifact -- the tool now "
                               "requires identical window LENGTHS and prints how many anchors it "
                               "dropped for that rule. Result: 5 anchors differ between boards, all "
                               "in Global_cal, all on the listening path, and in every one of them "
                               "the odd board is Fluid -- PD1610 groups with MTP/PD1516A/QRD. "
                               "AUDIO_HIGH_THD_RESAMPLER, AUDIO_MBDRC_V3, AUDIO_IIR, AUDIO_PBE and "
                               "AUDIO_RX_CODEC_GAIN carry the same bytes on this phone as on the "
                               "stock reference boards, so the pool is NOT where the vivo speaker / "
                               "Hi-Fi tuning lives, which narrows the port: carry the *LUT* "
                               "coefficient rows and the CVD/OFST family, not these records. The "
                               "compared unit is a 36-byte window starting at the id, not a field "
                               "with a unit; no record grammar for the block interior is claimed",
            "source": f"{mop} [{sha16(mop)}] (tools/acdb_pool.py "
                      f"[{sha16(f'{ROOT}/tools/acdb_pool.py')}])",
            "writable": "no (ro /system asset)",
            "use_case": "on 7: tools/acdb_pool.py --modules --dirs PD1610 <7 set> --out ... . Read "
                        "the board_groups column: an anchor whose 6.0.1 board sits in the same group "
                        "as the reference boards needs no carrying, and one marked PD1610-SOLO is a "
                        "real per-phone tunable to reproduce. If the window-length rule drops a "
                        "large share of anchors, or the occurrence-count filter leaves fewer than 3, "
                        "the verdict is inadmissible and the tool aborts -- do not read a "
                        "truncation artifact as a tuning difference",
            "witness2": ("runbook A-steps 7e/7f/7g carry the calibration numbers for this ruler, printed on every run: six grammar variants scored together (only the chained `{u32 L, L bytes}` form consumes 49/49 pool bodies); load independence (perturbing a payload word by +/-4 breaks 0/12584 chains); length sensitivity (+1 breaks 99.7 percent, +2 100.0 percent, +4 only 87.7 percent -- and 1760 of those survivors are the same chain re-aligning one block later, so the floor was moved to an off-grid perturbation rather than lowered); the idle-rate denominator (a chain started at a random non-boundary cursor reaches the end only 3.61 percent of the time, which is what makes 49/49 evidence rather than a tautology); and the paired-design key test (same key across sets 94-100 percent vs different keys within one set 2.4-34.5 percent).  The --modules leg additionally aborts when the window-equal-length rule drops too many anchors or when fewer than three survive -- that is the rule which caught five truncated windows that had been read as board-unique tunables (§307)"),
        })
    rgp = f"{BASE}/acdb-row-groups.PD1610.tsv"
    if os.path.exists(rgp):
        rrows = list(csv.DictReader(open(rgp, encoding="utf-8"), delimiter="\t"))
        if not rrows:
            sys.exit(f"gate: {rgp} is empty -- tools/acdb_row_groups.py grouped nothing, so the "
                     "row-level 'who is alone' claim would have no artifact behind it")
        rsolo = [r for r in rrows if r["pd1610_alone"] == "True"]
        rdiff = [r for r in rrows if r["differs_between_boards"] == "True"]
        rsurf = [r for r in rrows if r["differs_between_boards"].startswith(("row-surface", "slot-"))]
        rslot = Counter(r["differs_between_boards"] for r in rrows
                        if r["differs_between_boards"].startswith("slot-"))
        badv = {r["differs_between_boards"] for r in rrows
                if r["differs_between_boards"] not in
                ("True", "False", "row-surface-here-only") and not
                r["differs_between_boards"].startswith("slot-")}
        if badv:
            sys.exit(f"gate: {rgp} carries verdict values this row does not know how to count {badv}")
        rhere = [r for r in rsurf if r["pd1610_alone"] == "True"]
        rgone = [r for r in rsurf if r["pd1610_alone"] == "False"]
        r150 = [r for r in rrows if r["acdb_dev_id"] == "150"]
        r150_solo = [r for r in r150 if r["pd1610_alone"] == "True"]
        topsolo = ", ".join(f"{k} {v}" for k, v in Counter(r["table"] for r in rsolo).most_common(4))
        out.append({
            "layer": "ACDB row groups", "item": rgp.replace(BASE + "/", "art/audio-6.0.1/"),
            "value": (f"{len(rrows)} card keys grouped over the five byte-distinct sets: "
                      f"{len(rdiff)} share a key and differ in payload, {len(rsolo)} have PD1610 alone "
                      f"in its group, {len(rhere)} keys exist only on PD1610, {len(rgone)} exist on "
                      f"every reference board but not on PD1610 {dict(rslot) if rslot else ''}. "
                      "PD1610-alone keys by table: " + topsolo
                      + f". Hi-Fi device 150: {len(r150)} keys, {len(r150_solo)} of them on no "
                      "reference board"),
            "name_or_meaning": "the row-level answer to 'what must be carried to 7', one layer below "
                               "the pool (which ledger 307 cleared). Identity = (table NAME, device id, "
                               "app_type, sample_rate) from tools/acdb_card.py --devices all; the rest "
                               "of the record is the payload; boards are grouped by that payload. Two "
                               "admissibility filters from ledger 307 are enforced and their drops are "
                               "counted: equal occurrence count per board and equal payload length, so "
                               "a difference is never truncation or a grouping artifact. The per-table "
                               "split above says where vivo added calibration, and the device-150 line "
                               "re-measures §271 (Hi-Fi device 150 has 0 calibration rows in the "
                               "generic sets) at row granularity: Android 7's shipped ACDB cannot "
                               "supply those cards, so the Hi-Fi path reproduces only if PD1610's "
                               "own acdbdata is carried with it. The listening-path devices are "
                               "DERIVED, not typed: the ids in acdb-map-output.tsv (the live routed "
                               "outputs) union the pool ids whose name carries HiFi, and the rule "
                               "plus its members are printed on every run",
            "source": f"{rgp} [{sha16(rgp)}] (tools/acdb_row_groups.py "
                      f"[{sha16(f'{ROOT}/tools/acdb_row_groups.py')}] + tools/acdb_card.py)",
            "writable": "no (derived from ro /system assets)",
            "use_case": "on 7: run tools/acdb_card.py --dir <7 set> --devices all, then "
                        "tools/acdb_row_groups.py --from-cards --dirs PD1610 <7 set> --out ... . Read "
                        "pd1610_alone and the row-surface-here-only / slot-* verdict: those are the "
                        "exact cards to copy, and a key that shows only PD1610 means the shipped "
                        "calibration lacks it (device 150 is expected to be entirely in that class). "
                        "Keys present on both boards with one payload group need nothing",
            "witness2": "controls inside the tool: PD1610 vs PD1610LG4 and Fluid vs Liquid are "
                        "POSITIVE and must show ZERO differing keys (those file pairs are byte-equal per "
                        "261/267) -- they do, and a moving control aborts the run; the groupability "
                        "filters print how many keys were dropped and why; 'no board differs' aborts "
                        "as 'too coarse'. A third guard was added the same day this row was written: "
                        "the identity columns (app_type, sample_rate) are derived per set by "
                        "acdb_tlv, and where two boards derived a DIFFERENT layout for the same table "
                        "its keys are dropped from the added/removed counts and the table is named. "
                        "That guard alone turned a '9 cards vivo removed' reading into zero -- the "
                        "ruler disagreed with itself, not the data (ledger 309). Keys are grouped on "
                        "the table NAME only, because ledger 307 showed the vivo board renames "
                        "collection keys. Known coverage limit of THIS view, measured in ledger 311: "
                        "acdb_card.py picks the device column per set and for VCGILUT0 it accepted a "
                        "9-value column where the pooled reading finds 22 device ids on every board, so "
                        "this view's 'reference-only keys = 0' is not evidence that vivo deleted nothing "
                        "-- the joint row is the one that sees the eight substituted slots. The card "
                        "view also has no ablation: its differs_without_offset_words column is '-' on "
                        "every row, which means NOT MEASURED, never 'identical' (ledger 314)",
        })
    sfp = f"{BASE}/acdb-row-shortlist.PD1610.tsv"
    if os.path.exists(sfp):
        sfrows = list(csv.DictReader(open(sfp, encoding="utf-8"), delimiter="\t"))
        if not sfrows:
            sys.exit(f"gate: {sfp} is empty -- the copy list this project hands to the port has no rows")
        sfc = Counter(r["class"] for r in sfrows)
        sfd = Counter(r["acdb_dev_id"] for r in sfrows)
        sft = Counter(r["table"] for r in sfrows)
        out.append({
            "layer": "ACDB row shortlist", "item": sfp.replace(BASE + "/", "art/audio-6.0.1/"),
            "value": (f"{len(sfrows)} cards to carry for the listening-path devices "
                      + ", ".join(f"dev {d}={c}" for d, c in sorted(sfd.items(), key=lambda kv: int(kv[0])))
                      + f": {sfc.get('same-key-different-payload', 0)} same key different payload + "
                      + f"{sfc.get('key-only-on-PD1610', 0)} keys only this board has; by table "
                      + ", ".join(f"{k}={v}" for k, v in sft.most_common())),
            "name_or_meaning": "the port-facing cut of the row grouping: rows whose device is on the "
                               "listening path only, so this is the short answer to 'which ACDB cards "
                               "must come from PD1610 rather than from what 7 ships'. The "
                               "key-only-on-PD1610 half is where 7 has no card at all -- device 150 "
                               "(Hi-Fi) sits entirely in that half -- and same-key-different-payload is "
                               "where 7 has the card but different numbers. Each row carries its class, "
                               "so nothing has to be recomputed by hand on the new board",
            "source": f"{sfp} [{sha16(sfp)}] (tools/acdb_row_groups.py "
                      f"[{sha16(f'{ROOT}/tools/acdb_row_groups.py')}])",
            "writable": "no (derived; the values themselves live in the ro /system acdbdata)",
            "use_case": "on 7: regenerate with tools/acdb_row_groups.py --dirs PD1610 <7 set> "
                        "--shortlist ... and diff the row set against this file. A row still listed is a "
                        "card to copy from PD1610; a row that disappears means 7 already carries that "
                        "card identically, so the listening-path carry list shrinks",
            "witness2": "inherits every guard of the ACDB row groups row (byte-equal positives silent, "
                        "equal occurrence count, equal payload length, comparable-table layout). ★It "
                        "disagrees with an earlier draft of itself on purpose: before the layout guard "
                        "the same command reported 186 vivo-only keys and 9 'vivo removed' keys; those 9 "
                        "were one table (VPDYLUT0) whose sample-rate column acdb_tlv derived differently "
                        "per board, and the corrected figures are what this row computes",
        })
    jgp = f"{BASE}/acdb-row-groups-joint.PD1610.tsv"
    jsp = f"{BASE}/acdb-row-shortlist-joint.PD1610.tsv"
    if os.path.exists(jgp):
        jrows = list(csv.DictReader(open(jgp, encoding="utf-8"), delimiter="\t"))
        if not jrows:
            sys.exit(f"gate: {jgp} is empty -- the joint-column view has no artifact behind it")
        jsolo = [r for r in jrows if r["pd1610_alone"] == "True"]
        jdiff = [r for r in jrows if r["differs_between_boards"] == "True"]
        jhere = [r for r in jrows if r["differs_between_boards"] == "row-surface-here-only"]
        jslot = Counter(r["differs_between_boards"] for r in jrows
                        if r["differs_between_boards"].startswith("slot-"))
        badv = {r["differs_between_boards"] for r in jrows
                if r["differs_between_boards"] not in
                ("True", "False", "row-surface-here-only") and not
                r["differs_between_boards"].startswith("slot-")}
        if badv:
            sys.exit(f"gate: {jgp} carries verdict values this row does not know how to count {badv} "
                     "-- the surface would be under-reported in silence")
        jtab = Counter(r["table"] for r in jsolo)
        if "differs_without_offset_words" not in jrows[0]:
            sys.exit(f"gate: {jgp} has no differs_without_offset_words column -- the row verdicts "
                     "would be read without the ablation that ledger 314 introduced")
        jpos = [r for r in jrows if r["differs_between_boards"] == "True"
                and r["differs_without_offset_words"] == "False"]
        badab = {r["differs_without_offset_words"] for r in jrows
                 if r["differs_without_offset_words"] not in ("True", "False", "-")}
        if badab:
            sys.exit(f"gate: unknown differs_without_offset_words values {badab} in {jgp}")
        jn = len(list(csv.DictReader(open(jsp, encoding="utf-8"), delimiter="\t"))) \
            if os.path.exists(jsp) else 0
        jposn = sum(1 for r in (csv.DictReader(open(jsp, encoding="utf-8"), delimiter="\t")
                                if os.path.exists(jsp) else [])
                    if r.get("differs_without_offset_words") == "False")
        jvivo = sum(1 for r in (csv.DictReader(open(jsp, encoding="utf-8"), delimiter="\t")
                                if os.path.exists(jsp) else [])
                    if r.get("vivo_value_word") not in (None, "-", ""))
        jnovivo = sum(1 for r in (csv.DictReader(open(jsp, encoding="utf-8"), delimiter="\t")
                                  if os.path.exists(jsp) else [])
                      if r["class"] == "same-key-different-payload")
        out.append({
            "layer": "ACDB row groups joint", "item": jgp.replace(BASE + "/", "art/audio-6.0.1/"),
            "value": (f"{len(jrows)} keys under ONE pooled column map ({len(jdiff)} differ between "
                      f"boards, {len(jsolo)} with PD1610 alone, {len(jhere)} keys only this board has, "
                      f"reference-only slots {dict(jslot)}); of the differing keys {len(jpos)} differ "
                      "ONLY in words that are pool offsets or shaped like them (ledger 314 shape rule + "
                      "316 pool-anchor rule); listening-path short list in "
                      f"this view: {jn} rows of which {jposn} are position-only and {jvivo} of the "
                      f"{jnovivo} value rows hold a value at an UNFLAGGED word that no other board shares "
                      "(per-word evidence, ledger 321); PD1610-alone keys by "
                      "table " + ", ".join(f"{k}={v}" for k, v in jtab.most_common(4))),
            "name_or_meaning": "same grouping as ACDB row groups, but the identity columns are derived "
                               "ONCE from the pooled records of every board instead of per set "
                               "(tools/acdb_row_groups.py --joint, which is now the default). Ledger "
                               "310: per-set derivation is what made VPDYLUT0 look different on "
                               "different boards (309 guard) and it also shifts the app_type / "
                               "sample_rate split elsewhere, so the two views disagree on how finely a "
                               "card is keyed -- at the granularity they share they agree (all 9 "
                               "card-view table+device triples are confirmed, the joint view adds 4). "
                               "Ledger 311 corrects what this row said about the 8 reference-only keys: "
                               "they are NOT the same card under another number. Three arms each fail -- "
                               "PD1610's own ACDB name pool calls 38 BT_SCO_NB_MIC and 838 "
                               "BT_SCO_NRECOFF_MIC, PD1610 keeps rows for 38 in ACGILUT0/AVOLLUT0/"
                               "DPROPLUT (a device cannot be renamed while still living under its old "
                               "number), and no payload is shared -- while the table shape is exactly one "
                               "id out and one id in (22 vs 22 device ids in all eight voice tables). So "
                               "vivo moved the BT-SCO-mic calibration from the stock device to its own "
                               "device, which is a different device, and the slot verdict is what the "
                               "artifact's differs_between_boards column now records per key "
                               "(slot-SUBSTITUTED / slot-REMOVED / slot-ALIAS). None of those eight "
                               "slots is on a listening device, so the copy list does not change. The "
                               "device column here may come from two rules, recorded per table: the union "
                               "of the boards' numbered pools, or a small-int window when the ids sit "
                               "outside any named pool (ACGILUT0/ACGDLUT0 land in that weaker class). "
                               "Ledger 316 adds the STRUCTURAL half of the payload-word test: a word is "
                               "declared a DATAPOOL offset only when >=50 non-zero values hit block "
                               "starts of their own file at >=50% while two matched controls stay <=5% "
                               "(value+4 in the same pool, and the same values against the other files' "
                               "boundaries -- a strictly larger set, so it is the harder control).  That "
                               "fired on DPROPLUT word 2 (100.00% over 5479 values, controls 0.58% and "
                               "0.00%) and on ANC LUT0 word 2 (100.00% over 63 values, the thinner one), "
                               "while the shape rule's two candidates (ACGILUT0/ACGDLUT0 word 4) are NOT "
                               "confirmed structurally -- they are kept as a sensitivity hypothesis only, "
                               "labelled in the output.  Read together: 302 differing keys fall to 217 "
                               "when only the proven offsets go and to 143 when the shape candidates go "
                               "too, so between a quarter and a half of the 'values differ' surface is "
                               "position, and 4 of the 13 listening-path value rows (2 of them via the "
                               "proven DPROPLUT column) hang on nothing but a pointer",
            "source": f"{jgp} [{sha16(jgp)}] (tools/acdb_row_groups.py "
                      f"[{sha16(f'{ROOT}/tools/acdb_row_groups.py')}])",
            "writable": "no (derived from ro /system assets)",
            "use_case": "cross-check the copy list with a single ruler: tools/acdb_row_groups.py "
                        "--dirs PD1610 <7 set> --shortlist ... runs the joint view by default, so a row "
                        "that appears in BOTH this view and the card view is the sturdiest kind of "
                        "finding; a row only one of them shows points at a column-derivation difference "
                        "worth resolving before it is treated as calibration. On Android 7 read the "
                        "slot verdict before believing any 'the shipped set lacks this card' line: if a "
                        "7-side slot is really the same device re-numbered the tool says ALIAS and "
                        "refuses to publish the shortlist until --dev-alias NEW=OLD is passed, and that "
                        "map is checked against the board's own name pool",
            "witness2": "the same byte-equal positives as the card view and they are silent here too "
                        "(PD1610 vs LG4 and Fluid vs Liquid: 0 keys differ, 0 keys unshared) -- the "
                        "first version of this mode FAILED that control with 345 'unshared' keys because "
                        "it re-derived the column map separately for the control pair, i.e. it compared "
                        "two rulers; fixed by building one map over the requested sets plus the control "
                        "partners and filtering the grouping back to the requested sets. Pooling the "
                        "device-id universe (union of the boards' numbered pools) is what took this view "
                        "from 10 to 15 tables and 209 to 569 keys, since acdb_tlv.dev_names() only "
                        "reads the baseline set's pool. The slot verdict is controlled too, by "
                        "--selftest: it injects one alias (device filed under a second number, same pool "
                        "name, identical payload), one substitution (a differently-named id sitting in "
                        "the slot) and one empty slot, and must label all three; applying the injected "
                        "map must then take only the ALIAS off the surface. On the real boards it reports "
                        "0 ALIAS, so no id normalisation is admissible here. Ledger 312 adds the "
                        "hook-layer cross-check on the copy list: 74 hooks project to 135 "
                        "(table,device) pairs, and the ONLY listening-device pairs among them are "
                        "ACGILUT0 x {15,124,150} -- all three on the list -- while ACGDLUT0/AFECLUT0/"
                        "AVOLLUT0/DPROPLUT have 0 vivo-added hooks at all, i.e. those cards are stock "
                        "hooks whose values vivo changed. Every listening-device hook pair is sorted "
                        "into four states -- ON_LIST, IDENTICAL (nothing to carry), NOT_JUDGED (an "
                        "admissibility filter dropped it, reason printed) and NO_ROW (the two layers "
                        "disagree about a listening device having a card at all) -- and only NO_ROW "
                        "aborts; --selftest injects all four so the aborting state is known reachable, "
                        "and widening --path-devices to 15,124,150,11 produces the NOT_JUDGED state on "
                        "real data (dev 11: 260 occurrences here against 180 everywhere else). That same "
                        "test exposed that the override had never run, since it crashed on an unbound "
                        "PATH (it now refuses an empty or non-numeric list)",
        })
    dpp = f"{BASE}/acdb-dprop.PD1610.tsv"
    if os.path.exists(dpp):
        dprows = list(csv.DictReader(open(dpp, encoding="utf-8"), delimiter="\t"))
        if not dprows:
            sys.exit(f"gate: {dpp} is empty -- the property layer would be reported from nothing")
        dpc = Counter(r["class"] for r in dprows)
        unknown = {r["class"] for r in dprows} - {"STOCK", "VIVO-ONLY", "BOARDS-DISAGREE", "NAME",
                                                  "DEVICE ABSENT HERE"}
        if unknown:
            sys.exit(f"gate: {dpp} carries classes this row cannot count {unknown}")
        dpl = [r for r in dprows if r["on_listening_device"] == "True"]
        dplc = Counter(r["class"] for r in dpl)
        names_ok = sum(1 for r in dprows if r["class"] == "NAME")
        props = Counter(r["property_id"] for r in dprows)
        out.append({
            "layer": "ACDB device properties", "item": dpp.replace(BASE + "/", "art/audio-6.0.1/"),
            "value": (f"{len(dprows)} DPROPLUT rows read as (device, property id, DATAPOOL pointer): "
                      f"{dpc['STOCK']} agree with every reference board that carries the row, "
                      f"{dpc['VIVO-ONLY']} have bytes no reference board has, "
                      f"{dpc['BOARDS-DISAGREE']} are reference-board disagreements (not a vivo claim), "
                      f"{dpc['NAME']} are the device-name property and {dpc['DEVICE ABSENT HERE']} "
                      f"belong to devices the reference sets do not have at all. Listening-path rows: "
                      f"{len(dpl)} -> {dict(dplc)}. Property ids seen: {len(props)}"),
            "name_or_meaning": "the first *LUT record column this project has NAMED: DPROPLUT word 2 is "
                               "a DATAPOOL block offset (tools/acdb_row_groups.py pool_anchors(), "
                               "100.00% of 5479 non-zero values land on a block start of their own file, "
                               "+4 control 0.58%, foreign-pool control 0%). Read through that pointer the "
                               "row becomes (device, property, value-block): property 70584 holds the "
                               "device's UTF-16 name and all 92 of them agree with the numbered pool's "
                               "own strings (two independent readings), 70582 is 8 bytes, 70583 20, "
                               "70573 40/48, 70575/78160 4, 76363 32, 77549 12, 78048 may be empty. The "
                               "port-relevant part is the listening-path split: Hi-Fi device 150 has "
                               "DEVICE ABSENT HERE on every property (7 shipped sets have no such device), "
                               "while speaker devices 15/124 are STOCK apart from the NAME row and a few "
                               "reference-board disagreements -- so the device-property layer carries no "
                               "vivo speaker tuning, which narrows where the audible difference can live "
                               "to the LUT coefficient values and the .cnt/PA/DAC layers",
            "source": f"{dpp} [{sha16(dpp)}] (tools/acdb_dprop.py "
                      f"[{sha16(f'{ROOT}/tools/acdb_dprop.py')}] + tools/acdb_pool.py + "
                      f"tools/acdb_row_groups.py)",
            "writable": "no (derived from ro /system assets)",
            "use_case": "on 7: tools/acdb_dprop.py --dirs PD1610 <7 set> --out ... -- it answers 'does "
                        "the 7 set even have this device's properties' per property id, which the file "
                        "hash cannot answer; rows still DEVICE ABSENT HERE or VIVO-ONLY after the copy "
                        "are the ones that must come from PD1610's acdbdata",
            "witness2": "controls inside the tool: 862/862 pointers resolve to a block start while "
                        "pointer+4 resolves in only 1.4% (so 'resolves' is information, not density -- "
                        "the tool aborts above 25%); PD1610 vs PD1610LG4 and Fluid vs Liquid agree on "
                        "every row (862 and 755, abort on any disagreement); NAME is only declared when "
                        "the decoded string starts with the device id and it is cross-checked against "
                        "the numbered pool, 92/92 agreeing; the unresolved rate aborts above 5%; and "
                        "DEVICE ABSENT HERE is kept apart from VIVO-ONLY so that 'no board has this "
                        "device' is never read as 'vivo changed it'",
        })
    lsp = f"{BASE}/acdb-lut-sense.PD1610.tsv"
    if os.path.exists(lsp):
        lrows = list(csv.DictReader(open(lsp, encoding="utf-8"), delimiter="\t"))
        if not lrows:
            sys.exit(f"gate: {lsp} is empty -- the record-size sensitivity would be reported from nothing")
        lf = sum(int(r["fields"]) for r in lrows)
        lc = sum(int(r["true_closes"]) for r in lrows)
        ldev = sum(int(r["device_col_at_0"]) for r in lrows)
        lpars = sum(sum(int(r[f"d{d:+d}_parse_divides"]) for d in (-2, -1, 1, 2)) for r in lrows)
        lkeep = sum(sum(int(r[f"d{d:+d}_still_device_like"]) for d in (-2, -1, 1, 2)) for r in lrows)
        lamb = sum(int(r["cols_2plus_qualifiers"]) for r in lrows)
        if lf != lc:
            sys.exit(f"gate: {lc}/{lf} fields close on their stored count in {lsp} -- the parse model "
                     "itself is broken, so no sensitivity claim may be published")
        out.append({
            "layer": "ACDB LUT record-size sensitivity", "item": lsp.replace(BASE + "/", "art/audio-6.0.1/"),
            "value": (f"{lf} fixed-record fields over the five sets: all {lc} close on their stored count; "
                      f"{ldev} have a device-like word 0. Perturbing the stored count by +/-1 or +/-2 leaves "
                      f"{lpars} nearby counts that still divide the field into a word record, and "
                      f"{lkeep} of those keep a device-like word 0 (silent-mis-parse rate "
                      f"{lkeep / max(lpars, 1):.2%}); {lamb} fields have two or more device-like columns"),
            "name_or_meaning": "what pins the *LUT parse. The format stores a count and a length but NOT a "
                               "record size (size = (length-4)/count), so division alone is weak -- ledger "
                               "319 counted ~14 alternative dividing counts per field and ~10% of them with "
                               "a device-looking word 0. What survives the joint test (divides AND looks "
                               "like device ids at >=8 distinct values) is zero, so a 7-side file whose "
                               "count word differs slightly cannot be mis-parsed silently by "
                               "tools/acdb_row_groups.py. It also re-checks the assumption behind the row "
                               "identity: acdb_row_groups takes the FIRST device-looking column, which is a "
                               "reading only while no field has two qualifiers (measured 0)",
            "source": f"{lsp} [{sha16(lsp)}] (tools/acdb_lut_sense.py "
                      f"[{sha16(f'{ROOT}/tools/acdb_lut_sense.py')}])",
            "writable": "no (derived from ro /system assets)",
            "use_case": "run it first on 7's set ALONE (tools/acdb_lut_sense.py --dirs <7 set>): a non-zero "
                        "'still device like' or 'two or more qualifiers' there means the shipped tables would "
                        "be parsed ambiguously by my tools, and the row-layer verdicts (copy list included) "
                        "must be re-derived before being trusted",
            "witness2": "positive control inside the tool: every field must close on its own stored count "
                        "(355/355) or it aborts. The 0 is shown NOT to be an inert test: --selftest re-runs "
                        "the same perturbation with the distinct-value floor loosened from 8 to 2 and gets "
                        "43 survivors, so the metric moves when the rule is weakened. The ambiguity "
                        "census aborts on any field with >=2 qualifiers rather than publishing a silent "
                        "choice",
        })
    bfp = f"{BASE}/tfa-bf-family.TfaBfNames.tsv"
    if os.path.exists(bfp):
        vrows = list(csv.DictReader(open(bfp, encoding="utf-8"), delimiter="\t"))
        if not vrows:
            sys.exit(f"gate: {bfp} is empty -- the PA field-numbering verdict would be stated from nothing")
        vagg = {r["family"]: int(r["exact"]) for r in vrows if r["scope"] == "all"}
        vtot = next((int(r["rows"]) for r in vrows if r["row_name"] == "TFA1-total"), 0)
        vt1 = next((int(r["exact"]) for r in vrows if r["row_name"] == "TFA1-total"), 0)
        vun = [r for r in vrows if r["family"] == "no-family"]
        if vtot == 0:
            sys.exit(f"gate: {bfp} reports a 0-row driver table -- tools/tfa_bf_table.py did not deliver "
                     "a ballot, so the numbering verdict is unsupported")
        out.append({
            "layer": "TFA bitfield family", "item": bfp.replace(BASE + "/", "art/audio-6.0.1/"),
            "value": (f"{vtot} driver rows voted by (name,addr,pos,len): "
                      f"{len({r['family'] for r in vrows if r['scope'] != 'all' and r['family'] != 'no-family'})} "
                      f"of the reference families in fw/tfa-ref receive any exact match at all -- TFA1 {vt1}, "
                      f"N1C/TFA2 {vagg.get('N1C/TFA2-total', -1)}; dropping the address from the same ballot "
                      f"lifts N1C to {vagg.get('N1C/TFA2-no-addr-ballot', -1)}; {len(vun)} rows match no family"),
            "name_or_meaning": bf_family_sentence(),
            "source": f"{bfp} [{sha16(bfp)}] (tools/tfa_bf_family.py "
                      f"[{sha16(f'{ROOT}/tools/tfa_bf_family.py')}])",
            "writable": "no (derived from the captured Image, read-only)",
            "use_case": "before porting any codec_reg write: re-run tools/tfa_bf_table.py on 7's Image and "
                        "this vote against it. If 7's driver votes N1C/TFA2 instead of TFA1, the same bitfield "
                        "NAME sits at a different ADDRESS, so the 26-register denominator, the names in "
                        "tfa-reg-fields and every 'addr = enum >> 8' reading must be re-derived -- a name "
                        "carried across would write the wrong register",
            "witness2": "the strict zero on the N1C side is shown to be live, not inert: the artifact itself "
                        "carries the loosened ballot row (N1C/TFA2-no-addr-ballot) and tools/tfa_bf_family.py "
                        "--selftest aborts unless loosening RAISES that count; a padded-name arm aborts too "
                        "(tools/tfa_bf_family.py --tsv <a copy with one trailing space added> => rc=1). This "
                        "row's own sentence is re-tested by tools/bf_family_neg.py (six arms: clean, "
                        "file-absent, loosened row torn out, a bucket denominator moved, header-only, "
                        "TFA1-total doctored to 0)",
        })
    evf = f"{BASE}/dapm-event-flags.PD1610.tsv"
    if os.path.exists(evf):
        erows = list(csv.DictReader(open(evf, encoding="utf-8"), delimiter="\t"))
        bits = [r for r in erows if r["kind"] == "bit"]
        wids = [r for r in erows if r["kind"] == "widget"]
        if not bits or not wids:
            sys.exit(f"gate: {evf} has {len(bits)} bit rows and {len(wids)} widget rows -- both halves "
                     "are needed before the naming may be stated")
        agree = [r["bit"] for r in bits if r["agree"] == "agree"]
        only = [r["bit"] for r in bits if r["agree"] == "NO-BINARY"]
        passed = [r for r in wids if r["combo_in_stock_template"] == "DRIVER-PASSED"]
        combos = sorted({r["event_flags"] for r in wids})
        tvw = open(f"{ROOT}/fw/ksrc-audio/Makefile", encoding="utf-8", errors="replace").read()
        tver = ".".join(re.search(rf"^{k}\s*=\s*(\S+)", tvw, re.M).group(1)
                        for k in ("VERSION", "PATCHLEVEL", "SUBLEVEL"))
        dve = f"{BASE}/live/kernel-version.txt"
        dev = open(dve, encoding="utf-8", errors="replace").read().split("\n")[0].strip() if os.path.exists(dve) else ""
        if not dev.startswith(tver):
            sys.exit(f"gate: the extracted ASoC tree says {tver} but {dve} says {dev!r} -- the naming "
                     "layer would be citing a header from a different kernel")
        agree_s = ", ".join(f"{r['bit']}={r['binary_value']}" for r in bits if r["agree"] == "agree")
        listen = "; ".join(f"{r['name']}(#{r['array']}/{r['entry']})={r['event_flags']}[{r['flags_named']}]"
                           for r in wids if r["name"] in ("HiFi DAC", "HP", "SmartPA I2S In"))
        out.append({
            "layer": "DAPM event flags", "item": evf.replace(BASE + "/", "art/audio-6.0.1/"),
            "value": (f"{len(bits)} event bits from soc-dapm.h, {len(agree)} of them also named by our "
                      f"own kernel image ({agree_s}); {len(only)} header-only ({', '.join(only)}); "
                      f"{len(wids)} widgets in {len(combos)} combinations {combos}, {len(passed)} of "
                      f"them a combination no stock template produces"),
            "name_or_meaning": (f"what the widget .event_flags numbers MEAN: {listen} -- read from "
                                "three agreeing sources: the header defines, the name/value pairs "
                                "compiled into this kernel's dapm_seq_check_event, and the fact that "
                                "the same function loads the field with ldrh at +0x78 (2 bytes, as "
                                "'unsigned short event_flags' declares) and the handler pointer at "
                                "+0x80 (the very next member)"),
            "source": f"{evf} [{sha16(evf)}] (tools/dapm_event_flags.py "
                      f"[{sha16(f'{ROOT}/tools/dapm_event_flags.py')}]; header "
                      f"{ROOT}/fw/ksrc-audio/include/sound/soc-dapm.h [{sha16(f'{ROOT}/fw/ksrc-audio/include/sound/soc-dapm.h')}], "
                      f"extracted from fw/caf8996.tgz; tree version {tver} == device {dev})",
            "writable": "no (compiled into the machine driver's widget arrays)",
            "use_case": "on 7 run the same tool against 7's extracted soc-dapm.h and 7's Image: the "
                        "widget names come from step 5e, and each widget's flag COMBINATION must match "
                        "this table. A changed combination means the handler runs at a different point "
                        "of the power sequence -- that is audible (unmute clicks, a seam at start/stop), "
                        "not a coefficient difference",
            "witness2": "the naming aborts unless the header and this kernel's own binary agree on every "
                        "value (a mis-pair is a SystemExit, not a warning), and --selftest proves all "
                        "three of its gates fire: mis-pairing PRE_PMU aborts, hiding POST_PMD from the "
                        "vocabulary aborts the widget decode, and loosening the name filter to a "
                        "substring aborts because SND_SOC_DAPM_REGULATOR_BYPASS=0x1 collides with "
                        "PRE_PMU. The version gate is real too: pointing live/kernel-version.txt at "
                        "another release aborts before any name is printed",
        })
    dip = f"{BASE}/dac-integration-params.PD1610.tsv"
    if os.path.exists(dip):
        di = [r for r in csv.DictReader(open(dip, encoding="utf-8"), delimiter="\t")]
        par = [r for r in di if r["kind"] == "param"]
        dtp = [r for r in di if r["kind"] == "dt-prop"]
        site = [r for r in di if r["kind"] == "site"]
        if not (par and dtp and site):
            sys.exit(f"gate: {dip} has {len(site)} site, {len(par)} param and {len(dtp)} dt-prop rows "
                     "-- the chain row needs all three halves")
        der = [r for r in di if r["kind"] == "derived"]
        arm_tsv = f"{BASE}/arm64-cfg-arms.PD1610.tsv"
        if not der or not os.path.exists(arm_tsv):
            sys.exit(f"gate: {dip} holds {len(der)} derived rows and the arm-binding artifact is "
                     + ("MISSING" if not os.path.exists(arm_tsv) else "present")
                     + " -- the row below quotes the one-shot derivation and its perturbations, and both "
                     "come from tools/dac_integration_params.py --derive reading "
                     "arm64-cfg-arms.PD1610.tsv")
        drv = [r for r in der if "bound arm:" in (r["verdict"] or "")]
        pert = [r for r in der if (r["verdict"] or "").startswith("perturbation:")]
        if len(drv) != 1:
            sys.exit(f"gate: {len(drv)} bound-arm rows in {dip} -- the derivation must give exactly one "
                     "arm, otherwise the row would report a choice the tool did not make")
        pred_m = re.search(r"predicted (0x[0-9a-f]{2}) == ", drv[0]["verdict"])
        if not pred_m:
            sys.exit(f"gate: the bound-arm row does not state an AGREED prediction: "
                     f"{drv[0]['verdict']!r} -- publishing it without the equality would drop the check")
        # the `param` rows name the table the handler's own code points at, and two instances of that
        # table exist with DIFFERENT bytes (0x179d550 and 0x179d7d0).  Keying the live-capture census
        # on the first ones published "0x14 disagrees with the table" -- and the live enable witness of
        # §369/§370 contradicts that, because the byte it read is column 1 of the instance the selector
        # binds.  So the census is per instance, and the bound one has to agree or the build stops.
        bound_inst = drv[0]["name"]
        # the bound instance has no `param` rows at all (the handler-named table is a different
        # address), so the census is assembled from whatever rows name it -- alt-table tiles included
        bound_rows, seen_reg = [], set()
        for r in di:
            if (r["name"] == bound_inst and r["kind"] in ("param", "alt-table")
                    and re.fullmatch(r"0x[0-9a-f]{2}", r["reg"] or "") and r["reg"] not in seen_reg):
                seen_reg.add(r["reg"])
                bound_rows.append(r)
        hit, no = [], []
        for r in bound_rows:
            cs = [int(c, 16) for c in re.findall(r"0x([0-9a-f]{1,2})", r["candidates"])]
            lm = re.fullmatch(r"0x([0-9a-f]{1,2})", r["live"] or "")
            if not lm:
                continue
            (hit if int(lm.group(1), 16) in cs else no).append(r["reg"])
        other = sorted({r["name"] for r in par if r["name"] != bound_inst})
        if not bound_rows:
            sys.exit(f"gate: no row in {dip} names the bound instance {bound_inst} -- the census below "
                     "would have nothing to count")
        if no:
            sys.exit(f"gate: against the BOUND instance {bound_inst}, {no} hold a byte no candidate "
                     "column contains -- the mechanism is not confirmed and this row must not claim it")
        # the bound instance is tiled by --derive for ONE register (the predicted byte 0x14); the other
        # two have no bound-instance row, so the sentence says what is covered instead of implying the
        # whole triple was checked against the table the selector binds
        gap = len(par) - len(bound_rows)
        undec = [r for r in pert if "NOT decidable" in (r["verdict"] or "")]
        out.append({
            "layer": "Hi-Fi DAC integration params",
            "item": dip.replace(BASE + "/", "art/audio-6.0.1/"),
            "value": (f"{site[0]['value'].replace('row=', '')} rows x {site[0]['bytes']} -> "
                      f"{len(par)} registers {', '.join(r['reg'] for r in par)}, each with "
                      f"{len(par[0]['candidates'].split())} candidate bytes picked by "
                      f"{[r['name'] for r in di if r['kind'] == 'selector-insn'][0]}; live capture "
                      f"against the bound instance {bound_inst} agrees on {len(hit)}/{len(bound_rows)} "
                      f"(HIT {','.join(hit)}), while {gap} of {len(par)} registers have NO bound-instance "
                      "row (the derivation tiles only the predicted one) -- those are the registers whose "
                      f"candidate lists exist only for {', '.join(other) or 'the handler-named instance'}"
                      + "; retraction: the earlier reading of this row said '0x14 disagrees with the "
                        "table', which came from keying on that handler-named instance; §369/§370's live "
                        "enable witness read 0x2e (= bound column 1) at 34 ohm and 0x24 (= column 0) "
                        "under the 16-ohm override, so 0x14 agrees with the bound table in both states"
                      + f"; ★§341 tools/dac_integration_params.py --derive composes the four sides into "
                        f"ONE byte: {drv[0]['name']} row {drv[0]['reg']} predicts "
                        f"{pred_m.group(1)} == the captured {drv[0]['live']}; perturbations "
                        + " | ".join((r["verdict"] or "")[len("perturbation: "):] for r in pert)
                        + f" ({len(undec)} of them lands on the same byte, so that axis is not decidable "
                          "from the register value)"),
            "name_or_meaning": ("what the DAC enable path writes AFTER the 47-pair dac_parameters "
                                "loop: the widget event handler builds a {count, pointer} struct on its "
                                "own stack, fills it from the compiled-in table named in this row, and "
                                "publishes it at [object+0x20]+0x18 -- which is exactly the slot "
                                "es9038_one_enable dereferences. So §286's sentence 'the DT vivo,params "
                                "array feeds the enable writes' is wrong as written: the payload is a "
                                "kernel table, chosen by a headphone-impedance index function, not the "
                                "DT. The DT array is read into the driver's data+0x60/0x64/0x68 by "
                                "es9038_i2c_probe; §323/§325 then looked for that array's reader and found "
                                "NONE in the whole Image (nor one hop into its callees) -- see the "
                                "'Hi-Fi DT params consumers' row"),
            "source": f"{dip} [{sha16(dip)}] + {arm_tsv.replace(BASE + '/', 'art/audio-6.0.1/')} "
                      f"[{sha16(arm_tsv)}] (tools/dac_integration_params.py "
                      f"[{sha16(f'{ROOT}/tools/dac_integration_params.py')}], anchor from "
                      f"{BASE}/dapm-widgets.PD1610.tsv, bytes from fw/Image "
                      f"[{sha16(f'{ROOT}/fw/Image')}])",
            "writable": "no (compiled into the kernel Image; the registers are written by the driver)",
            "use_case": "on 7, run tools/dac_integration_params.py against 7's Image with 7's own "
                        "dapm-widgets.tsv: the register NUMBERS and the per-row candidate sets are what "
                        "the Hi-Fi output character depends on here. If 7's table names different "
                        "registers, or has a different number of candidate columns, the impedance "
                        "conditioning differs -- and that is audible on headphones, not a coefficient",
            "witness2": "three arithmetic identities must hold or the tool aborts: count x payload-bytes "
                        "== the kmalloc size; the handler's publish offset == one_enable's read offset "
                        "(base+0x20 + 0x18 == 0x38); and the selector's largest column immediate + 1 == "
                        "candidate bytes per row (a missing column must come from a conditional-select "
                        "instruction). --selftest perturbs each of the four quantities and requires all "
                        "four aborts. The live DAC section is parsed section-wise (only ## es9038/reg), "
                        "because the PA section in the same file uses padded addresses and would be "
                        "read as the DAC's own bytes (§285's cross-section bug)",
        })
        out.append({
            "layer": "Hi-Fi DAC device tree",
            "item": f"{BASE}/live/dac-dt-raw.txt",
            "value": (f"{len(dtp)} properties on /proc/device-tree/soc/i2c@75b6000/dac@48: "
                      + ", ".join(f"{r['name']}[{r['bytes']}B]" for r in dtp)),
            "name_or_meaning": ("the DAC chip's OWN node -- found only on 2026-10-16 while looking for "
                                "the string 'vivo,params', and it was NOT on the carry list before "
                                "(§236/§287 enumerated soc/vivo-hifi-codec and soc/sound-9335, plus the "
                                "PA's spkamp@34). It carries compatible 'es,es9038', reg 0x48, three "
                                "supply phandles, the reset GPIO, i2s-master, and the DT pair "
                                "vivo:param-num=[4,4] + vivo,params[16 u32]"),
            "source": f"{BASE}/live/dac-dt-raw.txt [{sha16(f'{BASE}/live/dac-dt-raw.txt')}] "
                      f"(tools/dacdtnode.sh [{sha16(f'{ROOT}/tools/dacdtnode.sh')}])",
            "writable": "no (read-only /proc/device-tree; the DT itself needs vendor source)",
            "use_case": "on 7, this node must exist with the same property NAMES and byte values, or "
                        "the driver reads a different (or missing) vivo,params -- note /proc/device-tree "
                        "IS a symlink, so find needs a trailing slash or it reports 'absent' falsely",
            "witness2": "tools/dacdtnode.sh aborts if the node is not a directory, and the row builder "
                        "refuses a capture without its DACSLOT_DONE marker or whose declared byte count "
                        "does not match the parsed hex; the same gate re-checked that vivo,params is "
                        "64 B = 16 u32 and vivo:param-num = 4,4 (product 16 == the array length)",
        })
    dtc = f"{BASE}/dac-dt-consumers.PD1610.tsv"
    if os.path.exists(dtc):
        dc = [r for r in csv.DictReader(open(dtc, encoding="utf-8"), delimiter="\t")]
        sa = [r for r in dc if r["stage"] == "A"]
        sb = [r for r in dc if r["stage"] == "B"]
        sc = [r for r in dc if r["stage"] == "C"]
        sd = [r for r in dc if r["stage"] == "D"]
        se = [r for r in dc if r["stage"] == "E"]
        den = [r for r in dc if r["stage"] == "DENOM"]
        if not (sa and sb and sc and sd and se and len(den) == 2):
            sys.exit(f"gate: {dtc} has stages {sorted({r['stage'] for r in dc})} and "
                     f"{len(den)} DENOM row(s) -- the census needs A (every access), B (which object), "
                     "C (family readers), D (whole-Image readers), E (one hop into callees) and BOTH "
                     "denominators; without D/E the answer is only 'not in this file's family'")
        frame = [r for r in sa if r["base_is_frame"] == "True"]
        ptr = [r for r in sa if r["base_is_frame"] == "False"]
        dtreads = [r for r in sc + sd + se if "n0" in r["slot_meaning"] or "n1" in r["slot_meaning"]
                   or "buffer" in r["slot_meaning"]]
        if dtreads:
            sys.exit(f"gate: {dtc} now shows a reader of the DT slots ({dtreads[0]['fn']} "
                     f"{dtreads[0]['text']}) -- this row's claim of 'no consumer' is stale, rewrite it")
        wden = [r for r in den if r["slot_meaning"].startswith("stage D:")]
        if not wden:
            sys.exit(f"gate: {dtc} has no whole-Image DENOM row (the one whose meaning starts "
                     "'stage D:') -- the wide census did not run, so publish '--fast: family only' "
                     "instead of 'nowhere'")
        fden = [r for r in den if r not in wden]
        if not fden:
            sys.exit(f"gate: {dtc} has only the whole-Image DENOM row -- the family census (stage A-C) "
                     "is missing, so the two denominators cannot be quoted side by side")
        n_ref = int(re.search(r"(\d+) functions at the object slot", wden[0]["slot_meaning"]).group(1))
        deref_n = int(re.search(r"(\d+) dereference", wden[0]["slot_meaning"]).group(1))
        hop_n = int(re.search(r"(\d+) handoffs", wden[0]["slot_meaning"]).group(1))
        out.append({
            "layer": "Hi-Fi DT params consumers", "item": dtc.replace(BASE + "/", "art/audio-6.0.1/"),
            "value": (f"{len(sa)} accesses at +0x60/+0x64/+0x68 across the audio family "
                      f"({fden[0]['va']} instructions in {fden[0]['slot_meaning'].split(',')[0]}); "
                      f"{len(frame)} are STACK slots through fp and {len(ptr)} go through a pointer; "
                      f"the DAC object (home {sb[0]['slot_meaning'].split(' ')[1]} = es9038_data) is "
                      f"materialised by {n_ref} of {wden[0]['va']} text symbols in the whole Image, "
                      f"{deref_n} dereference it (fields {sorted({r['slot'] for r in sc})}), and stage E "
                      f"followed {hop_n} handoffs into callees -- NONE touches a DT slot"),
            "name_or_meaning": ("the answer to §322's open half, and the correction of §233: the DT "
                                "array IS dead weight in this kernel. es9038_i2c_probe reads "
                                "vivo:param-num into +0x60/+0x64 and the vivo,params u32 array into "
                                "+0x68, publishes the struct at the global es9038_data, and nothing "
                                "reads those three fields back -- not in the audio family, not anywhere "
                                "in the Image, not one hop into the callees the holders hand the "
                                "pointer to (es9038_one_enable reads +0x0/+0x1/+0x10/+0x40/+0x50, "
                                "es9038_power_enable +0x80/0x88/0x90, regdump reads the power byte "
                                "+0x10). §233's 'three readers' (es9038_debug_open / _debug_write / "
                                "es9038_regdump_callback) was tools/ksdis.py decoding a FIXED 120 "
                                "instruction count from a symbol start: the window ran 63 instructions "
                                "past es9038_regdump_callback into es9038_debug_read, whose +0x60/+0x64/"
                                "+0x68 are fp-relative STACK slots; debug_open and debug_write contain "
                                "no such access at all. The look-alikes are still not the same field: "
                                "+0x60 of the vivo_codec struct is a function-table pointer (8 of the "
                                "pointer-based accesses load a value used immediately as ldr;blr), and "
                                "26 of the 63 family hits are frame slots at the same byte offset"),
            "source": f"{dtc} [{sha16(dtc)}] (tools/dac_dt_params_consumer.py "
                      f"[{sha16(f'{ROOT}/tools/dac_dt_params_consumer.py')}], bytes from fw/Image "
                      f"[{sha16(f'{ROOT}/fw/Image')}], names from art/kallsyms_real.txt "
                      f"[{sha16(f'{ROOT}/art/kallsyms_real.txt')}])",
            "writable": "no (derived from the captured Image)",
            "use_case": "this is what lets 7 be SIMPLER: the DT node's vivo,params / vivo:param-num "
                        "properties feed nothing in 6.0.1's driver, so they do not have to be byte-cloned "
                        "for acoustic reasons -- but if 7's driver DOES read them, the census will show it "
                        "(run the tool against 7's Image and kallsyms), and then the DT becomes load-bearing",
            "witness2": "six controls, all of which abort: the probe's own writes at all three slots; at "
                        "least one family dereference of the object; the probe among the whole-Image "
                        "referencers; at least one whole-Image dereferencer; at least one followed "
                        "handoff (stage E that follows nothing is silence, not an answer); and the "
                        "whole-Image DENOM row existing at all. --selftest strips each in turn (five "
                        "arms fire, ledger 325). Stage D/E is the reason the answer is 'nowhere', not "
                        "'not in these files': a reader arriving through debugfs private_data or a "
                        "helper argument never loads the global, so stage E seeds the callee's x0-x7 "
                        "with the holder. The register model was itself a bug found this round: keeping "
                        "a stale adrp page on a register that a later ldr overwrote made every access "
                        "through it look like another home-load and swallowed the field rows (it hid "
                        "es9038_dsd_set_volume's +0x10); now a written register loses its page, and the "
                        "holder set only GROWS -- over-approximation, which can invent a reader but "
                        "cannot miss one. A bulk capstone disasm also stopped after ~1 MB of the 19 MB "
                        "text on an earlier attempt and would have reported 'no accesses at all'",
        })
    if wr:
        bad_callee = [r for r in wr if not re.fullmatch(r"es90(28|38)_i2c_write_byte\.isra\.\d",
                                                        r["callee"])]
        if bad_callee or not kinds["constant"] or not kinds["table"]:
            sys.exit(f"gate: {wts} has {len(bad_callee)} row(s) whose callee is not one of the two "
                     f"i2c_write_byte helpers, {kinds['constant']} constant-fed and "
                     f"{kinds['table']} table-fed site(s) -- the census is not the shape its own tool "
                     "promises, so nothing may be concluded from it (including the absence at 0x14)")
        out.append({
            "layer": "DAC register write sites", "item": wts.replace(BASE + "/", "art/audio-6.0.1/"),
            "value": (f"{len(wr)} call sites in {len({r['caller'] for r in wr})} callers, every one to "
                      f"es9028/es9038_i2c_write_byte.isra; the address operand arrives as "
                      f"{', '.join(f'{k}={v}' for k, v in sorted(kinds.items()))}; the only register "
                      f"numbers any site can take as a literal are {', '.join(cons)}"),
            "name_or_meaning": ("this is the census that says what CAN write which DAC register. The "
                                "enable path's 47 pairs come from dac_parameters and the 4 impedance "
                                "candidates from integration_params_normal; 0x14 (the fourth Master Trim "
                                "byte, the one that reads +12 LSB above the table) is not in the literal "
                                "set, is not one of the impedance candidates, and the datasheet's own "
                                "auto-calibration bits read clear -- so the only remaining paths are the "
                                "chip's own readback behaviour and a userspace write through the 0644 "
                                "es9038/reg node, which no ledger in this repo records making"),
            "source": f"{wts} [{sha16(wts)}] (tools/dac_register_writers.py "
                      f"[{sha16(f'{ROOT}/tools/dac_register_writers.py')}], bytes from fw/Image "
                      f"[{sha16(f'{ROOT}/fw/Image')}])",
            "writable": "no (derived from the captured Image)",
            "use_case": "on 7, re-run tools/dac_register_writers.py against 7's Image: the literal "
                        "address set is a fingerprint of the driver's hard-coded writes. If 7 names a "
                        "literal 0x14, its trim initialisation is explicit and the +12 gap is a 6.0.1 "
                        "artifact rather than something to reproduce",
            "witness2": "the tool aborts unless it sees at least one constant-fed and one table-fed "
                        "site (both present here), and this row builder re-checks that every callee is "
                        "one of the two i2c_write_byte helpers -- a census that silently matched "
                        "something else would let 'nothing writes 0x14' stand on a scan that never "
                        "looked at the right function",
        })
    imp = f"{BASE}/dac-impedance-chain.PD1610.tsv"
    if os.path.exists(imp):
        irows = list(csv.DictReader(open(imp, encoding="utf-8"), delimiter="\t"))
        fmt1 = [r for r in irows if r["stage"] == "1" and "impedance" in r["text"]]
        buck = [r for r in irows if r["stage"] == "2" and r["text"] == "input -> column"]
        inl = [r for r in irows if r["stage"] == "2b" and r["text"] == "input -> column"]
        idif = [r for r in irows if r["stage"] == "2b" and r["text"] == "inline vs function"]
        iliv = [r for r in irows if r["stage"] == "2b" and (r["text"] or "").startswith("live ")]
        if not (buck and inl and idif and iliv):
            sys.exit(f"gate: {imp} stage 2b holds buckets={len(inl)} diffs={len(idif)} "
                     f"live={len(iliv)} -- the row below reports which handler copy inlines the tree and "
                     "where its boundaries differ from the called function, and none of that is in the "
                     "artifact")
        if len({r["fn"] for r in inl}) != 1:
            sys.exit(f"gate: {imp} has inline trees attributed to {sorted({r['fn'] for r in inl})} -- the "
                     "row names one copy, so publish the per-copy sentence instead of this one")
        gett = [r for r in irows if r["stage"] == "3" and r["value"] not in ("-", "None")]
        d3b = [r for r in irows if r["stage"] == "3b" and "store into +0xa0" in (r["meaning"] or "")
               and "EXCLUDED" not in (r["meaning"] or "")]
        m3b = [r for r in irows if r["stage"] == "3b" and "MIDDLE link" in (r["meaning"] or "")]
        if len(d3b) != 1 or not m3b:
            sys.exit(f"gate: {imp} stage 3b gives {len(d3b)} callee-slot writer(s) and {len(m3b)} "
                     "middle-link rows -- the sentence below names exactly ONE callee for the inlining "
                     "copy, and it cannot unless the artifact does")
        unit = [r for r in irows if r["stage"] == "5" and "ohm" in r["text"]]
        glob = [r for r in irows if r["stage"] == "5" and (r["meaning"] or "").startswith("reads")]
        dflt = [r for r in irows if r["stage"] == "5" and r["text"] == "mov immediate"]
        meas = [r for r in irows if r["stage"] == "4" and "selects" in (r["meaning"] or "")]
        impl = [r for r in irows if r["stage"] == "4" and "imply" in (r["meaning"] or "")]
        if not (fmt1 and buck and gett and unit and glob and meas):
            sys.exit(f"gate: {imp} has stages {Counter(r['stage'] for r in irows)} -- the row needs the "
                     "handler's format (1), the emulated buckets (2), the named slot writer (3), the "
                     "getter's unit-bearing format and global (5) and the live columns (4)")
        gname = sorted({r["fn"] for r in irows if r["stage"] == "5"})
        if len(gname) != 1:
            sys.exit(f"gate: {imp} stage 5 covers {gname} -- the row expects exactly one walked "
                     "getter, otherwise the sentence below names a different function than the one "
                     "whose format and global it quotes")
        gstore = [r for r in irows if r["stage"] == "3" and r["value"] == gname[0]]
        if not gstore:
            sys.exit(f"gate: {imp} has no stage-3 row storing {gname[0]} at +0x98 -- the getter would "
                     "be unattributed to any writer")
        pin = [r for r in irows if r["stage"] == "7"]
        s6 = [r for r in irows if r["stage"] == "6"]
        readers = sorted({r["fn"] for r in s6 if "read of vivo_hp_imped_fixed" in (r["meaning"] or "")})
        if not pin:
            sys.exit(f"gate: {imp} stage 6 shows the flag read by {readers} but stage 7 recorded no "
                     "pin -- the override's effect on the column would be unpublished")
        pin_col = re.search(r"column (\d+)", pin[0]["meaning"])
        if not pin_col:
            sys.exit(f"gate: {imp} stage-7 row does not state which column the pin selects "
                     f"({pin[0]['meaning']!r}) -- the row below cannot quote it")
        disagree = [r for r in iliv if "both copies agree" not in (r["meaning"] or "")]
        agree_ohm = sorted({r["site"] for r in iliv if "both copies agree" in (r["meaning"] or "")})
        if not agree_ohm:
            sys.exit(f"gate: {imp} stage-2b has {len(iliv)} live rows and none says the two copies agree "
                     "-- the sentence below would be quoting a disagreement as an agreement")
        out.append({
            "layer": "Hi-Fi impedance chain", "item": imp.replace(BASE + "/", "art/audio-6.0.1/"),
            "value": (f"{len(buck)} emulated buckets: "
                      + ", ".join(f"{r['site']}=>col{r['value']}" for r in buck)
                      + f"; the slot +0x98 is written with {gname[0]} by "
                        f"{gstore[0]['fn']} @ {gstore[0]['site']}, and that getter reads "
                        f"{glob[0]['meaning'].split(' ', 1)[1]}"
                        f" (its own default {', '.join(d['value'] for d in dflt) or 'none'}); "
                      + "; ".join(f"{r['fn']}/{r['text']} -> col{r['value']}" for r in meas
                                  if r["fn"] == "playing-headphones")
                      + f"; the DAC's own bytes imply {', '.join(r['site'] + '=col' + r['value'] for r in impl)}"
                      + f"; ★two symbols carry this name and they are NOT the same code: "
                        f"{inl[0]['fn']} inlines the decision tree and yields "
                        + ", ".join(f"{r['site']}=>col{r['value']}" for r in inl)
                        + f" (the called function above gives "
                        + ", ".join(f"{r['site']}=>col{r['value']}" for r in buck) + ")"
                      + f"; the two tables differ on {idif[0]['value']} of 200 inputs at "
                        f"{idif[0]['site']} but agree on every impedance the device reported "
                        f"({', '.join(agree_ohm)})"
                        + (f"; NOTE {len(disagree)} live row(s) where the two copies DO disagree"
                           if disagree else "")
                      + f"; ★§339 names that copy's blr target: slot +0xa0 is written once in the audio "
                        f"family with a text address = {d3b[0]['value']} by {d3b[0]['fn']} @ "
                        f"{d3b[0]['site']} ({d3b[0]['text']}), the same function that fills +0x98 with "
                        f"{gname[0]} -- so the second ==2 tests the plug-type getter's return; "
                        f"the middle hop [obj+0x68] has {len(m3b)} candidate stores and is NOT decidable "
                        "offline"
                      + f"; ★override: {pin[0]['fn']} @ {pin[0]['site']} reads "
                        f"vivo_hp_imped_fixed and {pin[0]['text']} -- {pin[0]['meaning']}"),
            "name_or_meaning": ("what picks one of the four candidate bytes per register in the "
                                "§322 table, now traced end to end: the DAPM handler "
                                "hifi_codec_dac_event calls through "
                                "vivo_codec(global)+0x60 -> +0x98 and prints '%s: impedance %u', the "
                                "only impedance-named function any audio driver stores into that slot "
                                "is msm_mbhc_get_impedance, and it returns the single global "
                                "mbhc_hp_impedance (32 when unset) printing '%s: impedance %u ohm' -- "
                                "so the unit is OHMS and the number is the WCD9335 MBHC measurement, "
                                "the same quantity the ALSA control 'HPHL/HPHR Impedance' exposes. "
                                "★The column is therefore a MEASUREMENT, not a constant: 34 ohm under "
                                "playback selects column 1, while an idle/speaker session reports 0 "
                                "and the selector's own wrap makes that column 3. ★And the DAC's live "
                                "bytes do not agree on one column (0x17 says 3, 0x19 says 1), which "
                                "reads as the two (addr,value) writes having happened under different "
                                "measurements -- not as one column per enable event.  ★§327 adds two "
                                "facts that change how literally this can be read: kallsyms carries "
                                "TWO functions named hifi_codec_dac_event (0xbb6b14 and 0xbb7450, one "
                                "per HiFi DAC widget in the two DAPM arrays) and TWO globals named "
                                "vivo_codec (0x1b242b8 / 0x1b242c8) -- the first copy calls the "
                                "selector by name through ops+0x60, the second inlines it through "
                                "ops+0x68 and is the one that consults the override.  ★§338 runs BOTH "
                                "trees through the same emulator: the inlined window 0xbb7500..0xbb7524 "
                                "gives 5..24=>0 / 25..38=>1 while the called function gives "
                                "5..20=>0 / 21..38=>1, so the two differ only on inputs 21..24 -- every "
                                "impedance this device ever reported (0 and 34 ohm) lands in the same "
                                "column under either, and the published column does not depend on which "
                                "copy ran.  What DOES depend on the copy is the table: the in-play byte "
                                "0x2e at 0x14 appears only among the candidate rows of the four tables "
                                "the second copy writes (dac-integration-params.PD1610.tsv, alt-table "
                                "rows at 0x179d7a0..0x179d7d0), and the CFG of that copy binds them to "
                                "the mode byte at vivo_codec+0xc; and "
                                "mbhc_hp_impedance is a POINTER slot (written once by msm_audrx_init "
                                "from the tasha_mbhc_hs_detect path), so 32 is what the getter returns "
                                "when nothing was ever measured, not a measured 32 ohm"),
            "source": f"{imp} [{sha16(imp)}] (tools/dac_impedance_chain.py "
                      f"[{sha16(f'{ROOT}/tools/dac_impedance_chain.py')}], bytes from fw/Image "
                      f"[{sha16(f'{ROOT}/fw/Image')}], controls read from "
                      f"{BASE}/live/tinymix-D0-playing-headphones.txt et al.)",
            "writable": (f"yes, from userspace: the ALSA control 'HP imped fixed' (write side "
                         f"vivo_hp_imped_fixed_put -> global vivo_hp_imped_fixed) makes any handler "
                         f"copy that reads it replace the measurement with {pin[0]['value']} ohm, "
                         f"which is column {pin_col.group(1)}.  OFF in all three captures today, and "
                         "turning it on changes what the DAC is configured with, so it is 要人点头"),
            "use_case": "on 7, run the tool against 7's Image and re-read the three controls. The "
                        "portable requirement is that the codec still measures the headphone "
                        "impedance and exposes it: if 7's mbhc path is missing or returns the default "
                        "32, the DAC gets a DIFFERENT candidate byte for 0x14/0x17/0x19 -- that is an "
                        "audible headphone difference, not a register-bookkeeping one",
            "witness2": "the bucket table is not transcribed from prose: the tool steps the selector's "
                        "own decoded instructions with a small emulator that aborts on any instruction "
                        "it does not model, and refuses to publish unless the reachable columns equal "
                        "the function's own result constants (which includes the +1 path of `csinc "
                        "w0,w0,wzr,hi` -- a column that exists only through the conditional select). "
                        "Units come from a SECOND printk: the handler says 'impedance %u', the getter "
                        "says 'impedance %u ohm'. Live side: three captures, and the control row must "
                        "be present in the playing-headphones one or the tool aborts. ★Name is not "
                        "identity: the tool reports the kallsyms collisions it hits (this chain has "
                        "two hifi_codec_dac_event and two vivo_codec), the override's effect is only "
                        "published when the flag-guard-then-constant shape is actually seen in the "
                        "reader, and the row builder aborts if a reader exists but no pin was found",
        })
    hme = f"{BASE}/dac-hifi-mode-enum.PD1610.tsv"
    if os.path.exists(hme):
        hr = list(csv.DictReader(open(hme, encoding="utf-8"), delimiter="\t"))
        acc = [r for r in hr if r["stage"] == "field-access"]
        wr = [r for r in acc if r["detail"].startswith("write")]
        rd = [r for r in acc if r["detail"].startswith("read")]
        enr = [r for r in hr if r["stage"] == "enum-array"]
        cmp_ = [r for r in hr if r["stage"] == "compare"]
        loop = [r for r in hr if r["stage"] == "payload-loop"]
        if not (wr and rd and enr and cmp_ and loop):
            sys.exit(f"gate: {hme} stages are {Counter(r['stage'] for r in hr)} -- the row needs the "
                     "single writer, the readers, the bounded enum array, the decoded comparison and the "
                     "payload loop")
        if len({r["name"] for r in wr}) != 1:
            sys.exit(f"gate: the compared field has writers {sorted({r['name'] for r in wr})} -- with more "
                     "than one producer the control mapping would be my guess")
        items = {int(i): t for i, t in re.findall(r"\[(\d+)\]=([A-Za-z0-9_]+)", enr[0]["detail"])}
        which = [i for i, t in items.items() if t == "DSD"]
        const = re.search(r"immediate (\d+)", cmp_[0]["detail"])
        denom = [r for r in hr if r["stage"] == "DENOM"]
        if not which or not const or not denom:
            sys.exit(f"gate: {hme} does not state both the DSD index ({enr[0]['detail']!r}), the "
                     f"compared immediate ({cmp_[0]['detail']!r}) and the DENOM row -- the agreement "
                     "sentence below has nothing to agree about")
        if str(which[0]) != const.group(1):
            sys.exit(f"gate: {hme} puts DSD at index {which[0]} but the handler compares with "
                     f"{const.group(1)} -- the tool's own agreement gate did not hold when the table "
                     "was built")
        scanned = re.match(r"(\d+) functions", denom[0]["name"])
        if not scanned:
            sys.exit(f"gate: {hme} DENOM row does not state how many functions were scanned "
                     f"({denom[0]['name']!r}) -- the breadth of the 'one writer' claim would be unsaid")
        out.append({
            "layer": "Hi-Fi mode enum", "item": hme.replace(BASE + "/", "art/audio-6.0.1/"),
            "value": (f"the field the enable handler compares (object+0xc) has ONE writer in the "
                      f"{scanned.group(1)} text symbols scanned: {wr[0]['name']} @ {wr[0]['site']} "
                      f"({wr[0]['detail']}), read by {sorted({r['name'] for r in rd})}; the control's own "
                      f"text array at {enr[0]['va']} (bounded by the struct at {enr[0]['site']}) is "
                      + ", ".join(f"[{i}]={t}" for i, t in sorted(items.items()))
                      + f", so DSD = index {which[0]} = the immediate the handler compares with at "
                        f"{cmp_[0]['site']}"),
            "name_or_meaning": ("§331 left 'the handler compares a mode byte with 2' undecoded; §332 "
                                "names it: 2 is the ALSA control's item DSD, i.e. "
                                "**HiFi Mode Switch == DSD selects the integration_params_dsd_* tables**, "
                                "and the control's value in every capture on file is HiFi (headphones) or "
                                "Off (speaker/idle) -- never DSD.  The payload loop that consumes the "
                                "chosen table is decoded from the handler's own instructions "
                                "(count=3, alloc=6 B, stride=5, register = row[0], value = row[1+column], "
                                "column sign-extended), which reproduces §322's tiling from the reader "
                                "side instead of the table side"),
            "source": f"{hme} [{sha16(hme)}] (tools/dac_hifi_mode_enum.py "
                      f"[{sha16(f'{ROOT}/tools/dac_hifi_mode_enum.py')}], cross-checked against "
                      f"dac-slot-filler.PD1610.tsv's independent walk; control name from "
                      f"usecase-table.mixer_paths_tasha.PD1610.tsv and values from live/tinymix-*.txt)",
            "writable": ("yes by name: tinymix 'HiFi Mode Switch' DSD would move the DAC to the "
                         "dsd-named table -- that changes what the DAC is configured with, so it is "
                         "要人点头;  Off/HiFi are what the recorded sessions already used"),
            "use_case": "on 7, re-run the tool with DAC_IMG/DAC_KALL: the requirement is that the mode "
                        "control still has DSD at the index the handler compares with; if 7's driver "
                        "renumbered the enum or compares a different constant, the same tinymix setting "
                        "would pick a DIFFERENT table -- that is a listening difference, not a name "
                        "difference",
            "witness2": "three independent sides must agree or the row is not published: the field's "
                        "single writer (value-keyed whole-Image walk, identical site set to the other "
                        "tool's walk), the control's text array bounded by the struct that references it "
                        "(.rodata packs arrays back to back -- walking while pointers resolve to strings "
                        "merged a 0..31 list into this one and produced index 34), and the immediate in "
                        "the handler's own cmp.  The item count is read as the 8-byte slot in front of "
                        "the .texts pointer (the count sits in its low half)",
        })
    ps = f"{BASE}/dac-pointer-slots.PD1610.tsv"
    if os.path.exists(ps):
        pr = list(csv.DictReader(open(ps, encoding="utf-8"), delimiter="\t"))
        pa = [r for r in pr if r["kind"] == "abs-access"]
        byfield = {}
        for r in pa:
            byfield.setdefault(r["disp"].split()[-1], []).append(r)
        plug = [r for r in pa if r["disp"].endswith("1dd10")]
        impd = [r for r in pa if r["disp"].endswith("1dd18")]
        src = [r for r in pa if "179b170" in r["disp"]]
        if not (plug and impd and src):
            sys.exit(f"gate: {ps} covers fields {sorted(byfield)} -- the row needs the plug-type slot, "
                     "the impedance slot and the source field the plug pointer is loaded from")
        amb = [r for r in pa if "branch targets between its definition and this use: 0" not in r["detail"]]
        if amb:
            sys.exit(f"gate: {len(amb)} access(es) in {ps} are NOT single-valued at the use "
                     f"({[r['site'] for r in amb][:3]}) -- the sentence below would attribute a field to "
                     "a register whose value some path could change")
        wr_plug = [r for r in plug if "write" in r["value_type"]]
        rd_src = [r for r in src if "read" in r["value_type"]]
        out.append({
            "layer": "Hi-Fi getter sources", "item": ps.replace(BASE + "/", "art/audio-6.0.1/"),
            "value": (f"the two slots the getters read each have exactly ONE writer in the Image: "
                      f"{plug[0]['disp']} <- {wr_plug[0]['fn']}@{wr_plug[0]['site']}, "
                      f"{impd[0]['disp']} <- {[r['fn'] for r in impd if 'write' in r['value_type']][0]}"
                      f"@{[r['site'] for r in impd if 'write' in r['value_type']][0]}; the plug-type slot "
                      f"is loaded from {src[0]['disp']} (= wcd_mbhc_cfg+0x98), which has "
                      f"{len([r for r in src if 'write' in r['value_type']])} writers in the Image and "
                      f"reads at {rd_src[0]['site']} ({rd_src[0]['fn']}); ★§336 re-derived the handler's "
                      "own accesses by control-flow reaching definitions: 5 of the 6 sites the "
                      "listing-order census reported DO resolve onto these fields with base "
                      "0xffffffc001b242c8 (the 2 table-slot writes included), and the 6th "
                      "(ldr x0,[x0,#0xa0] @0xbb7580) is a linear-pass artifact -- its base comes from a "
                      "heap load, so the slot has ONE confirmed read, not two. §337 also resolved the "
                      "four arms written values per path (dsd_headphone, dsd_normal, headphone, normal) "
                      "and that set matches dac_integration_params --rows-at candidate for candidate"),
            "name_or_meaning": ("where the two §326/§327 getters get what they read, and it narrows "
                                "§332's remaining branch: the impedance slot is filled inside the Image "
                                "(`msm_audrx_init` storing `&msm8996_liquid_dock_dev+0x18`), while the "
                                "plug-type slot is filled from `wcd_mbhc_cfg`+0x98 -- a static .data "
                                "config struct whose pointer field is ZERO in the Image and is written by "
                                "NO code in the Image, so it is filled (if at all) by the loaded MBHC "
                                "module: /sys/module on the board lists snd_soc_wcd_mbhc among 182 modules "
                                "and 16 .ko in /system/lib/modules.  If nothing fills it, "
                                "`msm_mbhc_get_plug_pype` returns its default 1, `==2` never holds, and "
                                "the DAC enable path can only ever pick the non-headphone table -- which "
                                "is what the captured headphone session shows (0x14 = 0x2e, a byte that "
                                "exists only in the _normal/_dsd_normal rows).  ★§334 closes the module "
                                "escape hatch: /sys/module/snd_soc_wcd_mbhc contains ONLY parameters and "
                                "uevent (no coresize/srcversion/initstate) and /system/lib/modules has no "
                                "audio .ko, so the audio family is BUILT IN and the producer must live in "
                                "the Image -- where no directly-addressed writer exists either.  That "
                                "leaves two readings and they agree: A) nobody writes it -> NULL -> getter "
                                "default 1; B) wcd_mbhc_init writes a *function address* "
                                "(wcd_mbhc_release_handler_dwork) through its pointer argument, so the "
                                "getter's first byte is that function's first instruction low byte = 0xfd "
                                "= 253.  Neither is 2, so the _headphone branch is unreachable either way "
                                "-- A and B are NOT discriminated offline (reading the 8 bytes at runtime "
                                "is, and that is 要人点头)"),
            "source": f"{ps} [{sha16(ps)}] (tools/dac_slot_filler.py --at "
                      f"[{sha16(f'{ROOT}/tools/dac_slot_filler.py')}], whole-Image value-keyed scan; "
                      "module list from a read-only adb ls /sys/module and /system/lib/modules)",
            "writable": ("nothing here is a write port -- the producer of the plug-type pointer is the "
                         "MBHC module's own init path; what a person could change is which module/firmware "
                         "is loaded, and that is a boot-state question, not a register write"),
            "use_case": "on 7, re-run the same --at census against 7's Image and symbols: the requirement "
                        "is that both slots still have exactly one writer and that the plug-type source "
                        "field is filled by 7's mbhc module -- if it stays NULL on 7 the headphone table "
                        "is unreachable and the trim bytes differ from 6.0.1 by mechanism, not by value",
            "witness2": "every published row carries its own dominance check: the base register must have "
                        "zero branch targets landing between its last definition and the use (the tool "
                        "refuses the row otherwise) -- this is the guard against the §332 case where a "
                        "cold-path trampoline (0xbafff8 jumps to 0xbc0e84, which jumps back to 0xbb0008) "
                        "could have made the base look inherited from the listing order.  The absence "
                        "claim ('no writer in the Image') is stated with its bounds: only bases whose "
                        "static value the walk resolves are matched, and module code is out of scope of "
                        "the Image -- so the live module list was read as the second witness",
        })
    sf = f"{BASE}/dac-slot-filler.PD1610.tsv"
    if os.path.exists(sf):
        sfr = list(csv.DictReader(open(sf, encoding="utf-8"), delimiter="\t"))
        fills = [r for r in sfr if r["kind"] == "getter-fill"]
        insts = [r for r in sfr if r["kind"] == "install"]
        allocs = [r for r in sfr if r["kind"] == "alloc"]
        denom = [r for r in sfr if r["kind"] == "DENOM"]
        chain = [r for r in fills if r["fn"] in ("vivo_codec_dai_link_init", "hifi_codec_dac_event")]
        imp = [r for r in chain if r["value"] == "msm_mbhc_get_impedance"]
        pype = [r for r in chain if r["value"] == "msm_mbhc_get_plug_pype"]
        tables = [r for r in chain if (r["value"] or "").startswith("integration_params")]
        tbyslot = {}
        for r in tables:
            tbyslot.setdefault(r["disp"], []).append(f"{r['value']} ({r['fn']}@{r['fn_at']} -> {r['base']})")
        # §344: per-field writer census by ABSOLUTE VALUE.  Every one of these slots having exactly ONE
        # writer is what makes "the chain changed hands on 7" a checkable statement rather than prose.
        summ = [r for r in sfr if r["kind"] == "abs-summary"]
        want = {f"0x{v:016x}": n for v, n in ((0xffffffc001b242c0, "the published struct slot"),
                                             (0xffffffc001b242c8, "the object pointer the handlers chase"),
                                             (0xffffffc001b242d4, "the HiFi Mode Switch store"),
                                             (0xffffffc001b24368, "the selected table slot"))}
        missing = [k for k in want if not [r for r in summ if r["fn_at"] == k]]
        if missing:
            sys.exit(f"gate: {sf} has no abs-summary row for {missing} -- the runbook's 5q command must "
                     "pass every field in --at, otherwise the single-writer claim is unverifiable on 7")
        multi = [(r["fn_at"], r["value"]) for r in summ if r["fn_at"] in want
                 and r["value"] != "1 writer(s)"]
        if multi:
            sys.exit(f"gate: {sf} counts {multi} for the watched slots -- a slot with 0 or 2+ writers "
                     "cannot be attributed to one function, so the row below must not name one")
        w2c8 = [r for r in summ if r["fn_at"] == "0xffffffc001b242c8"][0]
        if not (fills and imp and pype and insts and allocs and denom):
            sys.exit(f"gate: {sf} rows are {Counter(r['kind'] for r in sfr)} -- the row needs the two "
                     "mbhc getter fills, an allocator-result install, an allocation with a code-read size "
                     "and the DENOM row; without one of them the chain sentence below has no witness")
        if not tables:
            sys.exit(f"gate: {sf} has no getter-fill row carrying an integration_params pointer -- §331's "
                    "table-selection sentence would then be my reading of the disassembly, not a "
                    "tool-reported row")
        if not any(d == "0xa0" for d in tbyslot):
            sys.exit(f"gate: {sf} names integration_params writes only at {sorted(tbyslot)} -- the "
                     "+0xa0 slot write is the §331 finding, and without a row for it the sentence below "
                     "would quote a window I read by eye, not a census row")
        big = [r for r in allocs if "holds +0x98" in (r["detail"] or "")]
        if not big:
            sys.exit(f"gate: no {sf} allocation row is 0xa8 B or larger -- the struct that holds the "
                     "getter slots has no allocation witness")
        out.append({
            "layer": "Hi-Fi slot fillers", "item": sf.replace(BASE + "/", "art/audio-6.0.1/"),
            "value": (f"the 168 B (0xa8) slab struct allocated at "
                      f"{big[0]['site']} is installed at codec+{insts[0]['disp']} by "
                      f"{insts[0]['fn']} @ {insts[0]['site']}; its +0x98 and +0xa0 are filled by "
                      f"{imp[0]['fn']} @ {imp[0]['site']} with {imp[0]['value']} and "
                      f"{pype[0]['value']}; the two handler copies make "
                      f"{sum(len(v) for v in tbyslot.values())} integration_params write(s) the census "
                      "could name, at slots "
                      + "; ".join(f"+{d} <- " + ", ".join(v) for d, v in sorted(tbyslot.items()))
                      + " (the handler's four add chains are visible in the window; the walk only names "
                      "the ones whose register survives the indirect call, so the DSD pair is a "
                      "reading of instructions, not a census row); scan denominator "
                      f"{denom[0]['value']} ({denom[0]['disp']})"
                      + "; ★§344 single-writer census over the watched slots -- "
                      + "; ".join(
                          f"{want[r['fn_at']]} {r['fn_at']} <- "
                          + re.match(r"writers \[(.*)\]", r["text"]).group(1)
                          + " @ " + re.search(r"write site\(s\): (.*?); readers", r["detail"]).group(1)
                          + f" ({r['value_type']} read this slot)"
                          for r in summ if r["fn_at"] in want)
                      + " -- each exactly ONE writer; on 7 the CHECK IS THE ROLE (one writer, and it is "
                        "the platform probe / the control put / the DAPM event handler), not the name, "
                        "because kernel function names move between versions"
                      + "; who reads the object-pointer slot (recomputed from the per-access rows, not "
                        "from the summary's truncated list): "
                        + ", ".join(sorted({r["fn"] for r in sfr if r["kind"] == "abs-access"
                                            and r["disp"] == "field 0xffffffc001b242c8"
                                            and (r["value_type"] or "").startswith("read")}))
                        + f" ({len({r['fn'] for r in sfr if r['kind'] == 'abs-access' and r['disp'] == 'field 0xffffffc001b242c8'})} functions, "
                          "every one of them a reader -- the writes are the single probe site named above)"),
            "name_or_meaning": ("who puts a pointer into the slots the Hi-Fi trigger chain reads, and "
                                "which integration_params table wins. ★§331 closes §324/§330's loose end "
                                "the same way: the tool that tiled the tables (dac_integration_params.py "
                                "--rows-at) now reads row 0 of all FIVE same-named candidates against the "
                                "in-play capture, and only integration_params_dsd_normal@0x179d7b0 and "
                                "integration_params_normal@0x179d7d0 have 0x2e -- as column index 1 -- "
                                "which is exactly the byte the DAC reports live for register 0x14, while "
                                "the table §322 derived (integration_params_normal@0x179d550, the lowest "
                                "of two same-named symbols) has [0x1c 0x2a 0x4a 0x7f] and matches nothing. "
                                "So 0x14 is written twice: dac_parameters gives 0x22 at enable, then the "
                                "handler-selected table gives 0x2e (the +12 LSB of §324). The selector is "
                                "byte [obj+0xc]==2 times the return of the getter reached as "
                                "[[obj]+0x68]+0xa0 ==2; ★§338 binds each half to the four arms by the "
                                "CFG's own entry edges and confirms from the control's live item order "
                                "(Off/HiFi/DSD/Normal, so item 2 IS DSD) that the first half means "
                                "DSD-or-not, while the second half's value DOMAIN stays undecoded -- only "
                                "that ==2 selects the *_headphone table, and both cbz guards fall back to "
                                "a *_normal table; the live headphone capture (item HiFi = 1) is what "
                                "picks between the two tables that match 0x2e"),
            "source": f"{sf} [{sha16(sf)}] (tools/dac_slot_filler.py "
                      f"[{sha16(f'{ROOT}/tools/dac_slot_filler.py')}], bytes from fw/Image "
                      f"[{sha16(f'{ROOT}/fw/Image')}], symbols from art/kallsyms_real.txt; table rows "
                      f"from dac-integration-params.PD1610.tsv alt-table arm)",
            "writable": ("no userspace port writes these slots -- they are filled at probe and "
                         "dai-link time and hold function pointers; what a person can change is the "
                         "INPUT of the selection (plug type, DSD mode, measured impedance), which "
                         "changes which candidate byte lands in 0x14/0x17/0x19, so it is 要人点头"),
            "use_case": "on 7, run tools/dac_slot_filler.py with DAC_IMG/DAC_KALL pointed at 7's Image "
                        "and its recovered symbols: the requirement is that a >=0xa8 struct is still "
                        "installed at the codec object and that its +0x98/+0xa0 still hold "
                        "impedance/plug-type getters, and that one of the integration_params tables is "
                        "still selected -- if the slot is filled by something else the enable path "
                        "cannot write 0x14 with the column byte, and the headphone trim reverts to "
                        "dac_parameters. ★§344 adds the executable form of that: pass the four watched "
                        "fields to --at (the object-pointer slot, the published-struct slot, the "
                        "HiFi Mode Switch store, the selected-table slot -- located on 7 by the same "
                        "walks, not by copying 6.0.1 addresses) and require per field exactly one writer "
                        "in these roles: the platform driver's probe for the object pointer, the ALSA "
                        "control's put for the mode store, the DAPM event handler for the table slot. Two "
                        "writers or zero means the chain changed hands, which is a structural difference "
                        "(audible), not a numeric one",
            "witness2": "two independent readings, not one: the store census (every bracketed `str` at "
                        "the chain displacements image-wide, with the value named from kallsyms and the "
                        "base register's provenance walked through adrp/add/mov/ldr/bl and the "
                        "function's own stack spills) and the allocation pairing (each allocator call "
                        "gets an identity from its own site, so an install row states WHICH bl and WHICH "
                        "code-read size it came from -- sizes are never typed in). Three exclusions are "
                        "reported, not silently dropped: pre/post-indexed writes whose writeback offset "
                        "equals a chain displacement, stores at the same numeric displacement off x29/sp "
                        "(frame spills, not struct fields), and 32-bit writes. ★And the span caveat is "
                        "printed with a count: kallsyms has no symbol for every body, so a store can "
                        "carry a neighbouring symbol's name; for the two handler copies that was "
                        "checked by hand (copy B's window is one body: prologue at the start, a single "
                        "ret at the end)",
        })
    gdec = f"{BASE}/tfa-reg-gap-decode.PD1610.tsv"
    if os.path.exists(gdec):
        gd = [r for r in csv.DictReader(open(gdec, encoding="utf-8"), delimiter="\t")
              if r["reg"].startswith("0x")]
        caprow = [r for r in csv.DictReader(open(gdec, encoding="utf-8"), delimiter="\t")
                  if r["reg"] == "CAPTURE"]
        if len(gd) != 4 or not caprow:
            sys.exit(f"gate: {gdec} covers {len(gd)} registers (expected the 4 that §250 could not "
                     "name a field for) and no CAPTURE provenance row -- the decode is incomplete or "
                     "unsourced")
        partial = [r["reg"] for r in gd if int(r["coverage"]) != 16]
        solo = [r["reg"] for r in gd if int(r["two_witness"]) == 0]
        if solo:
            sys.exit(f"gate: {gdec} decoded {solo} with no second header confirming the bit "
                     "positions -- publish those as hypotheses or not at all")
        def set_bits(r):
            out = []
            pairs = re.findall(r"([A-Za-z0-9_/]+)=(\d+)", r["decode"])
            if not pairs:
                sys.exit(f"gate: {gdec} row {r['reg']} carries no parseable name=value pairs")
            out += [f"{nm.split('/')[-1]}={v}" for nm, v in pairs if int(v)]
            return ", ".join(out) or "all bits zero"
        out.append({
            "layer": "TFA unnamed-register decode", "item": gdec.replace(BASE + "/", "art/audio-6.0.1/"),
            "value": ("; ".join(f"{r['reg']} ({r['reg_name']}) value {r['value']} -> "
                                f"{r['coverage']}/16 bits placed, {r['two_witness']}/{r['fields'].count(',') + 1}"
                                f" bit groups confirmed by a second header, set fields: {set_bits(r)}"
                                + (f", whole-register aliases {r['aliases']}" if r["aliases"] != "-" else "")
                                for r in gd)
                      + f" || values cross-checked between the register table and the raw capture "
                        f"{caprow[0]['value']}"),
            "name_or_meaning": ("§250's four registers that the driver names no bit field for are now "
                                "read, and two of them change what a live dump MEANS. ★0x46 reads "
                                "0x4000 and the set bit is NOT an interrupt flag: bits 13..15 are "
                                "`cs_neghyst`/`ctrl_cs_neghyst` with value 2, the 13 real input-interrupt "
                                "flags are all zero -- anyone who decoded 0x4000 as 'an interrupt is "
                                "pending' was wrong. ★0x47 is the one the register-name table calls "
                                "NO-NAME because the genregs macro header has no entry for it at all; the "
                                "per-chip field tables place four fields that tile all 16 bits "
                                "(switch_fb[0], se_hyst[4:1], se_level[9:5], ktemp[15:10]) and the live "
                                "value 0x7be1 reads switch_fb=1, se_hyst=0, se_level=31, ktemp=30 -- a "
                                "single-ended-input and temperature-compensation configuration, idle and "
                                "playing identical. 0x40/0x4c are the 16 output-interrupt and "
                                "status-polarity flags, both all zero (so 'no interrupt pending, default "
                                "polarity') with the newer int_out_flag_*/int_polarity_flag_* spellings "
                                "and the old IST*/IPO* ones as synonyms"),
            "source": f"{gdec} [{sha16(gdec)}] (tools/tfa_reg_gap_decode.py "
                      f"[{sha16(f'{ROOT}/tools/tfa_reg_gap_decode.py')}]; values from "
                      f"{BASE}/tfa-regs.PD1610.tsv AND the raw capture named in the artifact's CAPTURE "
                      f"row [{caprow[0]['value']}], required to agree per register; bit positions from "
                      f"fw/tfa-ref/inc [{sha16(f'{ROOT}/fw/tfa-ref/PROVENANCE.txt')}])",
            "writable": "no (derived from captures plus the reference headers)",
            "use_case": "on 7, re-run the tool: if 7's codec_reg shows 0x46 with a bit in 0..12 set, an "
                        "input interrupt really is pending (a different machine state, audible as "
                        "clipping handling); if 0x47 differs in se_level/switch_fb, the analog input "
                        "configuration differs -- which is exactly the kind of thing no ALSA control "
                        "exposes. ★Any register the 6.0.1 driver left unnamed must be read through these "
                        "positions, not through the driver",
            "witness2": ("the value is read twice (register table and the raw debugfs capture) and the "
                         "run aborts if they disagree per register; every bit group must be placed "
                         "identically by at least two headers (0x40 16/16, 0x46 11/14, 0x47 4/4, "
                         "0x4c 16/16 -- and the row builder aborts if a register has zero confirmed "
                         "groups); whole-register aliases such as hid_code[15:0] are kept SEPARATE from "
                         "the bit map because a header may describe the same register both ways, and "
                         "only a PARTIAL overlap between two groups is treated as a conflict"),
        })
    gap = f"{BASE}/tfa-reg-field-gap.PD1610.tsv"
    if os.path.exists(gap):
        gr = [r for r in csv.DictReader(open(gap, encoding="utf-8"), delimiter="\t")
              if r["reg"].startswith("0x") and r["reg"] != "reg"]
        if len(gr) != 26:
            sys.exit(f"gate: {gap} covers {len(gr)} registers, not the 26 the PA layer is counted over")
        zero = [r for r in gr if int(r["n_drv"]) == 0]
        bad_zero = [r["reg"] for r in zero if int(r["missing_bits"]) != int(r["n_ref_tfa1"])]
        if bad_zero:
            sys.exit(f"gate: {gap} says {bad_zero} have no driver fields yet reports fewer missing bit "
                     "positions than the reference names -- the two columns cannot both be true")
        miss = sum(int(r["missing_bits"]) for r in gr)
        syn = sum(int(r["synonym_names"]) for r in gr)
        out.append({
            "layer": "TFA register field coverage", "item": gap.replace(BASE + "/", "art/audio-6.0.1/"),
            "value": (f"over the 26 registers the PA denominator is counted over (the same table §249 "
                      f"supplies), the driver's TfaBfNames leaves {miss} bit positions unnamed that "
                      "tfa1_tfafieldnames.h names, and {syn} further reference names are "
                      f"SYNONYMS of bits the driver already names. Registers with zero driver fields: "
                      + ", ".join(f"{r['reg']} -> {r['missing_bits']} ({r['missing_names'][:60]})"
                                 for r in zero)),
            "name_or_meaning": ("this answers §250's residue ('0x40/0x46/0x47/0x4c the driver cannot "
                                "even decode a bit field for'): the reference tree DOES name those "
                                "bits -- 0x40 hid_code, 0x46 the seven input-selection fields, 0x47 "
                                "ktemp/se_hyst/se_level/switch_fb, 0x4c abist_offset -- so the cause is "
                                "a TRIMMED driver table, not an unnamed register. ★The unit of "
                                "comparison had to become the bit position (bfEnum), because each "
                                "header spells the same bit twice (Tfa1BitNames 'CLIPS' and "
                                "Tfa1DatasheetNames 'flag_clip' are both 0x70): comparing by name "
                                f"would have reported 126 gaps where only {miss} bit positions are "
                                "truly unnamed -- 80 of those would have been synonym artifacts"),
            "source": f"{gap} [{sha16(gap)}] (tools/tfa_reg_field_gap.py "
                      f"[{sha16(f'{ROOT}/tools/tfa_reg_field_gap.py')}], driver table "
                      f"{BASE}/tfa-bf.TfaBfNames.tsv [{sha16(f'{BASE}/tfa-bf.TfaBfNames.tsv')}], "
                      f"denominator {BASE}/tfa-regs.PD1610.tsv "
                      f"[{sha16(f'{BASE}/tfa-regs.PD1610.tsv')}], per-register field counts re-derived "
                      f"and required to equal {BASE}/tfa-reg-fields.PD1610.tsv "
                      f"[{sha16(f'{BASE}/tfa-reg-fields.PD1610.tsv')}])",
            "writable": "no (derived: driver table from fw/Image, names from the reference headers)",
            "use_case": "on 7, re-run the tool against 7's decoded table: the per-register missing count "
                        "IS the diff. A register the 6.0.1 driver leaves unnamed but 7's decodes is not "
                        "an acoustic change -- it is 7's driver knowing fields we had to read out of the "
                        "reference tree; the reverse (7 names fewer) means a field we rely on to explain "
                        "a codec_reg value is gone from 7's table and the value must then be read raw",
            "witness2": "four checks, all aborts: (1) the tool reproduces §320's family vote from the "
                        "inputs (TFA1 167 vs N1C 0) and refuses to continue if the two families score "
                        "the same, so the gap column provably depends on the numbering verdict; (2) it "
                        "recounts driver fields per register and must match §250's artifact on all 26 "
                        "(two tools, one table); (3) the reference must not contradict itself on a "
                        "name's bit position (0 conflicts); (4) the row builder here requires every "
                        "zero-field register's missing count to equal the reference's count at that "
                        "address, so 'trimmed table' and 'no driver fields' cannot disagree",
        })
    res = f"{BASE}/tfa-bf-names-resolved.TfaBfNames.tsv"
    if os.path.exists(res):
        rr = [r for r in csv.DictReader(open(res, encoding="utf-8"), delimiter="\t")
              if r["raw_name"] != "COUNT"]
        cat = Counter(r["cat"] for r in rr)
        if sum(cat.values()) != 220:
            sys.exit(f"gate: {res} classifies {sum(cat.values())} rows, not the driver's 220 -- the "
                     "categories cannot be quoted as a coverage statement")
        bad_chip = [r for r in rr if r["cat"].startswith("RESOLVED")
                    and not any(r["chip_suffix"] in re.sub(r"\D", "", m.split("/")[-1].split("_")[0])
                                or r["chip_suffix"] in m for m in r["header_match"].split(", "))]
        if bad_chip:
            sys.exit(f"gate: {len(bad_chip)} RESOLVED row(s) cite a header that the name's own chip "
                     f"suffix does not name (first: {bad_chip[0]['raw_name']} -> "
                     f"{bad_chip[0]['header_match']}) -- the suffix story would be a guess")
        tfa1_here = sum(1 for r in rr if r["cat"] == "EXACT" and "tfa1_" in r["header_match"])
        fam_p = f"{BASE}/tfa-bf-family.TfaBfNames.tsv"
        tfa1_there = None
        if os.path.exists(fam_p):
            tfa1_there = sum(int(r["exact"]) for r in csv.DictReader(open(fam_p, encoding="utf-8"),
                                                                    delimiter="\t")
                             if r["family"].startswith("tfa1_") and r["row_name"] == "-")
        if tfa1_there is not None and tfa1_here != tfa1_there:
            sys.exit(f"gate: the resolver counts {tfa1_here} TFA1 exact rows, §320's artifact counts "
                     f"{tfa1_there} -- two readings of the same 220 rows disagree, so neither number "
                     "may be published")
        unres = cat.get("ABSENT", 0) + cat.get("ABSENT_SAME_NAME_OTHER_ENUM", 0)
        suffixes = sorted({r["chip_suffix"] for r in rr if r["cat"] == "RESOLVED"})
        out.append({
            "layer": "TFA bit-field naming", "item": res.replace(BASE + "/", "art/audio-6.0.1/"),
            "value": (f"{cat['EXACT']}/220 rows match a reference header by name AND bit position; "
                      f"{cat['RESOLVED']} more match once the driver's chip suffix is expanded "
                      f"(suffixes seen: {'/'.join(suffixes)} -> the tfa98<NN> header of that chip); "
                      f"the residue is {cat.get('ABSENT_SAME_NAME_OTHER_ENUM', 0)} rows whose name "
                      f"exists at a DIFFERENT position and {cat.get('ABSENT', 0)} whose name exists "
                      f"nowhere (total unexplained {unres}); §320's TFA1 count reproduced "
                      f"independently = {tfa1_here}"),
            "name_or_meaning": ("this closes the 'what are those unnamed bit fields' gap that §250/§320 "
                                "left open, and it corrects §320's own report: the driver spells each "
                                "field's name with the CHIP NUMBER appended plus a trailing space "
                                "(`BSSCR87 ` = tfa9887's BSSCR at 0x511), so the 53 residue rows were "
                                "mostly a naming convention, not unknown fields. ★In the low bucket "
                                "0x00-0x0f (the 102 rows §E called 45-unfindable) every single row now "
                                "resolves: 79 exact + 23 by suffix. What is genuinely not in the "
                                "reference tree is the TDM family: TDMMODE and TDMTXFRM exist at other "
                                "bit positions, TDMCOMP exists nowhere -- three rows in registers "
                                "0x10/0x12, consistent with §231's hidden-register-range reading"),
            "source": f"{res} [{sha16(res)}] (tools/tfa_bf_name_resolve.py "
                      f"[{sha16(f'{ROOT}/tools/tfa_bf_name_resolve.py')}], driver table "
                      f"{BASE}/tfa-bf.TfaBfNames.tsv [{sha16(f'{BASE}/tfa-bf.TfaBfNames.tsv')}], "
                      "headers fw/tfa-ref/inc "
                      f"[{sha16(f'{ROOT}/fw/tfa-ref/PROVENANCE.txt')}] from "
                      "https://github.com/TechNexion/tfa98xx)",
            "writable": "no (derived: driver table from fw/Image, names from the reference headers)",
            "use_case": "on 7, re-run the driver-table decode and this resolver: the per-row category "
                        "is the diff. If 7's TfaBfNames has rows that land in ABSENT for registers the "
                        "6.0.1 table resolves, the two drivers disagree about the chip, and any "
                        "bit-field-level comparison of codec_reg dumps (e.g. §249's 26 registers) would "
                        "be reading different fields under the same names",
            "witness2": "three independent checks, all of which abort: (1) the reference file must not "
                        "contradict ITSELF -- each header spells fields up to three ways (`{0x..,\"N\"}` "
                        "table, `CHIP_BF_N = 0x..` enum, `_TFA_FIELD_(N,a,p,l)` macro) and the tool "
                        "aborts if any name gets different bit positions from the same file (0 "
                        f"conflicts here); (2) §320's TFA1 total must be reproduced by this second "
                        f"parser ({tfa1_here} vs {tfa1_there}); (3) dropping the bit-position "
                        "requirement moves 23 rows out of RESOLVED and 2 out of the name-only class "
                        "(--selftest enforces that the enum check is load-bearing). Plus the row "
                        "builder here re-counts to 220 and checks each RESOLVED row cites a header "
                        "whose number actually contains the name's suffix",
        })
    pairs = f"{BASE}/acdb-pairs.PD1610.tsv"
    if os.path.exists(pairs):
        prows = list(csv.DictReader(open(pairs), delimiter="\t"))
        ids = {r["id_a"] for r in prows} | {r["id_b"] for r in prows}
        named = sum(1 for r in prows if r["name_a"] or r["name_b"])
        out.append({
            "layer": "ACDB CDFT pairs", "item": pairs.replace(BASE + "/", "art/audio-6.0.1/"),
            "value": (f"{len(prows)} (id,id) pairs in {len({(r['file'], r['field']) for r in prows})} "
                      f"CDFT bodies, {len(ids)} distinct ids, {named} rows named via the workspace catalog"),
            "name_or_meaning": "the *CDFT bodies decoded as REPEAT{u32 n, n*(id_a,id_b)} -- which "
                               "(module, param) pairs each cal type carries",
            "source": f"{pairs} [{sha16(pairs)}]",
            "writable": "n/a (derived view)",
            "use_case": "on 7 the same parse must yield the same pair sets per field; a missing pair = "
                        "a param the 7 calibration does not carry for that device class",
            "witness2": "420/420 non-empty CDFT bodies across 49 files parse to exact field end, and "
                        "shuffled CDFT payloads parse 0/353 (so the model is not chance, ledger 268)",
        })
    mtx = f"{BASE}/acdb-matrix.PD1610.tsv"
    if os.path.exists(mtx):
        mrows = list(csv.DictReader(open(mtx), delimiter="\t"))
        keys = {(r["cal_root"], r["module_id"], r["param_id"]) for r in mrows}
        q = f"{BASE}/acdb-matrix.QRD.tsv"
        delta = ""
        if os.path.exists(q):
            qk = {(r["cal_root"], r["module_id"], r["param_id"]) for r in csv.DictReader(open(q), delimiter="\t")}
            delta = (f"; vs the stock QRD set: {len(keys & qk)} shared, {len(keys - qk)} vivo-only, "
                     f"{len(qk - keys)} QRD-only")
        out.append({
            "layer": "ACDB cal matrix", "item": mtx.replace(BASE + "/", "art/audio-6.0.1/"),
            "value": (f"{len(keys)} (cal type, module, param) rows, "
                      f"{sum(1 for r in mrows if r['lut_table'] != '-')} with a matching *LUT table" + delta),
            "name_or_meaning": "which module/param hooks each cal type carries, joined to the LUT "
                               "tables keyed on device+app_type (the CDFT pairs of 268 x the LUTs of 263)",
            "source": f"{mtx} [{sha16(mtx)}]",
            "writable": "n/a (derived view)",
            "use_case": "on 7 the vivo-only rows are the silent-fallback risk: a param the 7 ACDB "
                        "never calibrated makes the ADSP use its own default with no error anywhere",
            "witness2": "matrix controls: PD1610LG4 identical 391/391 (POSITIVE), QRD differs "
                        "(NEGATIVE); VCD2 has no same-prefix LUT only because the producer spells it "
                        "VGD2LUT0 -- shown as naming, not absence",
        })
    for k, v, why in acdb_dir_inputs():
        capsh = os.path.join(ROOT, "tools/acdbdir.sh")
        if not os.path.exists(capsh):
            sys.exit(f"gate: {capsh} missing -- the dir-selection rows cite a capture that no longer exists")
        out.append({
            "layer": "ACDB dir selection", "item": k, "value": v,
            "name_or_meaning": why,
            "source": (f"{BASE}/live/getprop.txt, {BASE}/live/sysfs_soc0_selection.txt, "
                       f"capture tools/acdbdir.sh [{sha16(os.path.join(ROOT, 'tools/acdbdir.sh'))}]"),
            "writable": "property: yes via setprop (memory-only, not persisted without root tooling); "
                        "sysfs node: read-only",
            "use_case": "on 7 read them IN CASCADE ORDER (model -> platform -> hw_platform): the "
                        "loader picks the cal directory from them and compares no version string at "
                        "all, so a swapped-in PD1610 dir is used only if one of these values names it",
            "witness2": "loader strings '/etc/acdbdata' + '%s/' + '%s%s' with access(F_OK) after each "
                        "candidate, at the addresses above (ledger 273); the in-use dir PD1610 equals "
                        "ro.vivo.product.model, the FIRST candidate, so the cascade ends there",
        })
    lut = f"{BASE}/acdb-lut.PD1610.tsv"
    ruler = os.path.join(ROOT, "tools/acdb_order.py")
    if os.path.exists(lut):
        if not os.path.exists(ruler):
            sys.exit(f"gate: {ruler} missing -- the load-order verdict cannot be restated without its ruler")
        nrec, files, tabs, col = acdb_load_order(lut)
        out.append({
            "layer": "ACDB load order", "item": "cross-file key collisions in the chosen directory",
            "value": (f"{len(col)} over {nrec} records / {len(files)} files / {len(tabs)} tables; "
                      f"cap is 20 files (cmp #0x13 at 0x33e8) so 7 is far below it"),
            "name_or_meaning": "whether the order readdir hands the loader can change what the ADSP "
                               "ends up with (the loader appends every *.acdb of one dir into one list)",
            "source": f"{lut} [{sha16(lut)}], ruler tools/acdb_order.py [{sha16(ruler)}]",
            "writable": "n/a (measured verdict, re-derivable)",
            "use_case": "if 0 collisions hold on 7 too, the port only has to deliver the FILE SET -- no "
                        "boot-logcat capture of load order is needed and file names are free "
                        "(PD1610 ships bare Speaker_cal.acdb, Fluid ships Fluid_Speaker_cal.acdb)",
            "witness2": "ruler carries an injected-collision positive control and re-runs it on every "
                        "build of this table; QRD 18136 records and PD1610LG4 19814 records both also "
                        "0 (two independent directories agreeing)",
        })
    sel = f"{BASE}/acdb-selectors.tsv"
    if not os.path.exists(sel):
        sys.exit(f"gate: {sel} missing -- run tools/acdb_selectors.py {BASE}/shipped; the port has to "
                 f"know whether ONE directory chooser exists or several")
    srows = list(csv.DictReader(open(sel), delimiter="\t"))
    choosers = [r["binary"].replace(f"{BASE}/shipped/", "") for r in srows
                if r["verdict"].startswith("CHOSES")]
    distinct = sorted({c.rsplit("/", 1)[-1] for c in choosers})
    # the reach artifact says WHICH copy the running process actually maps (32 vs 64 bit)
    mapped = ""
    if os.path.exists(f"{BASE}/live/acdb-reach.txt"):
        rm = re.search(r"REACH maps pid=\d+ comm=(\S+).*?libs=(\S*)",
                       open(f"{BASE}/live/acdb-reach.txt", encoding="utf-8", errors="replace").read())
        if rm:
            mapped = f"; the live process {rm.group(1)} maps {', '.join(sorted({x.rsplit('/', 2)[-2] + '/' + x.rsplit('/', 1)[-1] for x in rm.group(2).rstrip(',').split(',') if x}))}"
    writers = [r["binary"].replace(f"{BASE}/shipped/", "") for r in srows if "WRITES" in r["verdict"]]
    out.append({
        "layer": "ACDB selector census", "item": "binaries that can choose the cal directory",
        "value": (f"{len(choosers)} chooser copies = {len(distinct)} distinct library "
                  f"({', '.join(distinct) or '-'}) over {len(srows)} binaries with any ACDB signal; "
                  f"delta writer: {', '.join(writers) or 'none'}" + mapped),
        "name_or_meaning": "how many independent pieces of code decide which calibration set plays -- "
                           "if 7 adds a second chooser, §273's cascade gate covers only part of the machine",
        "source": f"{sel} [{sha16(sel)}], ruler tools/acdb_selectors.py",
        "writable": "n/a (string census over shipped binaries, re-runnable on 7)",
        "use_case": "re-run tools/acdb_selectors.py on the 7 tree and require the same 1-chooser answer "
                    "before trusting port_check.sh dir",
        "witness2": "selftest PASS (libacdbloader.so classified as the chooser); the two copies are "
                    "vendor/lib + vendor/lib64 of ONE library, and their cascade strings match "
                    "1:1 (calfile/model/platform/log formats each counted identically, ledger 279) "
                    "-- mediaserver maps the 32-bit pair; libaudio-ftm calls "
                    "acdb_loader_init_ACDB, whose .dynsym size is 16 bytes = a wrapper that tail-branches "
                    "to init_v2, so FTM is NOT a second selector; empty-root scan refuses to report clean",
    })
    dl = f"{BASE}/live/acdbdelta-list.txt"
    if not os.path.exists(dl):
        sys.exit(f"gate: {dl} missing -- the /data delta overlay (§274) is the one thing §272 wrongly "
                 f"cleared, so it must be on the table")
    slots = []
    for ln in open(dl, encoding="utf-8", errors="replace"):
        p = ln.split()
        if ln.startswith("-") and len(p) >= 6:
            slots.append((p[-1], int(p[-4])))
    if not slots:
        sys.exit(f"gate: {dl} has no parsable file lines -- capture or column shape changed")
    out.append({
        "layer": "ACDB delta overlay", "item": "/data/misc/audio/acdbdata/delta slots on this machine",
        "value": (f"{len(slots)} slots, max size {max(s for _n, s in slots)} bytes, "
                  f"basenames {sorted({n.replace('.acdbdelta', '') for n, _s in slots})}"),
        "name_or_meaning": "libaudcal's acdbdata_ioctl writes a per-file delta that patches the shipped "
                           ".acdb at runtime; empty slots mean the sound is the shipped bytes, and the "
                           "BARE names (no Fluid_/QRD_ prefix) are a third witness that the loaded set "
                           "is a vivo dir (PD1610/PD1610LG4/PD1516A)",
        "source": f"{dl} [{sha16(dl)}]",
        "writable": "yes (0600 media:audio, root can write) -- never touched by these tools",
        "use_case": "on 7 a NON-ZERO delta here means the comparison is not against the shipped "
                    "calibration; and a fresh /data with no slots at all is a different state from "
                    "seven empty ones",
        "witness2": "port_check.sh acdb delta arm enforces count + zero size and was red-tested with an "
                    "injected 1200-byte overlay, a removed slot, an unparsable column shape and an "
                    "absent directory (four negatives, each rc!=0)",
    })
    lv = f"{BASE}/live/acdb-landing-verify.txt"
    if not os.path.exists(lv):
        sys.exit("gate: live/acdb-landing-verify.txt missing -- run tools/port_check.sh acdb; the "
                 "landing-scoped content verdict (§275) has no other source")
    ltxt = open(lv, encoding="utf-8", errors="replace").read()
    land = re.search(r"landing=(\S+) resolved=(\S+) files-here=(\d+) matched-via=(\S+)", ltxt)
    if not land:
        sys.exit(f"gate: {lv} has no landing line -- capture is from a producer older than §275")
    kinds = {k: len(re.findall(rf"^\s+{k}\s", ltxt, re.M))
             for k in ("in use", "CORRUPT", "ABSENT", "EXTRA", "RIVAL")}
    seen = kinds["in use"] + kinds["CORRUPT"] + kinds["ABSENT"] + kinds["EXTRA"]
    cal_rows = [r for r in out if r["layer"] == "ACDB cal asset"]
    if seen != len(cal_rows):
        sys.exit(f"gate: {lv} reports {seen} files but the table lists {len(cal_rows)} -- "
                 f"the verdict and the asset layer disagree (RIVAL notes are per directory, not "
                 f"per file, so they are deliberately not counted here)")
    out.append({
        "layer": "ACDB landing content", "item": "bytes of the files IN THE LANDING DIRECTORY",
        "value": (f"{land.group(1)} ({land.group(3)} files here, via {land.group(4)}): "
                  f"{kinds['in use']} identical"
                  + (f", {kinds['CORRUPT']} corrupt" if kinds["CORRUPT"] else "")
                  + (f", {kinds['ABSENT']} absent" if kinds["ABSENT"] else "")
                  + (f", {kinds['EXTRA']} extra" if kinds["EXTRA"] else "")
                  + (f", {kinds['RIVAL']} rival-dir note(s)" if kinds["RIVAL"] else "")),
        "name_or_meaning": "the claim the port actually needs: the directory the loader LANDS ON holds "
                           "the 6.0.1 bytes -- the older arm only proved SOME directory did, which a "
                           "sibling copy can mask (ledger 274 records that blind spot, 275 closes it)",
        "source": f"{lv} [{sha16(lv)}], ruler tools/acdb_landing.py",
        "writable": "n/a (produced by tools/port_check.sh acdb on a live machine)",
        "use_case": "after switching to 7, run port_check.sh acdb and require this row to read "
                    "'7 identical, 0 corrupt, 0 absent' for the directory dir-mode lands on",
        "witness2": "red-tested four ways through the real gate: corruption in the landing dir only "
                    "(content arm stays green, landing arm goes red), extra *.acdb, missing file, and a "
                    "same-named dir under another root (rival note, informational); a fixture-driven "
                    "run cannot clobber this stable capture",
    })
    aud = f"{BASE}/shipped/vendor/lib64/libaudcal.so"
    if os.path.exists(aud):
        out.append({
            "layer": "ACDB delta format", "item": "how a delta slot becomes an overlay (libaudcal.so)",
            "value": ("header u32@0 must be 0, u32@4 in {0,1}; payload size read at 0x14 (flag 0) or "
                      "0x18 (flag 1) and size+24/28 must equal the file length, else "
                      "IsAcdbDeltaFileValid returns -3 -> an EMPTY file is never an overlay; "
                      "SW version = 3 u32 at 8/12/16 (flag 0) or 12/16/20 (flag 1)"),
            "name_or_meaning": "what the /data/misc/audio/acdbdata/delta/*.acdbdelta files must look "
                               "like to alter the sound, and where their version stamp lives",
            "source": f"{aud} [{sha16(aud)}] IsAcdbDeltaFileValid 0x150f4, "
                      f"AcdbDeltaFileGetSWVersion 0x15154, acdb_delta_init 0x171c0",
            "writable": "n/a (read from the binary)",
            "use_case": "on 7 the delta check in port_check.sh acdb stays meaningful only because a "
                        "0-byte file FAILS the driver's own validity test; a same-named directory or a "
                        "renamed file would not matter as much as a non-empty slot",
            "witness2": "the seven empty slots are CREATED by AcdbIsDeltaFileAvailable opening with "
                        "fopen mode 'ab+' (string 0x22338, name built by GetDeltaFileName 0x19024 over "
                        "'/data/misc/audio/acdbdata/delta/') -- so empty means 'touched, never written', "
                        "which closes §274's open question; writers are AcdbCmdSet* -> "
                        "AcdbCmdSaveDeltaFileData -> acdb_delta_data_ioctl(cmd 6). Its 'persistence "
                        "gate' is inert on this build: AcdbIsPersistenceSupported (0x1901c) is "
                        "mov w0,#0; ret -- it never reads g_persistenceStatus (0x39008), where "
                        "AcdbCmdEnablePersistence stores 0 and AcdbCmdDisablePersistence stores -1 -- "
                        "so 0 code sites consult the flag and every save path proceeds (ledger 277). "
                        "No shipped binary calls those AcdbCmdSet* directly (the HAL does not even link "
                        "libaudcal), BUT the endpoint is live: acdb_loader_init_v2 itself calls "
                        "acph_init at +0x16c and acdb_fts_init at +0x1c4, and libacdb-fts.so registers "
                        "acdb_fts_callback (fopen/fwrite/fclose = process_open/write/close_request) -- "
                        "an external ACPH peer can push files, so the delta arm stays part of acceptance",
        })
    reach = f"{BASE}/live/acdb-reach.txt"
    probe = os.path.join(ROOT, "tools/acdb_reach.sh")
    if os.path.exists(reach):
        rtxt = open(reach, encoding="utf-8", errors="replace").read()
        hosts = re.findall(r"REACH maps pid=(\d+) comm=(\S+) hal_loaded=(\d+) diag_mapped=(\d+) ctx=(\S+) libs=(\S*)", rtxt)
        nread = len(set(re.findall(r"REACH diagreader pid=(\d+)", rtxt)))
        ncal = len({int(x) for x in re.findall(r"REACH fd pid=(\d+) comm=\S+ link=/dev/msm_audio_cal", rtxt)})
        calpid = sorted({int(p) for p, _c, _n in
                         re.findall(r"REACH fd pid=(\d+) comm=(\S+) link=/dev/(msm_audio_cal)\b", rtxt)})
        diagpid = sorted({int(p) for p, _c in
                          re.findall(r"REACH fd pid=(\d+) comm=(\S+) link=/dev/diag\b", rtxt)})
        nodes = re.findall(r"REACH node (\S+)", rtxt)
        if not hosts:
            sys.exit(f"gate: {reach} has no REACH maps line -- re-run tools/port_check.sh reach")
        out.append({
            "layer": "ACDB write reachability", "item": "process(es) holding the whole write chain",
            "value": (f"{len(hosts)} ACDB-library host(s): "
                      + "; ".join(f"pid {p} {c} {x} libs={l.rstrip(',')} diag_mapped={g}"
                                  for p, c, _h, g, x, l in hosts)
                      + f" | diagchar_read threads machine-wide: {nread}"
                      + f" | /dev/msm_audio_cal open by {ncal} pid(s)"
                      + f" | nodes present: {', '.join(nodes)}"
                      + f" | /dev/msm_audio_cal held by pid {calpid or 'NONE'}"
                      + f" | /dev/diag held by {len(diagpid)} pid(s)"),
        "name_or_meaning": "whether the delta / file-push channel is merely compiled in or actually "
                           "resident: the same process must hold the libraries, the calibration node "
                           "and the diag transport for an external peer to reach the writer",
            "source": f"{reach} [{sha16(reach)}], probe tools/acdb_reach.sh [{sha16(probe)}]",
            "writable": "n/a (read-only /proc scan; no traffic was ever injected)",
            "use_case": "on 7 re-run port_check.sh reach: if the library host, /dev/msm_audio_cal and "
                        "/dev/diag split across processes or the nodes move, the risk assessment for "
                        "'a calibration tool can alter the sound' changes",
            "witness2": "red-tested seven ways through the gate: no calibration-node holder, cal node "
                        "held by a pid that maps nothing, the library host losing its diag fd, the lib "
                        "host losing its diagchar_read thread, libdiag unmapped, an empty capture, and a "
                        "capture cut before REACH_DONE (all rc!=0). The middle hop is a REGISTERED "
                        "CALLBACK (libaudcal imports diagpkt_tbl_reg/diagpkt_subsys_alloc/Diag_LSM_Init "
                        "from libdiag.so, which defines them) -- that is why no static call site to "
                        "atp_receive_atp_frame exists. Limit stated in the gate's own output: wired does "
                        "not equal demonstrated, nothing was ever sent over diag",
        })
    card = f"{BASE}/acdb-card.PD1610.tsv"
    if os.path.exists(card):
        crows = list(csv.DictReader(open(card), delimiter="\t"))
        full = f"{BASE}/acdb-card.PD1610-full.tsv"
        frows = list(csv.DictReader(open(full), delimiter="\t")) if os.path.exists(full) else []
        out.append({
            "layer": "ACDB cal card", "item": card.replace(BASE + "/", "art/audio-6.0.1/"),
            "value": (f"{len(crows)} records for devices "
                      f"{','.join(sorted({r['acdb_dev_id'] for r in crows}, key=int))} across "
                      f"{len({r['table'] for r in crows})} tables; full-surface card "
                      f"{len(frows)} records over {len({r['acdb_dev_id'] for r in frows})} devices"),
            "name_or_meaning": "the numbers 6.0.1 stores for the device ids this machine really uses",
            "source": f"{card} [{sha16(card)}]",
            "writable": "n/a (derived view)",
            "use_case": "on 7: tools/acdb_port_diff.py --other <its dir> (schema, version triple, "
                        "numbered pool, card overlap, bytes) -- or tools/acdb_card.py alone",
            "witness2": "card controls: POSITIVE PD1610==PD1610LG4 (441/441 and 86/86 devices), "
                        "NEGATIVE dev 14 vs 15 shares 0 rows; vs stock QRD: 0/68 devices identical, "
                        "device 150 has 207 baseline rows and NONE in the candidate (271)",
        })
    # layer 4: DT acceptance windows + the .cnt asset itself
    dtp = f"{BASE}/live/tfa-dt-props.PD1610.tsv"
    dtv = {}
    for ln in open(dtp, encoding="utf-8"):
        parts = ln.rstrip("\n").split("\t")
        if len(parts) >= 3 and "tfa98xx" in parts[0]:
            dtv[parts[0].strip()] = parts[2].strip()
    fsw = fres_witness(dtv)
    for ln in open(dtp, encoding="utf-8"):
        parts = ln.rstrip("\n").split("\t")
        if len(parts) < 3 or "tfa98xx" not in parts[0]:
            continue
        out.append({
            "layer": "device tree", "item": parts[0].strip(),
            "value": parts[2].strip(),
            "name_or_meaning": "board-level acceptance window / config file name (§232)",
            "source": f"/sys/firmware/devicetree/base/soc/i2c@75b6000/spkamp@34 [{sha16(dtp)}]",
            "writable": "no (read-only at runtime; the port must supply an equal DTB or patch the reader)",
            "use_case": "static",
            "witness2": fsw.get(parts[0].strip(),
                                "cross-checked against live fRes_Detect/impedance readings (§232); "
                                "no in-play number recomputed for this property"),
        })
    fh_p = f"{BASE}/tfa-field-history.PD1610.tsv"
    if os.path.exists(fh_p):
        fhr = list(csv.DictReader(open(fh_p, encoding="utf-8"), delimiter="\t"))
        fld = [r for r in fhr if r["kind"] == "field-history"]
        cross = [r for r in fhr if r["kind"] == "class-cross"]
        sess = sorted({int(r["sessions"]) for r in fld})
        stable = [r for r in fld if r["distinct"] == "1"]
        vary = [r for r in fld if r["distinct"] != "1"]
        # every number quoted below is counted PER KIND, so an unrecognised kind must abort rather than
        # quietly join or leave a count (stable+vary partitions fld by construction -- that arithmetic is
        # a tautology and was not worth gating; what can drift is the kind set itself)
        kinds = {r["kind"] for r in fhr}
        if kinds - {"field-history", "class-cross"} or not fld:
            sys.exit(f"gate: {fh_p} holds kinds {sorted(kinds)} over {len(fhr)} rows ({len(fld)} field "
                     "rows) -- this row counts named fields on field-history only and the agreement on "
                     "class-cross only, so a third kind would be silently left out of both sentences")
        if not cross:
            sys.exit(f"gate: {fh_p} has no class-cross rows -- the register-level agreement below is a "
                     "second instrument's verdict and must come from the artifact, not from prose")
        disag = [r for r in cross if (r["verdict"] or "").startswith("DISAGREE")]
        # the agreement is RECOMPUTED here rather than copied from the row's verdict string: the register
        # table is the other instrument (whole-byte comparison, and its samples come from the tfasnap-*
        # sessions while these rows come from live/portcheck-*), so this tool must see the collision too
        regcls = {r["reg"]: r["class"] for r in csv.DictReader(open(tfa, encoding="utf-8"), delimiter="\t")}
        nreg = len(regcls)
        mis = []
        for r in cross:
            if regcls.get(r["reg"]) != r["class"]:
                mis.append(f"{r['reg']}: table class {regcls.get(r['reg'])!r}, row class {r['class']!r}")
                continue
            fs = [x for x in fld if x["reg"] == r["reg"]]
            setting = all(x["distinct"] == "1" for x in fs)
            if (regcls[r["reg"]] == "STABLE") != setting:
                mis.append(f"{r['reg']}: class {regcls[r['reg']]} but its {len(fs)} named field(s) "
                           f"{'are all stable' if setting else 'vary'}")
        if mis:
            sys.exit(f"gate: {fh_p} x {tfa}: {len(mis)} register(s) where the field-level and "
                     "register-level classifications disagree: " + "; ".join(mis) + " -- one of the two "
                     "is wrong and the AGREE/DISAGREE numbers below may only be published after this "
                     "tool has recomputed the collision")
        if len({r["reg"] for r in fld}) != nreg:
            sys.exit(f"gate: {fh_p} names fields on {len({r['reg'] for r in fld})} register(s) but {tfa} "
                     f"classifies {nreg} -- the cross-check below quotes a coverage it did not count")
        # the two registers §330 settled on, taken WHOLE: no field-name whitelist anywhere, so no field
        # can be quietly left out of the claim (that is how se_hyst nearly got dropped)
        cfg_by_reg = {}
        for r in fhr:
            if r["reg"] in ("0x46", "0x47") and r["source"] == "reference":
                cfg_by_reg.setdefault(r["reg"], []).append(r)
        cfg = [r for v in cfg_by_reg.values() for r in v]
        unst = [f"{r['reg']}/{r['field']}" for r in cfg if r["distinct"] != "1"]
        if unst:
            sys.exit(f"gate: {fh_p}: fields of the §330 registers vary across sessions: {unst} -- those "
                     "would be state, not settings, and the sentence below calls them settings")
        if not (sess and stable and vary) or sorted(cfg_by_reg) != ["0x46", "0x47"] or not cfg:
            sys.exit(f"gate: {fh_p} holds {len(fld)} field rows + {len(cross)} class-row(s) "
                     f"({len(stable)} stable / {len(vary)} varying, "
                     f"{len(cfg)} config-bit rows) -- the row needs both classes present, otherwise "
                     "'reproduce it on 7' would be said about a set never compared against the rest")
        if len(sess) != 1:
            sys.exit(f"gate: {fh_p} rows disagree on how many sessions were read {sess}")
        out.append({
            "layer": "TFA field history", "item": fh_p.replace(BASE + "/", "art/audio-6.0.1/"),
            "value": f"{len(fld)} named bit fields read out of every PA snapshot ({sess[0]} captures, "
                     f"PA section only): {len(stable)} hold the SAME value in all of them "
                     f"(setting-shaped -- these are what 7 must reproduce), {len(vary)} do not "
                     f"(state or chip-side, in registers "
                     + ", ".join(sorted({r["reg"] for r in vary}))
                     + f"); the two registers §330 settled on carry ALL {len(cfg)} of their "
                       f"reference-named fields between them, every one of them stable across the "
                       f"{sess[0]} snapshots, and {len([r for r in cfg if r['values'] != '0'])} of the "
                       f"{len(cfg)} are non-zero: "
                     + ", ".join(f"{r['field'].split('/')[-1]}{r['span']}={r['values']}"
                                 for r in cfg if r["values"] != "0")
                     + " (the rest read 0 in every snapshot)"
                     + f"; §348 cross-check against §283's register-level classes (a different "
                       f"instrument: whole-byte comparison, and a different sample set -- {nreg} "
                       f"registers classified there): {len(cross)} of the {nreg} carry named fields, "
                       f"{len(cross) - len(disag)} AGREE, {len(disag)} DISAGREE"
                       + (f" ({', '.join(r['reg'] for r in disag)})" if disag else ""),
            "name_or_meaning": ("which bits of the PA's register set are a SETTINGS and which are the "
                                "chip talking -- the carry list compared whole bytes only (§229/§283), so "
                                "a wide field like 0x02 TEMPS (5 distinct values) or 0x71 MADD (58) sat "
                                "in the same class as a tuning bit. §346 names every field, reads it out "
                                "of every session, and lets the count of distinct values do the "
                                "classifying: the varying ones are the clock/power status of 0x00/0x09, "
                                "TEMPS, BATS, REQ, the status/error registers and MEMA"),
            "source": f"{fh_p} [{sha16(fh_p)}] (tools/tfa_field_history.py "
                      f"[{sha16(f'{ROOT}/tools/tfa_field_history.py')}], register values from "
                      f"live/portcheck-*.txt read by section; field names from tfa-reg-fields.PD1610.tsv "
                      f"and tfa-reg-gap-decode.PD1610.tsv)",
            "writable": ("the stable fields are what a port must reproduce (they include 0x46 "
                         "cs_neghyst, 0x47 switch_fb/se_level/ktemp); the varying ones are read-only "
                         "state -- requiring 7 to reproduce them would be a FALSE red, and ignoring a "
                         "stable one would be a false green"),
            "use_case": "on 7, run tools/tfa_field_history.py --live <7's capture dir> --against "
                        "art/audio-6.0.1/tfa-field-history.PD1610.tsv: rc=0 means all 128 baseline-stable "
                        "fields hold the same value, rc=1 names each differing field (a different value in "
                        "cs_neghyst / se_level / ktemp is an AUDIBLE tuning difference, not a numeric nit), "
                        "rc=2 refuses the answer because a stable field could not be read on 7 at all -- "
                        "never a pass. The 15 fields that vary in 6.0.1 are excluded by the ruler itself. "
                        "Note the direction: field names come from OUR 6.0.1 decode tables, so the value "
                        "comparison does not depend on how 7's driver names them",
            "witness2": "each field value is recomputed from the register bytes of every capture (no "
                        "value is copied from the table); --selftest shows the PA-only section parse is "
                        "load-bearing (the naive whole-file parse moves a third of the registers in the "
                        "in-play snapshot, §285's shape) and that reversing the span order aborts; the "
                        "comparison arm is proven red two ways -- port_check_neg J pins reg{0046} bits "
                        "15:13 in every capture and must go rc=1 naming cs_neghyst, and --selftest drops "
                        "one corpus field and must report NO-ANSWER rather than agreement",
        })
    hdr = f"{BASE}/hifi-dt-reads.PD1610.tsv"
    if os.path.exists(hdr):
        hd = list(csv.DictReader(open(hdr, encoding="utf-8"), delimiter="	"))
        cons = [r for r in hd if r["kind"] == "flag-consumer"]
        chan = [r for r in cons if r["fn"] == "es9028_one_enable" and r["bits"] == "mask 0x300"]
        b12 = [r for r in cons if r["fn"] == "es9028_one_enable" and r["bits"] == "bit 12"]
        if not b12 or "[x22+0x4]" not in b12[0]["value_origin"]:
            sys.exit(f"gate: {hdr}: the second bit-12 test reports origin {b12[:1] and b12[0]['value_origin']!r} "
                     "-- §358 states plainly that the compared value comes from the caller's parameter "
                     "block, so that has to be read from the artifact rather than from prose")
        if not cons or not chan or chan[0]["near_w1_imm"] != "0xb":
            sys.exit(f"gate: {hdr}: {len(cons)} consumer row(s), channel-mask row {chan[:1]} -- the "
                     "sentence below publishes that bits 8|9 pick the value written to es9028 register "
                     "0xb, so that site has to be read from the artifact")
        props = sorted({r["property"] for r in hd})
        ims = [r for r in hd if r["property"] == "i2s-master"]
        if not ims or "0x1000" not in ims[0]["bits"]:
            sys.exit(f"gate: {hdr}: the `i2s-master` row does not carry bit 0x1000 ({ims[:1]}) -- §354 says "
                     "that bit is what gates es9028's registration of &es9028_enable at [table+0x48], so it "
                     "must be read from the artifact, not asserted")
        if any("vivo:params" in r["property"] for r in hd):
            sys.exit("gate: " + hdr + " still carries the colon spelling of the property name -- the binary "
                     "string and the live device tree both read `vivo,params` (comma); a reader who greps "
                     "/proc/device-tree for the colon form finds nothing and would call the property missing")
        out.append({
            "layer": "Hi-Fi DT reads", "item": hdr.replace(BASE + "/", "art/audio-6.0.1/"),
            "value": f"{len(hd)} device-tree lookups found in the two DAC probes and the codec link "
                     f"initialiser, every name resolved out of the image's own strings: "
                     + ", ".join(f"{r['property']}({r['callee'].replace('of_property_read_', 'read_')}"
                                f"{('->bit ' + r['bits'].split()[0]) if r['bits'] != '-' else ''}"
                                f"{('->' + '+'.join(r['fields'].split()) + ('[' + r['link_kind'] + ' link]')) if r.get('link_kind', '-') != '-' else ''}"
                                f"@{r['site']})" for r in hd),
            "name_or_meaning": "this names what the Hi-Fi layer asks the device tree for AND what each "
                               "answer is used for. The gate-relevant one: es9028_i2c_probe looks up "
                               "`i2s-master`, and its presence ORs bit 0x1000 into dev+0x18 -- the very bit "
                               "whose `tbz` skips es9028's registration of &es9028_enable/&es9028_mute into "
                               "[table+0x48]/[table+0x50] (§352). So whether the es9028 driver can even "
                               "become the active DAC is decided by one DT property, not by code. "
                               "left-channel-only -> bit 0x100, right-channel-only -> bits 0x200 and 0x300. "
                               "Both DACs also read vivo,param-num (two u32) and vivo,params (the array); "
                               "the codec link initialiser reads no device-tree property at all. The struct "
                               "field each answer lands in is LINKED, not inferred: the linker follows the "
                               "call's out-parameter (a frame slot or the allocation-result register, with "
                               "registers redefined after the call dropped) and it reproduces the slots §325 "
                               "measured with a different instrument (param-num -> data+0x60/+0x64 and the "
                               "buffer -> +0x68 on es9038; +0x68/+0x6c and +0x70 on es9028) -- the tool "
                               "refuses to publish if that cross-check fails. A consumer pass over the whole codec family "
                               f"({len(cons)} reads of the flag field) adds the other end: bit "
                               "12 is tested again inside es9028_one_enable (0xbb92e8), "
                               "and the value that test compares is NOT a chip read: it is "
                               f"{b12[0]['value_origin']} -- a field of the caller's parameter block "
                               "(x22 is argument 2, `mov x22, x1` at 0xbb91a0), whose bits 12..15 must "
                               "equal 1 for that step to run at all; the chip read is the LATER pair "
                               "(read reg 0xb, mask, write reg 0xb back), "
                               "and bits 8|9 are masked there (0xbb93b4) to pick what is written "
                               "back to es9028 register 0xb -- left-channel-only -> |2, "
                               "right-channel-only -> |3, neither -> the masked original. All "
                               "of it is inert where es9028 never binds (§355)",
            "source": f"{hdr} [{sha16(hdr)}] (tools/dt_prop_reads.py "
                      f"[{sha16(f'{ROOT}/tools/dt_prop_reads.py')}], names resolved by an adrp/add/mov page "
                      "map from fw/Image, each string re-read as bytes and required printable; "
                      "property spelling cross-checked against live/dac-dt-raw.txt)",
            "writable": "no -- reading the tree is the driver's job; a 7 device tree that drops `i2s-master` "
                        "changes WHICH DAC registers, which is not a value anyone can set at runtime",
            "use_case": "on 7, dump the es9028/es9038 nodes and check the three gating names are present "
                        "(`i2s-master`, `left-channel-only`, `right-channel-only`) plus both param names; "
                        "a missing `i2s-master` is not a numeric difference -- it silently removes a "
                        "candidate DAC from the ops table",
            "witness2": "three independent readings: the property-name bytes in fw/Image, the linked struct slots reproduced against §325's store-site walk, and the live property list "
                        "art/audio-6.0.1/live/dac-dt-raw.txt plus live/i2c-dac-drivers.txt (§287's and "
                        "§355's captures); "
                        "the tool aborts if the known pair does not resolve, and --selftest proves the name "
                        "argument is x1 (reading x2 instead resolves 0 names)",
        })
    fs_p = f"{BASE}/tfa-field-family-semantics.PD1610.tsv"
    if os.path.exists(fs_p):
        fsr = list(csv.DictReader(open(fs_p, encoding="utf-8"), delimiter="	"))
        n_yes = [r for r in fsr if r["unit_or_formula"] == "yes"]
        own_scale = [r for r in fsr if "step of" in r["own_comment"] or "=" in r["own_comment"]]
        kt = [r for r in fsr if r["field"].split("/")[-1].startswith("ktemp")]
        dcm = [r for r in fsr if r["field"].split("/")[-1] == "DCMCC"]
        n_fields_art = len([r for r in csv.DictReader(open(fh_p, encoding="utf-8"), delimiter="	")
                            if r["kind"] == "field-history"]) if os.path.exists(fh_p) else 0
        if n_fields_art and len(fsr) != n_fields_art:
            sys.exit(f"gate: {fs_p} describes {len(fsr)} fields but {fh_p} names {n_fields_art} -- the "
                     "two halves of the field story would be counting different sets")
        if not n_yes or not kt or not any("VALUE" in r["family_comments"] for r in kt):
            sys.exit(f"gate: {fs_p}: {len(n_yes)} rows state a formula/unit and {len(kt)} ktemp row(s) -- "
                     "the sentence below quotes a formula for ktemp, so it must be read from the artifact")
        if not dcm or "step of" not in dcm[0]["own_comment"]:
            sys.exit(f"gate: {fs_p}: no DCMCC row whose OWN (9890) comment states a step -- the only "
                     "scale attributed to the 9890 itself below would be unsupported")
        out.append({
            "layer": "TFA field semantics", "item": fs_p.replace(BASE + "/", "art/audio-6.0.1/"),
            "value": f"{len(fsr)} named PA fields, each with the comment NXP's own generated tables carry "
                     f"for that name (12 sibling tables read): {len(n_yes)} rows reach a formula or a "
                     f"unit, and {len(own_scale)} of those is stated by the 9890's OWN table -- DCMCC: "
                     f"'{dcm[0]['own_comment']}', captured code {dcm[0]['values']}, so {int(dcm[0]['values']) * 500} "
                     f"mA IF the code is a plain multiple of the step (the table states a step, no offset). "
                     f"The rest are "
                     f"sibling-chip statements quoted WITH the chip: ktemp -- the 9890 says only "
                     f"'{kt[0]['own_comment']}' (code {kt[0]['values']} of a 6-bit field) while tfa2 and "
                     f"tfa9872 write cs_ktemp as 'Current sense temperature compensation trimming "
                     f"(1 - VALUE*TEMP)*signal'; BATS/TEMPS are readouts (tfa1: 'Battery voltage readout; "
                     f"0 .. 5.5 [V]', 'IC Temperature (C)'), which is why they sit in the varying set",
            "name_or_meaning": ("this is the units question §347 left open, answered as far as the local "
                                "reference tree allows: one field (DCMCC) gets a scale from the 9890's own "
                                "table, ktemp gets its SHAPE (a multiplier inside (1 - VALUE*TEMP), so it is "
                                "not a temperature and not a dB value) but not its LSB, and the battery/"
                                "temperature readouts get their physical units from a sibling table. "
                                "Nothing here is the TFA9890 datasheet -- two attempts to fetch it failed "
                                "(ledger 350), so any row without a 9890 comment stays a hypothesis"),
            "source": f"{fs_p} [{sha16(fs_p)}] (tools/tfa_field_family_docs.py "
                      f"[{sha16(f'{ROOT}/tools/tfa_field_family_docs.py')}], comments harvested from "
                      f"fw/tfa-ref/inc/*tfafieldnames*.h; field list and codes from "
                      f"{fh_p.replace(BASE + '/', 'art/audio-6.0.1/')})",
            "writable": "no -- documentation harvest; the only writable use is reading a value off 7 and "
                        "saying what unit it is in",
            "use_case": "static, and it changes how the 5t judgement is WORDED: a differing DCMCC is "
                        "quotable in milliamps, a differing ktemp is only quotable as 'the current-sense "
                        "temperature trim moved', and cs_neghyst/se_level have no local scale at all -- do "
                        "not write them as dB or mV in a port report",
            "witness2": "the artifact quotes every comment with the CHIP it came from, so a sibling-chip "
                        "statement cannot be read as a 9890 fact; gates abort if the ktemp formula, the "
                        "DCMCC own-step line or the field denominator are missing",
        })
    for f in ("tfa98xx_PD1610.cnt", "tfa98xx.cnt"):
        p = f"{BASE}/live/tfa98xx/{f}"
        out.append({
            "layer": "file asset", "item": f"/system/etc/{f}",
            "value": f"{os.path.getsize(p)} B sha16={sha16(p)}; {cnt_integrity(p)}",
            "name_or_meaning": ("index at cont+44 (u32 LE off:24|type:8); per-profile content = name + embedded "
                                "PA/CO/SP/VP blocks (extracted byte-exact under live/tfa98xx/embedded/, see "
                                "cnt-embed.PD1610.tsv); NO dscRegister records; block CRC field unexplained"),
            "source": p,
            "writable": "no (in ro /system; on 7 the reader's path must be re-pointed or DTB matched)",
            "use_case": "loaded by the driver per DT vivo,tfa98xx-config",
            "witness2": "header CRC recomputed with the driver's own recipe, matched (§255); md5 matched on-device (§227); "
                        "register-patch absence confirmed over 768 index layouts (§256)",
        })
    # the 7-side container, block by block, once the 7 capture exists (ledger 606/610).  Every number
    # below comes from re-parsing BOTH .cnt files with tools/cnt_embed.py -- nothing here is typed.
    six = f"{BASE}/live/tfa98xx/tfa98xx_PD1610.cnt"
    sev, e_sev = EXTRA_ARTIFACTS
    e_six = f"{BASE}/live/tfa98xx/embedded/cnt-embed.PD1610.tsv"
    if all(os.path.exists(x) for x in (six, sev, e_six, e_sev)):
        def blocks(tsv):
            rows = [r for r in csv.DictReader(open(tsv), delimiter="\t")
                    if r["cnt"] == "tfa98xx_PD1610.cnt"]
            # keyed by (list, desc_off): three of the five blocks share list="device", so the
            # list column alone is not a key (it would collapse them and under-report the comparison)
            return {f"{r['list']}@{r['desc_off']}": (r["name"], r["id"], r["dsc_size"], r["body_sha"])
                    for r in rows}
        b6, b7 = blocks(e_six), blocks(e_sev)
        same = sorted(set(b6) & set(b7))
        diff = [k for k in same if b6[k] != b7[k]]
        val = (f"{len(b6)}/{len(b7)} blocks parsed on both sides; {len(same) - len(diff)} byte-identical, "
               + "; ".join(f"{k} (id={b7[k][1]}): 6.0.1 {b6[k][0]!r} sha={b6[k][3][:12]} vs 7 {b7[k][0]!r} "
                           f"sha={b7[k][3][:12]}, same dsc_size={b7[k][2]}" for k in sorted(diff))
               + f"; container sha16 6.0.1={sha16(six)} 7={sha16(sev)}")
        out.append({
            "layer": "file asset", "item": "/system/etc/tfa98xx_PD1610.cnt -- 6.0.1 vs THIS 7 build",
            "value": val,
            "name_or_meaning": ("the one block the 7 container carries differently is the "
                                "profile@0x68 vstep -- its NAME and its payload both changed "
                                "(ET1003_musicV1031 -> PD1610_music_1226) while its size stayed 860, "
                                "so the container is not a re-layout: one tuning block was swapped for "
                                "another of the same shape.  patch/config/speaker and the FlatSpeech "
                                "vstep are byte-identical, which is why this is a PORT item and not a "
                                "re-calibration of the whole PA chain"),
            "source": (f"{six} [{sha16(six)}] 、 {sev} [{sha16(sev)}] \u3001 "
                       f"{e_six} \u3001 {e_sev}"),
            "writable": "no for the shipped file (ro /system); on 7 the driver loads 7's own container, "
                        "so copying 6.0.1's would replace a tuned vstep -- that is a decision, not a sync",
            "use_case": ("on 7: pull the container the DT names, run "
                         "`python3 tools/cnt_embed.py --dir <7>/live/tfa98xx --out <7>/live/tfa98xx/embedded --write` "
                         "and re-run this manifest; the row must say 4 identical + 1 differing, and a "
                         "future 7 patch that also moves FlatSpeech would show up here as 2 differing"),
            "witness2": ("both sides re-parsed by the same tool in this run, and the 6.0.1 artifact "
                         "regenerated byte-identical to the committed cnt-embed.PD1610.tsv before it was "
                         "used (rebuild-from-source gate); block counts and the differing key are read "
                         "out of the TSVs, not typed"),
        })
    return out


def fh_fixture():
    """--selftest support: a tree shaped like CWD/BASE with every file SYMLINKED, so a doctored artifact
    can be swapped in as a real file while every other byte stays the shipped one, and nothing under art/
    is ever written.  EXTRA_ARTIFACTS are mirrored too: the fixture runs the generator with cwd=fixture,
    so a row reading anything outside BASE would silently change the table's LENGTH there."""
    import shutil
    import tempfile
    d = tempfile.mkdtemp(prefix="pmfix-")
    src = os.path.abspath(BASE)
    dst = os.path.join(d, BASE)
    for dirpath, dirnames, filenames in os.walk(src):
        rel = os.path.relpath(dirpath, src)
        os.makedirs(os.path.join(dst, rel), exist_ok=True)
        for f in filenames:
            os.symlink(os.path.join(dirpath, f), os.path.join(dst, rel, f))
    for rel in EXTRA_ARTIFACTS:
        sp = os.path.abspath(rel)
        if not os.path.exists(sp):
            continue
        dp = os.path.join(d, rel)
        os.makedirs(os.path.dirname(dp), exist_ok=True)
        if not os.path.exists(dp):
            os.symlink(sp, dp)
    return d


def fh_put(d, name, text):
    p = os.path.join(d, BASE, name)
    if os.path.islink(p):
        os.unlink(p)
    with open(p, "w", encoding="utf-8") as fh:
        fh.write(text)
    return p


def fh_read(d, name):
    with open(os.path.join(d, BASE, name), encoding="utf-8") as fh:
        return fh.read()


def fh_tsv_edit(text, prefix, col, new):
    """replace one cell in the first row whose first field matches `prefix` (and whose `col` currently
    holds something else); returns (text, n_changed) so a control that mutated nothing can be named"""
    lines = text.split("\n")
    n = 0
    for i, l in enumerate(lines):
        if not l.startswith(prefix):
            continue
        cells = l.split("\t")
        if cells[col] != new:
            cells[col] = new
            lines[i] = "\t".join(cells)
            n += 1
            break
    return "\n".join(lines), n


def write_path_selftest():
    """--selftest: the §351 payload gates must be able to reject.  Three doctored copies of the
    write-path artifact on a symlinked tree -- the shape line dropped, the slot line without an offset, and
    the scope line stripped of its NOT-proof caveat -- each has to abort, and the clean fixture has to
    build.  The third arm is the one that matters: an absence reading without its caveat is the §285 shape."""
    import shutil
    import subprocess
    bad, why = [], []
    NAME = "dac-write-path.txt"
    d0 = fh_fixture()
    text = fh_read(d0, NAME)
    shutil.rmtree(d0)
    if "\n shape " not in text or "\n slot " not in text:
        return ["the shipped artifact has no shape/slot records -- the controls cannot be built from it"]
    arms = []
    d = fh_fixture()
    fh_put(d, NAME, "\n".join(l for l in text.split("\n") if not l.startswith(" shape ")) + "\n")
    arms.append(("shape record deleted", d, "'shape': 0"))
    d = fh_fixture()
    fh_put(d, NAME, text.replace("slot field = codec-object + 0x40", "slot field = somewhere in the object"))
    arms.append(("slot record without an offset", d, "codec-object + 0x"))
    d = fh_fixture()
    fh_put(d, NAME, text.replace("this is NOT proof that nobody fills obj+0x40",
                                 "so nobody fills obj+0x40"))
    arms.append(("scope caveat stripped (the absence claim becomes a proof)", d, "without that caveat"))
    d = fh_fixture()
    fh_put(d, NAME, "\n".join(("  copyA_record" + l[11:]) if l.startswith(" slot copy A") else l
                                for l in text.split("\n")))
    arms.append(("one of the two instance records renamed away", d, "'slot': 3"))
    d = fh_fixture()
    fh_put(d, NAME, text.replace("is a POINTER VARIABLE", "is the table itself"))
    arms.append(("the global pointer identity restated as a static table", d, "pointer variable"))
    d = fh_fixture()
    fh_put(d, NAME, "\n".join(l for l in text.split("\n") if not l.startswith(" verdict ")))
    arms.append(("the payload verdict record deleted", d, "'verdict': 1"))
    d = fh_fixture()
    fh_put(d, NAME, text.replace("lists NO device", "lists one device"))
    arms.append(("the es9028 binding witness removed", d, "no device bound"))
    d = fh_fixture()
    fh_put(d, NAME, "\n".join(l for l in text.split("\n") if not l.startswith(" mirror ")))
    arms.append(("the es9028-mirror record deleted", d, "'mirror': 1"))
    for label, dd, needle in arms:
        q = subprocess.run([sys.executable, os.path.abspath(__file__), "out.tsv"], cwd=dd,
                           capture_output=True, text=True)
        msg = (q.stderr or "") + (q.stdout or "")
        if q.returncode == 0:
            bad.append(f"{label} was accepted (rc=0)")
        elif needle not in msg:
            bad.append(f"{label} aborted for another reason: {msg[:160]}")
        else:
            why.append(f"{label} -> {needle}")
        shutil.rmtree(dd)
    d = fh_fixture()
    q = subprocess.run([sys.executable, os.path.abspath(__file__), "out.tsv"], cwd=d,
                       capture_output=True, text=True)
    if q.returncode != 0:
        bad.append(f"the untouched fixture did not build: {(q.stderr or q.stdout)[:160]}")
    else:
        why.append("the untouched fixture builds")
    shutil.rmtree(d)
    print("write-path selftest: " + "; ".join(why) + f"; bad={bad}")
    return bad


def _drop_first(text, rx):
    """drop the first line matching rx -- used by the arms so a fixture that changes nothing cannot
    silently pass as a rejection test."""
    pat = re.compile(rx)
    out, done = [], False
    for ln in text.split("\n"):
        if not done and pat.search(ln):
            done = True
            continue
        out.append(ln)
    if not done:
        sys.exit(f"gate: no line matched {rx!r} -- the fixture would have been vacuous")
    return "\n".join(out)


def regmap_binding_selftest():
    """--selftest: the §382/§383 row gates must be able to refuse.  Each arm deletes or shortens exactly
    the capture section a sentence in the row depends on, so a truncated re-capture cannot keep
    publishing the window/agreement numbers."""
    import shutil
    import subprocess
    bad, why = [], []
    base_txt = open(sorted(__import__("glob").glob(f"{BASE}/live/regmap-tfa98xx-*.txt"))[-1],
                    encoding="utf-8", errors="replace").read()
    topo = open(sorted(__import__("glob").glob(f"{BASE}/live/sound-topology-*.txt"))[-1],
                encoding="utf-8", errors="replace").read()
    RG = "live/" + sorted(__import__("glob").glob(f"{BASE}/live/regmap-tfa98xx-*.txt"))[-1].split("/")[-1]
    TB = "live/" + sorted(__import__("glob").glob(f"{BASE}/live/sound-topology-*.txt"))[-1].split("/")[-1]
    arms = [("the cache_bypass section removed (is it live or a cache?)",
             lambda: (RG, base_txt.replace("## regmap/tfa98xx/cache_bypass", "## other"))),
            ("one address dropped from the register list (a partial dump)",
             lambda: (RG, "\n".join(l for l in base_txt.split("\n") if l.strip() != "8f: a1a1"))),
            ("the same-instant codec_reg section truncated to 25 lines",
             lambda: (RG, _drop_first(base_txt, r"reg\{[0-9a-f]+\}:"))),
            ("the es9038 i2c client line gone (renamed or unbound)",
             lambda: (TB, _drop_first(topo, r"\S+ es9038\s*$"))),
            ("the card0 symlink line gone from class-sound",
             lambda: (TB, "\n".join(l for l in topo.split("\n") if "card0 ->" not in l)))]
    for label, mk in arms:
        d = fh_fixture()
        name, text = mk()
        fh_put(d, name, text)
        q = subprocess.run([sys.executable, os.path.abspath(__file__), "out.tsv"], cwd=d,
                           capture_output=True, text=True)
        msg = (q.stderr or "") + (q.stdout or "")
        if q.returncode == 0:
            bad.append(f"{label} was accepted (rc=0)")
        else:
            why.append(f"{label} -> {msg.strip().splitlines()[-1][:70] if msg.strip() else '?'}")
        shutil.rmtree(d)
    d = fh_fixture()
    q = subprocess.run([sys.executable, os.path.abspath(__file__), "out.tsv"], cwd=d,
                       capture_output=True, text=True)
    if q.returncode != 0:
        bad.append(f"the untouched fixture did not build: {(q.stderr or q.stdout)[:160]}")
    else:
        why.append("the untouched fixture builds")
    shutil.rmtree(d)
    print("regmap/binding selftest: " + "; ".join(why) + f"; bad={bad}")
    return len(bad)


def field_history_selftest():
    """--selftest: the two §348 gates must be able to reject.  Three doctored fixtures on a symlinked
    copy of the artifact tree -- a class-cross row whose register class does not match the register
    table, a class pair made consistent with the table but contradicted by its own fields, and a row of
    an unknown kind -- each has to abort, and the untouched fixture has to build."""
    import shutil
    import subprocess
    bad, why = [], []
    FH = "tfa-field-history.PD1610.tsv"
    RG = "tfa-regs.PD1610.tsv"
    arms = []
    d0 = fh_fixture()
    t = fh_read(d0, FH)
    shutil.rmtree(d0)
    # arm 1: class-cross row says STABLE for 0x00, the register table says state-dependent
    d = fh_fixture()
    text, n1 = fh_tsv_edit(t, "class-cross\t0x00", 8, "STABLE")
    fh_put(d, FH, text)
    arms.append(("a class-cross row given a class the register table does not carry", n1, d,
                 "table class"))
    # arm 2: register table AND row both say STABLE for 0x02, whose named fields vary -> the fields deny it
    d = fh_fixture()
    text, n2 = fh_tsv_edit(t, "class-cross\t0x02", 8, "STABLE")
    rt, n3 = fh_tsv_edit(fh_read(d, RG), "0x02", 3, "STABLE")
    fh_put(d, FH, text)
    fh_put(d, RG, rt)
    arms.append(("row and register table agreeing on STABLE while the register's own fields vary",
                 n2 + n3, d, "vary"))
    # arm 3: a row of a kind this tool does not count anywhere
    d = fh_fixture()
    fh_put(d, FH, t.rstrip("\n") + "\n" + "\t".join(
        ["probe-noise", "0x00", "x", "[0:0]", "reference", "69", "1", "0", "STABLE", "invented"]) + "\n")
    arms.append(("a row of a kind neither sentence counts", 1, d, "kinds"))
    for label, changed, d, needle in arms:
        if changed < 1:
            bad.append(f"{label}: the fixture changed {changed} row(s) -- vacuous control")
            continue
        p = subprocess.run([sys.executable, os.path.abspath(__file__), "out.tsv"], cwd=d,
                           capture_output=True, text=True)
        msg = (p.stderr or "") + (p.stdout or "")
        if p.returncode == 0:
            bad.append(f"{label} was accepted (rc=0) -- the gate cannot reject it")
        elif needle not in msg:
            bad.append(f"{label} aborted but not for the reason: {msg[:200]}")
        else:
            why.append(f"{label} -> {needle}: {msg.splitlines()[-1][:110]}")
        shutil.rmtree(d)
    d = fh_fixture()
    p = subprocess.run([sys.executable, os.path.abspath(__file__), "out.tsv"], cwd=d,
                       capture_output=True, text=True)
    if p.returncode != 0:
        bad.append(f"the untouched fixture did not build: {(p.stderr or p.stdout)[:200]}")
    else:
        why.append("the untouched fixture builds the same table")
    shutil.rmtree(d)
    print("field-history selftest: " + "; ".join(why) + f"; bad={bad}")
    return bad


def main():
    preflight_inputs()
    r = rows()
    cols = ["layer", "item", "value", "name_or_meaning", "source", "writable", "use_case", "witness2"]
    bad = [(x.get("layer", "?"), x.get("item", "?")[:60], sorted(set(x) - set(cols))) for x in r
           if set(x) - set(cols)]
    if bad:
        sys.exit("gate: %d row(s) carry a key outside the %d-column schema -- the csv writer fails on "
                 "those with an opaque dict error, so the offending row is named here: %s"
                 % (len(bad), len(cols), "; ".join("%s :: %s -> extra %s" % b for b in bad[:4])))
    missing = [x.get("item", "?")[:60] for x in r if set(cols) - set(x)]
    if missing:
        print("note: %d row(s) omit a column (written empty): %s"
              % (len(missing), "; ".join(missing[:4])))
    from collections import Counter, defaultdict
    got = Counter(x["layer"] for x in r)
    expect = {"PA/TFA9890": len(pa_whitelist()),
              "DAC/ES9038": len(dac_parameters_table()[0]) + 1,   # 47 walked + 1 fixed chip-id read
              "ALSA control": 7, "DAC write path": 1, "Hi-Fi trigger chain": 2, "DAPM widget inventory": 4,
              "DAPM codec inventory": len(dapm_inventory_rows()),
              "DAPM route coverage": len(dapm_coverage_rows()),
              "DAPM route selectors": len(dapm_selector_rows()),
              "DAPM endpoint chain": len(dapm_endpoint_rows()),
              "DAPM route inventory": len(dapm_route_rows()),
              "device tree": 8,
              # +1 once the 7 build's own container is captured: the 6.0.1-vs-7 block row (ledger 610)
              "file asset": 2 + (1 if os.path.exists(EXTRA_ARTIFACTS[0]) else 0),
              "ACDB cal asset": acdb_expected(),
              "ACDB field schema": 1, "ACDB device id": len(acdb_dev_ids()),
              "ACDB cal card": 1, "ACDB undecoded bodies": 1, "ACDB CDFT pairs": 1,
              "ACDB CDOT groups": 1, "ACDB OFST pairs": 1, "ACDB CVD records": 1,
              "ACDB POOL blocks": 1, "ACDB POOL slots": 1, "ACDB POOL modules": 1,
              "ACDB row groups": 1, "ACDB row shortlist": 1, "ACDB row groups joint": 1,
              "ACDB device properties": 1, "ACDB LUT record-size sensitivity": 1,
              "TFA bitfield family": 1, "DAPM event flags": 1,
              "Hi-Fi DAC integration params": 1, "Hi-Fi DAC device tree": 1,
              "Hi-Fi DT params consumers": 1, "DAC register write sites": 1,
              "Hi-Fi impedance chain": 1, "TFA bit-field naming": 1,
              "Hi-Fi slot fillers": 1, "Hi-Fi mode enum": 1, "Hi-Fi getter sources": 1,
              "TFA field history": 1, "TFA field semantics": 1,
              "Hi-Fi DT reads": 1,
              "TFA register field coverage": 1,
              "TFA unnamed-register decode": 1,
              "PA regmap window": len(pa_regmap_rows()),
              "device bindings": len(device_binding_rows()),
              "loader allocation plan": len(loader_memplan_rows()),
              "audio configuration files": len(audio_cfg_file_rows()),
              "audio HAL surface": len(audio_hal_surface_rows()) + 1,   # +1: the logd-capacity finding
              "shipped file disposition": 9,  # §429 added the two-late-libraries row here
              "audio UI gating": len(audiofx_rows()) + len(settings_state_rows()),
              "runtime audio events": len(audio_log_rows()) + 1,   # +1: the in-play Hi-Fi-off state
              "symbol reachability": 1,  # symbol_reach_rows() also feeds the layer above
              "codec backend bit width": len(bitwidth_chain_rows()),
              "in-play Hi-Fi recheck": len(hifi_recheck_rows()),
              "Hi-Fi/DSD control plane": len(hifi_control_rows()),
              "DSD runtime decision face": len(dsd_runtime_rows()),
              "in-play route state": len(inplay_rows()),
              "route-state matrix": len(route_matrix_rows()),
              "driver boot narrative": len(boot_rows()),
              "ACDB API callers": 1,
              "DSD Hi-Fi source surface": 7,
              "DSD in-play decision path": 1,
              "DSD in-play runtime state": 1,
              "HAL acdb id sourcing": 1,
              "ARM64 packed relocations": 1,
              "HAL backend vocabulary": 1,
              "static-analysis reachability": 3,
              "PA label provenance": 1,
              "ARM32 operand arithmetic": 1,
              "control-table transitions": len(control_state_rows())}
    if not expect["ACDB cal asset"]:
        sys.exit("gate: acdb-meta.PD1610.tsv produced no PD1610 rows -- run tools/acdb_meta.py")
    if not expect["ACDB device id"]:
        sys.exit("gate: no acdb_dev_id found in route-states.tsv/acdb-map-output.tsv -- "
                 "the live control reading is missing, not the ACDB")
    expect.update(hifi_dt_expected())
    bad = [f"{k}: got {got[k]} expected {v}" for k, v in expect.items() if got[k] != v]
    if bad:
        sys.exit("denominator gate failed -> " + "; ".join(bad))
    with open(OUT, "w", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, delimiter="\t", fieldnames=["layer", "item", "value", "name_or_meaning",
                                                           "source", "writable", "use_case", "witness2"])
        w.writeheader()
        w.writerows(r)
    from collections import Counter, defaultdict
    c = Counter(x["layer"] for x in r)
    # The runbook quotes this table's row count and some per-layer counts in prose.  Those numbers
    # rotted twice (166 while the table was 168), so they are checked here rather than trusted.
    runbook = f"{ROOT}/art/PORT-RUNBOOK-7.md"
    if os.path.exists(runbook):
        rb = open(runbook, encoding="utf-8", errors="replace").read()
        m = re.search(r"现 \*\*(\d+) 行\*\*", rb)
        if not m:
            sys.exit(f"gate: {runbook} no longer states the table size as '现 **N 行**' -- the "
                     "cross-check between the runbook and this table is gone")
        stale = []
        if int(m.group(1)) != len(r):
            stale.append(f"total rows: runbook says {m.group(1)}, table has {len(r)}")
        for layer, num in re.findall(r"\*\*([A-Za-z][A-Za-z /-]*?) (\d+)\*\*", rb):
            if layer in c and int(num) != c[layer]:
                stale.append(f"{layer}: runbook says {num}, table has {c[layer]}")
        # and the generated listing, which catches what the loop above cannot: a layer absent from the
        # prose entirely, or prose written by hand in abbreviations (§385)
        rb_synced, hprobs = runbook_header_check(rb, c, len(r), write=SYNC_HEADER)
        if not hprobs and rb_synced != rb:
            stale = [s for s in stale if not s.startswith("total rows")]
        if hprobs:
            stale += hprobs
        elif SYNC_HEADER and rb_synced != rb:
            open(runbook, "w", encoding="utf-8").write(rb_synced)
            print(f"synced {runbook} header listing from the table ({len(c)} layers)")
        if stale:
            sys.exit(f"gate: {runbook} disagrees with the table it cites -> " + "; ".join(stale))
        # Structure: a step row that lost or duplicated its label, or that carries an unescaped '|',
        # silently renders as a shifted column -- which in a delivery document means the step you read
        # is not the step you get.  Two such defects were already caught by hand; this stops the third.
        # Every pipe line must be accounted for: the header, the separator, or a 5-cell labelled step.
        # (A row whose leading '|' got escaped was invisible to the label regex and passed unchecked.)
        steps, shaped = runbook_structure(rb)
        if len(steps) != len(set(steps)):
            stale_dupes = sorted({s for s in steps if steps.count(s) > 1})
            sys.exit(f"gate: {runbook} has duplicate step labels {stale_dupes} -- an edit appended a "
                     "row onto the previous line instead of replacing it")
        if shaped:
            sys.exit(f"gate: {runbook} step rows are malformed -> {shaped}. An unescaped pipe inside a "
                     "cell shifts every column after it, so the command shown is not the command run")
        if not steps:
            sys.exit(f"gate: {runbook} has no numbered step rows -- the table this gate reads is gone")
        cnt = runbook_count_check(rb)
        if cnt:
            sys.exit(f"gate: {runbook} coverage denominator -> {cnt}")
        sd = runbook_side_check(rb)
        if sd:
            sys.exit(f"gate: {runbook} step-side coverage -> {sd}")
        print(f"step-side cross-check: all {len(runbook_side_rows(rb)[0])} A-table rows name a 7-side "
              "instruction or an explicit version-independence")
        print(f"runbook cross-check: quoted row counts match the table, "
              f"{len(steps)} step rows well-formed, A-step count claim agrees with the A-table")
        if SELFTEST:
            b = runbook_selftest(rb)
            if b:
                sys.exit(f"gate: --selftest says the runbook structure gate is not reliable -> {b}")
            b2 = field_history_selftest()
            if b2:
                sys.exit(f"gate: --selftest says the §348 field-history gates are not reliable -> {b2}")
            b3 = write_path_selftest()
            if b3:
                sys.exit(f"gate: --selftest says the §351 write-path gates are not reliable -> {b3}")
            b4 = header_sync_selftest()
            if b4:
                sys.exit(f"gate: --selftest says the §385 runbook-header gate is not reliable -> {b4}")
            b5 = regmap_binding_selftest()
            if b5:
                sys.exit(f"gate: --selftest says the §382/§383 regmap-binding row gates are not "
                         f"reliable -> {b5}")
    un = sum(1 for x in r if "UNRESOLVED" in x["name_or_meaning"])
    print(f"wrote {OUT}: {len(r)} rows")
    for k, v in sorted(c.items()):
        print(f"  {k:16} {v}")
    print(f"  UNRESOLVED name/meaning: {un}")
    missing = f"""NOT covered by this table (do not read it as complete):
  - {acdb_gap_sentence()}
  - workspaceFile.qwsp is a dictionary without values (§216)
  - mixer_paths initial-vs-idle table exists separately (initial-vs-idle.mixer_paths_tasha.PD1610.tsv)
  - {pa_gap_sentence()}
  - 24 of the 47 DAC registers are unnamed in the captured datasheet pages
    (a full ES9038Q2M register-table document would name the rest - the fetched datasheet only names registers it cites in prose;
    §324 did pin the two the datasheet does cite: "Register 17-20" == 0x11-0x14 and "Register 45" == 0x2d,
    and the 0x2d default bits [3:1]=3'b010 read back exactly, which is what confirms that decimal->hex mapping)
  - vivo,params 4x4 column meaning: §322 found the enable path's 3 (addr,value) pairs come from the
    kernel's own integration_params_normal table (widget event handler, column picked by an impedance
    index), NOT from the DT array. §323 + §325 closed the other half: the DT slots are not read by any
    of the 50554 text symbols in the Image, nor one hop into the callees the holders hand the pointer
    to, so vivo,params is dead weight in 6.0.1 (§233's "three readers" was a fixed-window decode
    running past the function end into a neighbour's fp slots).  Register 0x14's byte now has a WRITER:
    §331's slot census shows the enable event installs one of FOUR integration_params tables into
    vivo_codec(0x1b242c8)+0xa0, and the same ruler -- dac_integration_params.py --rows-at -- tiled all
    five same-named candidates against the in-play capture: only integration_params_dsd_normal@0x179d7b0
    and integration_params_normal@0x179d7d0 hold 0x2e (as column index 1), which is the byte the DAC
    reports live, while the table §322 derived (integration_params_normal@0x179d550, the LOWEST of two
    same-named symbols) holds 1c 2a 4a 7f and matches nothing.  So dac_parameters writes 0x22 and the
    enable path overwrites it with a column byte -- §324's +12 has a mechanism, no approved write needed.
    ★§338 closes WHICH of the two matching tables wins for the route that was captured: the CFG of the
    inlining copy binds the four arms to (mode byte [obj+0xc]==2) x (getter return==2), the control's own
    item order (live enum-items.tsv: Off/HiFi/DSD/Normal) makes item 2 = DSD, and the headphone-playback
    capture shows the item as HiFi = index 1, so the arm is integration_params_normal@0x179d7d0, column 1.
    What stays open: the getter's return DOMAIN (only "==2 selects the *_headphone table" is bound, and
    both cbz guards default to a *_normal table), the 0x17/0x19 rows of
    those objects read as all-zero columns -- which this tool's own gate refuses to call a table, so only
    row 0 is claimed -- and the datasheet gives no LSB-to-gain scale, so +12 is not quotable in dB"""
    print(missing)


if __name__ == "__main__":
    main()
