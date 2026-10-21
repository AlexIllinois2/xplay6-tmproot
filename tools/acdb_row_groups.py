#!/usr/bin/env python3
"""tools/acdb_row_groups.py -- which COEFFICIENT rows are vivo's own: group boards per card key.

Why this exists.  §307 ended the pool as a candidate home for the tuning ("PD1610-SOLO = 0"), and §271
had already found that the Hi-Fi device 150 has 0 calibration rows in the generic sets against a 207-row
baseline.  This tool answers the same question one layer down, where the sound floor actually is: the
*LUT* coefficient rows.  Each row is identified by (table, acdb_dev_id, app_type, sample_rate) -- the
card view tools/acdb_card.py --devices all emits -- and everything else in the record is the payload.
Boards are then grouped by that payload, so the answer is not "does this file differ" but "which named
rows does this phone share with the reference boards, and which does it not".

The two admissibility rules ledger 307 established are applied here, and both can drop rows:
  * occurrence count per board must be equal -- a key that exists twice on one board and once on another
    is not the same object, so comparing them measures my grouping, not the calibration;
  * payload length must be equal -- a record truncated on one board would always "differ";
  * and (ledger 310) the identity columns must come from ONE pooled reading of every board.  The
    card artifacts let each set pick its own columns, and for VPDYLUT0 that produced "device + 4
    words" on PD1610 against "device + sample-rate + 3 words" on the reference boards, although
    every board stores the same 20-byte record -- which invented 9 "cards vivo removed".  Reading
    the tables here and deciding the columns once removes the failure mode instead of guarding it.
Dropped counts are printed, never hidden.

Identity columns are board-stable BY CONSTRUCTION here: the table NAME, the device id, the app_type and
the sample rate -- never a byte offset or a table_off (ledger 307: PD1610 files the same records under
different collection keys, so positional columns are not identities).

Controls: PD1610 vs PD1610LG4 and Fluid vs Liquid must show ZERO differing rows because those file pairs
are byte-equal (ledger 261/267); if a control moves, the grouping is broken and the tool aborts.  A
cross-board pair must move, or the ruler is too coarse to name anything.

Row-surface verdicts (ledger 311).  A row that exists on every reference board and not here is not
automatically a card vivo deleted, and it was nearly read as the opposite: ledger 310 labelled every
reference-only slot whose table the main board filed under another device id 'RE-NUMBERED'.  Three arms
must now pass before that label may be used (slot_verdicts): the board's own ACDB name pool has to call
both ids the same device, the missing id must have no row anywhere else on this board, and the candidate
id must carry an identical payload at the same table+app+rate.  On this board all eight such slots fail
all three -- the pool names 38 BT_SCO_NB_MIC and 838 BT_SCO_NRECOFF_MIC, PD1610 keeps rows for 38 in
three other tables, and no payload is shared -- so those eight voice-table rows are a substitution by a
DIFFERENT device, not one card under two numbers.  --dev-alias is there for the case where the arms do
pass (Android 7 may really re-number), and it refuses a map that merges two differently-named ids.  All
three states are exercised by --selftest, which injects an alias, a substitution and an empty slot.

The listening-path device set is DERIVED, not typed (ledger 309): it is the union of
  * every id in art/audio-6.0.1/acdb-map-output.tsv -- the live routed outputs (SND_DEVICE_OUT_SPEAKER=15,
    SND_DEVICE_OUT_SPEAKER_PROTECTED=124), and
  * every id whose ACDB pool name carries "HiFi" (150 = 150_HEADSET_SPKR_STEREO_HiFi), because the Hi-Fi
    path is a switch, not the currently-routed device, so it never shows up in a live map capture.
The rule and its members are printed, and --path-devices overrides them for a board whose routing differs.

usage: tools/acdb_row_groups.py [--dirs PD1610 PD1516A QRD MTP Fluid] [--out TSV] [--shortlist TSV]
                                [--path-devices auto|15,124,150] [--dev-alias NEW=OLD,...] [--selftest]

The copy list is finally checked against the HOOK layer (ledger 312, tools/acdb_matrix.py's
acdb-matrix.PD1610-missing-in-QRD.tsv): a hook is (cal_root, module, param) with a LUT table and the
devices it serves, so the only common key with a row is (table, device) -- a projection, and a one-sided
pair is a granularity difference, not a contradiction.  Every listening-device hook pair is therefore
sorted into four states (classify_hook_pairs): ON_LIST, IDENTICAL (values equal everywhere, nothing to
carry), NOT_JUDGED (an admissibility filter dropped its keys, and the reason is printed) and NO_ROW (the
hook layer says this LUT serves this listening device while the row layer has no identity for it on ANY
board).  Only NO_ROW aborts.  On this board the hook layer's listening pairs are exactly ACGILUT0 x
{15,124,150} and all three are ON_LIST, while ACGDLUT0/AFECLUT0/AVOLLUT0/DPROPLUT have 0 vivo-added hooks
at all -- those cards are stock hooks whose VALUES vivo changed.  --selftest injects all four states so
the aborting one is known to be reachable.  Widening --path-devices to 15,124,150,11 shows NOT_JUDGED on
real data (dev 11 in VCGILUT0/VPSTLUT0: 260 occurrences here against 180 on every reference board), and
that flag had never run at all before ledger 312 -- the override branch read PATH before binding it, so
the documented override crashed on first use.

Ledger 316 replaced the guess half of that with a PROOF: pool_anchors() asks, per (table, word), whether
the non-zero values land on a DATAPOOL block start of the record's own file, against two matched controls
(value+4 in the same pool, and the same values against the other files' boundary sets).  Zeros are
excluded because block 0 starts at 0 -- including them had scored a column whose real value was 0 at 97%.
On these boards that names one column outright: DPROPLUT word 2 (100.00% over 5479 non-zero values,
controls 0.58% and 0.00%), plus ANC LUT0 word 2 on 63 values.  The two words the shape rule had flagged
(ACGILUT0/ACGDLUT0 word 4) are NOT confirmed and stay labelled shape-only.  The grouping therefore reads
three ways: 302 differing keys, 217 with only the proven offsets removed, 143 with the shape candidates
removed too -- so a quarter to a half of the 'values differ' surface is position.
"""
import argparse
import collections
import csv
import hashlib
import os
import struct
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))
import acdb_tlv  # noqa: E402
import acdb_pool  # noqa: E402

ACDB = acdb_tlv.ACDB
ART = os.path.join(ROOT, "art/audio-6.0.1")
RATEISH = {0, 8000, 11025, 12000, 16000, 22050, 24000, 32000, 44100, 48000, 64000,
             88200, 96000, 176400, 192000}


def table_records(stem):
    """raw fixed-record tables read straight out of one set's .acdb files: {table: [words tuple]}"""
    d = os.path.join(ACDB, stem)
    if not os.path.isdir(d):
        sys.exit(f"gate: {d} is not a calibration dir")
    out = collections.defaultdict(list)
    for f in sorted(x for x in os.listdir(d) if x.endswith(".acdb")):
        b = open(os.path.join(d, f), "rb").read()
        for off, raw, ln in acdb_tlv.walk(b)[0]:
            name = raw.strip()
            if not acdb_tlv.is_table(name):
                continue
            cnt, rs = acdb_tlv.count_rec(b, off, ln)
            if not rs or rs == "empty" or rs % 4:
                continue
            words, base = rs // 4, off + 16
            for i in range(cnt):
                at = base + i * rs
                if at + rs > off + 12 + ln:
                    break
                out[name].append(struct.unpack_from("<%dI" % words, b, at))
    return out


def pool_anchors(dirs):
    """per (table, word): the share of NON-ZERO record values that equal a DATAPOOL block start in the
    record's OWN file, measured against two matched controls (ledger 316).

    This is the structural version of the shape test in joint_keys: zeros are excluded because block 0
    starts at 0 (the shape-free version of that trap scored 97% for a column whose real value was 0),
    ctrlA shifts the value by +4 (aligned but one word wrong) and ctrlB tests the same numbers against
    the OTHER files' boundary sets (a strictly larger set, so it is the harder control).  A word that
    hits ~1.00 while both controls stay near 0 is a pool offset -- that names a column of a *LUT record
    for the first time in this project (DPROPLUT word 2)."""
    stats = collections.defaultdict(lambda: collections.defaultdict(lambda: [0, 0, 0, 0]))
    for st in dirs:
        d = os.path.join(ACDB, st)
        if not os.path.isdir(d):
            sys.exit(f"gate: {d} is not a calibration dir -- the pool-anchor test needs the real files")
        board, files = set(), []
        for f in sorted(x for x in os.listdir(d) if x.endswith(".acdb")):
            b = open(os.path.join(d, f), "rb").read()
            fields = {}
            for off, raw, ln in acdb_tlv.walk(b)[0]:
                fields.setdefault(raw.strip(), []).append((off + 12, ln))
            bounds = set()
            for p, ln in fields.get("DATAPOOL", []):
                for (bo, _L, _pay) in acdb_pool.walk(b[p:p + ln])[0]:
                    if bo:
                        bounds.add(bo)
            board |= bounds
            files.append((bounds, fields, b))
        for (bounds, fields, b) in files:
            foreign = board - bounds
            for name, spans in fields.items():
                if not acdb_tlv.is_table(name):
                    continue
                for p, ln in spans:
                    cnt, rs = acdb_tlv.count_rec(b, p - 12, ln)
                    if not rs or rs == "empty" or rs % 4:
                        continue
                    for i in range(cnt):
                        at = p + 4 + i * rs
                        if at + rs > p + ln:
                            break
                        for q, x in enumerate(struct.unpack_from("<%dI" % (rs // 4), b, at)):
                            if x == 0:
                                continue
                            s = stats[name][q]
                            s[0] += 1
                            s[1] += x in bounds
                            s[2] += x + 4 in bounds
                            s[3] += x in foreign
    return stats


def joint_keys(dirs, anchor=None, rules=("anchor", "shape")):
    """derive the identity columns ONCE per table from the pooled records of every board.

    Why (ledger 310): the card artifacts let each SET pick its own columns, and VPDYLUT0 came out as
    "device + 4 payload words" on PD1610 but "device + sample-rate + 3 words" on the reference
    boards -- although the record is the same 20 bytes / 5 words everywhere.  The disagreement was in
    the ruler and it manufactured 9 phantom 'removed' cards.  Pooling the rows BEFORE deciding makes
    the identity shared by construction, so no table has to be excluded for layout disagreement."""
    pooled = collections.defaultdict(dict)
    for st in dirs:
        for tab, recs in table_records(st).items():
            pooled[tab][st] = recs
    # the device-id universe must be pooled too: acdb_tlv.dev_names() reads only the BASELINE set's
    # numbered pool, and testing rows from four other boards against it refused ACGILUT0 / AVOLLUT0 /
    # DPROPLUT -- exactly the tables the port cares about (ledger 310)
    devset = set(acdb_tlv.dev_names())
    dp = os.path.join(ART, "acdb-devs.ALL.tsv")
    if os.path.exists(dp):
        for r in csv.DictReader(open(dp, encoding="utf-8"), delimiter="\t"):
            if r["acdb_dev_id"].isdigit():
                devset.add(int(r["acdb_dev_id"]))
    CARDS, LAYOUTS, info = {}, {}, {}
    ABL = {}                                     # same grouping, flagged payload words left out
    for tab, per in sorted(pooled.items()):
        rows = [r for st in dirs if st in per for r in per[st]]
        if not rows:
            continue
        words = len(rows[0])
        if any(len(r) != words for st in per for r in per[st]):
            info[tab] = ("skipped: record size varies inside the table", None, None, None, len(per))
            continue
        def dev_at(q):
            vals = {r[q] for r in rows}
            if len(vals) < 8:
                return None
            if vals <= devset:
                return "numbered pool (union over the sets compared)"
            if 1 <= min(vals) and max(vals) <= 0x1000:
                return "small-int window (ids outside the named pool)"
            return None
        dpos = next((q for q in range(words) if dev_at(q)), None)
        drule = dev_at(dpos) if dpos is not None else None
        apos = next((q for q in range(words) if q != dpos and acdb_tlv.app_type_column(
            {r[q] for r in rows}) is not None), None)
        fpos = next((q for q in range(words) if q not in (dpos, apos)
                     and {r[q] for r in rows} <= RATEISH), None)
        if dpos is None or len(per) < len(dirs):
            info[tab] = ("skipped: no device column, or the table is absent on some board",
                         dpos, apos, fpos, len(per))
            continue
        # offset-shaped payload words (ledger 314 shape rule, 316 structural rule).  A word leaves the
        # payload digest when either fires:
        #   anchor  -- >=50 non-zero values, >=50% land on a DATAPOOL block start of their own file while
        #              the +4 and foreign-pool controls stay <=5% (this NAMES the column)
        #   shape   -- never a rate, >=8 distinct values, cross-board value overlap <=0.20, word-aligned
        #              and non-decreasing inside a device run (this only makes a SENSITIVITY claim)
        susp = []
        for q in range(words):
            if q in (dpos, apos, fpos):
                continue
            sets = [{r[q] for r in per[st]} for st in dirs if st in per]
            if not sets:
                continue
            u, i = set().union(*sets), set.intersection(*sets)
            if len(u) < 8 or u <= RATEISH:
                continue
            a = (anchor or {}).get(tab, {}).get(q)
            anch = None
            if a and a[0] >= 50:
                h, ca, cb = a[1] / a[0], a[2] / a[0], a[3] / a[0]
                if h >= 0.50 and ca <= 0.05 and cb <= 0.05:
                    anch = (h, ca, cb, a[0])
            runs = []
            for st in dirs:
                by = collections.defaultdict(list)
                for r in per[st]:
                    by[r[dpos]].append(r[q])
                runs += [lst for lst in by.values() if len(lst) > 3]
            mono = (sum(sum(1 for k in range(len(lst) - 1) if lst[k + 1] >= lst[k]) / (len(lst) - 1)
                        for lst in runs) / len(runs)) if runs else 0.0
            div4 = sum(1 for r in rows if r[q] % 4 == 0) / len(rows)
            ov = len(i) / len(u)
            shape = ov <= 0.20 and div4 >= 0.95 and mono >= 0.90
            if anch or shape:
                susp.append((q, "anchor" if anch else "shape", round(ov, 3), round(div4, 2),
                             round(mono, 3), anch))
        info[tab] = ("ok", dpos, apos, fpos, len(per), drule, susp)
        drop = {s[0] for s in susp if (s[1] == "anchor" and "anchor" in rules)
                or (s[1] == "shape" and "shape" in rules)}
        for st in dirs:
            c = CARDS.setdefault(st, {})
            a = ABL.setdefault(st, {})
            for r in per[st]:
                # keep the identity as TEXT: the listening-path set comes from artifacts as
                # strings, and an int-vs-str key would silently match nothing downstream
                key = (tab, str(r[dpos]),
                       str(r[apos]) if apos is not None else "-",
                       str(r[fpos]) if fpos is not None else "-")
                rest = tuple(r[q] for q in range(words) if q not in (dpos, apos, fpos))
                c.setdefault(key, []).append(hashlib.sha256(repr(rest).encode()).hexdigest()[:12]
                                            + "/" + str(len(rest)))
                rest2 = tuple(r[q] for q in range(words) if q not in {dpos, apos, fpos} | drop)
                a.setdefault(key, []).append(hashlib.sha256(repr(rest2).encode()).hexdigest()[:12]
                                             + "/" + str(len(rest2)))
            LAYOUTS.setdefault(st, {})[tab] = {(words, False, False)}
    return CARDS, LAYOUTS, info, ABL, pooled


def path_devices(set_hint="PD1610"):
    """derive the listening-path device ids and return (ids, provenance lines)"""
    ids, why = set(), []
    mp = os.path.join(ART, "acdb-map-output.tsv")
    if os.path.exists(mp):
        for r in csv.reader(open(mp, encoding="utf-8"), delimiter="\t"):
            if len(r) == 2 and r[1].strip().isdigit():
                ids.add(r[1].strip())
                why.append(f"{r[1].strip()}={r[0]} (live routed output)")
    dp = os.path.join(ART, f"acdb-devs.{set_hint}.tsv")
    if os.path.exists(dp):
        for r in csv.DictReader(open(dp, encoding="utf-8"), delimiter="\t"):
            if "hifi" in (r.get("names") or "").lower().replace("_", ""):
                ids.add(r["acdb_dev_id"])
                why.append(f"{r['acdb_dev_id']}={r['names'].split(';')[0]} (Hi-Fi switch path)")
    if not ids:
        sys.exit("gate: no listening-path device id could be derived (acdb-map-output.tsv and "
                 "acdb-devs.<set>.tsv both empty or missing) -- refusing to fall back to a typed list")
    return ids, why


def card_path(stem):
    for suffix in ("-full", ""):
        p = os.path.join(ART, f"acdb-card.{stem}{suffix}.tsv")
        if os.path.exists(p):
            return p, suffix == "-full"
    sys.exit(f"gate: no card table for {stem} -- run: python3 tools/acdb_card.py --dir {stem} --devices all")


def load(stem):
    p, full = card_path(stem)
    if not full:
        print(f"  NOTE {stem}: only the named-device card {os.path.basename(p)} exists; its row set is "
              "narrower than --devices all, so shared rows may look 'only on this board'. "
              "Re-run tools/acdb_card.py --devices all for a fair compare")
    out = collections.defaultdict(list)
    layout = collections.defaultdict(set)
    for r in csv.DictReader(open(p, encoding="utf-8"), delimiter="\t"):
        key = (r["table"], r["acdb_dev_id"], r["app_type"], r["sample_rate"])
        words = len((r["rest_of_record"] or "").split()) if r["rest_of_record"] else 0
        out[key].append(hashlib.sha256((r["rest_of_record"] or "").encode()).hexdigest()[:12] +
                        f"/{words}")
        # the layout fingerprint tools/acdb_card.py chose for this table on this board: how many words
        # are left after the identity columns, and whether it found an app_type / sample-rate column at
        # all.  Those columns are DERIVED per set, so two boards that disagree here were not read with
        # the same ruler and their keys must not be counted as added or removed (ledger 309).
        layout[r["table"]].add((words, r["app_type"] == "-", r["sample_rate"] == "-"))
    return out, layout


def comparable(layouts):
    """a table is comparable only when every board carries it AND the derived layout matches there"""
    tabs = sorted({t for l in layouts.values() for t in l})
    ok, dropped = set(), []
    for tab in tabs:
        present = [l[tab] for l in layouts.values() if tab in l]
        fps = {frozenset(fp) for fp in present}
        if len(present) == len(layouts) and len(fps) == 1:
            ok.add(tab)
        else:
            dropped.append((tab, len(present), len(fps)))
    return ok, dropped


def tab_index(cards, oktab):
    """table -> device id -> the boards that carry a row for it in that table"""
    m = collections.defaultdict(lambda: collections.defaultdict(set))
    for st, c in cards.items():
        for (t, dev, _a, _r) in c:
            if t in oktab:
                m[t][dev].add(st)
    return m


def slot_verdicts(cards, oktab, main, names):
    """for every (table, device) slot that every reference board calibrates and MAIN DOES NOT, decide
    between three readings instead of assuming one.

    Ledger 310 printed 'RE-NUMBERED?' whenever the main board carried the same table/app/rate under some
    other device id.  In this data every one of those hits was dev 38 vs dev 838 in the same 8 voice
    tables with 22 devices on both sides -- a shape that looks exactly like a re-numbering, but is not:
    PD1610's own ACDB name pool calls 38 BT_SCO_NB_MIC and 838 BT_SCO_NRECOFF_MIC, and PD1610 keeps
    rows for 38 in three other tables (coexistence).  So the label was a guess about the ruler's blind
    spot, and the blind spot is a claim about vivo's calibration.  Three arms now have to pass before a
    slot may be called an alias, and the arm that fails is printed:
      A name      the main board's pool must call both ids the SAME device tail (unknown = not admissible)
      B coexist   the main board must NOT have rows for the missing id anywhere else
      C payload   a row for the candidate id must carry the SAME payload in the same table/app/rate
    Otherwise the slot is SUBSTITUTED (another named device sits in it) or REMOVED (nothing sits in it).
    """
    refs = [st for st in cards if st != main]
    ti = tab_index(cards, oktab)
    out = []
    for tab in sorted(ti):
        for dev, boards in sorted(ti[tab].items(), key=lambda kv: int(kv[0])):
            if main in boards or not set(refs) <= boards:
                continue
            cands = sorted([d2 for d2, b2 in ti[tab].items()
                            if main in b2 and not (set(refs) & b2)], key=int)
            best, arms, is_alias = None, {}, False
            for c in cands:
                n1, n2 = names.get(int(dev)), names.get(int(c))
                pay = sum(1 for k1 in cards[main] if k1[0] == tab and k1[1] == c
                          for k2 in cards[refs[0]]
                          if k2[0] == tab and k2[1] == dev and k2[2] == k1[2] and k2[3] == k1[3]
                          and sorted(cards[main][k1]) == sorted(cards[refs[0]][k2]))
                co = any(tab2 != tab and main in ti[tab2][dev] for tab2 in ti)
                ok_arms = (n1 is not None and n1 == n2, not co, pay > 0)
                if all(ok_arms):
                    best, is_alias = c, True
                    arms = dict(name=f"{dev} and {c} are both '{n1}'",
                                coexist=f"no row for {dev} on {main} in any comparable table",
                                payload=f"{pay} identical payload row(s)")
                    break
                if best is None:
                    best, arms = c, dict(
                        name=(f"differ: {dev}='{n1}' vs {c}='{n2}'" if n1 != n2 else
                              "unknown (one id is not in this board's name pool)"
                              if n1 is None or n2 is None else "same"),
                        coexist=(f"{main} also carries {dev} in other tables -> both ids are live, "
                                 "so they cannot be one device" if co else "no"),
                        payload=f"{pay} identical payload row(s)")
            cls = "REMOVED" if best is None else "ALIAS" if is_alias else "SUBSTITUTED"
            out.append((tab, dev, best, arms, cls))
    return out, ti, refs


def apply_alias(cards, amap):
    """rewrite every board's device column through a measured id map (used only when a slot verdict says
    the same device really is filed under another number -- ledger 311)"""
    moved = 0
    for st, c in cards.items():
        new = {}
        for k, v in c.items():
            k2 = (k[0], amap.get(k[1], k[1]), k[2], k[3])
            moved += k2 != k
            new.setdefault(k2, []).extend(v)
        cards[st] = new
    return moved


def parse_alias(spec):
    out = {}
    for part in (spec or "").split(","):
        if "=" in part:
            a, b = part.split("=", 1)
            out[a.strip()] = b.strip()
    return out


def alias_selftest(oktab, names):
    """inject a real re-numbering and prove the detector calls it ALIAS (the measured data calls 0)."""
    base = {st: {} for st in ("MAIN", "REF1", "REF2", "REF3")}
    for st in base:
        for dev in ("15", "124", "38"):
            base[st][("DPROPLUT", dev, "-", "-")] = ["deadbeef/4"]
        base[st][("VPSTLUT0", "38", "-", "16000")] = ["cafe1234/3"]
    # MAIN: device 15 is filed under 900 (one device, two numbers), device 124's slot is filled by no
    # id of that name at all (only 900 sits there, and it names a different device), and VPSTLUT0 loses
    # device 38 with nothing left in the table
    base["MAIN"][("DPROPLUT", "900", "-", "-")] = base["MAIN"].pop(("DPROPLUT", "15", "-", "-"))
    del base["MAIN"][("DPROPLUT", "124", "-", "-")]
    del base["MAIN"][("VPSTLUT0", "38", "-", "16000")]
    names2 = {**names, 900: names.get(15)}
    v, _ti, _r = slot_verdicts(base, {"DPROPLUT", "VPSTLUT0"}, "MAIN", names2)
    got = {tab + "/" + dev: cls for (tab, dev, _b, _a, cls) in v}
    want = {"DPROPLUT/15": "ALIAS", "DPROPLUT/124": "SUBSTITUTED", "VPSTLUT0/38": "REMOVED"}
    bad = {k: (got.get(k), want[k]) for k in want if got.get(k) != want[k]}
    if bad:
        sys.exit(f"gate: alias detector mislabels the injected cases {bad} -- the verdict it prints on "
                 "the real boards would be untested")
    n = apply_alias(base, {"900": "15"})
    v2, _ti2, _r2 = slot_verdicts(base, {"DPROPLUT", "VPSTLUT0"}, "MAIN", names2)
    got2 = {t + "/" + d: c for (t, d, _b, _a, c) in v2}
    if ("DPROPLUT", "15", "-", "-") not in base["MAIN"] or "DPROPLUT/15" in got2:
        sys.exit(f"gate: the injected map rewrote {n} keys but the aliased pair never joined the row -- "
                 "--dev-alias would change nothing while looking like it fixed the surface")
    want2 = {"DPROPLUT/124": "REMOVED", "VPSTLUT0/38": "REMOVED"}
    bad2 = {k: (got2.get(k), want2[k]) for k in want2 if got2.get(k) != want2[k]}
    if bad2 or len(got2) != len(want2) or any(c == "ALIAS" for c in got2.values()):
        sys.exit(f"gate: normalisation left a slot in the wrong state {bad2} (surface after it: {got2})")
    return (f"injected 15->900 read as ALIAS, a slot held by a differently-named id as SUBSTITUTED, "
            f"an empty slot as REMOVED; applying 900=15 rewrote {n} key(s), took ALIAS off the surface "
            f"and left no slot able to be called an alias")



def classify_hook_pairs(hpath, union, bypair, unjudged):
    """four states for a hook pair that serves a listening device (ledger 312).

    Only NO_ROW may not be published past: it means the hook layer says this LUT serves this listening
    device while the coefficient row layer has no identity for it on ANY board -- two independent
    readings of the same table disagree.  NOT_JUDGED is a gap I must name (with the filter that dropped
    it) but it is not a contradiction, and ON_LIST / IDENTICAL are both legitimate absences from the
    copy list (one because the values are the same everywhere, one because it IS on the list)."""
    cls = {"ON_LIST": [], "NO_ROW": [], "NOT_JUDGED": [], "IDENTICAL": []}
    for p in sorted(hpath, key=lambda x: (x[0], int(x[1]))):
        if p in union:
            cls["ON_LIST"].append(p)
        elif not bypair.get(p):
            cls["NO_ROW"].append(p)
        elif p in unjudged:
            cls["NOT_JUDGED"].append(p)
        else:
            cls["IDENTICAL"].append(p)
    return cls


def hook_arm_selftest():
    """all four states injected, and the hard one must be reachable (it never happens on these boards)."""
    hpath = {("T1", "15"), ("T2", "15"), ("T3", "15"), ("T4", "15")}
    union = {("T1", "15")}
    bypair = {("T2", "15"): ["k"], ("T4", "15"): ["k"]}
    unjudged = {("T2", "15"): ["occurrence count [260, 180]"]}
    cls = classify_hook_pairs(hpath, union, bypair, unjudged)
    want = {"ON_LIST": [("T1", "15")], "NO_ROW": [("T3", "15")],
            "NOT_JUDGED": [("T2", "15")], "IDENTICAL": [("T4", "15")]}
    if {k: sorted(v) for k, v in cls.items()} != want:
        sys.exit(f"gate: the hook arm misclassifies the injected four states {cls} -- its report on the "
                 "real boards would be unreadable")
    return ("injected pairs classified ON_LIST/NO_ROW/NOT_JUDGED/IDENTICAL as expected, so the aborting "
            "state is reachable even though these boards never produce it")


def anchor_selftest(anchor, tabs):
    """the anchor rule must have a positive AND a negative on this data (ledger 316)."""
    tested = flagged = 0
    for tab in tabs:
        for q, a in (anchor.get(tab) or {}).items():
            if a[0] < 50:
                continue
            tested += 1
            h, ca, cb = a[1] / a[0], a[2] / a[0], a[3] / a[0]
            if h >= 0.50 and ca <= 0.05 and cb <= 0.05:
                flagged += 1
                if h < 10 * max(ca, cb, 1e-9) and max(ca, cb) > 0.005:
                    sys.exit(f"gate: {tab} word {q} was declared an offset with controls at "
                             f"{ca:.2%}/{cb:.2%} -- the rule no longer separates anchor from chance")
    if not tested:
        sys.exit("gate: no payload word had >=50 non-zero values to test -- the anchor rule would be "
                 "reporting from an empty denominator")
    if not flagged:
        sys.exit("gate: the anchor rule flagged nothing on data where DPROPLUT word 2 is a known pool "
                 "offset -- a rule with no positive here is not a ruler")
    if flagged == tested:
        sys.exit(f"gate: the anchor rule flagged ALL {tested} tested words -- it has no selectivity")
    return (f"{tested} payload words had >=50 non-zero values, {flagged} declared pool offsets "
            f"(positive exists), {tested - flagged} rejected by the +4/foreign-pool controls (negative exists)")


def hooks_file():
    return os.path.join(ART, "acdb-matrix.PD1610-missing-in-QRD.tsv")


def hook_projection():
    """the (lut_table, device) pairs behind the hook layer's 'vivo added this hook' list (ledger 270).

    A hook is (cal_root, module_id, param_id) with a LUT table and the devices that table serves for it;
    a copy-list row is (table, device, app_type, rate).  Only (table, device) is common, so this is a
    PROJECTION and a disagreement between the two layers is not a contradiction -- it is what comparing
    different granularities looks like.  What IS admissible to gate: a hook that serves a listening device
    and is missing from the copy list, because then the audible path has a vivo-added object the port
    would not carry."""
    hp = hooks_file()
    if not os.path.exists(hp):
        sys.exit(f"gate: {hp} is missing -- the hook layer cannot be compared with the copy list, so no "
                 "cross-check may be printed (run tools/acdb_matrix.py first)")
    rows = list(csv.DictReader(open(hp, encoding="utf-8"), delimiter="\t"))
    if not rows:
        sys.exit(f"gate: {hp} has 0 rows -- comparing the copy list against an empty hook list proves "
                 "nothing")
    pairs, odd = set(), collections.Counter()
    for h in rows:
        tab = h["lut_table"].strip()
        devs = [d.strip() for d in h["lut_devices"].split(",") if d.strip()]
        if not tab or tab == "-":
            odd["hook rows with no lut_table"] += 1
            continue
        if not devs:
            odd["hook rows with an empty device list"] += 1
        for d in devs:
            pairs.add((tab, d))
    return rows, pairs, odd, hp


def we_words(we, k):
    return "|".join(str(q) for q in we[k]["words"]) if k in we and we[k]["words"] else "-"


def we_partners(we, k):
    if k not in we or not we[k]["words"]:
        return "-"
    return ";".join(f"{q}:{','.join(we[k]['partners'][q]) or 'none'}" for q in we[k]["words"])

def ablate(cards, abl, oktab):
    """key -> (differ with the full payload, differ with the offset-shaped words left out).

    Same filters as the main grouping (>=3 boards, equal occurrence count, equal payload length), so the
    two verdicts are the same statistic read twice -- not a second ruler (ledger 310's lesson)."""
    out = {}
    if not abl:
        return out
    keys = {k for st in cards for k in cards[st] if k[0] in oktab}
    for k in sorted(keys):
        pf = {st: cards[st][k] for st in cards if k in cards[st]}
        pa = {st: abl[st][k] for st in abl if k in abl[st]}
        if len(pf) < 3 or len({len(v) for v in pf.values()}) != 1:
            continue
        if set(pa) != set(pf):
            sys.exit(f"gate: key {k} sits on {sorted(pf)} in the full payload but on {sorted(pa)} in the "
                     "ablated one -- the two digests would not be readings of the same object")
        if len({o.split("/")[1] for lst in pf.values() for o in lst}) != 1:
            continue
        out[k] = (len({tuple(sorted(v)) for v in pf.values()}) > 1,
                  len({tuple(sorted(v)) for v in pa.values()}) > 1)
    return out


def word_evidence(pooled, info, main, refs, keys):
    """per row key -> which PAYLOAD word positions differ, which boards agree with MAIN at each of them,
    and whether the difference is only in how values are PAIRED across records.

    Why the last one matters: the row verdict digests the whole payload as a multiset.  If every single
    position holds the same multiset on all boards while the digest still differs, what differs is the
    order/pairing of the sub-records, not any value -- a formatting difference, not tuning, and it must
    not be handed to Android 7 as 'carry these numbers'.  Per position this also says whether the
    differing words are the ones this tool already flagged as pool offsets or offset-shaped."""
    idx = collections.defaultdict(dict)
    for tab, per in pooled.items():
        if tab not in info or info[tab][0] != "ok":
            continue
        dpos, apos, fpos = info[tab][1], info[tab][2], info[tab][3]
        for st, recs in per.items():
            for r in recs:
                k = (tab, str(r[dpos]), str(r[apos]) if apos is not None else "-",
                     str(r[fpos]) if fpos is not None else "-")
                idx[st].setdefault(k, []).append(r)
    out = {}
    for k in sorted(keys):
        per = {st: idx[st][k] for st in [main] + refs if k in idx[st]}
        if main not in per or not per[main] or len({len(v) for v in per.values()}) != 1:
            continue
        dpos, apos, fpos = info[k[0]][1], info[k[0]][2], info[k[0]][3]
        flagged = {f[0] for f in (info[k[0]][6] if len(info[k[0]]) > 6 else [])}
        ms = {st: [collections.Counter(r[q] for r in v) for q in range(len(per[main][0]))]
              for st, v in per.items()}
        diff = []
        for q in range(len(per[main][0])):
            if q in (dpos, apos, fpos):
                continue
            if len({tuple(sorted(ms[st][q].items())) for st in per}) > 1:
                diff.append(q)
        partners = {q: sorted(st for st in per if st != main and ms[main][q] == ms[st][q]) for q in diff}
        # 'no board agrees with MAIN at this position' means two different things depending on whether the
        # position is a flagged offset: a unique VALUE, or a unique POINTER (pointers are unique by
        # construction because every file lays its pool out differently).  Keep them apart.
        novivo = [q for q in diff if not partners[q]]
        out[k] = dict(words=diff, flagged_only=bool(diff) and all(q in flagged for q in diff),
                      partners=partners, pairing_only=not diff,
                      no_partner=novivo,
                      vivo_value=[q for q in novivo if q not in flagged],
                      unique_pointer=[q for q in novivo if q in flagged])
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dirs", nargs="*", default=["PD1610", "PD1516A", "QRD", "MTP", "Fluid"])
    ap.add_argument("--out")
    ap.add_argument("--shortlist")
    ap.add_argument("--path-devices", default="auto")
    ap.add_argument("--from-cards", dest="joint", action="store_false",
                    help="use the per-set card artifacts (the ledger 309 path): each set derived "
                         "its own identity columns, which is what produced the phantom "
                         "removed cards")
    ap.add_argument("--joint", default=True, action="store_true")
    ap.add_argument("--dev-alias", default="",
                    help="device-id normalisation, e.g. --dev-alias 838=38,900=15 (new=canonical). "
                         "Only admissible for pairs the slot verdict calls ALIAS; it is applied to "
                         "every board before grouping so an aliased card is compared instead of being "
                         "counted as removed here and added there")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.path_devices == "auto":
        PATH, WHY = path_devices(a.dirs[0] if a.dirs else "PD1610")
    else:
        # the given list, not a set literal built while PATH was still unbound: this branch had been
        # printing WHY from PATH and crashed before it could (ledger 312), so the documented override
        # --path-devices had never actually run
        PATH = {x.strip() for x in a.path_devices.split(",") if x.strip()}
        if not PATH:
            sys.exit(f"gate: --path-devices {a.path_devices!r} parsed to no device ids")
        for x in sorted(PATH, key=int):
            if not x.isdigit():
                sys.exit(f"gate: --path-devices member {x!r} is not a device id")
        WHY = [f"{x} (given on the command line, NOT derived from the routing artifacts)"
               for x in sorted(PATH, key=int)]
    print("listening-path devices (derived, not typed): " + ", ".join(sorted(PATH, key=int)))
    for line in WHY:
        print(f"   {line}")
    CONTROLS = (("PD1610", "PD1610LG4"), ("Fluid", "Liquid"))
    if a.joint:
        # one column map for everything, control partners included: deriving the map twice over
        # different set groups puts the control on another ruler (it did -- 345 keys came out
        # 'unshared' between two byte-identical sets)
        extra = [y for x, y in CONTROLS if x in a.dirs and y not in a.dirs]
        ALLD = list(a.dirs) + extra
        ANCH = pool_anchors(ALLD)
        CARDS, LAYOUTS, TINFO, ABL, POOLED = joint_keys(ALLD, ANCH)
        ok = [t for t, v in TINFO.items() if v[0] == "ok"]
        sus = {t: v[6] for t, v in TINFO.items() if v[0] == "ok" and v[6]}
        print(f"joint column derivation: {len(TINFO)} fixed-record tables, {len(ok)} carry a device "
              f"column found on every board; e.g. "
              + ", ".join(f"{t}(dev={TINFO[t][1]},app={TINFO[t][2]},rate={TINFO[t][3]},"
                          f"{TINFO[t][5]})" for t in sorted(ok)[:5]))
        print(f"offset-shaped payload words in {len(sus)} of {len(ok)} tables "
              "(anchor = lands on a DATAPOOL block start of its own file, proven; "
              "shape = cross-board overlap<=0.20 AND word-aligned AND non-decreasing in a device run, "
              "sensitivity only):")
        for t in sorted(sus):
            print(f"   {t:10} " + ", ".join(
                (f"w{q}=POOL OFFSET (hit {an[0]:.2%}, +4 control {an[1]:.2%}, foreign-pool control "
                 f"{an[2]:.2%} over {an[3]} non-zero values)" if rule == "anchor"
                 else f"w{q} shape-only (overlap {ov}, div4={d4}, monotone {mo})")
                for (q, rule, ov, d4, mo, an) in sus[t]))
    else:
        CARDS, LAYOUTS, ABL, POOLED = {}, {}, {}, {}
        ALLD, ANCH = list(a.dirs), {}
        for st in a.dirs:
            CARDS[st], LAYOUTS[st] = load(st)
    CTRL = dict(CARDS)                        # includes the byte-equal control partners
    if not a.joint:                           # the card path loads one set per call, so fetch partners
        for _ka, _kb in CONTROLS:
            if _ka in CTRL and _kb not in CTRL:
                CTRL[_kb] = load(_kb)[0]
    CARDS = {st: CARDS[st] for st in a.dirs}   # the grouping itself sees only the requested boards
    LAYOUTS = {st: LAYOUTS[st] for st in a.dirs}
    ABLC = dict(ABL)
    ABL = {st: ABL[st] for st in a.dirs if st in ABL}
    NAMES = acdb_tlv.dev_names()
    AMAP = parse_alias(a.dev_alias)
    if AMAP:
        for k, v in AMAP.items():
            if not (k.isdigit() and v.isdigit()):
                sys.exit(f"gate: --dev-alias expects '<new id>=<canonical id>' in digits, got {k}={v}")
            n1, n2 = NAMES.get(int(k)), NAMES.get(int(v))
            if n1 and n2 and n1 != n2:
                sys.exit(f"gate: --dev-alias {k}={v} would merge two ids this board's own ACDB name pool "
                         f"calls different devices ({k}='{n1}', {v}='{n2}'). Only pairs the slot verdict "
                         "labels ALIAS may be normalised -- and on these boards it labels none")
        n_main, n_ctrl = apply_alias(CARDS, AMAP), apply_alias(CTRL, AMAP)
        n_abl = apply_alias(ABL, AMAP) + apply_alias(ABLC, AMAP)
        if n_abl != n_main + n_ctrl:
            sys.exit("gate: the id map rewrote a different number of keys in the ablated digest than in "
                     "the main one -- the two verdicts would then be read off different key sets")
        print(f"device-id normalisation applied to every board (and to the control copies): "
              f"{AMAP} -- {n_main} keys rewritten in the grouping, {n_ctrl} in the controls")
    for st, c in sorted(CARDS.items()):
        print(f"  {st:10} {sum(len(v) for v in c.values()):6} records in {len(c):5} keys")
    OKTAB, DROPTAB = comparable(LAYOUTS)
    if DROPTAB:
        print(f"tables read with DIFFERENT layouts on different boards (derived identity columns disagree)"
              f" -> their keys are NOT counted as added or removed: {len(DROPTAB)} of "
              f"{len(OKTAB) + len(DROPTAB)} tables")
        for (tab, npres, nfp) in DROPTAB[:10]:
            print(f"   {tab:10} present on {npres}/{len(CARDS)} boards, "
                  f"{nfp} distinct layout fingerprints")
    if not OKTAB:
        sys.exit("gate: no table was read with the same layout on every board -- the grouping has no "
                 "common ruler, so no row-surface verdict may be printed")

    # byte-equal-set controls first: they must be silent
    for ka, kb in CONTROLS:
        if ka not in CARDS or ka not in a.dirs:
            continue
        CB = CTRL.get(kb, {})
        CA = CARDS[ka]
        diff = sum(1 for k in set(CA) & set(CB) if sorted(CA[k]) != sorted(CB[k]))
        asym = len(set(CA) ^ set(CB))
        print(f"  POSITIVE control {ka} vs {kb} (byte-equal per 261/267): {diff} shared keys differ, "
              f"{asym} keys not shared (want 0 and 0)")
        if diff or asym:
            sys.exit(f"gate: byte-equal sets disagree ({diff} differ, {asym} unshared) -- the "
                     "grouping is not a pure function of the bytes")
        if ABL and ka in ABL and kb in ABLC:
            da = sum(1 for k in set(ABL[ka]) & set(ABLC[kb]) if sorted(ABL[ka][k]) != sorted(ABLC[kb][k]))
            print(f"  POSITIVE control, ablated digest (offset-shaped words left out) {ka} vs {kb}: "
                  f"{da} shared keys differ (want 0)")
            if da:
                sys.exit(f"gate: the ablated digest moves between byte-equal sets ({da} keys) -- the "
                         "second digest is not a pure function of the bytes either")

    all_keys = set().union(*[set(c) for c in CARDS.values()])
    keys = {k for k in all_keys if k[0] in OKTAB}
    print(f"keys inside comparable tables {len(keys)}/{len(all_keys)} (the rest sit in a table whose derived layout differs by board)")
    groupable, dropped, drop_reasons = [], collections.Counter(), []
    for k in sorted(keys):
        per = {st: CARDS[st][k] for st in CARDS if k in CARDS[st]}
        if len(per) < 3:
            dropped["keys in fewer than 3 boards"] += 1
            drop_reasons.append((k, "in fewer than 3 boards"))
            continue
        if len({len(v) for v in per.values()}) != 1:
            dropped["occurrence count differs (not the same object)"] += 1
            drop_reasons.append((k, f"occurrence count {[len(v) for v in per.values()]}"))
            continue
        lengths = {occ.split("/")[1] for lst in per.values() for occ in lst}
        if len(lengths) != 1:
            dropped["payload length differs (would measure truncation)"] += 1
            drop_reasons.append((k, f"payload lengths {sorted(lengths)}"))
            continue
        sig = {tuple(sorted(v)) for v in per.values()}
        groupable.append((k, per, sig))
    print(f"keys total {len(keys)}; groupable (>=3 boards, equal occurrence and length) {len(groupable)}; "
          f"dropped {dict(dropped)}")
    if not groupable:
        sys.exit("gate: nothing was groupable -- no verdict may be printed")
    AB = ablate(CARDS, ABL, OKTAB)
    SENS = {}
    if AB:
        both = [k for k, (a, b) in AB.items() if a and b]
        only_full = [k for k, (a, b) in AB.items() if a and not b]
        SENS = {"differ_full": sum(1 for a, b in AB.values() if a),
                "differ_ablated": sum(1 for a, b in AB.values() if b),
                "position_only": len(only_full), "robust": len(both)}
        print(f"offset-sensitivity of the same statistic (one ruler read twice): "
              f"{SENS['differ_full']} keys differ on the full payload, {SENS['differ_ablated']} still "
              f"differ with the offset-shaped words left out => {SENS['position_only']} "
              f"({SENS['position_only']/max(SENS['differ_full'],1):.1%}) of the differences are carried "
              f"by words that may be position rather than tuning; "
              f"{SENS['robust']} differ either way")
        if a.joint and ANCH:
            _C2, _L2, _T2, A2, _P2 = joint_keys(ALLD, ANCH, rules=("anchor",))
            AB2 = ablate(CARDS, {st: A2[st] for st in CARDS if st in A2}, OKTAB)
            n2 = sum(1 for _df, da in AB2.values() if da)
            n1 = sum(1 for df, _da in AB2.values() if df)
            if n1 != SENS["differ_full"]:
                sys.exit(f"gate: the anchor-only pass counts {n1} differing keys on the FULL payload "
                         f"while the main grouping counts {SENS['differ_full']} -- the second read is "
                         "not the same ruler")
            print(f"     proven-only version (only columns PROVEN to be pool offsets removed): "
                  f"{n1} -> {n2} differing keys")
        pl = [k for k in only_full if k[1] in PATH]
        ol = [k for k in only_full if k[1] not in PATH]
        for k in pl + ol[:8]:
            print(f"     position-only difference: {k[0]:10} dev {k[1]:>4} app {k[2][:18]:18} "
                  f"rate {k[3]:>6}" + ("  <-- LISTENING PATH" if k[1] in PATH else ""))
        if len(ol) > 8:
            print(f"     ... and {len(ol) - 8} more off the listening path (all listed in --out)")

    differ = [g for g in groupable if len(g[2]) > 1]
    pd_solo = []
    for (k, per, sig) in differ:
        mine = tuple(sorted(per.get("PD1610", [])))
        others = {tuple(sorted(v)) for st, v in per.items() if st != "PD1610"}
        if mine and mine not in others:
            pd_solo.append((k, per, sig))
    only_here = [k for k in keys if {st for st in CARDS if k in CARDS[st]} == {"PD1610"}]
    only_there = [k for k in keys
                  if "PD1610" not in {st for st in CARDS if k in CARDS[st]}
                  and len({st for st in CARDS if k in CARDS[st]}) == len(CARDS) - 1]
    print(f"groupable rows differing between boards: {len(differ)}/{len(groupable)} = "
          f"{len(differ)/len(groupable):.1%}; of those PD1610 stands alone in {len(pd_solo)}")
    if AB and SENS.get("differ_full") != len(differ):
        sys.exit(f"gate: the ablated read counts {SENS['differ_full']} differing keys while the main "
                 f"grouping counts {len(differ)} -- the two paths are not the same ruler")
    print(f"row surface: keys ONLY on PD1610 {len(only_here)}, keys on every other board but not PD1610 "
          f"{len(only_there)}")
    if not differ:
        sys.exit("gate: no board differs on any row -- the grouping cannot tell boards apart, too "
                 "coarse to name rows")

    VERD, TI, REFS = slot_verdicts(CARDS, OKTAB, a.dirs[0], NAMES)
    WE = word_evidence(POOLED, TINFO, a.dirs[0], REFS, keys) if POOLED else {}
    if WE:
        dks = [g[0] for g in differ]
        with_main = [k for k in dks if k in WE]
        pair = [k for k in with_main if WE[k]["pairing_only"]]
        fonly = [k for k in with_main if WE[k]["flagged_only"]]
        orph = [k for k in with_main if WE[k]["vivo_value"]]
        ptr = [k for k in with_main if WE[k]["unique_pointer"] and not WE[k]["vivo_value"]]
        print(f"word-level evidence over the {len(differ)} differing rows (read {len(with_main)} of them; "
              f"{len(dks) - len(with_main)} keys have no row on {a.dirs[0]} so positions cannot be "
              f"assigned): {len(pair)} rows differ ONLY in how the payload is paired -- every word "
              f"position holds the same multiset on every board, so that is formatting, not a value; "
              f"{len(fonly)} rows differ only in words already flagged as offsets; "
              f"{len(orph)} rows carry a differing word that is NOT a flagged offset AND that no other "
              f"board shares with {a.dirs[0]} -- those are vivo's own numbers; "
              f"{len(ptr)} more rows differ only in a UNIQUE POINTER (a pointer is unique by "
              "construction because every file lays its pool out differently, so that is not tuning)")
        vt = collections.Counter(k[0] for k in orph)
        print(f"     where vivo's own numbers actually sit: {vt.most_common(8)}; "
              f"on the listening devices {sum(1 for k in orph if k[1] in PATH)} of {len(orph)} rows "
              f"(0 means no listening row carries a value unique to {a.dirs[0]} -- those rows differ as "
              "board groups or by pointer)")
        same = [g[0] for g in groupable if len(g[2]) == 1 and g[0] in WE]
        contra = [k for k in same if WE[k]["words"]]
        if contra:
            sys.exit(f"gate: {len(contra)} rows are 'identical' by payload digest yet the position-wise "
                     f"read finds a differing word {sorted(contra)[:4]} -- the two reads of the same "
                     "records disagree, so neither may be published")
        print(f"   invariant check against the digest read: {len(same)} rows called identical, "
              f"{len(contra)} disagree position-wise (must be 0: a multiset of tuples fixes its projections)")
    VCLS = collections.Counter(cls for (_t, _d, _b, _a, cls) in VERD)
    print(f"\nreference-only (table,device) slots: {len(VERD)}, covering {len(only_there)} row keys -- "
          f"a slot may be called a re-numbering only when ALL THREE arms pass (same name tail in this "
          "board's ACDB pool / the missing id has no row anywhere else on this board / the candidate id "
          "carries an identical payload at the same table+app+rate)")
    for (tab, dev, cand, arms, cls) in VERD:
        nslots = sum(1 for k in only_there if k[0] == tab and k[1] == dev)
        print(f"   {tab:10} dev {dev:>4} ({NAMES.get(int(dev), 'UNNAMED'):28}) {nslots} row slot(s) "
              f"-> {cls}" + (f", {a.dirs[0]} candidate dev {cand} "
                             f"({NAMES.get(int(cand), 'UNNAMED'):26})" if cand else ""))
        if cand:
            for arm in ("name", "coexist", "payload"):
                print(f"        {arm:8} {arms.get(arm, 'not evaluated')}")
            survive = sorted([t2 for t2 in TI if dev in TI[t2] and a.dirs[0] in TI[t2][dev]])
            print(f"        rows for {dev} on {a.dirs[0]} survive in {len(survive)} other table(s): "
                  f"{survive if survive else 'none'}")
            # the shape of the table itself: one id out, one id in, same total, read from the SAME pooled
            # device column.  That is what makes this a substitution and not a lost row -- and it is also
            # the check that the card view could not make, because acdb_card.py filed a 9-value column as
            # VCGILUT0's device id where the pooled reading finds 22 on every board (ledger 311)
            mine = {d for d, b in TI[tab].items() if a.dirs[0] in b}
            theirs = {d for d, b in TI[tab].items() if set(REFS) <= b}
            print(f"        table shape: {a.dirs[0]} {len(mine)} ids vs reference {len(theirs)} ids; "
                  f"out {sorted(theirs - mine, key=int)} in {sorted(mine - theirs, key=int)}")
    print(f"  verdict counts: {dict(VCLS)}")
    ALIAS_SPEC = ",".join(sorted({f"{c}={d}" for (_t, d, c, _a, cls) in VERD if cls == "ALIAS"}))
    if ALIAS_SPEC and not AMAP:
        print(f"  GATE: {VCLS['ALIAS']} slot(s) really are the same device under another number. The "
              f"row surface double-counts them until they are normalised -- re-run with "
              f"--dev-alias {ALIAS_SPEC}; the shortlist is refused below until then")

    bytab = collections.Counter(k[0] for (k, _p, _s) in pd_solo)
    bydev = collections.Counter(k[1] for (k, _p, _s) in pd_solo)
    path_solo = [g for g in pd_solo if g[0][1] in PATH]
    print(f"  PD1610-solo rows by table (top): {bytab.most_common(6)}")
    print(f"  PD1610-solo rows by device (top): {bydev.most_common(6)}")
    print(f"  PD1610-solo rows on the listening devices 15/124/150: {len(path_solo)}")
    for (k, per, sig) in path_solo[:20]:
        print(f"     {k[0]:10} dev {k[1]:>4} app {k[2][:22]:22} rate {k[3]:>6}  "
              f"boards {sorted(per)}  groups {len(sig)}")

    if a.out:
        gw = set()
        with open(a.out, "w", encoding="utf-8") as fh:
            hdr = ("table\tacdb_dev_id\tapp_type\tsample_rate\ton_listening_device\tn_boards\t"
                   "boards\tpayload_groups\tpd1610_alone\tdiffers_between_boards\t"
                   "differs_without_offset_words\tdiffering_words\twords_flagged_only\t"
                   "pairing_only_only\tboards_sharing_main_per_word")
            fh.write(hdr + "\n")
            ncols = len(hdr.split("\t"))
            def emit(line):
                gw.add(len(line.rstrip("\n").split("\t")))
                fh.write(line)
            for (k, per, sig) in sorted(groupable):
                mine = tuple(sorted(per.get("PD1610", [])))
                others = {tuple(sorted(v)) for st, v in per.items() if st != "PD1610"}
                emit(f"{k[0]}\t{k[1]}\t{k[2]}\t{k[3]}\t{k[1] in PATH}\t{len(per)}\t"
                     f"{'|'.join(sorted(per))}\t{len(sig)}\t"
                     f"{bool(mine) and mine not in others}\t{len(sig) > 1}\t"
                     f"{AB.get(k, (None, None))[1] if k in AB else '-'}\t"
                     f"{we_words(WE, k)}\t"
                     f"{WE.get(k, {}).get('flagged_only', '-') if k in WE else '-'}\t"
                     f"{WE.get(k, {}).get('pairing_only', '-') if k in WE else '-'}\t"
                     f"{we_partners(WE, k)}\n")
            for k in sorted(set(only_here) | set(only_there)):
                present = sorted(st for st in CARDS if k in CARDS[st])
                vcls = {f"slot-{cls}" for (t, d, _c, _a, cls) in VERD if t == k[0] and d == k[1]}
                emit(f"{k[0]}\t{k[1]}\t{k[2]}\t{k[3]}\t{k[1] in PATH}\t{len(present)}\t"
                     f"{'|'.join(present)}\t1\t{'PD1610' in present}\t"
                     f"{'row-surface-here-only' if 'PD1610' in present else (vcls.pop() if len(vcls) == 1 else 'row-surface-unjudged')}\t-\t-\t-\t-\t-\n")
        # counted while writing: re-reading the path here would see the buffer unflushed and look empty
        if gw != {ncols}:
            sys.exit(f"gate: {a.out} rows disagree on column count {sorted(gw)} (header says {ncols}) "
                     "-- a reader taking the header's column names would silently mis-key the rest")
        print(f"wrote {a.out} ({len(groupable) + len(only_here) + len(only_there)} rows)")
    if a.joint and os.path.exists(os.path.join(ART, "acdb-row-shortlist.PD1610.tsv")) and a.shortlist:
        card_rows = {r["class"].split(":", 1)[0] + "|" + r["table"] + "|" + r["acdb_dev_id"]
                     for r in csv.DictReader(open(os.path.join(ART, "acdb-row-shortlist.PD1610.tsv"),
                                                  encoding="utf-8"), delimiter="\t")}
        joint_rows = set()
        for (tab, dev, app, rate), occ in sorted(CARDS.get(a.dirs[0], {}).items()):
            if dev not in PATH:
                continue
            per = {st: CARDS[st][(tab, dev, app, rate)] for st in CARDS
                   if (tab, dev, app, rate) in CARDS[st]}
            if len(per) >= 3 and len({tuple(sorted(v)) for v in per.values()}) > 1:
                joint_rows.add("same-key-different-payload|" + tab + "|" + dev)
            elif len(per) == 1 and next(iter(per)) == a.dirs[0]:
                joint_rows.add("key-only-on-" + a.dirs[0] + "|" + tab + "|" + dev)
        both = card_rows & joint_rows
        print(f"cross-check vs the published card-path shortlist: joint view has {len(joint_rows)} "
              f"listening-path rows, card view {len(card_rows)}; agreeing {len(both)}; "
              f"joint-only {len(joint_rows - card_rows)}; card-only {len(card_rows - joint_rows)}")
        for r in sorted(card_rows - joint_rows)[:8]:
            print(f"   card-only (check whether its table has no device column in the joint view): {r}")
    if a.shortlist:
        if ALIAS_SPEC and not AMAP:
            sys.exit(f"gate: refusing to publish a shortlist while {VCLS['ALIAS']} row slot(s) are the "
                     f"same device under two numbers -- re-run with --dev-alias {ALIAS_SPEC}")
        path_there = [k for k in only_there if k[1] in PATH]
        print(f"  listening-path rows that exist ONLY on the reference boards: {len(path_there)} -- "
              "these are cards this board does NOT have (nothing to carry), but the verdict decides "
              "whether they were dropped or are filed under another device id")
        for k in sorted(path_there):
            vcls = {cls for (t, d, _c, _a, cls) in VERD if t == k[0] and d == k[1]}
            print(f"     {k[0]:10} dev {k[1]:>4} rate {k[3]:>6} -> {sorted(vcls)}")
        keep = [(k, per, sig) for (k, per, sig) in groupable
                if k[1] in PATH and (len(sig) > 1)]
        add = [k for k in only_here if k[1] in PATH]
        pos_only = [k for (k, _p, _s) in keep if AB.get(k, (True, True)) == (True, False)]
        sw = set()
        with open(a.shortlist, "w", encoding="utf-8") as fh:
            hdr = ("table\tacdb_dev_id\tapp_type\tsample_rate\tclass\tn_boards\tboards\t"
                   "payload_groups\tdiffers_without_offset_words\tdiffering_words\t"
                   "words_flagged_only\tpairing_only_only\tvivo_value_word\t"
                   "unique_pointer_only")
            fh.write(hdr + "\n")
            ncols2 = len(hdr.split("\t"))

            def emit2(line):
                sw.add(len(line.rstrip("\n").split("\t")))
                fh.write(line)
            for (k, per, sig) in sorted(keep):
                emit2(f"{k[0]}\t{k[1]}\t{k[2]}\t{k[3]}\tsame-key-different-payload\t"
                      f"{len(per)}\t{'|'.join(sorted(per))}\t{len(sig)}\t"
                      f"{AB.get(k, (None, None))[1] if k in AB else '-'}\t"
                      f"{we_words(WE, k)}\t"
                      f"{WE.get(k, {}).get('flagged_only', '-') if k in WE else '-'}\t"
                      f"{WE.get(k, {}).get('pairing_only', '-') if k in WE else '-'}\t"
                      f"{'|'.join(str(q) for q in WE[k]['vivo_value']) if k in WE and WE[k]['vivo_value'] else '-'}\t"
                      f"{bool(WE.get(k, {}).get('unique_pointer')) and not WE[k]['vivo_value'] if k in WE else '-'}\n")
            for k in sorted(add):
                present = sorted(st for st in CARDS if k in CARDS[st])
                emit2(f"{k[0]}\t{k[1]}\t{k[2]}\t{k[3]}\tkey-only-on-PD1610\t"
                      f"{len(present)}\t{'|'.join(present)}\t1\t-\t-\t-\t-\t-\t-\n")
        print(f"shortlist for the listening devices {sorted(PATH, key=int)} -> {a.shortlist}: "
              f"{len(keep)} same-key-different-payload + {len(add)} key-only-on-PD1610 = "
              f"{len(keep) + len(add)} rows to carry")
        if sw != {ncols2}:
            sys.exit(f"gate: {a.shortlist} rows disagree on column count {sorted(sw)} (header says "
                     f"{ncols2}) -- the copy list would be mis-read by anyone taking the header's names")
        if AB:
            print(f"   of those {len(keep)} value rows, {len(pos_only)} differ ONLY in the offset-shaped "
                  f"words {sorted({(k[0], k[1], k[3]) for k in pos_only})} -- carry them but read them as "
                  "'the row is not the same object on the two boards', not as 'vivo tuned these numbers'")
        bytab = collections.Counter(k[0] for (k, _p, _s) in keep)
        print(f"   by table: {bytab.most_common(6)}")
        # the copy list against the hook layer (ledger 270: 74 hooks QRD does not have)
        hrows, hpairs, odd, hp = hook_projection()
        this = {(k[0], k[1]) for (k, _p, _s) in keep} | {(k[0], k[1]) for k in add}
        pub = os.path.join(ART, "acdb-row-shortlist.PD1610.tsv")
        union = set(this)
        if a.joint and os.path.exists(pub):
            union |= {(r["table"], r["acdb_dev_id"])
                      for r in csv.DictReader(open(pub, encoding="utf-8"), delimiter="\t")}
        inter = union & hpairs
        print(f"  hook layer {os.path.basename(hp)}: {len(hrows)} hooks project to {len(hpairs)} "
              f"(table,device) pairs {dict(odd) if odd else ''}; this copy list has {len(union)} pairs, "
              f"{len(inter)} of them are also a vivo-added hook, {len(union - hpairs)} have no hook "
              "behind them (= stock hook, different values -- that is the 'carry the numbers' class)")
        print(f"     projection caveat: the two layers share only (table, device); a pair on one side and "
              "not the other is a granularity difference, NOT a contradiction. Each listening-device hook "
              "pair is therefore classified into one of four states, and only the layer-disagreeing one "
              "aborts:")
        hpath = {p for p in hpairs if p[1] in PATH}
        print(f"     denominator of that gate: {len(hpath)} hook pair(s) serve a listening device "
              f"{sorted(hpath)} -- if that were 0 this arm could never fire and would be vacuous")
        if not hpath:
            sys.exit("gate: no hook in the layer serves a listening device, so the 'listening hook must "
                     "be accounted for by the copy list' arm has nothing to judge -- reporting it as "
                     "passed would be a green from an idle ruler")
        bypair, unjudged = collections.defaultdict(list), collections.defaultdict(list)
        for k in keys:
            bypair[(k[0], k[1])].append(k)
        for (k, why) in drop_reasons:
            unjudged[(k[0], k[1])].append(why)
        cls = classify_hook_pairs(hpath, union, bypair, unjudged)
        LABEL = {"ON_LIST": "on the copy list",
                 "IDENTICAL": "judged identical on every board = nothing to carry",
                 "NOT_JUDGED": "NOT JUDGED, admissibility filter dropped it",
                 "NO_ROW": "NO ROW on any board (layers disagree)"}
        for key in ("ON_LIST", "IDENTICAL", "NOT_JUDGED", "NO_ROW"):
            if not cls[key]:
                continue
            ex = ""
            if key == "NOT_JUDGED":
                p = cls[key][0]
                ex = f" e.g. {p}: {unjudged[p][:2]}"
            print(f"     {LABEL[key]}: {len(cls[key])} {cls[key][:6]}{ex}")
        if cls["NO_ROW"]:
            sys.exit(f"gate: the hook layer says {cls['NO_ROW']} serve a listening device but the "
                     "coefficient row layer has no identity for them on ANY board -- two independent "
                     "readings of the same table disagree, so the copy list may not be published until "
                     "that is resolved")
        tabs_with_hooks = collections.Counter(r["lut_table"] for r in hrows)
        for t, d in sorted(union - hpairs):
            print(f"     no-hook pair {t:10} dev {d:>4}: this table has "
                  f"{tabs_with_hooks.get(t, 0)} vivo-added hook row(s), none of which lists device {d}")
    if a.selftest:
        print("selftest: " + alias_selftest(OKTAB, NAMES))
        print("selftest: " + hook_arm_selftest())
        if a.joint and ANCH:
            print("selftest: " + anchor_selftest(ANCH, [t for t, v in TINFO.items() if v[0] == "ok"]))
        else:
            print("selftest: pool-anchor arm NOT RUN in --from-cards mode (it needs the raw files)")
        print("selftest: derived listening-path rule + byte-equal-set positives silent + groupability filters with dropped counts "
              "printed + at least one board differing + per-table/device breakdown + listening-device "
              "flag from the live routing ids (not assumed)")


if __name__ == "__main__":
    main()
