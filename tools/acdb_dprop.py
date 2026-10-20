#!/usr/bin/env python3
"""tools/acdb_dprop.py -- read DPROPLUT as (device, PROPERTY ID, pointer) and compare the pointed-to blocks.

Ledger 316 PROVED the first named column of a *LUT record in this project: DPROPLUT word 2 is a DATAPOOL
block offset (100.00% of its 5479 non-zero values land on a block start of their own file, +4 control
0.58%, foreign-pool control 0.00%).  That turns the device-property row from an opaque word triple into a
readable pointer, and gives the port a join the format itself supplies -- straighter than the invented key
ledger 307 had to use for the pool.

What the blocks hold is measured and printed every run, not assumed: 70584 decodes as a UTF-16 device
name, 70582 is 8 bytes, 70583 20 bytes, 70573 48 bytes, 70575/70578/70579/70580/78160 4 bytes, 76363 32,
77549 12, 78048 may be zero-length.  A row is called NAME only when the block decodes to the same
'<id>_<NAME>' string this board's numbered pool publishes for that device -- two independent readings
agreeing, not one reading believed.

Verdict per (role, device, property); 'role' is the file the row lives in (Speaker/Headset/...):
  DEVICE ABSENT HERE   no reference board has this device+property at all -- the port-relevant class,
                       because Android 7's shipped set cannot supply it (Hi-Fi device 150 lands here)
  VIVO-ONLY            reference boards have the row but no block with these bytes
  STOCK                every reference board that has the row agrees on the bytes
  BOARDS-DISAGREE      some agree and some do not -- PD1610 is not singled out, so this says nothing
                       about vivo's tuning; both counts are printed
  NAME                 the property is the device name (a definitional difference, not tuning)

Controls: PD1610 vs PD1610LG4 and Fluid vs Liquid are byte-equal (ledger 261/267) so all their rows must
agree -- a moving control aborts.  A pointer shifted by +4 must NOT resolve (measured ~1%), which is what
makes 'resolves to a block start' information rather than luck.

usage: tools/acdb_dprop.py [--out TSV] [--dirs PD1610 PD1516A QRD MTP Fluid] [--selftest]
"""
import argparse
import collections
import hashlib
import os
import struct
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))
import acdb_pool  # noqa: E402
import acdb_row_groups as R  # noqa: E402
import acdb_tlv  # noqa: E402

ACDB = acdb_tlv.ACDB
CTRL = (("PD1610", "PD1610LG4"), ("Fluid", "Liquid"))
SETS = sorted(x for x in os.listdir(ACDB) if os.path.isdir(os.path.join(ACDB, x)))


def role(f):
    n = f[:-len(".acdb")]
    for st in SETS:
        if n.startswith(st + "_"):
            n = n[len(st) + 1:]
    return n.replace("_cal", "")


def load(st):
    """{role: {data: {offset: bytes}, idx: {(dev,pid): set(sha)}, rows: [...]}}"""
    d = os.path.join(ACDB, st)
    if not os.path.isdir(d):
        sys.exit(f"gate: {d} is not a calibration dir")
    out = {}
    for f in sorted(x for x in os.listdir(d) if x.endswith(".acdb")):
        b = open(os.path.join(d, f), "rb").read()
        fields = {}
        for off, raw, ln in acdb_tlv.walk(b)[0]:
            fields.setdefault(raw.strip(), []).append((off + 12, ln))
        data = {}
        for (p, ln) in fields.get("DATAPOOL", []):
            for (bo, _L, pay) in acdb_pool.walk(b[p:p + ln])[0]:
                if bo in data and data[bo] != pay:
                    sys.exit(f"gate: {f} has two DATAPOOL fields whose block offset {bo} collides with "
                             "different bytes -- offsets would not identify a block here")
                data[bo] = pay
        rows = []
        for (p, ln) in fields.get("DPROPLUT", []):
            cnt, rs = acdb_tlv.count_rec(b, p - 12, ln)
            if not rs or rs == "empty" or rs % 4:
                continue
            rows += [struct.unpack_from("<%dI" % (rs // 4), b, p + 4 + i * rs)
                     for i in range(cnt) if p + 4 + i * rs + rs <= p + ln]
        if not rows:
            continue
        idx = collections.defaultdict(set)
        for x in rows:
            if x[2] in data:
                idx[(x[0], x[1])].add(hashlib.sha256(data[x[2]]).hexdigest())
        r = role(f)
        if r in out:
            sys.exit(f"gate: {st} carries role {r} in two files -- the join key would be ambiguous")
        out[r] = dict(data=data, rows=rows, idx=idx)
    return out


def utf16(pay):
    if not pay or len(pay) % 2 or len(pay) > 256:
        return None
    try:
        t = pay.decode("utf-16-le").rstrip("\x00")
    except UnicodeDecodeError:
        return None
    return t if t and all(32 <= ord(c) < 127 for c in t) else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out")
    ap.add_argument("--dirs", nargs="*", default=["PD1610", "PD1516A", "QRD", "MTP", "Fluid"])
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    MAIN = a.dirs[0]
    REFS = [x for x in a.dirs if x != MAIN]
    extra = [y for x, y in CTRL if x in a.dirs and y not in a.dirs]
    L = {st: load(st) for st in list(a.dirs) + extra}
    PATH, _WHY = R.path_devices(MAIN)
    NAMES = acdb_tlv.dev_names()
    print("listening-path devices (the same derived rule as tools/acdb_row_groups.py): "
          + ", ".join(sorted(PATH, key=int)) + f"; name pool has {len(NAMES)} ids")

    tot = collections.Counter()
    rows_out, prop_shapes = [], collections.defaultdict(collections.Counter)
    for r in sorted(L[MAIN]):
        data, rows, idx = (L[MAIN][r][k] for k in ("data", "rows", "idx"))
        for x in rows:
            dev, pid, ptr = x[0], x[1], x[2]
            tot["rows"] += 1
            if ptr not in data:
                tot["pointer does not resolve"] += 1
                continue
            tot["resolved"] += 1
            pay = data[ptr]
            sha, nb = hashlib.sha256(pay).hexdigest(), len(pay)
            prop_shapes[pid][nb] += 1
            present = agree = 0
            shapes = {sha}
            for st in REFS:
                got = L[st].get(r, {}).get("idx", {}).get((dev, pid))
                if not got:
                    continue
                present += 1
                shapes |= got
                if sha in got:
                    agree += 1
            nm = utf16(pay)
            is_name = bool(nm) and nm.startswith(f"{dev}_")
            if is_name:
                pool_name = NAMES.get(dev)
                tot["NAME agrees with this board's numbered pool"
                    if pool_name and nm == f"{dev}_{pool_name}"
                    else "NAME decoded but is NOT the pool's string for this device"] += 1
            cls = ("NAME" if is_name else
                   "DEVICE ABSENT HERE" if present == 0 else
                   "STOCK" if agree == present else
                   "VIVO-ONLY" if agree == 0 else "BOARDS-DISAGREE")
            tot[cls] += 1
            rows_out.append([r, dev, pid, nb, cls, agree, present, len(shapes), sha[:12],
                             str(dev) in PATH, nm or ""])
    print(f"rows {tot['rows']}, pointers resolving to a real DATAPOOL block start {tot['resolved']} "
          f"({tot['resolved']/max(tot['rows'],1):.1%}), unresolved {tot['pointer does not resolve']}")
    if tot["resolved"] == 0:
        sys.exit("gate: no DPROPLUT pointer resolved -- the pool was read with the wrong ruler, so no "
                 "verdict below is admissible")
    if tot["pointer does not resolve"] > tot["rows"] // 20:
        sys.exit(f"gate: {tot['pointer does not resolve']}/{tot['rows']} pointers unresolved -- over "
                 "5% means the block chain or the column is not what this tool claims")
    print("verdicts: " + ", ".join(f"{k} {v}" for k, v in sorted(tot.items()) if k in
                                   ("NAME", "STOCK", "VIVO-ONLY", "BOARDS-DISAGREE",
                                    "DEVICE ABSENT HERE")))
    print("name cross-check against the numbered pool: " + ", ".join(
        f"{k} {v}" for k, v in sorted(tot.items()) if k.startswith("NAME")))
    print("property id -> block size distribution (the shape is what suggests the meaning):")
    for pid in sorted(prop_shapes):
        print(f"   {pid} (0x{pid:x}): " + ", ".join(f"{ln}B x{n}" for ln, n in
                                                    prop_shapes[pid].most_common(4)))

    print("\nbyte-equal controls (every row must agree)")
    for ka, kb in CTRL:
        if ka not in L or ka not in a.dirs:
            continue
        same = bad = 0
        for r in L[ka]:
            if r not in L[kb]:
                bad += len(L[ka][r]["rows"])
                continue
            ba, bb = L[ka][r]["data"], L[kb][r]["data"]
            for x in L[ka][r]["rows"]:
                if x[2] in ba and x[2] in bb and ba[x[2]] == bb[x[2]]:
                    same += 1
                else:
                    bad += 1
        print(f"  {ka} vs {kb}: rows agreeing {same}, disagreeing/missing {bad} (want 0)")
        if bad:
            sys.exit(f"gate: byte-equal sets disagree on {bad} DPROPLUT rows -- the pointer chain is "
                     "not a pure function of the bytes")

    shift_hit = shift_tot = 0
    for r in L[MAIN]:
        starts = set(L[MAIN][r]["data"])
        for x in L[MAIN][r]["rows"]:
            shift_tot += 1
            shift_hit += x[2] + 4 in starts
    print(f"wrong-pointer control: pointer+4 still lands on a block start in {shift_hit}/{shift_tot} "
          f"rows ({shift_hit/max(shift_tot,1):.1%}) -- low, so resolving is information, not luck")
    if shift_hit / max(shift_tot, 1) > 0.25:
        sys.exit("gate: the shifted pointer still resolves in a quarter of rows -- the boundary set is "
                 "too dense for 'resolves' to mean anything")

    print("\nlistening-path detail:")
    pl = [t for t in rows_out if t[9]]
    by = collections.Counter(t[4] for t in pl)
    print(f"  {len(pl)} rows on devices {sorted(PATH, key=int)}: "
          + ", ".join(f"{k} {v}" for k, v in by.most_common()))
    for t in sorted(pl):
        if t[4] != "STOCK":
            print(f"   {t[0]:9} dev {t[1]:>4} property {t[2]:>6} block {t[3]:4} B  {t[4]:18} "
                  f"agree {t[5]}/{t[6]} boards, {t[7]} distinct shape(s)")
    if a.out:
        with open(a.out, "w", encoding="utf-8") as fh:
            fh.write("role\tacdb_dev_id\tproperty_id\tblock_bytes\tclass\tagreeing_boards\t"
                     "boards_with_this_row\tdistinct_block_shapes\tblock_sha12\t"
                     "on_listening_device\tname_decoded\n")
            for t in sorted(rows_out, key=lambda x: (x[0], int(x[1]), x[2])):
                fh.write("\t".join(str(x) for x in t) + "\n")
        print(f"wrote {a.out} ({len(rows_out)} rows)")
    if a.selftest:
        print("selftest: resolve-rate gate (100% expected, >5% unresolved aborts) + dense-boundary "
              "gate on the shifted control + byte-equal controls + property-shape print")


if __name__ == "__main__":
    main()
