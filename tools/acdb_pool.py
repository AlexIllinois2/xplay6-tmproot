#!/usr/bin/env python3
"""tools/acdb_pool.py -- DATAPOOL is a chain of byte-length-prefixed blocks: {u32 L, L bytes}.

three modes: (default) grammar gates over the sets given; --compare A B walks two sets by block
index (valid only where the files are supposed to be the same, ledger 305); --slots builds the
(role, key) census that IS valid across boards; --modules anchors on a named module id inside a
block and compares the bytes that follow it board to board (ledger 306).

This is the one ACDB family §264/§303 left with NO grammar ("DATAPOOL 块文法 0 解" -- 0/49 bodies
consumed exactly under any counted-array stride).  The stride family was the wrong question: the pool
is not an array of equal records, it is a sequence of VARIABLE-SIZE blocks, each declared by a single
u32 that counts the BYTES that follow it:

    cursor i:  L = u32@i      payload = bytes[i+4 : i+4+L]      next block = i + 4 + L

Measured over all seven sets: 49/49 pools are consumed to the last byte, 8243 blocks, mean 168 per
pool.  This also explains the odd lengths that broke the word-array reading -- 16/49 pools are not a
whole number of words, yet the chain closes exactly because L counts bytes.

Six variants were scored and the reading is unique, not the best of a lenient family (printed every
run): V1 49/49, while "L covers the block including its header", "L counts words (after / including
the header)" and both two-word-header forms all take 0/49.

THE RULER IS CALIBRATED, NOT ASSUMED -- three arms give the reading its scale:
  * payload independence: perturbing a PAYLOAD word by +-4 breaks the walk in 0/12584 trials, so the
    layout really is governed by the header words and nothing else;
  * length sensitivity on a shift the chain cannot absorb: +-1 breaks 99.7 %, +-2 breaks 100 %.  The
    floor is put on THAT arm, not on +-4 (measured 87.7 %, and 1760/2019 survivors are the same chain
    re-syncing by splitting one block -- a +-4 shift stays on the 4-byte grid, so it can hand the walk
    to a neighbouring chain that still ends at the pool end.  Reporting +-4 while gating on +-1/+-2 is
    the honest shape; gating on +-4 would have aborted a true reading, and quietly lowering the +-4
    floor would have hidden why);
  * base rate: from a random NON-boundary, 4-aligned cursor the walk closes only 3.6 % of the time,
    which is what makes "49/49 close from cursor 0" a statement rather than an artefact of a
    zero-heavy blob (pools hold 9-46 % zero words, so a null arm is required).

What is NOT claimed: what a block IS.  The payload-shape census is printed (word-alignment, whether
the payload opens on an id-band word 0x10000-0x14000, a small count, or zero) but no block type is
named and no value's unit is asserted.  The bodies therefore STAY in tools/acdb_bodies.py's digest
census; what improves is granularity -- every block now has an index, offset, byte length and its own
sha16, so "the region we cannot read" is diffable block by block on Android 7 instead of only as one
field digest.

Controls that can fail and abort: byte-phase null (starting 1-3 bytes late must never close), the
byte-equal-set positives (PD1610 vs PD1610LG4 per 261, Fluid vs Liquid per 267 -- identical files must
give identical walks) and cross-board negatives (different boards must move some walks).

usage: tools/acdb_pool.py [--dirs PD1610 ...] [--out TSV] [--selftest]
"""
import argparse
import collections
import hashlib
import os
import random
import struct
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))
import acdb_tlv  # noqa: E402

ACDB = acdb_tlv.ACDB
IDBAND = (0x10000, 0x14000)
MASK32 = 0xFFFFFFFF


def u32(pool, p):
    return struct.unpack_from("<I", pool, p)[0] if p + 4 <= len(pool) else None


VARIANTS = {
    "V1 {u32 L, L bytes}": (0, lambda i, L: i + 4 + L),
    "V2 L covers the header": (0, lambda i, L: i + L),
    "V3 L counts words after header": (0, lambda i, L: i + 4 + 4 * L),
    "V4 L counts words incl header": (0, lambda i, L: i + 4 * L),
    "V5 two-word header, L bytes": (4, lambda i, L: i + 8 + L),
    "V6 two-word header, L words": (4, lambda i, L: i + 8 + 4 * L),
}
WINNER = "V1 {u32 L, L bytes}"


def walk(pool, at=0, variant=WINNER, cap=400000):
    """follow the block chain -> (blocks as (off, L, payload), landed exactly on the end)"""
    len_at, advance = VARIANTS[variant]
    p, out = at, []
    while p < len(pool):
        L = u32(pool, p + len_at)
        if L is None:
            return out, False
        nxt = advance(p, L)
        if nxt <= p or nxt > len(pool):
            return out, False
        head = p + len_at + 4 if len_at else p + 4
        out.append((p, L, pool[head:nxt]))
        p = nxt
        if len(out) > cap:
            return out, False
    return out, True


def pools(dirs):
    out = {}
    for stem in dirs:
        d = os.path.join(ACDB, stem)
        if not os.path.isdir(d):
            sys.exit(f"gate: {d} is not a calibration dir -- the unanimity below needs the real sets")
        for f in sorted(x for x in os.listdir(d) if x.endswith(".acdb")):
            b = open(os.path.join(d, f), "rb").read()
            for off, name, ln in acdb_tlv.walk(b)[0]:
                if name.strip() == "DATAPOOL" and ln:
                    out[(stem, f)] = b[off + 12:off + 12 + ln]
    if not out:
        sys.exit(f"gate: no non-empty DATAPOOL body in {dirs} -- nothing to judge")
    return out


def perturb(pool, at, value):
    v = bytearray(pool)
    struct.pack_into("<I", v, at, value & MASK32)
    return bytes(v)


def role_of(kf):
    stem, f = kf
    return f[len(stem) + 1:] if f.startswith(stem + "_") else f


def compare(da, db):
    """per-block diff of two calibration sets -- the finest unit this layer can offer"""
    pa, pb = pools([da]), pools([db])
    ra = {role_of(kf): (kf, pool) for kf, pool in pa.items()}
    rb = {role_of(kf): (kf, pool) for kf, pool in pb.items()}
    shared = sorted(set(ra) & set(rb))
    if not shared:
        sys.exit(f"gate: {da} and {db} share no cal-file role ({sorted(ra)[:3]} vs {sorted(rb)[:3]}) "
                 "-- a compare that joins nothing must not print a verdict")
    print(f"block compare {da} vs {db}: {len(shared)} shared roles"
          + (f", only in {da}: {sorted(set(ra)-set(rb))}" if set(ra) - set(rb) else "")
          + (f", only in {db}: {sorted(set(rb)-set(ra))}" if set(rb) - set(ra) else ""))
    tot = collections.Counter()
    for r in shared:
        (ka, poola), (kb, poolb) = ra[r], rb[r]
        ba, bb = walk(poola), walk(poolb)
        if not (ba[1] and bb[1]):
            sys.exit(f"gate: role {r} does not close in this set -- the chain grammar is the claim, "
                     "so a walk that fails here is a real finding, not a skip")
        la = [(L, hashlib.sha256(p).hexdigest()[:16]) for (_o, L, p) in ba[0]]
        lb = [(L, hashlib.sha256(p).hexdigest()[:16]) for (_o, L, p) in bb[0]]
        n = min(len(la), len(lb))
        lendif = sum(1 for i in range(n) if la[i][0] != lb[i][0])
        shadiff = sum(1 for i in range(n) if la[i][1] != lb[i][1])
        grew = abs(len(la) - len(lb))
        same_bytes = poola == poolb
        tot["roles"] += 1
        tot["blocks compared"] += n
        tot["L differs"] += lendif
        tot["payload differs"] += shadiff
        tot["blocks added/dropped"] += grew
        tot["byte-identical pools"] += same_bytes
        if same_bytes and shadiff:
            sys.exit(f"gate: {r} pools are byte-identical yet {shadiff} blocks differ -- the walk "
                     "is not a pure function of the bytes")
        if not same_bytes and shadiff == 0 and lendif == 0 and grew == 0:
            tot["pools differing invisibly to this compare"] += 1
        print(f"  {r:24} blocks {len(la):4}/{len(lb):4}  L differs {lendif:4}  payload differs "
              f"{shadiff:4}  added/dropped {grew:3}  pools byte-equal: {same_bytes}")
    if tot["byte-identical pools"] == 0 and tot["payload differs"] == 0:
        print("  NOTE: no pool is byte-equal in this pair AND nothing differed block by block -- the "
              "compare saw no change; that is only evidence if a positive pair has been run too")
    print("  totals: " + ", ".join(f"{k} {v}" for k, v in tot.items()))


def block_offsets(pool):
    """the set of byte offsets at which a block starts in this pool -- §316's structural test uses
    "a value lands on a block head of THIS file" to call a word a pool pointer rather than a tuning
    value, so the two controls (value+4, and another file's block heads) stay meaningful."""
    return {o for (o, _L, _p) in walk(pool)[0]} | {len(pool)}


def field_words(stem, f):
    """this file's fields as {name: payload bytes} -- the referrer arm has to see the WHOLE container,
    not only the pool, because the pointers into the pool live in the sibling *CDOT/DPROPLUT fields."""
    b = open(os.path.join(ACDB, stem, f), "rb").read()
    return {n.strip(): b[o + 12:o + 12 + l] for o, n, l in acdb_tlv.walk(b)[0]}


def groups(payload, mult):
    """REPEAT{u32 n, n*mult words} -> (group word-index-ranges, count-slot indices), or (None, None)
    if it does not consume the field exactly.  mult=1 is the CDOT reading (a list of pool offsets),
    mult=2 the CDFT/OFST reading (pairs).  The count slots are reported because a word that equals a
    block offset while SITTING in a count slot is a group size that happens to match, not a pointer --
    without that split the owner column would read `1 hit` for two different claims."""
    w = [struct.unpack_from("<I", payload, i)[0] for i in range(0, len(payload) - 3, 4)]
    out, cnt, q = [], [], 0
    while q < len(w):
        n = w[q]
        if n == 0 or n > 100000 or q + 1 + mult * n > len(w):
            return None, None
        cnt.append(q)
        out.append(list(range(q + 1, q + 1 + mult * n)))
        q += 1 + mult * n
    return (out, cnt) if q == len(w) else (None, None)


def pointer_scale(kf, heads, plen, cache):
    """the SCALE of §316's predicate, measured on this file: P(a block HEAD offset occurs as a word in
    the field) against P(a NON-head 4-aligned offset occurs).  Without this, "one word in ACGICDOT
    equals this block's offset" is only interesting because the null was measured at 0.000 -- pool
    offsets and CDOT values share the same numeric range, so the coincidence risk is real and §300's
    census (96.7 % of CDOT words BELOW 0x10000) is exactly what makes it worth testing."""
    key = kf
    if key in cache:
        return cache[key]
    stem, f = kf
    fl = field_words(stem, f)
    rnd = random.Random(11)
    hl = sorted(heads)
    rnd.shuffle(hl)
    hl = hl[:300]
    nonh = [o for o in range(0, plen - 3, 4) if o not in heads]
    rnd.shuffle(nonh)
    nonh = nonh[:300]
    out = {}
    allw = set()
    for nm, payload in fl.items():
        ws = {struct.unpack_from("<I", payload, i)[0] for i in range(0, len(payload) - 3, 4)}
        allw |= ws
        if not ws:
            continue
        ph = sum(1 for o in hl if o in ws) / max(1, len(hl))
        pn = sum(1 for o in nonh if o in ws) / max(1, len(nonh))
        if ph or pn:
            out[nm] = (round(ph, 3), round(pn, 3))
    out["*ANY-FIELD*"] = (round(sum(1 for o in hl if o in allw) / max(1, len(hl)), 3),
                          round(sum(1 for o in nonh if o in allw) / max(1, len(nonh)), 3))
    cache[key] = out
    return out


def coords(kf):
    """per field, the group ranges of whichever REPEAT grammar consumes it exactly (n*u32 first, then
    n*pairs) -- so a hit can be reported as (group, slot) instead of a bare word index."""
    out = {}
    for nm, payload in field_words(*kf).items():
        for mult in (1, 2):
            g, c = groups(payload, mult)
            if g:
                out[nm] = (g, c, mult)
                break
    return out


def referrers(kf, pool, off, heads, scale, coord=None):
    """§316's pointer predicate run BACKWARDS: §316 asks "is this differing word a pool offset?" and
    this asks "which field holds a word equal to this block's pool offset, and at what coordinate in
    that field?" -- the only route this container offers from an anonymous DATAPOOL block to the
    tuning unit that reads it.

    A field contributes ONLY if this file's own measurement says its head-hit rate beats the
    non-head rate (pointer_scale); otherwise the match is reported as coincidence, not as an owner.
    Each count also carries the near-miss control `off+4` (a word inside this block's own header,
    never a valid head)."""
    stem, f = kf
    fl = field_words(stem, f)
    hits, ctrls = collections.Counter(), collections.Counter()
    where = {}
    for nm, payload in fl.items():
        for i in range(0, len(payload) - 3, 4):
            w = struct.unpack_from("<I", payload, i)[0]
            if w == off:
                hits[nm] += 1
                g = "nogroups"
                if coord and nm in coord:
                    # `i` is a BYTE index into the field payload; groups() speaks WORD indices.
                    wi = i // 4
                    rngs, cnt, _m = coord[nm]
                    if wi in cnt:
                        g = "COUNT-SLOT(size %d), not a pointer" % struct.unpack_from(
                            "<I", payload, i)[0]
                    else:
                        for gi, rng in enumerate(rngs):
                            if wi in rng:
                                g = "g%d/w%d" % (gi, rng.index(wi))
                                break
                where[nm] = g
            elif w == off + 4:
                ctrls[nm] += 1
    if not hits:
        return "-"
    parts = []
    for nm, _ in sorted(hits.items(), key=lambda x: (-x[1], x[0]))[:4]:
        ph, pn = scale.get(nm, (0.0, 0.0))
        tag = "" if ph > pn else "(NOT-EVIDENCE p_head %s<=p_non %s)" % (ph, pn)
        parts.append(f"{nm} {hits[nm]}/{ctrls.get(nm, 0)}@{where.get(nm) or '-'}{tag}")
    return ("off0-ambiguous " if off == 0 else "") + ";".join(parts)


def coord_positive_control(kf, heads, coord, sample=40):
    """the coordinate machinery's own positive control: over a deterministic sample of block heads,
    count the words that sit in a VALUE slot of a field with an exact REPEAT grammar AND equal one of
    those heads.  Zero means this arm is BLIND (a byte-vs-word index slip did exactly that on its
    first run) -- it must not be read as "the pool is unreferenced".  The scale for the other reading
    is pointer_scale's union rate, which is measured over every field including the ungrouped ones."""
    rnd = random.Random(5)
    hl = sorted(heads)
    rnd.shuffle(hl)
    hs = set(hl[:sample])
    ok = 0
    for nm, payload in field_words(*kf).items():
        if nm not in coord:
            continue
        rngs, _cnt, _m = coord[nm]
        vals = {i for r in rngs for i in r}
        for i in range(0, len(payload) - 3, 4):
            if (i // 4) in vals and struct.unpack_from("<I", payload, i)[0] in hs:
                ok += 1
    return ok, len(hs)


def compare_by_key(da, db, out=None):
    """the same comparison, but joining blocks by their FIRST PAYLOAD WORD (ledger 305: the block
    index is NOT a cross-board key -- 0.6 % agreement, lower than shuffled).  compare() above matches
    by index, which is fine inside one byte-identical pool but inflates the diff as soon as one block
    is added or dropped -- exactly the shape seen between the 6.0.1 and 7.1.1 Speaker/Handset/Headset
    pools (one block added/dropped per file).  Both numbers are printed so the reader can see how much
    of the index-based count was shift rather than change.

    Each differing block is then classified word by word: a word that equals a block offset in the
    same file's pool is a POINTER (layout, not tuning), anything else is a VALUE word -- and a value
    word is only called vivo's own number if no other board in the reference set shares it (that arm
    needs several dirs, so with two dirs the column says `unattributed` rather than pretending)."""
    pa, pb = pools([da]), pools([db])
    ra = {role_of(kf): (kf, pool) for kf, pool in pa.items()}
    rb = {role_of(kf): (kf, pool) for kf, pool in pb.items()}
    shared = sorted(set(ra) & set(rb))
    if not shared:
        sys.exit(f"gate: {da} and {db} share no cal-file role -- nothing to join by key either")
    ids = load_ids()
    SC, rows, tot = {}, [], collections.Counter()
    for r in shared:
        (ka, poola), (kb, poolb) = ra[r], rb[r]
        ba, bb = walk(poola), walk(poolb)
        if not (ba[1] and bb[1]):
            sys.exit(f"gate: role {r} does not close -- the chain grammar is the claim")
        oa, ob = block_offsets(poola), block_offsets(poolb)
        sa, sb = pointer_scale(ka, oa, len(poola), SC), pointer_scale(kb, ob, len(poolb), SC)
        ca, cb = coords(ka), coords(kb)
        pok, pden = coord_positive_control(ka, oa, ca)
        if pok == 0:
            print(f"  GATE {r}: the coordinate arm found NO value-slot pointer in {pden} sampled heads "
                  "of this file while pointer_scale measures a head-hit rate of "
                  f"{sa['*ANY-FIELD*'][0]} -- one of the two is blind; owner columns for this role are "
                  "UNMEASURED, not empty")
        print(f"  {r:20} referrer coverage: {len(oa)} blocks, head-hit rate {sa['*ANY-FIELD*'][0]} "
              f"against non-head null {sa['*ANY-FIELD*'][1]} | coordinate positive control "
              f"{pok}/{pden} sampled heads found in a value slot | fields beating their null: "
              + (", ".join(f"{nm} {v[0]}/{v[1]}" for nm, v in sorted(sa.items())
                           if v[0] > v[1] and nm != "*ANY-FIELD*") or "NONE"))
        # A block shorter than one word has no first word to key on; give each such block its own
        # negative index so it can never accidentally match a real (u32) key in the other pool.
        # MEASURED, and it changes the join: the first word is NOT unique inside one pool (Handset
        # 450 blocks / 217 distinct keys -- 289 blocks share a key with another block; Bluetooth
        # 204/115, Headset 300/159, Speaker 429/197).  So a key maps to a LIST of blocks and the two
        # sides are equal only when their payload MULTISETS are equal.  The first version of this arm
        # kept the LAST block of each key and diffed an arbitrary pair of members.
        def bkey(items):
            d = collections.defaultdict(list)
            for i, (o, _L, p) in enumerate(items[0]):
                d[(struct.unpack_from("<I", p, 0)[0]) if len(p) >= 4 else -(i + 1)].append((o, p))
            return d
        A, B = bkey(ba), bkey(bb)
        common = set(A) & set(B)
        tot["keys joined"] += len(common)
        tot["keys only in " + da] += len(set(A) - set(B))
        tot["keys only in " + db] += len(set(B) - set(A))
        tot["blocks behind joined keys"] += sum(len(A[k]) + len(B[k]) for k in common)
        for k in sorted(common):
            la = sorted(A[k], key=lambda t: t[1])
            lb = sorted(B[k], key=lambda t: t[1])
            if [p for _o, p in la] == [p for _o, p in lb]:
                continue
            tot["differing keys"] += 1
            tot["differing keys with a different block COUNT"] += (len(la) != len(lb))
            for idx in range(max(len(la), len(lb))):
                oa_ = la[idx] if idx < len(la) else None
                ob_ = lb[idx] if idx < len(lb) else None
                pa_ = oa_[1] if oa_ else None
                pb_ = ob_[1] if ob_ else None
                own_a = "-" if pa_ is None else referrers(ka, poola, oa_[0], oa, sa, ca)
                own_b = "-" if pb_ is None else referrers(kb, poolb, ob_[0], ob, sb, cb)
                if pa_ is None or pb_ is None or pa_ != pb_:
                    n = (min(len(pa_ or b""), len(pb_ or b"")) // 4) if (pa_ and pb_) else 0
                    ptr_a = ptr_b = val = 0
                    for i in range(n):
                        wa = struct.unpack_from("<I", pa_, i * 4)[0]
                        wb = struct.unpack_from("<I", pb_, i * 4)[0]
                        if wa == wb:
                            continue
                        if wa in oa or wb in ob:
                            ptr_a += (wa in oa)
                            ptr_b += (wb in ob)
                        else:
                            val += 1
                    mods = []
                    # ledger 307's anchor rule ("any band word names the module") measured FALSE here:
                    # the band words of these blocks (0x10001, 0x10002, 0x119ba) are ABSENT from the id
                    # ledger, which names 0x10010..0x12e1b.  And a lookup with NO band fires on
                    # 0/1/2/3, which are device ids the ledger also names -- §305's null ("coefficient
                    # words hit every catalogue") in a new costume.  The two classes are printed apart
                    # and neither is called the block's owner; the referrer arm is the one with a
                    # measured scale.
                    strong = weak = 0
                    for src in (x for x in (pa_, pb_) if x):
                        for i in range(0, min(len(src), 4 * 64) - 3, 4):
                            w = struct.unpack_from("<I", src, i)[0]
                            nm = ids.get(w)
                            if not nm:
                                continue
                            if IDBAND[0] <= w <= IDBAND[1]:
                                strong += 1
                                mods.append("w%d=%08x(%s)" % (i // 4, w, nm[:40]))
                            else:
                                weak += 1
                    tot["differing blocks: strong anchor"] += (strong > 0)
                    tot["differing blocks: small-id words only (ledger null)"] += (strong == 0 and weak > 0)
                    rows.append((da, db, r, "%08x" % (k or 0), len(pa_ or b""), len(pb_ or b""), n,
                                 ptr_a + ptr_b, val,
                                 ";".join(sorted(set(mods))[:6]) or f"none in band (small-id words: {weak})",
                                 own_a, own_b, "no" if (pa_ is None or pb_ is None) else "yes"))
                    tot["blocks with a value word"] += (val > 0)
                    tot["value words (not pointers)"] += val
                    tot["pointer words"] += ptr_a + ptr_b
                    tot["differing blocks whose referrer beats its null"] += sum(
                        1 for s in (own_a, own_b) if s != "-" and "NOT-EVIDENCE" not in s
                        and "off0" not in s and "@g" in s)
                    tot["differing blocks whose only hit is a group-size word"] += sum(
                        1 for s in (own_a, own_b) if s != "-" and "@g" not in s)
                    if pa_ is None or pb_ is None:
                        tot["unpaired blocks (key has a different number of members)"] += 1
                    else:
                        tot["paired blocks with differing bytes"] += 1
    print(f"key join {da} vs {db}: " + ", ".join(f"{k} {v}" for k, v in tot.items()))
    print("  NOTE: a key is a MULTISET: the first word is not unique inside a pool (Handset 450 blocks "
          "/ 217 keys), so two sides are equal only when their payload multisets are equal, and a "
          "differing key is reported per member (paired by sorted order) plus UNPAIRED rows for a "
          "member with no partner.  'keys only in X' counts keys, not features.")
    print("  NOTE: `owner_*` = '<field> <hits>/<off+4 control>@<group/slot>' for the fields whose u32 "
          "words equal THIS block's pool offset (§316's predicate run backwards).  A field is tagged "
          "NOT-EVIDENCE when this file's own measurement cannot separate a head offset from a non-head "
          "offset inside it (pointer_scale), and off0-ambiguous when the offset is 0, which any zero "
          "word matches.  The group coordinate is a coordinate only: the CDFT and CDOT group sequences "
          "agree in 36/120 fields, so slot -> cal type pairing is NOT established (ledger 577).")
    if out:
        with open(out, "w", encoding="utf-8") as fh:
            fh.write("set_a\tset_b\trole_file\tkey_hex\tlen_a\tlen_b\twords\tword_pointer\tword_value"
                     "\tmodule_anchor\towner_a\towner_b\tpaired\n")
            for row in rows:
                fh.write("\t".join(str(x) for x in row) + "\n")
        print(f"  wrote {out} ({len(rows)} differing keys)")


def load_ids():
    """id -> names from art/audio-6.0.1/acdb-ids.ALL.tsv (the universe ledger 305 measured as the one
    the pool keys actually live in: 22 % of blocks are keyed by an id this table names, while LUT
    coefficient words hit every catalogue at 0.0 %)"""
    p = os.path.join(ROOT, "art/audio-6.0.1/acdb-ids.ALL.tsv")
    out = {}
    if not os.path.exists(p):
        return out
    import csv as _csv
    for r in _csv.DictReader(open(p, encoding="utf-8"), delimiter="\t"):
        v = (r.get("id") or "").strip()
        if v.startswith("0x"):
            try:
                out[int(v, 16)] = (r.get("acdb_names") or r.get("workspace_catalog") or "").strip()
            except ValueError:
                pass
    return out


def coord_map(kf, pool, heads):
    """(field, group, slot) -> the block that slot points at.  This is the join that the container
    itself supports: a pool block is addressed by the value slot that points at it, and the same slot
    name means the same cal blob on both boards.  Pairing blocks by sorted payload order -- what
    compare_by_key does for a key with several members -- produced mirror rows (A#1/B#2 then A#2/B#1),
    which is the tell that the pairing was invented rather than read."""
    slots = {}
    for nm, (rngs, _cnt, _m) in coords(kf).items():
        for gi, rng in enumerate(rngs):
            for si, wi in enumerate(rng):
                slots[(nm, wi)] = (gi, si)
    fl = field_words(*kf)
    pay = {o: p for (o, _L, p) in walk(pool)[0]}
    out = {}
    for (nm, wi), (gi, si) in slots.items():
        off = struct.unpack_from("<I", fl[nm], wi * 4)[0]
        if off in pay:
            out[(nm, gi, si)] = (off, pay[off])
    return out


def compare_by_coordinate(da, db, out=None):
    """join the two sets by referrer coordinate and diff the blocks that the same coordinate selects"""
    pa, pb = pools([da]), pools([db])
    ra = {role_of(kf): (kf, pool) for kf, pool in pa.items()}
    rb = {role_of(kf): (kf, pool) for kf, pool in pb.items()}
    rows, tot = [], collections.Counter()
    for r in sorted(set(ra) & set(rb)):
        (ka, poola), (kb, poolb) = ra[r], rb[r]
        A = coord_map(ka, poola, {o for (o, _L, p) in walk(poola)[0]})
        B = coord_map(kb, poolb, {o for (o, _L, p) in walk(poolb)[0]})
        common = set(A) & set(B)
        # a moved pointer is only a CONTENT change if the bytes it pointed at do not exist on the other
        # side at all; if they do, the group was REORDERED (the deltas are not one constant, and many
        # come in +/- pairs, so "one dropped block shifted the pool" is not the story).
        exists_b, exists_a = {p for _o, p in B.values()}, {p for _o, p in A.values()}
        tot["coordinates joined"] += len(common)
        tot["coordinates only in " + da] += len(set(A) - set(B))
        tot["coordinates only in " + db] += len(set(B) - set(A))
        for c in sorted(common):
            if A[c] == B[c]:
                continue
            (oa_, ba_), (ob_, bb_) = A[c], B[c]
            n = min(len(ba_), len(bb_)) // 4
            dw = sum(1 for i in range(n)
                     if struct.unpack_from("<I", ba_, i * 4)[0]
                     != struct.unpack_from("<I", bb_, i * 4)[0])
            # the split that matters for a port: a slot whose POINTER moved is layout, a slot that
            # still points at the same offset but reads different bytes is content.
            moved = oa_ != ob_
            if moved:
                both = (ba_ in exists_b) and (bb_ in exists_a)
                tot["coordinates moved, bytes exist on BOTH sides (reordering)"] += both
                tot["coordinates moved, a byte-string appears on ONE side only"] += (not both)
                kind = "MOVED-REORDERED" if both else "MOVED-NEW-BYTES"
            else:
                kind = "SAME-OFFSET"
            tot["coordinates whose pointer moved (layout)"] += moved
            tot["coordinates whose content differs at the SAME offset"] += (not moved)
            if not moved:
                tot["differing words at same-offset coordinates"] += dw
            rows.append((da, db, r, "%s g%d/w%d" % c, kind,
                         (str(oa_) if not moved else "%d->%d" % (oa_, ob_)),
                         len(ba_), len(bb_), n, dw))
        tot["coordinates compared"] += len(common)
    print(f"coordinate join {da} vs {db}: " + ", ".join(f"{k} {v}" for k, v in tot.items()))
    if tot["coordinates joined"] == 0:
        sys.exit("gate: the coordinate join found nothing in common -- that is a blind ruler, not a "
                 "clean port")
    if out:
        with open(out, "w", encoding="utf-8") as fh:
            fh.write("set_a\tset_b\trole_file\tcoordinate\tkind\toffset_a_or_moved\tlen_a\t"
                     "len_b\twords\tdiffering_words\n")
            for row in rows:
                fh.write("\t".join(str(x) for x in row) + "\n")
        print(f"  wrote {out} ({len(rows)} coordinates)")
    for row in rows[:40]:
        print(f"  {row[2]:20} {row[3]:22} {row[4]:13} off {row[5]}  len {row[6]}/{row[7]}  "
              f"differing words {row[8]}/{row[9]}")
    if len(rows) > 40:
        print(f"  ... {len(rows) - 40} more rows in the TSV")


def copy_list(da, db, out=None):
    """THE migration artifact: pool blocks whose BYTES exist on only one of the two boards, each named
    by the coordinates that address it (`field group/slot`) -- a block nobody addresses cannot be the
    reason a listening path sounds different, and a block whose bytes are the same on both sides does
    not need copying.  This is deliberately NOT the index join (layout moves blocks) nor the
    same-slot join (a moved pointer reads as a diff): it asks only "do these bytes exist over there?".

    The positive control that makes the number mean something: two byte-equal calibration sets must
    give zero one-sided blocks; if that ever stops being true the join is broken, not the boards."""
    pa, pb = pools([da]), pools([db])
    ra = {role_of(kf): (kf, pool) for kf, pool in pa.items()}
    rb = {role_of(kf): (kf, pool) for kf, pool in pb.items()}
    rows, tot = [], collections.Counter()
    for r in sorted(set(ra) & set(rb)):
        (ka, poola), (kb, poolb) = ra[r], rb[r]
        A = collections.defaultdict(list)
        B = collections.defaultdict(list)
        for o, _L, p in walk(poola)[0]:
            A[p].append(o)
        for o, _L, p in walk(poolb)[0]:
            B[p].append(o)
        tot["blocks on " + da] += len(A)
        tot["blocks on " + db] += len(B)
        who_a = collections.defaultdict(list)
        who_b = collections.defaultdict(list)
        for cm, who in ((coord_map(ka, poola, set(A)), who_a), (coord_map(kb, poolb, set(B)), who_b)):
            for (nm, gi, si), (off, p) in cm.items():
                who[p].append("%s g%d/w%d" % (nm, gi, si))
        uniq = [(p, offs, da, who_a) for p, offs in A.items() if p not in B]
        uniq += [(p, offs, db, who_b) for p, offs in B.items() if p not in A]
        tot["one-sided blocks " + r] = 0
        for p, offs, side, who in sorted(uniq, key=lambda x: (-len(x[1]), x[0][:4])):
            names = who.get(p, [])
            tot["one-sided blocks"] += 1
            tot["one-sided on " + side] += 1
            tot["one-sided blocks addressed by a named table"] += bool(names)
            tot["one-sided blocks NOBODY addresses"] += (not names)
            tot["one-sided bytes"] += len(p)
            rows.append((da, db, r, hashlib.sha1(p).hexdigest()[:12], len(p), len(offs),
                         ",".join(str(o) for o in offs[:4]), side, ";".join(sorted(names)[:6]) or "UNADDRESSED"))
    print(f"copy list {da} vs {db}: " + ", ".join(f"{k} {v}" for k, v in tot.items() if not k.endswith(" blocks")))
    print("  NOTE: a block that is one-sided AND unaddressed cannot reach the listener through the "
          "cal path -- it is reported so the reader can exclude it, not so it gets copied.")
    if out:
        with open(out, "w", encoding="utf-8") as fh:
            fh.write("set_a\tset_b\trole_file\tpayload_sha12\tbytes\tcopies\to offsets\tside_only_here\taddressed_by\n")
            for row in rows:
                fh.write("\t".join(str(x) for x in row) + "\n")
        print(f"  wrote {out} ({len(rows)} one-sided blocks)")
    if tot["one-sided blocks"] and tot["one-sided blocks addressed by a named table"] == 0:
        sys.exit("gate: every one-sided block reads as UNADDRESSED -- the coordinate map is blind, "
                 "not the boards")
    return rows


def slots(dirs, out_path):
    """the (role, key-word) census -- ledger 305: the block INDEX is not a cross-board key (0.6 %
    agreement, BELOW the 1.2 % shuffled null), so the join key has to be the block's own first payload
    word.  Whether that word really carries the size is judged by a MATCHED-PAIRS design:
        signal = P(same key, two sets -> equal L)
        null   = P(different keys, one set -> equal L)
    Both are cell-equality rates over the same table, so they are comparable.  The first version of
    this arm compared whole key-to-key L-sets and read 100 % on a role with no signal at all -- the
    '尺没刻度' failure in a new costume, caught by printing the null next to the signal every run."""
    P = pools(dirs)
    byrole = collections.defaultdict(lambda: collections.defaultdict(dict))
    for kf, pool in sorted(P.items()):
        stem, f = kf
        role = f[len(stem) + 1:] if f.startswith(stem + "_") else f
        bl, ok = walk(pool)
        if not ok:
            sys.exit(f"gate: {kf} does not close -- the chain grammar is the claim under test here")
        for (off, L, payload) in bl:
            if L < 4 or len(payload) % 4:
                continue                      # byte-tail payloads have no u32 key to read
            byrole[role][struct.unpack_from("<I", payload, 0)[0]].setdefault(
                stem, []).append((off, L, hashlib.sha256(payload).hexdigest()[:16]))
    ids = load_ids()
    rnd = random.Random(5)
    need = min(3, len(dirs))   # two sets still make a legitimate port comparison, so do not idle
    print(f"{len(dirs)} sets, {len(byrole)} cal-file roles; the key is the block's first payload word; "
          f"a key must appear in >= {need} set(s)")
    rows, no_signal = [], []
    for role in sorted(byrole):
        per = byrole[role]
        multi = {k: v for k, v in per.items() if len(v) >= need}
        if len(multi) < 2:
            print(f"  {role:24} fewer than 2 keys in >= {need} sets -- nothing to align on")
            continue
        s_h = s_t = 0
        for v in multi.values():
            if len(v) < 2:
                continue
            for _ in range(20):
                a, b = rnd.sample(sorted(v), 2)
                s_t += 1
                s_h += {x[1] for x in v[a]} == {x[1] for x in v[b]}
        n_h = n_t = 0
        ks = sorted(multi)
        for _ in range(2000):
            a, b = rnd.sample(ks, 2)
            shared = sorted(set(multi[a]) & set(multi[b]))
            if not shared:
                continue
            s = rnd.choice(shared)
            n_t += 1
            n_h += {x[1] for x in multi[a][s]} == {x[1] for x in multi[b][s]}
        sig = s_h / max(s_t, 1)
        nul = n_h / max(n_t, 1)
        tun = sum(1 for v in multi.values()
                  if len({tuple(sorted(x[2] for x in lst)) for lst in v.values()}) > 1)
        print(f"  {role:24} keys={len(per):5} in>={need} sets={len(multi):5}  "
              f"same-key/different-set L-equal {s_h}/{s_t} = {sig:5.1%}  vs  "
              f"different-key/same-set {n_h}/{n_t} = {nul:5.1%}  "
              f"[{'SIGNAL' if sig > nul else 'NO SIGNAL -- the key does not carry the size here'}]   "
              f"payload differs {tun}/{len(multi)} = {tun/len(multi):5.1%}   "
              f"named by acdb-ids {sum(1 for k in multi if k in ids)}/{len(multi)}")
        if sig <= nul:
            no_signal.append((role, round(sig, 3), round(nul, 3)))
        for k, v in sorted(multi.items()):
            ls = sorted({x[1] for lst in v.values() for x in lst})
            # two different questions, two columns: sha variety anywhere (a board may repeat a key with
            # different content) vs sha variety BETWEEN boards (the port-relevant one)
            variety = len({x[2] for lst in v.values() for x in lst})
            per_board = {tuple(sorted(x[2] for x in lst)) for lst in v.values()}
            rows.append((role, k, len(v), ls, variety, len(per_board) > 1, ids.get(k, "")))
    if no_signal:
        print(f"  NOTE: the key word carries NO size signal in {no_signal} -- for those roles the slot "
              "table is a coincidence list and must not be used as the port join key")
    if out_path:
        with open(out_path, "w", encoding="utf-8") as fh:
            fh.write("role\tkey_hex\tkey_dec\tn_sets\tL_values\tlen_is_unanimous\t"
                     "distinct_payload_sha\tcross_board_differs\tno_size_signal_role\tname\n")
            flagged = {x[0] for x in no_signal}
            for (role, k, n, ls, variety, cross, nm) in rows:
                fh.write(f"{role}\t{k:#010x}\t{k}\t{n}\t{','.join(map(str, ls))}\t"
                         f"{len(ls) == 1}\t{variety}\t{cross}\t{role in flagged}\t{nm[:60]}\n")
        print(f"wrote {out_path} ({len(rows)} key rows; the per-role verdict is the printed SIGNAL line "
              "-- a role listed in NO size signal must not be joined on)")
    return no_signal


def modules(dirs, matrix_path, devices, out_path):
    """module-record anchors -- ledger 306/307. The anchor is (cal-file role, module id, offset of that
    id INSIDE its block), NOT (role, block key, id): ledger 307 found that PD1610 stores the same
    records at the same intra-block offsets but under a DIFFERENT collection key (0x4 -> 0x7,
    0x6 -> 0xc) and in a LONGER block (1572 -> 2748, 236 -> 524), so keying on the block key silently
    split the vivo board off the reference boards and made its records look absent.  The block key and
    block length are reported as columns instead of being part of the identity.

    The compared unit is the WINDOW of words starting at the id, because no record grammar for the
    block interior is established -- a differing window means 'the bytes at this module differ', not
    'this field is dB'.  Gates: the matrix file must exist (names and the path rule come from it),
    anchors must exist in >=3 sets, and EVERY occurrence of an id inside a block is kept (letting the
    last one win compares different sub-records between boards)."""
    if not os.path.exists(matrix_path):
        sys.exit(f"gate: {matrix_path} is missing -- the naming and the listening-path rule both come "
                 "from it, so this arm cannot run without it")
    import csv as _csv

    def hid(v):
        v = (v or "").strip()
        return int(v, 16) if v.startswith("0x") else None

    info = {}
    rows_ = list(_csv.DictReader(open(matrix_path, encoding="utf-8"), delimiter="\t"))
    for r in rows_:
        for key in ("module_id", "param_id"):
            iv = hid(r.get(key))
            if iv is None:
                continue
            rec = info.setdefault(iv, {"roots": set(), "names": set(), "on_path": False})
            rec["roots"].add(r.get("cal_root", ""))
            nm = (r.get("module_name") if key == "module_id" else r.get("param_name")) or ""
            if nm:
                rec["names"].add(nm)
            rec["on_path"] = rec["on_path"] or bool(
                {x for x in (r.get("lut_devices") or "").split(",") if x} & devices)
    print(f"matrix {os.path.basename(matrix_path)}: {len(rows_)} rows, {len(info)} module/param ids, "
          f"{sum(1 for v in info.values() if v['on_path'])} on the listening path "
          f"(rule: its LUT device list contains one of {sorted(devices)})")

    P = pools(dirs)
    # (role, id, intra-block offset) -> {set: [(block_key, block_len, window_sha)]}
    H = collections.defaultdict(lambda: collections.defaultdict(list))
    zero_w = tot_w = 0
    for kf, pool in sorted(P.items()):
        stem, f = kf
        role = f[len(stem) + 1:] if f.startswith(stem + "_") else f
        bl, ok = walk(pool)
        if not ok:
            sys.exit(f"gate: {kf} does not close")
        for (off, L, payload) in bl:
            if L < 8 or len(payload) % 4:
                continue
            bkey = struct.unpack_from("<I", payload, 0)[0]
            nw = len(payload) // 4
            for j in range(nw):
                v = struct.unpack_from("<I", payload, 4 * j)[0]
                if v not in info:
                    continue
                win = payload[4 * j:4 * min(nw, j + 9)]
                tot_w += 1
                if not any(struct.unpack_from("<I", win, 4 * t)[0] for t in range(len(win) // 4)):
                    zero_w += 1
                H[(role, v, 4 * j)][stem].append((bkey, L, len(win),
                                                  hashlib.sha256(win).hexdigest()[:12]))
    multi = {k: v for k, v in H.items() if len(v) >= 3}
    if not multi:
        sys.exit(f"gate: no (role, module, offset) anchor exists in >=3 of {dirs} -- the compare had "
                 "nothing to align, so no verdict may be printed")
    # two admissibility filters, both able to fail.  (1) the same number of occurrences per board, or
    # the windows compare different sub-records.  (2) the SAME WINDOW LENGTHS on every board -- a record
    # sitting at the tail of a short block gets its window truncated there while a board with a longer
    # block sees nine words, and that difference would be my ruler rather than the data (ledger 307
    # caught exactly this: five anchors at offsets 212..232 of a 236-byte block looked PD1610-specific)
    same_count = {k: v for k, v in multi.items() if len({len(occ) for occ in v.values()}) == 1}
    equal_occ = {k: v for k, v in same_count.items()
                 if len({tuple(sorted(x[2] for x in occ)) for occ in v.values()}) == 1}
    print(f"anchors (role, id, intra-block offset): {len(H)}; in >=3 sets {len(multi)}; same occurrence "
          f"count on every board {len(same_count)}/{len(multi)}; of those, same window LENGTHS "
          f"everywhere {len(equal_occ)}/{len(same_count)} -- {len(same_count) - len(equal_occ)} dropped "
          "ones sit at a block tail in some board, where a 'difference' is truncation, not tuning")
    if len(equal_occ) < 3:
        sys.exit("gate: too few anchors have a stable occurrence count -- the windows would compare "
                 "different numbers of sub-records, so this verdict is not admissible")
    print(f"content null: {zero_w}/{tot_w} windows are all zero "
          f"({zero_w/max(tot_w,1):.1%}) -- 'identical window' would be vacuous if that share were high")

    # how often does a board put the SAME record under a different collection key?
    key_split = collections.Counter()
    out_rows, differ, path_differ = [], 0, 0
    for k, v in sorted(equal_occ.items()):
        role, idv, aoff = k
        per_board = {st: sorted({(x[0], x[1]) for x in occ}) for st, occ in v.items()}
        keys_seen = sorted({x[0] for occ in v.values() for x in occ})
        lens_seen = sorted({x[1] for occ in v.values() for x in occ})
        winlen = sorted({x[2] for occ in v.values() for x in occ})
        shas = {tuple(sorted(x[3] for x in occ)) for occ in v.values()}
        groups = collections.defaultdict(list)
        for st, occ in v.items():
            groups[tuple(sorted(x[3] for x in occ))].append(st)
        info_v = info[idv]
        verdict = "BOARD-DEPENDENT" if len(shas) > 1 else "identical"
        differ += len(shas) > 1
        path_differ += len(shas) > 1 and info_v["on_path"]
        if len(keys_seen) > 1:
            key_split["anchors whose block key differs on some board"] += 1
            for st, ps in per_board.items():
                if len({p[0] for p in ps}) > 1:
                    key_split[f"{st} itself splits this record across keys"] += 1
        grp = " / ".join(("PD1610-SOLO " if gs == ["PD1610"] else "") + ",".join(sorted(gs))
                         for gs in sorted(groups.values(), key=len, reverse=True))
        out_rows.append((role, idv, aoff, info_v, sorted(v), keys_seen, lens_seen, len(shas),
                         verdict, winlen, grp))
    print(f"  anchors whose containing block key is NOT the same on every board: "
          f"{key_split.most_common(4)}")
    print(f"  windows differing between boards: {differ}/{len(equal_occ)}; of those on the listening "
          f"path: {path_differ}")
    solo = 0
    for (role, idv, aoff, info_v, sets, ks, ls, nvar, verdict, wl, grp) in out_rows:
        if verdict == "BOARD-DEPENDENT":
            solo += "PD1610-SOLO" in grp
            print(f"   {role:22} id {idv:#010x} off {aoff:6} keys {[hex(x) for x in ks]} L {ls} "
                  f"win {'|'.join(map(str, wl))} B "
                  f"{'PATH ' if info_v['on_path'] else '     '}"
                  f"[{','.join(sorted(x for x in info_v['roots'] if x))}] "
                  f"{sorted(info_v['names'])[:1]}  variants {nvar}/{len(sets)}  groups {grp}")
    print(f"  of the differing anchors, {solo} have PD1610 alone in its group "
          f"(vivo-specific records) and {differ - solo} split some other way")
    if out_path:
        with open(out_path, "w", encoding="utf-8") as fh:
            fh.write("role\tmodule_id\tmodule_names\tcal_roots\ton_listening_path\tbyte_offset\t"
                     "block_keys_seen\tblock_lengths_seen\tsame_key_everywhere\twindow_bytes\t"
                     "n_sets\tsets\tboard_payload_variants\tboard_groups\tverdict\n")
            for (role, idv, aoff, info_v, sets, ks, ls, nvar, verdict, wl, grp) in out_rows:
                fh.write(f"{role}\t{idv:#010x}\t{'|'.join(sorted(info_v['names']))[:80]}\t"
                         f"{','.join(sorted(x for x in info_v['roots'] if x))}\t{info_v['on_path']}\t"
                         f"{aoff}\t{'|'.join(hex(x) for x in ks)}\t{'|'.join(map(str, ls))}\t"
                         f"{len(ks) == 1}\t{'|'.join(map(str, wl))}\t{len(sets)}\t"
                         f"{'|'.join(sets)}\t{nvar}\t{grp}\t{verdict}\n")
        print(f"wrote {out_path} ({len(out_rows)} anchor rows; block key and length are COLUMNS, not "
              "part of the identity)")
    return len(equal_occ), differ, path_differ


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dirs", nargs="*", default=["PD1610"])
    ap.add_argument("--compare", nargs=2, metavar=("SET_A", "SET_B"))
    ap.add_argument("--copylist", nargs=2, metavar=("SET_A", "SET_B"),
                    help="blocks whose bytes exist on only one side, named by the addressing coordinate")
    ap.add_argument("--slots", action="store_true")
    ap.add_argument("--modules", action="store_true")
    ap.add_argument("--matrix", default=os.path.join(ROOT, "art/audio-6.0.1/acdb-matrix.PD1610.tsv"))
    ap.add_argument("--devices", default="15,124,150")
    ap.add_argument("--out")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.copylist:
        copy_list(*a.copylist, out=a.out)
        return
    if a.compare:
        compare(*a.compare)
        compare_by_key(*a.compare, out=a.out)
        compare_by_coordinate(*a.compare,
                              out=(a.out.replace(".tsv", "-coords.tsv") if a.out else None))
        return
    if a.slots:
        slots(a.dirs, a.out)
        return
    if a.modules:
        modules(a.dirs, a.matrix, {x for x in a.devices.split(",") if x}, a.out)
        return
    P = pools(a.dirs)
    print(f"{len(P)} DATAPOOL bodies across {len({kf[0] for kf in P})} set(s); "
          f"{sum(1 for v in P.values() if len(v) % 4)} are not a whole number of words")

    scored = {}
    for label in VARIANTS:
        scored[label] = sum(1 for pool in P.values() if walk(pool, variant=label)[1])
    for label in VARIANTS:
        print(f"  {label:32} exact-consume {scored[label]}/{len(P)}")
    if [k for k, v in scored.items() if v == len(P)] != [WINNER]:
        sys.exit(f"gate: the chain reading is underdetermined (winners "
                 f"{[k for k, v in scored.items() if v == len(P)]}) -- no grammar may be claimed")

    blocks = {}
    for kf, pool in sorted(P.items()):
        bl, ok = walk(pool)
        if not ok:
            sys.exit(f"gate: {kf} does not close under {WINNER}")
        blocks[kf] = bl
    per = [len(v) for v in blocks.values()]
    lvals = collections.Counter(L for bl in blocks.values() for (_o, L, _p) in bl)
    print(f"{sum(per)} blocks, min {min(per)} max {max(per)} mean {sum(per)/len(per):.1f}; "
          f"{len(lvals)} distinct block sizes, most common {lvals.most_common(5)}")
    if len(lvals) < 2:
        sys.exit("gate: every block has the same length -- the 'chain' is a fixed-record array and "
                 "the variant table would not have distinguished them")

    # 1) payload independence -- layout must depend on header words ONLY
    pbr = ptl = 0
    for kf, pool in sorted(P.items()):
        for (off, L, payload) in blocks[kf]:
            if L < 8 or len(payload) < 8:
                continue
            base = struct.unpack_from("<I", payload, 4)[0]
            for d in (4, -4):
                pbr += not walk(perturb(pool, off + 8, base + d))[1]
                ptl += 1
    if ptl == 0:
        sys.exit("gate: no payload word to perturb -- independence untested")
    prate = pbr / ptl
    print(f"payload independence: perturbing a PAYLOAD word by +-4 breaks the walk {pbr}/{ptl} = "
          f"{prate:.2%} (want ~0 -- otherwise the header/payload split is wrong)")
    if prate > 0.01:
        sys.exit(f"gate: {prate:.1%} of payload edits move the layout -- those are not payload words")

    # 2) length sensitivity on shifts the chain cannot absorb (+-1, +-2); +-4 reported with its reason
    rates = {}
    for delta in (1, 2, 4):
        br = tl = 0
        for kf, pool in sorted(P.items()):
            for (off, L, _p) in blocks[kf]:
                if L < delta:
                    continue
                for s in (1, -1):
                    br += not walk(perturb(pool, off, L + s * delta))[1]
                    tl += 1
        rates[delta] = (br, tl)
    for delta in (1, 2, 4):
        br, tl = rates[delta]
        print(f"length sensitivity +-{delta}d: breaks {br}/{tl} = {br/max(tl,1):.1%}")
    absorb = collections.Counter()
    for kf, pool in sorted(P.items()):
        n0 = len(blocks[kf])
        for (off, L, _p) in blocks[kf]:
            if L < 4:
                continue
            for s in (4, -4):
                bl, ok = walk(perturb(pool, off, L + s))
                if ok:
                    absorb["survivors"] += 1
                    absorb["re-sync (block count moves by one)"] += abs(len(bl) - n0) == 1
                    absorb["same block count"] += len(bl) == n0
    print(f"  why +-4 is absorbable: {absorb.most_common()} -- a 4-byte shift stays on the grid and "
          "the chain re-joins one block later; that is why the floor sits on +-1/+-2")
    gate = (rates[1][0] + rates[2][0]) / (rates[1][1] + rates[2][1])
    if gate < 0.90:
        sys.exit(f"gate: only {gate:.1%} of off-grid length edits break the walk -- those words do "
                 "not govern the layout, so call this a coincidence, not a format")

    # 3) base rate: does a random NON-boundary cursor also close?  (fixed seed, so it is reproducible)
    rnd = random.Random(20261016)
    close = tot = 0
    for kf, pool in sorted(P.items()):
        bounds = {o for (o, _L, _p) in blocks[kf]}
        cand = [i for i in range(0, len(pool) - 8, 4) if i not in bounds]
        if not cand:
            continue
        for _ in range(60):
            close += walk(pool, at=rnd.choice(cand))[1]
            tot += 1
    if tot == 0:
        sys.exit("gate: no non-boundary cursor to sample -- the base rate is untested, so the "
                 "49/49 closure has no scale")
    base = close / tot
    print(f"base rate: random non-boundary 4-aligned cursors close {close}/{tot} = {base:.2%} "
          f"-- the 49/49 closure from offset 0 is {(1 - base):.1%} unlike that")
    if base > 0.10:
        sys.exit(f"gate: a random cursor closes {base:.1%} of the time -- the pool is so zero-heavy "
                 "that walking to the end proves nothing")

    # 4) byte-phase null
    ph = pt = 0
    for kf, pool in sorted(P.items()):
        for d in (1, 2, 3):
            pt += 1
            ph += walk(pool, at=d)[1]
    print(f"byte-phase null: starting 1-3 bytes late closes {ph}/{pt} (want 0)")
    if ph:
        sys.exit(f"gate: {ph}/{pt} off-grid starts still walk to the end -- the walk is too lenient "
                 "to carry the reading")

    # 5) set controls, joined by cal-file ROLE (stock dirs prefix the name with the set, vivo ones do not)
    byset = collections.defaultdict(dict)
    for kf, bl in blocks.items():
        byset[kf[0]][role_of(kf)] = [(o, L) for (o, L, _p) in bl]
    for ka, kb, expect_same in (("PD1610", "PD1610LG4", True), ("Fluid", "Liquid", True),
                                ("PD1610", "QRD", False), ("QRD", "MTP", False),
                                ("PD1516A", "MTP", False)):
        if ka not in byset or kb not in byset:
            print(f"  control {ka} vs {kb} SKIPPED -- that set was not requested")
            continue
        shared = sorted(set(byset[ka]) & set(byset[kb]))
        same = sum(1 for r in shared if byset[ka][r] == byset[kb][r])
        print(f"  {'POSITIVE (byte-equal files)' if expect_same else 'NEGATIVE (other boards)'} "
              f"{ka} vs {kb}: {same}/{len(shared)} roles agree on the block sequence")
        if not shared:
            sys.exit(f"gate: {ka} and {kb} share no cal-file role -- that control compared nothing")
        if expect_same and same != len(shared):
            sys.exit(f"gate: byte-equal sets disagree on {len(shared) - same} walks -- the walk is "
                     "not a pure function of the bytes")
        if not expect_same and same == len(shared):
            sys.exit(f"gate: {ka} and {kb} walked identically in every role -- the chain cannot tell "
                     "boards apart, too coarse to be the format")

    # 6) payload shape census, reported only
    kind = collections.Counter()
    for bl in blocks.values():
        for (off, L, payload) in bl:
            if L == 0:
                kind["empty"] += 1
            elif L % 4:
                kind["byte-tail"] += 1
            else:
                first = struct.unpack_from("<I", payload, 0)[0]
                kind["id-band" if IDBAND[0] <= first <= IDBAND[1] else
                     "zero" if first == 0 else "small-count" if first < 64 else "other"] += 1
    tb = sum(kind.values())
    print(f"payload shape over {tb} blocks: " + ", ".join(f"{k} {v} ({v/tb:.1%})"
                                                          for k, v in kind.most_common()))

    if a.out:
        with open(a.out, "w", encoding="utf-8") as fh:
            fh.write("cal_set\tacdb_file\tblock\tblock_off\tL\tpayload_sha16\tw0\tw1\tshape\n")
            for kf, bl in sorted(blocks.items()):
                for i, (off, L, payload) in enumerate(bl):
                    w0 = struct.unpack_from("<I", payload, 0)[0] if L >= 4 else 0
                    w1 = struct.unpack_from("<I", payload, 4)[0] if L >= 8 else 0
                    shape = ("empty" if L == 0 else "byte-tail" if L % 4 else
                             "id-band" if IDBAND[0] <= w0 <= IDBAND[1] else
                             "zero" if w0 == 0 else "small-count" if w0 < 64 else "other")
                    fh.write(f"{kf[0]}\t{kf[1]}\t{i}\t{off}\t{L}\t"
                             f"{hashlib.sha256(payload).hexdigest()[:16]}\t{w0}\t{w1}\t{shape}\n")
        print(f"wrote {a.out} ({sum(len(v) for v in blocks.values())} blocks; sets in the file "
              f"{sorted({kf[0] for kf in blocks})} -- .PD1610 labels the baseline set, not the rows)")
    if a.selftest:
        print("selftest: 6-way variant uniqueness + 49/49 exact-consume + payload independence ~0% "
              "+ off-grid length sensitivity >=90% (+-4 reported with its absorb mechanism) + base "
              "rate <=10% + byte-phase null + byte-equal positives + cross-board negatives + shape "
              "census, all from the files (block MEANING deliberately not claimed)")


if __name__ == "__main__":
    main()
