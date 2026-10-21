#!/usr/bin/env python3
"""tools/cnt_layout_search.py -- exhaustive, anchored search for the container's entry layout.

Answers one question with a hard scale instead of a feeling: can ANY reading of the index entries
(base, stride, byte order, field order) make the device/profile lists walk cleanly AND point at
things we independently know are real?

Two external anchors only (self-consistency is not evidence -- §229/§251 both burned me on that):
  A1  profile/channel name payloads must land on the byte offsets where MUSIC_48000 / VOICE_48000 /
      left / right actually sit in this file (§230 found them by raw search; here they must be
      REACHED through the index).
  A2  every dscRegister (type 2) entry's payload must decode as {u8 addr; u16 val; u16 mask}
      (shape proven in tfaContWriteItem) with addr inside tfa98xx_regs -- the 26 registers the
      driver itself exposes (§249, read live out of fw/Image).

Usage: tools/cnt_layout_search.py [--dir art/audio-6.0.1/live/tfa98xx]
"""
import argparse
import os
import struct
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KALL = os.path.join(ROOT, "art/kallsyms_real.txt")
IMG = os.path.join(ROOT, "fw/Image")
TEXT_BASE = 0xFFFFFFC000080000
ANCHORS = ("MUSIC_48000", "VOICE_48000", "left", "right")
TYPES = ("dscDevice", "dscProfile", "dscRegister", "dscString", "dscFile", "dscPatch",
         "dscMarker", "dscMode", "dscSISel", "dscSOSel")


def whitelist():
    va = None
    for line in open(KALL, encoding="utf-8", errors="replace"):
        p = line.split()
        if len(p) == 3 and p[2] == "tfa98xx_regs":
            va = int(p[0], 16)
            break
    if va is None:
        sys.exit("gate: tfa98xx_regs not in kallsyms")
    blob = open(IMG, "rb").read()
    return set(blob[va - TEXT_BASE: va - TEXT_BASE + 26])


def cstr(b, o, lim=48):
    e = b.find(b"\0", o)
    if e < 0 or e - o > lim:
        return None
    s = b[o:e]
    return s.decode("latin-1") if s and all(32 <= c < 127 for c in s) else None


def read_entry(b, o, order):
    if o + 4 > len(b):
        return None
    r = b[o:o + 4]
    if order == "le":
        e = struct.unpack("<I", r)[0]
        return e & 0xFFFFFF, (e >> 24) & 0xFF
    if order == "be":
        e = struct.unpack(">I", r)[0]
        return e >> 8, e & 0xFF
    if order == "type_first_le":
        return struct.unpack("<I", b"\x00" + r[:3])[0], r[0]
    if order == "type_last_be":
        return struct.unpack(">I", r[:3] + b"\x00")[0], r[3]
    return None


def score(b, lst, base, stride, order, cnt, wl, anchor_offs):
    a = v = inv = reg_ok = reg_bad = 0
    for i in range(cnt):
        got = read_entry(b, lst + base + stride * i, order)
        if not got:
            break
        off, t = got
        if t <= 9 and 0 < off < len(b) - 4:
            v += 1
            if cstr(b, off) in anchor_offs:
                a += 1
            if t == 2:
                addr = b[off]
                struct.unpack_from("<HH", b, off + 1)
                if addr in wl:
                    reg_ok += 1
                else:
                    reg_bad += 1
        else:
            inv += 1
    return a, v, inv, reg_ok, reg_bad


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default=os.path.join(ROOT, "art/audio-6.0.1/live/tfa98xx"))
    args = ap.parse_args()
    wl = whitelist()
    if len(wl) != 26:
        sys.exit(f"gate: whitelist {len(wl)} != 26")
    files = sorted(f for f in os.listdir(args.dir) if f.endswith(".cnt"))
    if not files:
        sys.exit(f"gate: no .cnt in {args.dir}")
    for fn in files:
        b = open(os.path.join(args.dir, fn), "rb").read()
        anchor_offs = {n: b.find(n.encode()) for n in ANCHORS}
        anchor_offs = {n for n, o in anchor_offs.items() if o >= 0}
        print(f"\n{fn} len={len(b)} anchors present: {sorted(anchor_offs)}")
        # device list = index[0] of the container (cont+44), profiles are the two dscProfile entries
        e0 = struct.unpack_from("<I", b, 44)[0]
        if (e0 & 0xFFFFFF, (e0 >> 24) & 0xFF) != (0x34, 0):
            print(f"  gate: container index[0] @44 is not (off=0x34, type=dscDevice) -> {e0:#x}")
            continue
        rows = []
        lists = [("device", 0x34)]
        for base in range(0, 24):
            for stride in (4, 8):
                got = read_entry(b, 0x34 + base + stride * 9, "le")
                if got and got[1] == 1:
                    lists.append((f"prof@{got[0]:#x}", got[0]))
        seen = set()
        for lab, lst in lists:
            if lst in seen or not 0 < lst < len(b) - 8:
                continue
            seen.add(lst)
            for base in range(0, 24):
                for stride in (4, 8):
                    for order in ("le", "be", "type_first_le", "type_last_be"):
                        for cnt in sorted({b[lst], 4, 6, 10}):
                            if not 1 <= cnt <= 40:
                                continue
                            s = score(b, lst, base, stride, order, cnt, wl, anchor_offs)
                            if s[0] or s[3]:
                                rows.append((lab, lst, base, stride, order, cnt) + s)
        rows.sort(key=lambda r: (-r[6], -r[9], -r[8]))
        print(f"  hypotheses with >=1 anchor hit or >=1 in-whitelist register: {len(rows)}")
        for lab, lst, base, stride, order, cnt, a, v, inv, ok, bad in rows[:6]:
            print(f"    {lab:12s} base=+{base:<2d} stride={stride} {order:14s} cnt={cnt:<2d} "
                  f"anchors={a} valid={v} invalid={inv} reg_in_WL={ok} reg_out_WL={bad}")
        tot_ok = sum(r[9] for r in rows)
        print(f"  TOTAL dscRegister payloads landing in the 26-register whitelist, over ALL hypotheses: {tot_ok}")
        if tot_ok == 0:
            print("  => no reading of the index yields register-patch records; per §239 this closes the "
                  "'profiles contain raw regpatches' idea for good, on an anchored scale")
    return 0


if __name__ == "__main__":
    sys.exit(main())
