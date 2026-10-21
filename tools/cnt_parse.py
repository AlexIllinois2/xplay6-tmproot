#!/usr/bin/env python3
"""tools/cnt_parse.py -- raw entry dump for the TFA container (SUPERSEDED for the walk).

SUPERSEDED by tools/cnt_embed.py: this version tried device-list entry bases including +8, but +8 is
the list's own `name` descriptor ('left'); entries start at +12 (tfaContProfile). Kept because
ledger 255/256 cite the unfiltered entry dump it produces -- read those sections' "+8" claim as
corrected by 257. Run tools/cnt_embed.py for anything you intend to act on.

Facts from machine code (fw/Image), not from the reference headers -- §241/§242 already proved the
2016 build does not match tfa98xx_parameters.h:

  tfaContShowHeader @0xffffffc000bbd088
      id/version/subversion  = 3 x u16 at +0/+2/+4      ("id:%.2s version:%.2s subversion:%.2s")
      size   = u16 at +6,  CRC = u32 at +8              ("size:%d CRC:0x%08x")
      customer/application/type = 8 bytes each at +12/+20/+28
  tfaContWriteItem @0xffffffc000bbd500
      type   = ldrb [entry, #3]           -> the index entry is a LE u32: offset = low 24 bits
      offset = [entry] & 0xffffff         -> payload lives at cont + offset
      switch only reaches types 0..9      -> anything else is a parse error, not a "new type"
      register payload = {u8 addr; u16 val; u16 mask} read at +0/+1/+3 (little-endian, byte packed)
  tfaContProfile @0xffffffc000bbcd94      device list: count = list[0],  entries at list+12, stride 4
  tfaContWriteProfile @0xffffffc000bbd694 profile list: count = prof[0], entries at prof+8,  stride 4

What the code does NOT say: where the CONTAINER's own index[] begins (the reference struct says +46,
which §242 could not make work). So the start is searched -- but scoring is anchored on an
independent fact, not on self-consistency: profile names MUSIC_48000 / VOICE_48000 really exist in
these files (§230). A candidate parse must POINT at those byte offsets, not merely stay in range.

Usage: tools/cnt_parse.py [--anchor] [file.cnt ...]
"""
import os
import struct
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TYPES = ["dscDevice", "dscProfile", "dscRegister", "dscString", "dscFile", "dscPatch",
         "dscMarker", "dscMode", "dscSetInputSelect", "dscSetOutputSelect"]
NAMES = ["MUSIC_48000", "VOICE_48000"]


def read_list(buf, base, hdr, cnt):
    """cnt LE u32 entries at base+hdr -> [(offset, type)]; None on any structural violation"""
    if base + hdr + 4 * cnt > len(buf):
        return None
    out = []
    for i in range(cnt):
        e = struct.unpack_from("<I", buf, base + hdr + 4 * i)[0]
        off, typ = e & 0xFFFFFF, (e >> 24) & 0xFF
        if typ > 9 or off <= 0 or off > len(buf) - 2:
            return None
        out.append((off, typ))
    return out


def cstr(buf, off, limit=40):
    end = buf.find(b"\0", off)
    if end < 0 or end - off > limit:
        return None
    s = buf[off:end]
    return s.decode("latin-1") if s and all(32 <= c < 127 for c in s) else None


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    files = args or [os.path.join(ROOT, "art/audio-6.0.1/live/tfa98xx", f) for f in
                     ("tfa98xx_PD1610.cnt", "tfa98xx.cnt", "tfa98xx_PD1516A.cnt")]
    for path in files:
        buf = open(path, "rb").read()
        size = struct.unpack_from("<H", buf, 6)[0]
        crc = struct.unpack_from("<I", buf, 8)[0]
        cust = buf[12:20].split(b"\0")[0].decode("latin-1", "replace")
        app = buf[20:28].split(b"\0")[0].decode("latin-1", "replace")
        typ = buf[28:36].split(b"\0")[0].decode("latin-1", "replace")
        anchors = {n: buf.find(n.encode()) for n in NAMES}
        print(f"\n=== {os.path.basename(path)} len={len(buf)} size@6={size} CRC@8={crc:#010x} "
              f"customer={cust!r} app={app!r} type={typ!r}")
        print(f"  anchor offsets: " + ", ".join(f"{n}={a:#x}" if a >= 0 else f"{n}=ABSENT"
                                                for n, a in anchors.items()))
        if size != len(buf):
            print("  gate: header size != file length -- stop")
            continue

        found = []
        # the header itself tells the index length (ndev@40, nprof@42 -- read from the file below),
        # and index[] begins at +44: entry0 = u32 0x00000034 -> offset 0x34, type 0 = dscDevice.
        ndev = struct.unpack_from("<H", buf, 40)[0]
        nprof = struct.unpack_from("<H", buf, 42)[0]
        for idx0, c in ((44, ndev), (44, ndev + nprof)):
            ent = read_list(buf, idx0, 0, c)
            if ent is None:
                print(f"  container index @{idx0} count={c}: violates type<=9 / offset-in-file")
                continue
            hits = sum(1 for off, t in ent if t == 3 and cstr(buf, off) in NAMES)
            hits += sum(1 for n, a in anchors.items() if a >= 0 and any(o == a for o, _ in ent))
            found.append((hits, c, idx0, 0, ent))
            print(f"  container index @{idx0} (ndev={ndev} nprof={nprof}): " +
                  ", ".join(f"off={o:#x}/{TYPES[t]}" for o, t in ent))
        if not found:
            print("  => container index does not validate; stop here")
            continue
        hits, c, idx0, lhdr, ent = max(found, key=lambda x: x[0])
        print(f"  index parses, profile-name anchor hits={hits}")
        for i, (off, t) in enumerate(ent):
            if t != 0:
                continue
            dcnt = buf[off]
            dl = read_list(buf, off, 12, dcnt)
            if dl is None:
                print(f"    device[{i}] @{off:#x}: count byte={dcnt} -> entries at +12 DO NOT parse")
                continue
            print(f"    device[{i}] @{off:#x}: count={dcnt} (entries at +12)")
            for j, (poff, ptyp) in enumerate(dl):
                tag = cstr(buf, poff) if ptyp == 3 else None
                line = f"      dev.index[{j}] off={poff:#x} type={ptyp}({TYPES[ptyp]})"
                if ptyp == 1:
                    pcnt = buf[poff]
                    pl = read_list(buf, poff, 8, pcnt)
                    if pl is None:
                        print(line + f" profile: count byte={pcnt} -> items at +8 DO NOT parse")
                        continue
                    kinds = {}
                    recs = []
                    for o, tt in pl:
                        kinds[TYPES[tt]] = kinds.get(TYPES[tt], 0) + 1
                        if tt == 2:
                            addr = buf[o]
                            val, mask = struct.unpack_from("<HH", buf, o + 1)
                            recs.append((addr, val, mask))
                    print(line + f" profile @{poff:#x}: items={pcnt} kinds={kinds}")
                    if recs:
                        print(f"        regpatch records={len(recs)} "
                              f"distinct addrs={len({a for a, _, _ in recs})} "
                              f"full-mask={sum(1 for _, _, m in recs if m == 0xffff)}")
                        print("        first 10: " + ", ".join(f"{a:#02x}:{v:#04x}/{m:#04x}"
                                                              for a, v, m in recs[:10]))
                elif tag:
                    print(line + f" str={tag!r}")
                else:
                    print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
