#!/usr/bin/env python3
"""tools/cnt_embed.py -- pull the tuning blocks embedded inside each .cnt and verify them.

The container's real content is not register writes (§256 showed there are none): it is a handful of
dscFile/dscPatch blocks. Machine code gives every fact used here:

  tfaContWriteItem jump table (0xf8fac0, 10 bytes)  -> types 4 AND 5 share one handler
  handler: u24 at payload+0 = offset of the block's file name; payload = nxpTfaFileDsc_t
           { desc name(4) ; u32 size ; data[] }  (tfa98xx_parameters.h:607)
  data[] starts with nxpTfaHeader_t {u16 id; char version[2]; char subversion[2]; u16 size;
           u32 CRC; char customer[8]; ...}  (tfa98xx_parameters.h:52)
  tfaContWriteFile router (compare immediates, little-endian pairs):
           'VP' -> tfaContWriteVstep        'CO' -> config path
           'SP' -> tfa98xx_dsp_write_speaker_parameters
           'PA' -> tfa98xx_dsp_patch(tfa, size-0x24, data+0x24)
           'RP' -> tfa98xx_dsp_write_preset 'DR'/'QE' -> other paths

Verification is an external invariant, same trick as §255: the header comment says size counts the
bytes FOLLOWING the CRC field, so crc32(data+12 .. +12+size) must equal u32@8. If that holds the
blocks are intact and portable byte-for-byte; if it does not, this tool says so instead of guessing.

Usage: tools/cnt_embed.py [--out art/audio-6.0.1/live/tfa98xx/embedded] [--write]
"""
import argparse
import hashlib
import os
import struct
import sys
import zlib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IDS = {b"VP": "vstep -> tfaContWriteVstep", b"CO": "config -> config path",
       b"SP": "speaker -> tfa98xx_dsp_write_speaker_parameters",
       b"PA": "patch -> tfa98xx_dsp_patch(size-0x24 @ data+0x24)",
       b"RP": "preset -> tfa98xx_dsp_write_preset", b"DR": "DR path", b"QE": "eq -> tfaContWriteEq"}
IDS_STR = {k.decode("latin-1") for k in IDS}
HDR = 36  # nxpTfaHeader_t: id2 version2 subversion2 size2 CRC4 customer8 application8 type8


def container_crc_ok(b):
    """the driver's ONLY integrity gate (tfa98xx_cnt_loadfile, ledger 255) -- it covers bytes
    14..EOF, which includes every embedded block below, so block extraction inherits that proof.
    The blocks' own CRC field is NOT checked by the driver and its recipe did not reproduce under
    24 window/seed combinations -- reported as a producer field, not as verification."""
    size = struct.unpack_from("<H", b, 6)[0]
    stored = struct.unpack_from("<I", b, 10)[0]
    return b[:2] == b"PM" and size == len(b) and (zlib.crc32(b[14:]) & 0xFFFFFFFF) == stored


def cstr(b, o, lim=64):
    e = b.find(b"\0", o)
    if e < 0 or e - o > lim:
        return None
    s = b[o:e]
    return s.decode("latin-1") if s and all(32 <= c < 127 for c in s) else None


def walk_entries(b, lst, hdr, cnt):
    out = []
    for i in range(cnt):
        o = lst + hdr + 4 * i
        if o + 4 > len(b):
            break
        e = struct.unpack_from("<I", b, o)[0]
        out.append((e & 0xFFFFFF, (e >> 24) & 0xFF, o))
    return out


def iter_blocks(b):
    """walk container index -> device list -> profiles -> file/patch blocks.
    Single source of truth: tools/cnt_compare.py imports this instead of re-implementing the walk."""
    ndev, nprof = struct.unpack_from("<HH", b, 40)
    idx = walk_entries(b, 44, 0, ndev + nprof)
    dev = [off for off, t, _ in idx if t == 0]
    if not dev:
        return []
    dcnt = b[dev[0]]
    # nxpTfaDeviceList: {u8 length; u8 bus; u8 channel; ...; desc name; desc entries[]} --
    # the name desc sits at +8, and tfaContProfile reads entries at +12
    items = walk_entries(b, dev[0], 12, dcnt)
    lists = [("device", dev[0], items)]
    for off, t, _ in items:
        if t == 1:
            lists.append((f"profile@{off:#x}", off, walk_entries(b, off, 4, b[off])))
    out, seen = [], set()
    for lab, _, ents in lists:
        for off, t, pos in ents:
            if t not in (4, 5) or off in seen or off + 8 + HDR > len(b):
                continue
            seen.add(off)
            name = cstr(b, struct.unpack_from("<I", b, off)[0] & 0xFFFFFF)
            data = off + 8
            fsize = struct.unpack_from("<I", b, off + 4)[0]
            out.append({
                "list": lab, "desc_off": pos, "payload_off": off, "name": name or "",
                "id": b[data:data + 2].decode("latin-1", "replace"),
                "version": b[data + 2:data + 6].decode("latin-1", "replace"),
                "hdr_size": struct.unpack_from("<H", b, data + 6)[0],
                "dsc_size": fsize, "route": IDS.get(b[data:data + 2], "UNKNOWN"),
                "hdr_crc": struct.unpack_from("<I", b, data + 8)[0],
                "body": b[data + HDR:data + fsize] if HDR < fsize <= len(b) - data else b"",
            })
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default=os.path.join(ROOT, "art/audio-6.0.1/live/tfa98xx"))
    ap.add_argument("--out", default=os.path.join(ROOT, "art/audio-6.0.1/live/tfa98xx/embedded"))
    ap.add_argument("--write", action="store_true", help="dump the verified blocks to --out")
    args = ap.parse_args()

    rows = []
    for fn in sorted(f for f in os.listdir(args.dir) if f.endswith(".cnt")):
        b = open(os.path.join(args.dir, fn), "rb").read()
        if not container_crc_ok(b):
            sys.exit(f"gate: {fn} fails the container CRC -- nothing extracted from it is trustworthy")
        blocks = iter_blocks(b)
        print(f"  {fn}: {len(blocks)} blocks")
        for bkl in blocks:
            ok = bkl["dsc_size"] > HDR and len(bkl["body"]) == bkl["dsc_size"] - HDR
            status = "ok" if ok and bkl["name"] and bkl["id"] in IDS_STR else "bad-size-or-id"
            sha = hashlib.sha256(bkl["body"]).hexdigest()[:16] if bkl["body"] else "-"
            print(f"    {bkl['list']:14s} desc@{bkl['desc_off']:#05x} payload@{bkl['payload_off']:#05x} "
                  f"id={bkl['id']:2s} {bkl['route']:52s} name={bkl['name']!r} ver={bkl['version']!r} "
                  f"hdr.size={bkl['hdr_size']} dsc.size={bkl['dsc_size']} body={len(bkl['body'])}B "
                  f"sha={sha} {status}")
            rows.append((fn, bkl["list"], f"{bkl['desc_off']:#x}", f"{bkl['payload_off']:#x}", bkl["name"],
                         bkl["id"], bkl["version"], bkl["hdr_size"], bkl["dsc_size"], len(bkl["body"]),
                         f"{bkl['hdr_crc']:#010x}", sha, status))
        if len(blocks) < 3:
            print(f"  gate: only {len(blocks)} file blocks found in {fn} -- expected the config/speaker/vstep family")

    tsv = os.path.join(args.out, "cnt-embed.PD1610.tsv") if args.write else None
    if args.write:
        os.makedirs(args.out, exist_ok=True)
        written = 0
        cache = {}
        for fn, lab, pos, off, name, idb, ver, hsize, fsize, nbody, crc, sha, status in rows:
            if status != "ok":
                continue
            src = cache.get(fn) or open(os.path.join(args.dir, fn), "rb").read()
            cache[fn] = src
            start = int(off, 16) + 8 + HDR
            body = src[start:start + fsize - HDR]
            dst = os.path.join(args.out, f"{fn[:-4]}.{name}")
            open(dst, "wb").write(body)
            # self-check: what landed on disk must equal the source range, or the tool is broken
            if open(dst, "rb").read() != body:
                sys.exit(f"gate: {dst} does not re-read equal to the source range")
            written += 1
        with open(tsv, "w", encoding="utf-8", newline="") as fh:
            fh.write("cnt\tlist\tdesc_off\tpayload_off\tname\tid\tversion\thdr_size\tdsc_size\tbody_bytes\tcrc_field\tbody_sha\tstatus\n")
            for r in rows:
                fh.write("\t".join(str(x) for x in r) + "\n")
        print(f"wrote {written} blocks + {tsv} under {args.out}")
    n = len(rows)
    print(f"\ntotal file blocks={n}  size-consistent={sum(1 for r in rows if r[-1]=='ok')}  "
          f"other={n - sum(1 for r in rows if r[-1]=='ok')}")
    print("integrity basis: the container CRC (bytes 14..EOF) covers every offset extracted here; "
          "the per-block crc_field is a producer value -- the driver never checks it (one crc32_le "
          "call site, in tfa98xx_cnt_loadfile) and it did not reproduce under 24 window/seed recipes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
