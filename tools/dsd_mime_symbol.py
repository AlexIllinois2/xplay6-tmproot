#!/usr/bin/env python3
"""tools/dsd_mime_symbol.py -- the DSD MIME constant read as DATA, not as an instruction operand.

vivo added an exported constant `android::MEDIA_MIMETYPE_AUDIO_BBK_DSD` to libstagefright; it is a
pointer whose target is the literal `audio/dsd`.  Reading it needs no operand arithmetic at all, so
the same leg works on ARM32 and ARM64 -- which is what makes it usable on 7, where the player
service may have moved to 64-bit (the def-chain in tools/dsd_gate.py only decodes ARM32).

It answers a different question from dsd_gate.py --mime and must not be merged with it:
  dsd_gate   : does the framework still COMPARE the stream MIME against `audio/dsd`?  (needs code)
  this tool  : does the constant exist here and what string does it point at?          (data only)
"""
import argparse, os, re, struct, sys

SYM = "MEDIA_MIMETYPE_AUDIO_BBK_DSD"
EXPECT = b"audio/dsd"


def elf(path):
    d = open(path, "rb").read()
    if d[:4] != b"\x7fELF":
        sys.exit("gate: %s is not an ELF -- the constant cannot be read from a file that is not one" % path)
    cls = d[4]
    if cls not in (1, 2):
        sys.exit("gate: %s has ELF class %d, neither 32 nor 64" % (path, cls))
    if cls == 1:
        sh_off = struct.unpack_from("<I", d, 0x20)[0]
        sh_entry, sh_num, sh_str = (struct.unpack_from("<H", d, o)[0] for o in (0x2e, 0x30, 0x32))
        fmt = "<10I"
        ent = 16
    else:
        sh_off = struct.unpack_from("<Q", d, 0x28)[0]
        sh_entry, sh_num, sh_str = (struct.unpack_from("<H", d, o)[0] for o in (0x3a, 0x3c, 0x3e))
        fmt = "<IIQQQQIIQQ"
        ent = 24
    raw = [struct.unpack_from(fmt, d, sh_off + i * sh_entry) for i in range(sh_num)]
    shstrtab = raw[sh_str][4]  # sh_offset of the shstrtab section (both classes)
    shstr = d[shstrtab:]
    secs = {}
    for r in raw:
        if cls == 1:
            name, stype, flags, addr, off, size = r[0], r[1], r[2], r[3], r[4], r[5]
        else:
            name, stype, flags, addr, off, size = r[0], r[1], r[2], r[3], r[4], r[5]
        nm = shstr[name:shstr.index(b"\0", name)].decode("ascii", "replace")
        secs[nm] = dict(addr=addr, off=off, size=size, type=stype)
    packed = any(x["type"] == 0x60000002 for x in secs.values())   # SHT_ANDROID_RELA
    return d, secs, cls, ent, packed


def symbols(d, secs, ent):
    out = []
    for skey, stkey in ((".dynsym", ".dynstr"), (".symtab", ".strtab")):
        s, st = secs.get(skey), secs.get(stkey)
        if not s or not st:
            continue
        sb = d[st["off"]:st["off"] + st["size"]]
        for i in range(s["size"] // ent):
            if ent == 16:
                nm, value, size, info, other, shndx = struct.unpack_from("<IIIBBH", d, s["off"] + i * 16)
            else:
                nm, info, other, shndx, value, size = struct.unpack_from("<IBBHQQ", d, s["off"] + i * 24)
            if not nm:
                continue
            name = sb[nm:sb.index(b"\0", nm)].decode("ascii", "replace")
            out.append(dict(table=skey, name=name, value=value, size=size,
                            typ=info & 0xf, bind=(info >> 4) & 3, shndx=shndx))
    return out


def reloc_target(d, secs, at, cls):
    """The VA an absolute relocation at file-image address `at` points to, or 0."""
    if cls == 1:
        r = secs.get(".rel.dyn")
        if not r:
            return 0
        for i in range(r["size"] // 8):
            off, info = struct.unpack_from("<II", d, r["off"] + i * 8)
            if off == at and (info & 0xFF) == 2:      # R_ARM_ABS32: the file word IS the target
                return 0                              # (already read above; REL has no addend)
        return 0
    for key in (".rela.dyn", ".rela.sdata", ".rela.data"):
        r = secs.get(key)
        if not r:
            continue
        for i in range(r["size"] // 24):
            off, info, addend = struct.unpack_from("<QQq", d, r["off"] + i * 24)
            if off == at and (info & 0xFFFFFFFF) == 257:   # R_AARCH64_ABS64
                return addend
    return 0


def read_at(secs, va, n, d):
    for nm, s in secs.items():
        if s["addr"] and s["size"] and s["type"] != 8 and s["addr"] <= va < s["addr"] + s["size"]:
            o = s["off"] + va - s["addr"]
            return nm, d[o:o + n]
    return None, None


def cstr(raw):
    return raw.split(b"\0")[0]


def report(path, want=SYM, quiet=False):
    d, secs, cls, ent, packed = elf(path)
    allsyms = symbols(d, secs, ent)
    syms = [x for x in allsyms if want in x["name"]]
    ptr_size = 4 if cls == 1 else 8
    res = {"path": path, "class": cls, "hits": [], "imports": [], "packed_relocs": packed,
           "literal_present": EXPECT in d,
           "family": sorted({x["name"] for x in allsyms if "MEDIA_MIMETYPE_AUDIO" in x["name"]})}
    if not syms:
        sys.exit("gate: %s exports/defines no symbol containing %r -- on 7 this means the constant "
                 "was renamed or moved, and `absent here` must NOT be read as `the DSD route is gone`"
                 % (os.path.basename(path), want))
    for x in syms:
        if x["typ"] != 1:  # STT_OBJECT
            continue
        # the same name appears in both .dynsym and .symtab; SHN_UNDEF(0) means this library only
        # IMPORTS the constant, so its value is legitimately 0 here and the definition is elsewhere.
        if x["shndx"] == 0 or not x["value"]:
            res.setdefault("imports", []).append({"symbol": x["name"], "table": x["table"]})
            continue
        sn, raw = read_at(secs, x["value"], ptr_size, d)
        if raw is None:
            sys.exit("gate: %s has value %#x which is not inside any loaded section -- refusing to "
                     "guess what it points at" % (x["name"], x["value"]))
        ptr = int.from_bytes(raw, "little")
        # In a shared library the pointer slot is often 0 **in the file** and filled at load time by
        # a relocation (ARM64 uses RELA, so the target sits in r_addend).  Read it from there.
        origin = "file word"
        if not ptr:
            origin = "relocation addend"
            ptr = reloc_target(d, secs, x["value"], cls)
            if not ptr and packed:
                # Android lays .rela.dyn out PACKED (SHT_ANDROID_RELA), so an absolute data pointer is
                # 0 in the file and only exists after the linker unpacks it.  Say so plainly instead
                # of either refusing or pretending the string was read.
                res["hits"].append({"symbol": x["name"], "table": x["table"], "addr": hex(x["value"]),
                                    "size": x["size"], "bind": x["bind"], "status": "relocation-filled",
                                    "points_to": None, "section": None, "string": None})
                continue
            if not ptr:
                sys.exit("gate: %s holds 0 and no absolute relocation covers that address -- the "
                         "pointer is only established at load time, so its string is NOT statically "
                         "readable in this object" % x["name"])
        tn, traw = read_at(secs, ptr, 64, d)
        if tn is None:
            sys.exit("gate: %s holds %#x, which is not inside any loaded section -- refusing to name "
                     "a string that is not there" % (x["name"], ptr))
        sval = cstr(traw or b"")
        if not sval:
            sys.exit("gate: %s -> %#x holds an empty string -- an empty read is not an answer" %
                     (x["name"], ptr))
        if any(h["symbol"] == x["name"] for h in res["hits"]):
            continue  # same constant listed in a second symbol table
        res["hits"].append({"symbol": x["name"], "table": x["table"], "addr": hex(x["value"]),
                            "size": x["size"], "bind": x["bind"], "points_to": hex(ptr),
                            "section": tn, "string": sval.decode("ascii", "replace")})
    return res


def selftest():
    repo = os.environ.get("AUDIO_PORT_ROOT") or "/home/v/.local/project/xplay6"
    l32 = f"{repo}/art/audio-6.0.1/shipped/system/lib/libstagefright.so"
    l64 = "/tmp/stage429/libstagefright.64.so"
    arms = []
    def arm32_reads():
        r = report(l32)
        return (r["class"] == 1 and len(r["hits"]) == 1 and r["hits"][0]["string"] == "audio/dsd"
                and r["hits"][0]["points_to"].startswith("0x15"))
    arms.append(("ok: the ARM32 libstagefright defines the exported constant and it points at `audio/dsd`",
                 arm32_reads))

    def family_denominator():
        r = report(l32)
        return len(r["family"]) >= 2 and any("BBK_DSD" in f for f in r["family"])

    arms.append(("ok: the leg prints the neighbouring MEDIA_MIMETYPE_AUDIO_* constants it also sees "
                 "(so `only one DSD constant` is measured, not assumed)", family_denominator))

    def absent_symbol_refuses():
        b = bytearray(open(l32, "rb").read())
        d, secs, cls, ent = elf(l32)[:4]
        st = secs[".dynstr"]
        i = bytes(d[st["off"]:st["off"] + st["size"]]).find(SYM.encode())
        if i < 0:
            sys.exit("gate: the symbol name is not in .dynstr -- the fixture has nothing to erase")
        pos = st["off"] + i
        for k in range(len(SYM)):
            b[pos + k] = ord("x")
        tmp = l32 + ".renamed.tmp"
        open(tmp, "wb").write(bytes(b))
        try:
            report(tmp)
            return False
        except SystemExit as e:
            return "no symbol containing" in str(e)
        finally:
            os.remove(tmp)

    arms.append(("gate: renaming the constant out of .dynstr makes the leg REFUSE, not report `absent "
                 "so no DSD`", absent_symbol_refuses))

    def broken_pointer_refuses():
        b = bytearray(open(l32, "rb").read())
        d, secs, cls, ent = elf(l32)[:4]
        x = next(y for y in symbols(d, secs, ent) if SYM in y["name"] and y["typ"] == 1)
        sn, _ = read_at(secs, x["value"], 4, d)
        s = secs[sn]
        struct.pack_into("<I", b, s["off"] + x["value"] - s["addr"], 0xFFFFFFF0)
        tmp = l32 + ".badptr.tmp"
        open(tmp, "wb").write(bytes(b))
        try:
            report(tmp)
            return False
        except SystemExit as e:
            return "not inside any loaded section" in str(e)
        finally:
            os.remove(tmp)

    arms.append(("gate: point the constant at an address that is not in the image and the leg refuses "
                 "instead of printing an empty string", broken_pointer_refuses))

    if os.path.exists(l64):
        def arm64_boundary():
            r = report(l64)
            h = r["hits"][0]
            return (r["class"] == 2 and r["packed_relocs"] and h.get("status") == "relocation-filled"
                    and h["size"] == 8 and r["literal_present"] is True)

        arms.append(("ok: the SAME leg on the 64-bit libstagefright finds the symbol (8-byte OBJECT) and "
                     "says plainly that its pointer is filled at load time by PACKED Android "
                     "relocations (SHT_ANDROID_RELA) -- it claims the literal census, not a read string",
                     arm64_boundary))

        def erased_literal_is_caught():
            b = bytearray(open(l64, "rb").read())
            n = b.count(EXPECT + b"\x00")
            if not n:
                sys.exit("gate: the 64-bit file has no `audio/dsd` literal to erase")
            start = 0
            for _ in range(n):
                i = b.find(EXPECT + b"\x00", start)
                b[i:i + len(EXPECT)] = bytearray(len(EXPECT))
                start = i + 1
            tmp = l64 + ".nolit.tmp"
            open(tmp, "wb").write(bytes(b))
            try:
                r = report(tmp)
                return r["literal_present"] is False and r["packed_relocs"]
            finally:
                os.remove(tmp)

        arms.append(("gate: erase the literal from the 64-bit file and `literal_present` must go False -- "
                     "otherwise `relocation-filled` would silently read as `the string is there`",
                     erased_literal_is_caught))
    else:
        arms.append(("gate: the 64-bit sample is not staged at %s -- this arm must be RED, not skipped"
                     % l64, lambda: False))

    def every_hit_is_explicit():
        r32, r64 = report(l32), (report(l64) if os.path.exists(l64) else {"hits": []})
        return (all(h["string"] for h in r32["hits"])
                and all(h.get("string") or h.get("status") == "relocation-filled" for h in r64["hits"]))

    arms.append(("gate: every hit carries either a non-empty string or the explicit "
                 "`relocation-filled` status -- an empty read is never an answer", every_hit_is_explicit))
    bad = 0
    for label, fn in arms:
        try:
            ok = bool(fn())
        except SystemExit as e:
            ok = label.startswith("gate:") and ("gate:" in str(e))
        print(("ok   " if ok else "FAIL ") + label)
        bad += 0 if ok else 1
    print("selftest: %d arm(s) failed" % bad)
    return 1 if bad else 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--elf", action="append", default=None)
    ap.add_argument("--symbol", default=SYM)
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        sys.exit(selftest())
    repo = os.environ.get("AUDIO_PORT_ROOT") or "/home/v/.local/project/xplay6"
    paths = a.elf or [f"{repo}/art/audio-6.0.1/shipped/system/lib/libstagefright.so",
                      f"{repo}/art/audio-6.0.1/shipped/system/lib64/libstagefright.so"]
    for p in paths:
        if not os.path.exists(p):
            print("%s: ABSENT on disk -- this row can only be judged against a file that exists" % p)
            continue
        r = report(p, a.symbol)
        print("%s (ELF%d)  MEDIA_MIMETYPE_AUDIO_* constants seen: %d" % (p, r["class"], len(r["family"])))
        for h in r["hits"]:
            if h.get("status") == "relocation-filled":
                print("   %-52s @%s size=%d -- pointer is filled at load time by PACKED Android "
                      "relocations; literal `audio/dsd` present in this file: %s"
                      % (h["symbol"][-52:], h["addr"], h["size"], r["literal_present"]))
                continue
            print("   %-52s @%s size=%d bind=%d -> %s in %s = %r"
                  % (h["symbol"][-52:], h["addr"], h["size"], h["bind"], h["points_to"],
                     h["section"], h["string"]))
        for imp in r["imports"]:
            print("   %-52s UNDEFINED here -- this library only IMPORTS the constant" % imp["symbol"][-52:])
        if not r["hits"]:
            print("   symbol name present but no OBJECT entry under it -- the leg reports that as a "
                  "boundary, not as `no DSD`")


main() if __name__ == "__main__" else None
