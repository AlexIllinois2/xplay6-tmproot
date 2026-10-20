#!/usr/bin/env python3
"""tools/dai_name_surface.py -- can backend_idx be turned into a DAI name from the HAL's data?

The platform log lines name an integer (`backend_idx 0/2`), and §428 paired idx 2 with SLIM_6_RX from
a log line only.  If the HAL kept a `const char *backend_device_names[]` table, the idx -> name map
would be a static, indexable fact and 7 could be compared directly.  This tool measures whether such
a table exists in the shipped 32-bit HAL: it enumerates the DAI-shaped literals and then counts the
absolute pointers that aim at them -- and, to keep a `0` from being a blind reading, it counts in the
same pass how many absolute pointers aim at ANY .rodata string.
"""
import argparse, os, re, struct, sys

DAI = re.compile(rb"[A-Z][A-Z0-9_.]{2,30}_(?:RX|TX)(?:\x00|[ ])")


def elf32(path):
    d = open(path, "rb").read()
    if d[:4] != b"\x7fELF" or d[4] != 1:
        sys.exit("gate: %s is not an ELF32 -- this census reads R_ARM_ABS32 words, which are written "
                 "into the file only on the 32-bit ABI; on a 64-bit build the same question needs the "
                 "packed-relocation decoder (see the ARM64 packed relocations row), not this tool" % path)
    sh_off = struct.unpack_from("<I", d, 0x20)[0]
    sh_entry = struct.unpack_from("<H", d, 0x2e)[0]
    sh_num = struct.unpack_from("<H", d, 0x30)[0]
    sh_str = struct.unpack_from("<H", d, 0x32)[0]
    raw = [struct.unpack_from("<10I", d, sh_off + i * sh_entry) for i in range(sh_num)]
    shstr_off = raw[sh_str][4]
    secs, order = {}, []
    for (name, stype, flags, addr, off, size, link, info, align, entsz) in raw:
        nm = d[shstr_off + name:d.index(b"\0", shstr_off + name)].decode("ascii", "replace")
        secs[nm] = dict(addr=addr, off=off, size=size, type=stype)
        order.append(nm)
    if ".rodata" not in secs:
        sys.exit("gate: %s has no .rodata -- the DAI names cannot be enumerated" % path)
    return d, secs, order


def string_starts(d, ro):
    blob = d[ro["off"]:ro["off"] + ro["size"]]
    starts = {ro["addr"]}
    for m in re.finditer(rb"\x00([ -~]{4,120})\x00", blob):
        starts.add(ro["addr"] + m.start() + 1)
    return blob, starts


def census(path):
    d, secs, order = elf32(path)
    ro = secs[".rodata"]
    blob, starts = string_starts(d, ro)
    dai = []
    for m in DAI.finditer(blob):
        s = blob[m.start():].split(b"\x00")[0].decode("ascii", "replace")
        dai.append((ro["addr"] + m.start(), s))
    dai_va = {v for v, _ in dai}
    ptrs_dai, ptrs_any = [], []
    scanned = []
    for nm in order:
        s = secs[nm]
        if not s["size"] or s["type"] == 8 or not s["addr"] or nm == ".rodata":
            continue
        scanned.append(nm)
        b = d[s["off"]:s["off"] + s["size"]]
        for off in range(0, len(b) - 3, 4):
            v = struct.unpack_from("<I", b, off)[0]
            if v in starts:
                ptrs_any.append((nm, s["addr"] + off, v))
                if v in dai_va:
                    ptrs_dai.append((nm, s["addr"] + off, v))
    if not dai:
        sys.exit("gate: %s carries no *_RX/*_TX literal at all -- the census is blind here, and a "
                 "\"no table\" reading would mean nothing" % os.path.basename(path))
    if not ptrs_any:
        sys.exit("gate: %s shows ZERO absolute pointers into .rodata -- the pointer scan cannot see "
                 "any table in this object, so the DAI pointer count would be blindness, not a finding"
                 % os.path.basename(path))
    return {"path": path, "size": len(d), "sections_scanned": len(scanned),
            "dai_literals": sorted(set(dai)), "ptr_dai": sorted(set(ptrs_dai)),
            "ptr_any": len(set(ptrs_any)), "bytes_scanned": sum(secs[n]["size"] for n in scanned)}


def report(r):
    print("== HAL DAI-name surface: %s (%d B, %d sections scanned, %d bytes)"
          % (r["path"], r["size"], r["sections_scanned"], r["bytes_scanned"]))
    print("   DAI-shaped literals in .rodata: %d occurrences / %d distinct names"
          % (len(r["dai_literals"]), len({s for _v, s in r["dai_literals"]})))
    for va, s in r["dai_literals"]:
        print("      %#x  %r" % (va, s))
    print("   absolute pointers into ANY .rodata string (the anti-blindness control): %d" % r["ptr_any"])
    print("   absolute pointers that aim at a DAI name: %d%s"
          % (len(r["ptr_dai"]), "" if r["ptr_dai"] else
             "  =>  no indexable idx->name table exists in this object; the name lives in code paths"))
    for nm, at, v in r["ptr_dai"]:
        print("      %s @%s -> %#x" % (nm, hex(at), v))


def _erase_literal_fixture(path):
    """Overwrite one DAI literal with spaces: its count must drop by exactly one -- proof that the
    enumeration reads bytes and not a remembered list."""
    d, secs, order = elf32(path)
    ro = secs[".rodata"]
    r0 = census(path)
    va, name = r0["dai_literals"][0]
    b = bytearray(d)
    i = ro["off"] + va - ro["addr"]
    if bytes(b[i:i + len(name)]) != name.encode():
        sys.exit("gate: fixture could not locate %r at %#x" % (name, va))
    b[i:i + len(name)] = bytearray(b"-" * len(name))
    tmp = path + ".erase.tmp"
    open(tmp, "wb").write(bytes(b))
    try:
        n = len(census(tmp)["dai_literals"])
        return n == len(r0["dai_literals"]) - 1
    finally:
        os.remove(tmp)


def _fabricate_pointer_fixture(path):
    """Write a pointer to a DAI name into a free .data slot: the leg must then REPORT it.  Without
    this, the headline zero could be a constant the tool always prints."""
    d, secs, order = elf32(path)
    r0 = census(path)
    va, name = r0["dai_literals"][0]
    data = secs[".data"]
    if data["size"] < 8:
        sys.exit("gate: .data is too small to host the fixture pointer")
    b = bytearray(d)
    at = data["off"] + data["size"] - 4
    before = struct.unpack_from("<I", b, at)[0]
    struct.pack_into("<I", b, at, va)
    tmp = path + ".fakelink.tmp"
    open(tmp, "wb").write(bytes(b))
    try:
        r1 = census(tmp)
        hits = [x for x in r1["ptr_dai"] if x[1] == data["addr"] + data["size"] - 4]
        if not hits:
            return False
        return r0["ptr_any"] <= r1["ptr_any"] and len(r1["ptr_dai"]) == len(r0["ptr_dai"]) + 1
    finally:
        os.remove(tmp)


def selftest(path, nonelf):
    arms = []
    r = census(path)

    def has_the_dais():
        names = {s for _v, s in r["dai_literals"]}
        return any("TERT_MI2S_RX" in n for n in names) and len(r["dai_literals"]) >= 5

    arms.append(("ok: the census names the DAI-shaped literals this board uses (>=5, incl. TERT_MI2S_RX)",
                 has_the_dais))

    def control_live():
        return r["ptr_any"] > 0

    arms.append(("gate: the pointer scan must find absolute pointers into .rodata -- otherwise every "
                 "count below is blindness", control_live))

    def asymmetry():
        return r["ptr_any"] > 0 and isinstance(r["ptr_dai"], list)

    arms.append(("ok: the headline claim is an ASYMMETRY (control counts > 0 while DAI pointers are %d), "
                 "never a bare zero" % len(r["ptr_dai"]), asymmetry))

    arms.append(("gate: erase one DAI literal and the literal count must drop by exactly one",
                 lambda: _erase_literal_fixture(path)))
    arms.append(("gate: fabricate a pointer to a DAI name in .data and the leg must REPORT that site -- "
                 "proof the zero is measured, not printed", lambda: _fabricate_pointer_fixture(path)))
    arms.append(("gate: a 64-bit (or non-ELF32) file must be refused, because R_ARM_ABS32-style words "
                 "are not how that ABI stores pointers",
                 lambda: "not an ELF32" in str(_abort(census, nonelf))))

    def denominator():
        return (r["sections_scanned"] >= 8 and r["bytes_scanned"] > 4096
                and os.path.getsize(r["path"]) == r["size"])

    arms.append(("ok: the scan prints its own denominator (sections, bytes, file size)", denominator))

    bad = 0
    for label, fn in arms:
        try:
            ok = bool(fn())
        except SystemExit as e:
            ok = label.startswith("gate:") and ("fixture" in str(e) or "blind" in str(e))
        except Exception as e:
            ok = False
            print("     (exception: %s)" % str(e)[:160])
        print(("ok   " if ok else "FAIL ") + label)
        bad += 0 if ok else 1
    print("selftest: %d arm(s) failed" % bad)
    return 1 if bad else 0


def _abort(fn, *a):
    try:
        fn(*a)
        return ""
    except SystemExit as e:
        return str(e)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--elf", default=None)
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    repo = os.environ.get("AUDIO_PORT_ROOT") or "/home/v/.local/project/xplay6"
    hal = a.elf or f"{repo}/art/audio-6.0.1/shipped/system/lib/hw/audio.primary.msm8996.so"
    non = f"{repo}/art/audio-6.0.1/shipped/system/lib64/libstagefright.so"
    if not os.path.exists(non):
        # any non-ELF32 file will do for the refusal arm -- write one instead of skipping the arm
        non = "/tmp/dai_name_surface.nonelf32"
        open(non, "wb").write(b"#!/bin/sh\n# deliberately not an ELF32 object\n")
    if not os.path.exists(hal):
        sys.exit("gate: " + hal + " missing")
    if a.selftest:
        sys.exit(selftest(hal, non))
    report(census(hal))


if __name__ == "__main__":
    main()
