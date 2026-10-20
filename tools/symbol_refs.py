#!/usr/bin/env python3
"""tools/symbol_refs.py -- who defines and who imports a symbol, across the carried corpus.

Needed because §E asked "who calls `AVNuFactory::createNuPlayer(int)`?" and the answer must be
re-derivable on 7 rather than remembered.  A mangled C++ symbol has to appear as a string in any
binary that references it, so scanning file bytes for the name IS a sound reachability test for
these symbols -- with the limits this tool prints: it says nothing about `dlopen`+`dlsym` by
computed name, and it only covers the files you point it at.
"""
import argparse, os, re, struct, sys


def elf_is64(path):
    with open(path, "rb") as f:
        h = f.read(20)
    return h[:4] == b"\x7fELF" and (64 if h[4] == 2 else 32 if h[4] == 1 else None)


def dynsym_names(path):
    """The exported (defined) names of an ELF: .dynsym entries with st_shndx != SHN_UNDEF."""
    try:
        with open(path, "rb") as f:
            d = f.read()
        if d[:4] != b"\x7fELF" or d[4] not in (1, 2):
            return None
        if d[4] == 2:
            sh = struct.unpack_from("<Q", d, 0x28)[0]
            es = struct.unpack_from("<H", d, 0x3a)[0]
            num = struct.unpack_from("<H", d, 0x3c)[0]
            rec = [struct.unpack_from("<IIQQQQIIQQ", d, sh + i * es) for i in range(num)]
        else:
            sh = struct.unpack_from("<I", d, 0x20)[0]
            es = struct.unpack_from("<H", d, 0x2e)[0]
            num = struct.unpack_from("<H", d, 0x30)[0]
            rec = [struct.unpack_from("<10I", d, sh + i * es) for i in range(num)]
        symtab = next((r for r in rec if r[1] == 11), None)
        if not symtab:
            return None
        strtab = rec[symtab[6]]
        sb = d[strtab[4]:strtab[4] + strtab[5]]
        entsz = symtab[8] or (24 if d[4] == 2 else 16)
        out = set()
        for i in range(symtab[5] // entsz):
            if d[4] == 2:
                name, info, other, shndx = struct.unpack_from("<IBBH", d, symtab[4] + i * entsz)
            else:
                name, _v, _s, info, other, shndx = struct.unpack_from("<IIIBBH", d,
                                                                      symtab[4] + i * entsz)
            if shndx == 0:
                continue                      # undefined: imported here, defined elsewhere
            try:
                out.add(sb[name:sb.index(b"\0", name)].decode("ascii", "replace"))
            except ValueError:
                pass
        return out
    except Exception:
        return None


def files_under(roots):
    out = []
    for root in roots:
        if os.path.isfile(root):
            out.append(root)
            continue
        for dp, dn, fn in os.walk(root):
            for f in fn:
                p = os.path.join(dp, f)
                if os.path.isfile(p) and os.path.getsize(p) < 80 * 1024 * 1024:
                    out.append(p)
    return sorted(set(out))


def survey(roots, symbol):
    files = files_under(roots)
    needle = symbol.encode()
    definers, importers, unreadable = [], [], []
    for p in files:
        try:
            b = open(p, "rb").read()
        except Exception:
            unreadable.append(p)
            continue
        if needle not in b:
            continue
        names = dynsym_names(p)
        if names is None:
            # not an ELF we can parse (odex/apk/binaries of another format): the name is there,
            # the role is unknown -- reported as "text hit", never as a reference
            importers.append((p, "text-hit (no parseable .dynsym)", b.count(needle)))
            continue
        if symbol in names:
            definers.append((p, "defines", b.count(needle)))
        else:
            importers.append((p, "names-it-without-defining", b.count(needle)))
    if not definers and not importers:
        sys.exit("gate: %r appears in NONE of the %d scanned files -- that is a negative about this "
                 "file set only; point --root at 7's own tree before concluding 'nobody calls it'"
                 % (symbol, len(files)))
    return {"symbol": symbol, "files_scanned": len(files), "definers": definers,
            "importers": importers, "unreadable": unreadable}


def selftest(roots):
    sym = "_ZN7android11AVNuFactory14createNuPlayerEi"
    arms = [
        ("ok: the factory symbol's only carrier in the corpus is the player service that defines it",
         lambda: (lambda r: len(r["definers"]) == 1 and not r["importers"]
                  and "libmediaplayerservice" in r["definers"][0][0])(survey(roots, sym))),
        ("ok: a libc symbol the player service really imports must show up as a non-definer carrier "
         "(the ruler can see an import edge, so the empty result above is not blindness)",
         lambda: (lambda r: len(r["importers"]) >= 1)(survey(roots, "strcasecmp"))),
        ("gate: an absent symbol is refused as a finding, not reported as 'nobody calls it'",
         lambda: "gate:" in _abort(survey, roots, "_ZN7android33NoSuchSymbolAnywhereOnDeviceEv")),
        ("ok: the denominator is printed with the result",
         lambda: (lambda r: r["files_scanned"] > 100)(survey(roots, sym))),
    ]
    bad = 0
    for label, fn in arms:
        try:
            ok = bool(fn())
        except SystemExit as e:
            ok = "gate:" in label and "none of" in str(e).lower()
        except Exception as e:
            ok = False
            print("     (exception: %s)" % str(e)[:150])
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
    ap.add_argument("--root", action="append", default=[],
                    help="directory or file to scan (repeatable); default: the carried shipped tree")
    ap.add_argument("--symbol", default="_ZN7android11AVNuFactory14createNuPlayerEi")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    repo = os.environ.get("AUDIO_PORT_ROOT") or "/home/v/.local/project/xplay6"
    roots = a.root or [f"{repo}/art/audio-6.0.1/shipped"]
    if a.selftest:
        sys.exit(selftest(roots))
    r = survey(roots, a.symbol)
    print("== %s" % r["symbol"])
    print("   scanned %d file(s) under %s" % (r["files_scanned"], "・".join(roots)))
    for p, how, n in r["definers"]:
        print("   DEFINES   %-70s %d occurrence(s)" % (p, n))
    for p, how, n in r["importers"]:
        print("   %-12s %-70s %d occurrence(s)" % (how[:12], p, n))
    if r["unreadable"]:
        print("   unreadable: %d" % len(r["unreadable"]))
    print("   boundary: covers only the paths given; dlopen+dlsym with a computed name would not "
          "appear as bytes; on 7 pass --root <7 tree> (and sweep the device's own lib dirs too)")


if __name__ == "__main__":
    main()
