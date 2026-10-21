#!/usr/bin/env python3
"""tools/acdb_selectors.py -- which binaries on this firmware can choose the ACDB calibration set?

The port needs exactly one answer to "does anything besides libacdbloader.so pick a directory":
if a second chooser exists on 7, the dir gate of ledger 273 covers only half the machine. The scan
is a string census over the shipped binaries (no disassembly needed to LOCATE candidates) plus the
two code facts that decide whether a hit is a real chooser:

  * a binary that carries the directory strings ('/etc/acdbdata', 'hw_platform', calfile) picks it
  * a binary that only carries 'acdb_loader_init_ACDB' does NOT pick it independently -- in
    libacdbloader.so that symbol is a 16-byte wrapper (mov x0,#0 x3 + b acdb_loader_init_v2), so
    FTM lands in the same cascade (ledger 274)

Usage: tools/acdb_selectors.py <shipped-root> [-o out.tsv] [--entry-size ADDR NAME]
Exit != 0 when no binary carries the directory strings (that would mean the baseline reading is
wrong, not that the machine is clean).
"""
import argparse
import os
import sys

PAT = {
    # a chooser needs BOTH: somewhere to look (acdbdata) and the cascade inputs that name the
    # subdirectory. Counting them together would call the HAL a chooser for reading a model prop.
    "base_dir": (b"acdbdata",),
    "cascade_inputs": (b"hw_platform", b"persist.audio.calfile"),
    "loader_entry": (b"acdb_loader_init_v2", b"acdb_loader_init_ACDB"),
    # the delta channel is the two ACDB-specific names; /data/misc/audio/ on its own is only
    # a scratch dir (the HAL writes ssr pcm dumps there), so it must not print as "delta"
    "delta_path": (b"acdbdata_ioctl", b".acdbdelta"),
    "scratch": (b"/data/misc/audio/",),
}


def census(b):
    return {k: sum(b.count(p) for p in ps) for k, ps in PAT.items()}


def wrapper_check(path, name):
    """size of a named function, read out of .dynsym via tools/so_xref.py's own parser -- reused on
    purpose: a second hand-rolled ELF walk here would be a second implementation to drift"""
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import so_xref
    _b, _l, syms, _t, _p, _s, _pr, _rc = so_xref.parse(path)
    for _v, sz, nm in syms:
        if nm == name:
            return sz
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("root")
    ap.add_argument("-o", "--out", default=None)
    ap.add_argument("--selftest", action="store_true",
                    help="the census must find the known chooser in the known file, or a clean "
                         "answer means nothing")
    args = ap.parse_args()

    rows = []
    scanned = 0
    for dp, _dn, fn in os.walk(args.root):
        for f in sorted(fn):
            if ".so" not in f:
                continue
            p = os.path.join(dp, f)
            scanned += 1
            try:
                b = open(p, "rb").read()
            except OSError:
                continue
            c = census(b)
            if any(c.values()):
                rows.append((p, c))
    if not rows:
        sys.exit(f"gate: {scanned} shared objects scanned, NONE carries an ACDB selection string -- "
                 f"that contradicts §273, so treat this as a broken scan, not as a clean machine")
    chooser = [r for r in rows if r[1]["base_dir"] and r[1]["cascade_inputs"]]
    caller = [r for r in rows if r[1]["loader_entry"]]
    delta = [r for r in rows if r[1]["delta_path"]]
    cols = ["binary", "base_dir", "cascade_inputs", "loader_entry", "delta_path", "scratch", "verdict"]
    lines = ["\t".join(cols)]
    for p, c in sorted(rows):
        v = []
        if c["base_dir"] and c["cascade_inputs"]:
            v.append("CHOSES the directory")
        elif c["base_dir"]:
            v.append("mentions acdbdata only (path/list, not a chooser)")
        if c["loader_entry"]:
            v.append("references loader entry points")
        if c["delta_path"]:
            v.append("WRITES the /data delta overlay")
        elif c["scratch"]:
            v.append("uses /data/misc/audio for other dumps")
        lines.append("\t".join([p, str(c["base_dir"]), str(c["cascade_inputs"]),
                                str(c["loader_entry"]), str(c["delta_path"]), str(c["scratch"]),
                                "+".join(v)]))
    out = args.out or os.path.join(os.path.dirname(args.root.rstrip("/")), "acdb-selectors.tsv")
    with open(out, "w") as f:
        f.write("\n".join(lines) + "\n")
    sz = wrapper_check(os.path.join(args.root, "vendor/lib64/libacdbloader.so"), "acdb_loader_init_ACDB")
    print(f"scanned {scanned} shared objects under {args.root}: {len(chooser)} choose the directory, "
          f"{len(caller)} reference the loader entry points, {len(delta)} touch the delta path, "
          f"{len(rows)} files with any signal")
    for ln in lines[1:]:
        p, a, b_, c_, d_, sc, v = ln.split("\t")
        print(f"   {p.replace(args.root + '/', ''):52s} base={a:>2} cascade={b_:>2} "
              f"entry={c_:>2} delta={d_:>2} scratch={sc:>2}  {v}")
    print(f"acdb_loader_init_ACDB size in libacdbloader.so = {sz} bytes "
          f"({'wrapper -> the same cascade' if sz and sz <= 16 else 'NOT a wrapper -- read it'})")
    if args.selftest:
        want = [r for r in chooser if r[0].endswith("libacdbloader.so")]
        if not want:
            sys.exit("selftest FAIL: the known chooser was not recognised as one -- every zero here is unknown")
        print("selftest PASS: libacdbloader.so is classified as the directory chooser")
    # two copies of the SAME library (vendor/lib and vendor/lib64) are one chooser, not two --
    # but a chooser with a different BASENAME is, so de-duplicate only by file name
    names = sorted({r[0].rsplit("/", 1)[-1] for r in chooser})
    if len(chooser) != 1:
        print(f"  NOTE: {len(chooser)} copies qualify as choosers across {len(names)} distinct "
              f"library name(s) ({', '.join(names)}) -- copies of one library are one selector; "
              f"any ADDITIONAL distinct name would mean §273's cascade is not the whole story")
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
