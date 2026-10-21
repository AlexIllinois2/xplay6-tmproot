#!/usr/bin/env python3
"""tools/acdb_landing.py -- ONE implementation of libacdbloader's directory cascade.

Both device gates need the answer to "which directory is this machine actually loading?":
port_check.sh dir uses it as the verdict, and port_check.sh acdb uses it to decide WHICH files'
bytes to compare against the baseline (comparing "any directory on the machine" instead of the
landing directory is the semantics boundary recorded in ledger 274). Two copies of this ordering
would drift, so it lives here and both gates import it.

The rule, from the disassembly in ledger 273: base is the loader's own string "/etc/acdbdata/",
then property values in the order ro.vivo.product.model -> ro.vivo.product.platform -> the sysfs
hw_platform node, each gated by access(dir, F_OK); the first that exists wins.

Usage:
  tools/acdb_landing.py <capture-file>              # print the landing directory
  python3 -c "import acdb_landing; acdb_landing.landing(text)"   # from the gates
"""
import os
import re
import sys

BASES = ("/etc/acdbdata", "/system/etc/acdbdata", "/vendor/etc/acdbdata")


def parse_capture(text):
    m = re.search(r"ACDBDIR inputs model=(\S*) platform=(\S*) hw_platform=(\S*) node=(\S+)"
                  r"(?: device=(\S*))?(?: etcroot=(\S*))?", text)
    if not m:
        sys.exit("gate: capture has no 'ACDBDIR inputs' line -- the capture is not from acdbdir.sh")
    return {"inputs": [("ro.vivo.product.model", m.group(1)),
                       ("ro.vivo.product.platform", m.group(2)),
                       (m.group(4), m.group(3))],
            "device": m.group(5),
            "etcroot": m.group(6) or None,
            "cands": re.findall(r"ACDBDIR exists (\S+) acdb=(\d+) src=(\S+)", text),
            "calfiles": re.findall(r"ACDBDIR (calfile\d+)=(\S+)", text)}


def resolve(path, etcroot):
    """/etc is a symlink, so the loader's path and the path md5sum prints differ for the SAME dir"""
    if etcroot and path.startswith("/etc/"):
        return etcroot + path[len("/etc"):]
    return path


def landing(text):
    """returns dict(inputs, base, chosen, chosen_real, cascade) -- chosen is (path, count, src)
    in the loader's own order; chosen_real is the same directory as other tools will name it"""
    p = parse_capture(text)
    cands, etcroot = p["cands"], p["etcroot"]
    cascade = {base: [c for c in cands if c[0].startswith(base + "/")] for base in BASES}
    # /system/etc/acdbdata is not a second root when /etc IS /system/etc -- that is the same
    # directory, and reporting it as a rival root would scare a port for nothing
    equivalent = {"/etc"}
    if etcroot:
        equivalent.add(etcroot.rstrip("/"))
    for base in BASES:
        if cascade.get(base):
            path = cascade[base][0][0]
            seen, cas2 = {}, {}
            for b, l in cascade.items():
                rb = resolve(b, etcroot)
                if rb in seen:
                    continue
                seen[rb] = b
                cas2[b] = l
            return {"inputs": p["inputs"], "calfiles": p["calfiles"], "device": p["device"],
                    "etcroot": etcroot, "base": base, "chosen": cascade[base][0],
                    "chosen_real": resolve(path, etcroot), "cascade": cas2}
    return {"inputs": p["inputs"], "calfiles": p["calfiles"], "device": p["device"],
            "etcroot": etcroot, "base": None, "chosen": None, "chosen_real": None,
            "cascade": cascade}


def dir_variants(text, name):
    """every capture path whose directory is called `name`, grouped by root -- on 7 the same name can
    exist under both /system and /vendor with DIFFERENT bytes, which no 'any directory matches' check
    can see; that is a distinct answer from OK and must not be collapsed into it"""
    out = {}
    for path, _n, _src in re.findall(r"ACDBDIR exists (\S+) acdb=(\d+) src=(\S+)", text):
        if path.rstrip("/").split("/")[-1] == name:
            out.setdefault("/".join(path.rstrip("/").split("/")[:-1]), set()).add(path)
    return out


def verify(md5_text, meta_rows, capture_text):
    """the content check scoped to WHERE THE LOADER ACTUALLY LANDS (ledger 274's boundary):
    every baseline file must be present in the landing directory with the same bytes, nothing extra
    may sit there, and a same-named directory under a different root is reported separately because
    'some copy matches' is not the same claim as 'the copy in use matches'.
    meta_rows: {basename: md5}. returns (rc, lines)."""
    r = landing(capture_text)
    out = []
    if r["chosen"] is None:
        return 1, ["FAIL: no landing directory in the capture -- nothing can be compared"]
    path, n, src = r["chosen"]
    real = r["chosen_real"]
    live = {}
    for ln in md5_text.splitlines():
        m = re.match(r"^([0-9a-f]{32}) +(/\S+)$", ln.strip())
        if m:
            live.setdefault(os.path.dirname(m.group(2)), {})[os.path.basename(m.group(2))] = m.group(1)
    mine = live.get(real) or live.get(path)
    out.append(f"landing={path} resolved={real} files-here={0 if mine is None else len(mine)} "
               f"matched-via={src}")
    if mine is None:
        out.append(f"FAIL: the md5 capture contains no files under {real} -- the two captures are "
                   f"not from one run, or the glob in port_check.sh missed this root")
        return 1, out
    rc = 0
    for name in sorted(meta_rows):
        if name not in mine:
            out.append(f"  ABSENT  {name} is not in the landing directory")
            rc = 1
        elif mine[name] != meta_rows[name]:
            out.append(f"  CORRUPT {name} md5={mine[name][:12]} baseline={meta_rows[name][:12]} "
                       f"-- the copy IN USE differs from 6.0.1")
            rc = 1
        else:
            out.append(f"  in use  {name} md5={mine[name][:12]} identical")
    extra = sorted(set(mine) - set(meta_rows))
    if extra:
        out.append(f"  EXTRA   {', '.join(extra)} sit in the landing directory -- the loader globs "
                   f"*.acdb, so these get loaded too (cap 20)")
        rc = 1
    if int(n) != len(mine):
        out.append(f"  COUNT   capture said {n} but the md5 list has {len(mine)} under this dir -- "
                   f"one of the two probes is stale")
        rc = 1
    others = [d for d in live if d != real and os.path.basename(d) == os.path.basename(real)]
    for od in others:
        other = live[od]           # careful: `set(od)` would be the set of CHARACTERS of the path,
        diff = sorted(k for k in set(meta_rows) & set(other)   # which intersects with nothing and
                  if other[k] != meta_rows[k])                 # makes every rival look identical
        out.append(f"  RIVAL   same-named directory at {od}: "
                   + (f"{len(diff)} file(s) differ from the baseline ({', '.join(diff[:3])}) -- "
                      f"the loader would not see them, but a port that changes the base string would"
                      if diff else "identical to the baseline too"))
    return rc, out


def main():
    if "--verify" in sys.argv:
        import csv
        i = sys.argv.index("--verify")
        _md5f, metaf, capf = sys.argv[i + 1:i + 4]
        txt = open(_md5f, encoding="utf-8", errors="replace").read()
        meta = {r["file"]: r["md5"] for r in csv.DictReader(open(metaf), delimiter="\t")
                if r["dir"] == "PD1610"}
        if not meta:
            sys.exit("gate: meta table has no PD1610 rows -- the baseline denominator is empty")
        rc, lines = verify(txt, meta, open(capf, encoding="utf-8", errors="replace").read())
        print("\n".join(lines))
        print(f"verify rc={rc} over {len(meta)} baseline files")
        return rc
    if len(sys.argv) < 2:
        sys.exit("usage: tools/acdb_landing.py <capture-file> | --verify <md5-capture> <meta.tsv> <capture>")
    text = open(sys.argv[1], encoding="utf-8", errors="replace").read()
    r = landing(text)
    if r["chosen"] is None:
        print("NO-LANDING: the cascade found no directory under " + " or ".join(BASES))
        return 1
    path, n, src = r["chosen"]
    print(f"landing={path} resolved={r['chosen_real']} count={n} matched-via={src} base={r['base']}")
    for k, v in r["inputs"]:
        print(f"   input {k} = {v!r}")
    for b, lst in sorted(r["cascade"].items()):
        if b != r["base"] and lst:
            print(f"   NOTE: {b} also has candidates {[c[0] for c in lst]} -- a second root the "
                  f"loader does not use but a port might")
    return 0


if __name__ == "__main__":
    sys.exit(main())
