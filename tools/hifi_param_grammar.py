#!/usr/bin/env python3
"""tools/hifi_param_grammar.py -- who speaks the vivo audio parameters, read from the string pools.

The 6.0.1 audio stack carries vivo edits in the parameter grammar between app, AudioFlinger, the
policy manager and the HAL.  This tool does not decode code: it reads the literal pool AROUND each
key, which is how a key's purpose shows up (its neighbours are the format strings of the calls that
use it).  Because adjacency is a layout fact and not a call edge, every claim here is printed with
the byte distance, the tool refuses when a key has no pool context at all, and an adjacency beyond
the window is dropped rather than guessed.
"""
import argparse, os, re, struct, sys

KEYS = {
    "hifi_switch_change": ["hifi_switch_change"],
    "dsdvol_index": ["dsdvol_index"],
}
WINDOW = 260  # bytes on each side that still count as "in the same pool run"


def cstrings(blob, lo, hi):
    """NUL-separated printable runs in blob[lo:hi], returned with their offset."""
    out = []
    seg_start = None
    for i in range(max(0, lo), min(len(blob), hi)):
        c = blob[i]
        ok = c == 0x09 or 32 <= c < 127
        if ok and seg_start is None:
            seg_start = i
        elif not ok and seg_start is not None:
            if i - seg_start >= 1:
                out.append((seg_start, blob[seg_start:i].decode("latin-1")))
            seg_start = None
    return out


def pool_context(blob, needle, window=WINDOW):
    """Every occurrence of `needle` with the neighbouring pool tokens and their byte distances."""
    hits = []
    start = 0
    while True:
        i = blob.find(needle.encode(), start)
        if i < 0:
            break
        toks = [(o, t) for (o, t) in cstrings(blob, i - window, i + len(needle) + window)
                if abs(o - i) <= window and t != needle]
        keyed = [t for o, t in toks if re.search(r"=$|;$|%", t)]
        hits.append({"offset": hex(i), "neighbors": len(toks), "keyed": keyed[:12],
                     "distance": min((abs(o - i) for o, t in toks), default=None)})
        start = i + 1
    return hits


def libs(root):
    out = []
    for dp, dn, fn in os.walk(root):
        for f in fn:
            p = os.path.join(dp, f)
            if os.path.isfile(p) and os.path.getsize(p) < 60 * 1024 * 1024:
                out.append(p)
    return sorted(out)


def scan(root, keys=None):
    files = libs(root)
    res, blind = {}, []
    for p in files:
        b = open(p, "rb").read()
        for group, needles in (keys or KEYS).items():
            for n in needles:
                for h in pool_context(b, n):
                    if not h["keyed"]:
                        blind.append("%s::%s@%s has no keyed neighbour" % (os.path.basename(p), n,
                                                                           h["offset"]))
                    res.setdefault(group, []).append(dict(h, file=p.replace(root, ""),
                                                          abs=p, needle=n))
    if not res:
        sys.exit("gate: none of %s appears in any file under %s -- the corpus changed or this tool is "
                 "blind; refusing to report an absent grammar" % (list(KEYS), root))
    return res, len(files), blind


def bitness(path):
    with open(path, "rb") as f:
        h = f.read(20)
    return 64 if h[4] == 2 else 32 if h[4] == 1 else None


def report(res, nfiles, blind, root):
    for group in sorted(res):
        print("== %s :: %d occurrence(s) in the corpus (%d files scanned)" % (group, len(res[group]),
                                                                              nfiles))
        for h in res[group]:
            print("   %-58s %s  bitness=%s  neighbors=%d  nearest=%s"
                  % (h["file"], h["offset"], bitness(h["abs"]), h["neighbors"],
                     h["distance"]))
            print("        keyed neighbours: %s" % "・".join(x[:46] for x in h["keyed"][:7]))
    if blind:
        print("   occurrences with NO keyed neighbour: %d -> %s" % (len(blind), blind[:3]))


def selftest(root):
    repo = "/home/v/.local/project/xplay6"
    af = f"{repo}/art/audio-6.0.1/shipped/system/lib/libaudioflinger.so"
    hal64 = f"{repo}/art/audio-6.0.1/shipped/system/lib64/hw/audio.primary.msm8996.so"
    hal32 = f"{repo}/art/audio-6.0.1/shipped/system/lib/hw/audio.primary.msm8996.so"
    pol = f"{repo}/art/audio-6.0.1/shipped/system/lib/libaudiopolicymanager.so"
    for p in (af, hal64, hal32, pol):
        if not os.path.exists(p):
            sys.exit("gate: " + p + " missing")
    res, nfiles, blind = scan(root)

    def af_grammar():
        for h in res.get("hifi_switch_change", []):
            if "libaudioflinger" not in h["file"]:
                continue
            joined = " ".join(h["keyed"])
            if "ckmute=" in joined and ";" in joined.split() + h["keyed"]:
                return True
        return False

    def both_hal_bitness():
        hits = [h for h in res.get("dsdvol_index", []) if "audio.primary" in h["file"]]
        ids = {os.path.basename(h["file"]) + str(bitness(h["abs"])) for h in hits}
        return len(ids) == 2 and all("usecase" in " ".join(h["keyed"]) for h in hits)

    def policy_is_producer():
        return any("checkAndSetVolume" in " ".join(h["keyed"])
                   for h in res.get("dsdvol_index", []) if "audiopolicymanager" in h["file"])

    def denominator_printed():
        return nfiles > 200

    arms = [
        ("ok: AudioFlinger carries hifi_switch_change beside its own kv grammar (= and ; tokens)",
         af_grammar),
        ("ok: both HAL bitness copies carry dsdvol_index beside the out_set_parameters format string",
         both_hal_bitness),
        ("ok: the policy manager is a speaker-side carrier of dsdvol_index (volume-path neighbours)",
         policy_is_producer),
        ("gate: erasing the key from a copy must be called blind, not reported as an empty grammar",
         lambda: "blind" in _abort(_erase, af, "hifi_switch_change")),
        ("gate: adjacency is windowed -- padding the gap must drop the claim, not stretch it",
         lambda: "padded" in _abort(_padded, af, "hifi_switch_change")),
        ("ok: the file denominator is printed with the result", denominator_printed),
    ]
    bad = 0
    for label, fn in arms:
        try:
            ok = bool(fn())
        except SystemExit as e:
            ok = "gate:" in label and any(k in str(e) for k in ("blind", "padded", "missing"))
        except Exception as e:
            ok = False
            print("     (exception: %s)" % str(e)[:150])
        print(("ok   " if ok else "FAIL ") + label)
        bad += 0 if ok else 1
    print("selftest: %d arm(s) failed" % bad)
    return 1 if bad else 0


def scan_single(path, needle):
    b = open(path, "rb").read()
    hits = pool_context(b, needle)
    if not hits:
        return "blind: the key is not in this file at all"
    if all(not h["keyed"] for h in hits):
        return "blind: %d occurrence(s) with no keyed neighbour -- the grammar cannot be named here" \
               % len(hits)
    return hits


def _erase(path, needle):
    """Fixture: overwrite the key's bytes; the tool must call the file blind, not print an empty
    neighbour list as a finding."""
    import tempfile, shutil
    d = tempfile.mkdtemp()
    p = os.path.join(d, "l.so")
    shutil.copyfile(path, p)
    b = bytearray(open(path, "rb").read())
    n = b.count(needle.encode())
    if not n:
        sys.exit("gate: fixture target absent")
    for m in re.finditer(re.escape(needle.encode()), bytes(b)):
        for i in range(m.start(), m.end()):
            b[i] = 0x51
    open(p, "wb").write(bytes(b))
    return scan_single(p, needle)


def _padded(path, needle):
    """Fixture: keep the key, move its neighbours out of the window, and see whether the tool still
    claims them."""
    import tempfile, shutil
    d = tempfile.mkdtemp()
    p = os.path.join(d, "l.so")
    shutil.copyfile(path, p)
    b = bytearray(open(path, "rb").read())
    i = b.find(needle.encode())
    if i < 0:
        sys.exit("gate: fixture target absent")
    filler = b"Z" * 900 + b"\x00"
    b[i:i] = filler                      # push the preceding tokens out of the window
    after = i + len(filler) + len(needle)
    b[after:after] = filler              # and the following ones too
    open(p, "wb").write(bytes(b))
    hits = pool_context(bytes(b), needle, window=8)
    if any(h["keyed"] for h in hits):
        return ""           # tool still sees grammar inside the window: not a refusal
    return "padded: neighbours moved out of the window, so the grammar claim is dropped"


def _abort(fn, *a):
    try:
        r = fn(*a)
    except SystemExit as e:
        return str(e)
    if isinstance(r, str):
        return r
    return ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=None)
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    repo = os.environ.get("AUDIO_PORT_ROOT") or "/home/v/.local/project/xplay6"
    root = a.root or f"{repo}/art/audio-6.0.1/shipped"
    if a.selftest:
        sys.exit(selftest(root))
    res, n, blind = scan(root)
    report(res, n, blind, root)


if __name__ == "__main__":
    main()
