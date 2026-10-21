#!/usr/bin/env python3
"""Who is allowed to call the ACDB loader, and with which entry point (ledger 418).

Why this is a layer: the carry list already compares the calibration DATA (the .acdb card, the cal
assets, the 44-slot plan).  This compares the API -- a 7 port can hold a byte-identical ACDB card and
still lose a sub-path, because the caller that used to ask for it (the audio HAL, an effect module,
the sound-trigger HAL) no longer names that entry point.  The ST HAL and libqcbassboost only became
visible after ledger 417 widened the capture denominator, which is the practical reason to keep this
computed from bytes instead of asserted from a note.

Read from the shipped binaries only: an imported/exported name is a NUL-terminated string inside the
ELF, so no objdump/nm dependency and it works for both the 32-bit (loaded) and 64-bit copies.
"""
import argparse, collections, os, re, sys

ROOT = os.environ.get("AUDIO_PORT_ROOT") or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASE = "art/audio-6.0.1"
SYM = re.compile(rb"(acdb_loader_[A-Za-z0-9_]{3,40}|acdb_[A-Za-z0-9_]{4,40}|gsl_[a-z_0-9]{3,40})\x00")
LOADER = "libacdbloader.so"
# positive controls: edges this project established by other means, so the parse cannot be blind
KNOWN_EDGES = {
    "acdb_loader_init_v2": ("audio.primary.msm8996.so",),
    "acdb_loader_send_listen_afe_cal": ("sound_trigger.primary.msm8996.so",),
    "acdb_loader_get_audio_cal_v2": ("libqcbassboost.so",),
}


def held_els(base):
    out = []
    for dirpath, _, files in os.walk(os.path.join(base, "shipped")):
        for f in files:
            p = os.path.join(dirpath, f)
            if os.path.isfile(p) and open(p, "rb").read(4) == b"\x7fELF":
                out.append(p)
    if len(out) < 50:
        sys.exit(f"gate: only {len(out)} ELF files in the extract -- the API surface needs the whole "
                 "shipped set, and 417 established that the audio stack is spread over lib/lib64/vendor")
    return out


def mapped_names(base):
    p = os.path.join(base, "live/maps-mediaserver.txt")
    if not os.path.exists(p):
        sys.exit("gate: " + p + " missing -- whether a caller is LIVE is a live-map fact, not a guess")
    return {os.path.basename(l.strip()) for l in open(p, encoding="utf-8", errors="replace") if l.strip()}


def surface(base):
    by_entry = collections.defaultdict(dict)          # entry -> {binary: set(bitness)}
    files = held_els(base)
    for p in files:
        rel = os.path.relpath(p, os.path.join(base, "shipped"))
        bit = "32" if "/lib/" in "/" + rel else "64"
        blob = open(p, "rb").read()
        for m in set(SYM.findall(blob)):
            by_entry[m.decode()].setdefault(os.path.basename(rel), set()).add(bit)
    if not by_entry:
        sys.exit("gate: no acdb/gsl symbol names found in the extract -- the pattern is blind")
    return by_entry


def classify(by_entry, mapped):
    rows = []
    for entry, bins in sorted(by_entry.items()):
        loader_names = [b for b in bins if b == LOADER]
        callers = sorted(b for b in bins if b != LOADER)
        live = sorted(c for c in callers if c in mapped)
        rows.append({"entry": entry, "n_callers": len(callers),
                     "callers": callers, "live_callers": live,
                     "exported_by_loader": bool(loader_names)})
    return rows


def check(rows, mutate_note=""):
    """The parse must reproduce edges established independently -- otherwise a green table is silence."""
    by_entry = {r["entry"]: r for r in rows}
    for entry, want in KNOWN_EDGES.items():
        if entry not in by_entry:
            sys.exit(f"gate: {entry} is not in the surface at all{mutate_note} -- the loader exports it "
                     "(§392) so the scan is blind, not the machine")
        for w in want:
            if w not in by_entry[entry]["callers"]:
                sys.exit(f"gate: {entry} must be named by {w} (established independently){mutate_note} "
                         f"-- callers seen: {by_entry[entry]['callers']}")
    ext = {c for r in rows for c in r["callers"]}
    if len(ext) < 3:
        sys.exit("gate: only %d distinct external callers -- too few to be the API surface this layer "
                 "exists to report" % len(ext))
    return ext


def report(base, out_tsv=None):
    rows = classify(surface(base), mapped_names(base))
    ext = check(rows)
    n_entry = len(rows)
    print(f"acdb/gsl symbols named in the extract: {n_entry}  distinct external callers: {len(ext)}")
    print("callers: " + "・".join(sorted(ext)))
    for r in sorted(rows, key=lambda x: (-x["n_callers"], x["entry"]))[:18]:
        print(f"   {r['entry']:40s} callers={r['n_callers']:2d} live={len(r['live_callers']):2d} "
              f"{'・'.join(r['callers'])[:96]}")
    solo = [r for r in rows if r["n_callers"] == 0]
    print(f"   entry points with NO external caller in the extract: {len(solo)} (loader-internal: "
          + "・".join(r["entry"].replace("acdb_loader_", "") for r in solo[:10]) + ")")
    if out_tsv:
        with open(out_tsv, "w", encoding="utf-8") as f:
            f.write("entry\texported_by_loader\tn_callers\tlive_callers\tcallers\n")
            for r in rows:
                f.write("\t".join((r["entry"], "yes" if r["exported_by_loader"] else "no",
                                   str(r["n_callers"]), str(len(r["live_callers"])),
                                   "・".join(r["callers"]))) + "\n")
        print("wrote " + out_tsv + f" ({len(rows)} rows)")
    return rows


def selftest():
    """Two fixtures.  One read-only pass over the REAL extract (the only way to prove the matrix on the
    bytes that matter), and one synthetic 55-file extract that is small enough to mutate -- a mutation
    must never be applied to the baseline, and hardlinks are impossible here (/tmp is another device)."""
    import shutil, subprocess, tempfile
    tool = os.path.abspath(__file__)
    real = os.path.join(ROOT, BASE)
    bad = 0

    def show(label, out):
        nonlocal bad
        ok = label.startswith("ok:")
        print(("  ok   " if (ok or "gate:" in out) else "  FAIL ") + label +
              ("" if ok else " :: " + ((out.strip().splitlines() or ["-"])[-1])[:150]))
        bad += 0 if ok else 1

    r = subprocess.run([sys.executable, tool], capture_output=True, text=True)
    out = r.stdout + r.stderr
    if r.returncode == 0 and "distinct external callers" in r.stdout:
        print("  ok   ok: the stored extract yields a caller matrix")
    else:
        print("  FAIL ok: the stored extract yields a caller matrix :: " + out.strip()[-160:])
        bad += 1

    d = tempfile.mkdtemp(prefix="acdb-api-fixture-")
    os.makedirs(os.path.join(d, "shipped/system/lib"))
    os.makedirs(os.path.join(d, "shipped/vendor/lib/hw"))
    os.makedirs(os.path.join(d, "live"))
    # loader exports + the three edges the controls assert + 50 filler ELFs (the >=50 gate)
    os.makedirs(os.path.join(d, "shipped/system/lib64"), exist_ok=True)
    def elf(rel, names):
        p = os.path.join(d, "shipped", rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        body = b"\x7fELF" + b"".join(n.encode() + b"\x00" for n in names)
        open(p, "wb").write(body)
        return p
    elf("vendor/lib/libacdbloader.so", ["acdb_loader_init_v2", "acdb_loader_send_listen_afe_cal",
                                        "acdb_loader_get_audio_cal_v2", "acdb_loader_get_calibration"])
    elf("system/lib/hw_dummy.so", [])
    hal = elf("system/lib/hw/audio.primary.msm8996.so", ["acdb_loader_init_v2", "acdb_loader_get_calibration"])
    st = elf("vendor/lib/hw/sound_trigger.primary.msm8996.so",
             ["acdb_loader_init_v2", "acdb_loader_get_calibration", "acdb_loader_send_listen_afe_cal"])
    bb = elf("vendor/lib/soundfx/libqcbassboost.so", ["acdb_loader_get_audio_cal_v2"])
    for i in range(50):
        elf("system/lib/libfiller%02d.so" % i, ["gsl_open"])
    open(os.path.join(d, "live/maps-mediaserver.txt"), "w", encoding="utf-8").write(
        "/system/lib/hw/audio.primary.msm8996.so\n"
        "/system/vendor/lib/hw/sound_trigger.primary.msm8996.so\n"
        "/system/vendor/lib/soundfx/libqcbassboost.so\n")

    def run(*extra):
        return subprocess.run([sys.executable, tool, "--base", d, *extra], capture_output=True, text=True)

    r2 = run()
    o2 = r2.stdout + r2.stderr
    if r2.returncode == 0 and "sound_trigger.primary.msm8996.so" in o2:
        print("  ok   ok: a synthetic extract reproduces the three known edges")
    else:
        print("  FAIL ok: a synthetic extract reproduces the three known edges :: " + o2.strip()[-160:])
        bad += 1

    data = open(st, "rb").read().replace(b"acdb_loader_send_listen_afe_cal\x00", b"")
    open(st, "wb").write(data)
    r3 = run()
    o3 = r3.stdout + r3.stderr
    if r3.returncode != 0 and "must be named by sound_trigger.primary" in o3:
        print("  ok   gate: erasing one caller's literal must break the known-edge control")
    else:
        print("  FAIL gate: erasing one caller's literal must break the known-edge control :: " +
              o3.strip()[-160:])
        bad += 1

    os.remove(os.path.join(d, "live/maps-mediaserver.txt"))
    r4 = run()
    o4 = r4.stdout + r4.stderr
    if r4.returncode != 0 and "live/maps-mediaserver.txt" in o4:
        print("  ok   gate: without the live maps the caller table refuses to call anything LIVE")
    else:
        print("  FAIL gate: without the live maps the caller table refuses to call anything LIVE :: " +
              o4.strip()[-160:])
        bad += 1
    shutil.rmtree(d, ignore_errors=True)
    print("selftest: %d arm(s) failed" % bad)
    return 1 if bad else 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default=os.path.join(ROOT, BASE))
    ap.add_argument("--tsv", default=None)
    a = ap.parse_args()
    report(a.base, a.tsv)
    return 0


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        sys.exit(selftest())
    sys.exit(main())
