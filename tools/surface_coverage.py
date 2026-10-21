#!/usr/bin/env python3
"""tools/surface_coverage.py -- which readable audio surfaces of a machine does the baseline actually
cite?  (end state: every readable 6.0.1 artifact must exist as a cross-version reference)

The denominator is read from the device (a `find` over the audio-related roots) and grouped into surface
CLASSES -- hundreds of individual DAPM widget files are one class, not three hundred obligations.
A class counts as covered only when some artifact under art/audio-6.0.1 quotes the class's probe fragment
(a path or file basename that can only appear if that surface was actually read), and the report names the
citing files so the claim is checkable.  "It is in MANIFEST.txt" is not coverage: MANIFEST lists files we
made, not surfaces the device offers.

Two failure modes this is built to refuse:
  * a class the device does not expose prints as `0 files (absent on this build)` and is still counted in
    the denominator -- dropping empties silently is how a coverage report turns into a 100% lie;
  * the ruler is proven able to hit before its misses are believed: --selftest asserts a known-covered
    class reports covered AND that a fragment present in no artifact reports uncovered, on fixtures.

Usage:
  python3 tools/surface_coverage.py --selftest
  python3 tools/surface_coverage.py [--device] [--listing <file>] [--out <tsv>] [--root art/audio-6.0.1]
"""
import argparse
import csv
import os
import re
import subprocess
import sys
import collections

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ART = os.path.join(ROOT, "art", "audio-6.0.1")
ADB = os.environ.get("ADB", "adb")
SU = os.environ.get("SU", "su")  # SU=sux on 7.1.1: the vendor gate refuses execve of a path whose last component is "su" (ledger 579)


# (class, match-on-path regex, probe = ALL fragments must appear in the SAME artifact file)
# Conjunctive path-shaped probes matter: the first version used a single bare word ('hw_params') and
# reported COVERED for /proc/asound/.../hw_params on the strength of dmesg lines naming the kernel
# function `vivo_codec_hw_params` -- a code symbol, not a capture of the surface.
CLASSES = [
    ("asoc DAPM widget state", r"/asoc/.*/[^/]+$", ("asoc", "dapm")),
    ("asoc DAPM widget 'state' files", r"/asoc/.*/state$", ("dapm", "state")),
    ("asoc codec bias_level", r"/asoc/.*/bias_level$", ("asoc", "bias_level")),
    ("asoc codec register dumps", r"/asoc/.*/(codec_reg|registers|cache_sync)$", ("asoc", "codec_reg")),
    ("asoc hifi-codec subtree", r"/asoc/[^/]+/codec:hifi-codec(/|$)", ("codec:hifi-codec",)),
    ("asoc tasha_codec subtree", r"/asoc/[^/]+/codec:tasha_codec(/|$)", ("codec:tasha_codec",)),
    ("asoc tfa98xx subtree", r"/asoc/[^/]+/codec:tfa98xx(/|$)", ("codec:tfa98xx",)),
    ("asoc pcm-routing subtree", r"/asoc/[^/]+/platform:soc:qcom,msm-pcm-routing(/|$)", ("msm-pcm-routing",)),
    ("asoc dai-fe subtree", r"/asoc/[^/]+/soc:qcom,msm-dai-fe(/|$)", ("msm-dai-fe",)),
    ("asoc stub codec subtree", r"msm-stub-codec", ("msm-stub-codec",)),
    ("debugfs tfa98xx nodes", r"/debug/tfa98xx/", ("tfa98xx/codec_reg",)),
    ("debugfs es9038 nodes", r"/debug/es9038/", ("es9038/reg",)),
    ("regmap register dumps", r"/debug/regmap/.*/(registers|range|access|cache_bypass)$",
     ("regmap", "cache_bypass")),
    ("regmap per-device nodes", r"/debug/regmap/[^/]+/(name|cache_only)$", ("regmap", "cache_only")),
    ("sys/class/sound nodes", r"/sys/class/sound/", ("class/sound", "card0")),
    ("i2c device bindings", r"/sys/bus/i2c/devices/", ("bus/i2c/devices", "es9038")),
    ("debugfs clk tree", r"/debug/clk/", ("debug/clk", "clk_summary")),
    ("vivo audio latency nodes", r"/debug/audio_(in|out)_latency_measurement_node",
     ("latency_measurement_node",)),
    ("proc/asound per-pcm info", r"/proc/asound/card\d+/pcm[^/]*(/sub\d+)?/info$",
     ("proc/asound", "/info")),
    ("proc/asound pcm hw_params", r"/proc/asound/card\d+/pcm[^/]*/[^/]+/hw_params$",
     ("proc/asound", "hw_params")),
    ("proc/asound pcm sw_params", r"/proc/asound/card\d+/pcm[^/]*/[^/]+/sw_params$",
     ("proc/asound", "sw_params")),
    ("proc/asound pcm status", r"/proc/asound/card\d+/pcm[^/]*/[^/]+/status$",
     ("proc/asound", "/status")),
    ("proc/asound timers/hwdep/other", r"/proc/asound/(timers|hwdep|version|cards|devices|modules)",
     ("proc/asound", "hwdep")),
    ("soc0 identity nodes", r"/sys/devices/soc0/", ("/sys/devices/soc0",)),
    ("data/misc/audio overlay", r"/data/misc/audio", ("/data/misc/audio",)),
    ("acdbdata directories", r"/acdbdata/", ("/acdbdata",)),
]
PROP_CLASS = ("audio-ish properties", r"^prop:", ("persist.audio.calfile",))
MAX_SCAN_BYTES = 3 << 20


def sweep_device():
    roots = ["/proc/asound", "/sys/kernel/debug/asoc", "/sys/kernel/debug/tfa98xx",
             "/sys/kernel/debug/es9038", "/sys/kernel/debug/regmap", "/sys/kernel/debug/clk",
             "/sys/class/sound", "/sys/bus/i2c/devices", "/sys/devices/soc0", "/data/misc/audio",
             "/system/etc/acdbdata", "/vendor/etc/acdbdata"]
    out = []
    for r in roots:
        p = subprocess.run([ADB, "exec-out", f"{SU} -c 'find {r} -type f 2>/dev/null | head -4000'"],
                           capture_output=True, timeout=180)
        out += [ln.strip() for ln in p.stdout.decode("utf-8", "replace").split("\n") if ln.strip()]
    # these two roots hold first-level symlinks/dirs, not regular files: `find -type f` returns nothing
    # and the classes would read as "absent on this build" when the ruler was simply blind (§383's rule)
    for r in ["/sys/class/sound", "/sys/bus/i2c/devices"]:
        p = subprocess.run([ADB, "exec-out", f"{SU} -c 'find {r} -mindepth 1 -maxdepth 1'"],
                           capture_output=True, timeout=120)
        out += [ln.strip() for ln in p.stdout.decode("utf-8", "replace").split("\n") if ln.strip()]
    # loose files that are not under any of those roots
    for r in ["/sys/kernel/debug/audio_in_latency_measurement_node",
              "/sys/kernel/debug/audio_out_latency_measurement_node"]:
        p = subprocess.run([ADB, "exec-out", f"{SU} -c 'ls {r}'"], capture_output=True, timeout=60)
        out += [ln.strip() for ln in p.stdout.decode("utf-8", "replace").split("\n")
                if ln.strip() and "No such file" not in ln]
    p = subprocess.run([ADB, "exec-out", f"{SU} -c 'getprop'"], capture_output=True, timeout=120)
    for ln in p.stdout.decode("utf-8", "replace").split("\n"):
        if re.search(r"audio|acdb|smartpa|amp_|dsp|snd", ln, re.I):
            out.append("prop:" + ln.strip())
    return out


def build_index(root):
    """artifact file -> the set of probe fragments it quotes (a class is covered when ONE file quotes
    all of them, which is the whole point of conjunctive probes)"""
    frags = set()
    for _, _, probes in CLASSES:
        frags |= set(probes)
    frags |= set(PROP_CLASS[2])
    index = []
    for dirpath, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in ("shipped",)]
        for fn in files:
            if not re.search(r"\.(txt|tsv|md|json|log|raw|xml|rc|sh|py)$", fn, re.I):
                continue
            p = os.path.join(dirpath, fn)
            try:
                if os.path.getsize(p) > MAX_SCAN_BYTES:
                    continue
                t = open(p, encoding="utf-8", errors="replace").read()
            except OSError:
                continue
            hit = frozenset(f for f in frags if f in t)
            if hit:
                index.append((os.path.relpath(p, root), hit))
    return index


def citing(index, probes):
    need = set(probes)
    return sorted(rel for rel, hit in index if need <= hit)


def classify(paths):
    counts = collections.Counter()
    for p in paths:
        for name, rx, _ in CLASSES:
            if re.search(rx, p):
                counts[name] += 1
        if p.startswith("prop:"):
            counts[PROP_CLASS[0]] += 1
    return counts


def judge(counts, index):
    rows = []
    for name, _, probes in CLASSES + [PROP_CLASS]:
        n = counts.get(name, 0)
        cite = citing(index, probes)
        rows.append({"class": name, "device_files": n, "probe": "+".join(probes),
                     "cited_by": " ".join(cite[:4]), "cited_n": len(cite),
                     "verdict": ("COVERED" if cite and n else
                                 ("0 files (absent on this build)" if not n else
                                  "GAP: surface exists, no artifact quotes it"))})
    return rows


def selftest():
    bad, notes = [], []
    fixture = [
        "/sys/kernel/debug/asoc/card/codec:hifi-codec/dapm/HiFi DAC/state",
        "/sys/kernel/debug/asoc/card/codec:hifi-codec/bias_level",
        "/sys/kernel/debug/asoc/card/codec:tasha_codec/dapm/x/state",
        "/sys/kernel/debug/asoc/card/codec:tasha_codec/bias_level",
        "/proc/asound/card0/pcm0p/info",
        "/proc/asound/card0/pcm0p/sub0/info",
        "/proc/asound/card0/pcm0p/sub0/hw_params",
        "/proc/asound/card0/pcm0p/sub0/sw_params",
        "/sys/devices/soc0/hw_platform",
        "prop:[persist.audio.calfile0]: []",
    ]
    counts = classify(fixture)
    want = {"asoc codec bias_level": 2, "proc/asound per-pcm info": 2, "proc/asound pcm hw_params": 1,
            "proc/asound pcm sw_params": 1, "soc0 identity nodes": 1,
            "audio-ish properties": 1, "asoc hifi-codec subtree": 2}
    for k, v in want.items():
        if counts.get(k) != v:
            bad.append(f"fixture gave {k}={counts.get(k)}, want {v}")
    if counts.get("proc/asound pcm status"):
        bad.append("a listing with no status file still counted pcm status -- classes leak into each "
                   "other, so an uncovered class could be masked by a covered one")
    # the index must be able to say both yes and no -- and the yes must require ALL probe fragments
    idx = [("live/dmesg.txt", frozenset({"hw_params", "vivo_codec_hw_params"})),
           ("live/asound-dump.txt", frozenset({"proc/asound", "hw_params", "/info"}))]
    rows = judge(counts, idx)
    got = {r["class"]: r["verdict"] for r in rows}
    if got["proc/asound pcm hw_params"] != "COVERED":
        bad.append("a file quoting both probe fragments was not reported covered -- the ruler is blind")
    if got["asoc codec bias_level"] != "GAP: surface exists, no artifact quotes it":
        bad.append(f"bias_level (device file, no citation) read {got['asoc codec bias_level']} -- "
                   "a real gap would be silently reported as covered")
    # the exact false positive this rewrite exists to kill: a dmesg line naming the kernel function
    # vivo_codec_hw_params quotes 'hw_params' but never the path -- it must NOT count as coverage
    idx2 = [("live/dmesg.txt", frozenset({"hw_params"}))]
    got2 = {r["class"]: r["verdict"] for r in judge(counts, idx2)}
    if not got2["proc/asound pcm hw_params"].startswith("GAP"):
        bad.append("a single bare fragment was accepted as coverage -- that is how dmesg's "
                   "vivo_codec_hw_params made /proc/asound/.../hw_params look captured")
    if got2["proc/asound per-pcm info"].startswith("COVERED"):
        bad.append("persist-style miss reported as covered -- misses would never be found")
    zero = [r for r in rows if r["device_files"] == 0]
    if len(zero) + sum(1 for r in rows if r["device_files"]) != len(rows):
        bad.append("classes vanished from the report -- the denominator must include the empty ones")
    print(f"selftest: {len(bad)} arm(s) failed" + ("" if not bad else " -- " + "; ".join(bad))
          + f"  ({len(rows)} classes, {len(zero)} expected empty on the fixture)")
    return 1 if bad else 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--device", action="store_true", help="sweep the attached machine")
    ap.add_argument("--listing", help="judge an existing path listing instead of a live sweep")
    ap.add_argument("--root", default=ART, help="artifact tree to search for citations")
    ap.add_argument("--out", help="write the per-class table here")
    a = ap.parse_args()
    if a.selftest:
        return selftest()
    if a.listing:
        paths = [l.strip() for l in open(a.listing, encoding="utf-8", errors="replace") if l.strip()]
    elif a.device:
        paths = sweep_device()
    else:
        sys.exit("nothing to classify: give --device or --listing (see --selftest)")
    counts = classify(paths)
    index = build_index(a.root)
    rows = judge(counts, index)
    cov = sum(1 for r in rows if r["verdict"] == "COVERED")
    absent = sum(1 for r in rows if r["device_files"] == 0)
    print(f"  device paths: {len(paths)}; artifact tree: {a.root}")
    for r in rows:
        flag = "ok " if r["verdict"] == "COVERED" else ("-- " if r["device_files"] == 0 else "GAP")
        print(f"  {flag} {r['class']:<32} files={r['device_files']:>5}  {r['verdict']:<28} "
              f"probe={r['probe']!r} cited={r['cited_n']} {r['cited_by'][:70]}")
    print(f"coverage: {cov}/{len(rows)} classes cited by an artifact "
          f"({absent} classes absent on this machine)")
    if a.out:
        with open(a.out, "w", encoding="utf-8", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()), delimiter="\t")
            w.writeheader()
            w.writerows(rows)
        print(f"wrote {a.out} ({len(rows)} rows x {len(rows[0])} columns)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
