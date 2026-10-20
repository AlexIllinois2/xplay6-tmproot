#!/usr/bin/env python3
"""Surface of the audio HAL that DECIDES the audible path: config-file selection, Hi-Fi/DSD device
and control names, and its library edges -- captured as a cross-version reference (ledger 407).

Why this exists: the HAL binary is the component that opens the mixer/platform files, picks the DSD
path and maps devices to ACDB ids, yet the carry list named none of it -- and an earlier note of mine
claimed the HAL was "not in the extract" only because I looked in vendor/lib*/hw/ instead of
system/lib64/hw/.  Both facts are fixed here: the file is located by search (not by a remembered
path), and everything reported is a string/count taken from the binary in this run.

Gates (each aborts rather than printing a confident zero):
  1. the HAL must be found at all, and found the same way on both bitnesses' candidate dirs;
  2. `SND_DEVICE_OUT_HEADPHONE_HIFI` must be present -- if it is not, this whole layer is about a
     binary that does not implement the vivo Hi-Fi path and must not be quoted as one;
  3. the mixer-selection evidence must be a PAIR: a dynamic-path string AND the default-file string
     (one alone proves nothing about which file wins);
  4. control names are only reported when they also exist in the live control list OR in the board
     mixer file, so a stale string in the binary is never called a live capability.

Usage:
  python3 tools/audio_hal_surface.py [--tsv OUT.tsv]        # 6.0.1 report
  python3 tools/audio_hal_surface.py --root <dir-with-hw/>  # point at a 7 extract
  python3 tools/audio_hal_surface.py --selftest
"""
import glob, os, re, subprocess, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HAL_NAME = "audio.primary.msm8996.so"
CANDIDATE_DIRS = ["system/lib64/hw", "system/lib/hw", "vendor/lib64/hw", "vendor/lib/hw"]
MIXER_SELECT_STRINGS = ("new_mixer_xml_path", "Loading default mixer file")
HIFI_DEVICE = "SND_DEVICE_OUT_HEADPHONE_HIFI"
DSD_TOKENS = ("DSDEnable", "DSDEnbale", "HiFi DSD Volume Switch", "headphone-hifi-DSD",
              "AUDIO_OUTPUT_FLAG_HW_DSD", "mIsDSD", "HW_DSD is running")
SELF_PARAMS = ("always select HiFi DSD", "Could not set HiFi DSD Volume")


def find_hal(base):
    hits = []
    for rel in CANDIDATE_DIRS:
        hits += glob.glob(os.path.join(base, rel, HAL_NAME))
    return sorted(set(hits))


def elf_class(path):
    """Bitness straight from the header bytes -- readelf's wording is locale-dependent and this
    column decides which copy the device runs, so it must not depend on a translation."""
    with open(path, "rb") as f:
        h = f.read(20)
    if len(h) < 20 or h[:4] != b"\x7fELF":
        sys.exit(f"gate: {path} is not an ELF header I can read -- bitness unknown, stop")
    machine = int.from_bytes(h[18:20], "little")
    names = {0xB7: "AArch64", 0x28: "ARM"}
    return ("ELF64" if h[4] == 2 else "ELF32") + "/" + names.get(machine, f"machine{machine:#x}")


def live_hal_paths(live_dir):
    """Device paths of every mapped audio.primary HAL, from the maps capture."""
    p = os.path.join(live_dir, "loaders.txt")
    if not os.path.exists(p):
        sys.exit(f"gate: {p} is missing -- without the live maps I cannot say which bitness of this "
                 "HAL the device actually loads, and quoting one as 'the' HAL is exactly the mistake "
                 "this tool exists to prevent")
    mapped = set()
    for line in open(p, encoding="utf-8", errors="replace"):
        s = line.strip()
        if s.startswith("/") and s.endswith(".so"):
            mapped.add(s)
    if not mapped:
        sys.exit(f"gate: {p} parsed to zero mapped paths -- the pattern is blind")
    return mapped


def needed_libs(path):
    r = subprocess.run(["readelf", "-d", path], capture_output=True, text=True)
    if r.returncode:
        sys.exit(f"gate: readelf cannot read {path} ({r.stderr.strip()[:60]}) -- the library edges "
                 "column would then be silently empty")
    # readelf prints this line in the host locale ("Shared library: [x]" vs "共享库：[x]"), so match
    # only the bracketed soname on the (NEEDED) line -- an English-only pattern looked like
    # "this HAL links nothing", which is never true.
    libs = [m.group(1) for m in
            re.finditer(r"\(NEEDED\).*?\[([^\]]+\.so)\]", r.stdout, re.S)]
    if not libs:
        sys.exit(f"gate: {path} declares zero NEEDED libraries -- that means my parse is blind, not "
                 "that the HAL links nothing; fix the pattern before quoting this column")
    return libs


def analyse(path, live_ctls, board_ctls, base):
    blob = open(path, "rb").read()
    ss = [x.decode("utf-8", "replace").rstrip("\x00")
          for x in re.findall(rb"[ -~]{6,}\x00", blob)]
    def has(k):
        return sum(1 for s in ss if k in s)
    dyn = [s for s in ss if MIXER_SELECT_STRINGS[0] in s]
    dflt = [s for s in ss if MIXER_SELECT_STRINGS[1] in s]
    if not (dyn and dflt):
        sys.exit(f"gate: {path} does not show BOTH the dynamic mixer-path string and the "
                 f"'{MIXER_SELECT_STRINGS[1]}' fallback -- mixer selection is then unproven, and this "
                 "layer must not claim how the file is chosen")
    devices = sorted({s for s in ss if s.startswith("SND_DEVICE_")})
    if not any(HIFI_DEVICE == d for d in devices):
        sys.exit(f"gate: {path} does not declare {HIFI_DEVICE} -- this is not the binary that "
                 "implements the vivo Hi-Fi path; do not emit this layer from it")
    ctl_names = sorted({m for s in ss for m in re.findall(r"[A-Z][A-Za-z0-9_ ]*?(?:Switch|Volume|Mux|Enable)", s)})
    backed = sorted(c for c in ctl_names if c in live_ctls or c in board_ctls)
    unbacked = sorted(set(ctl_names) - set(backed))
    return {
        "path": path, "bytes": len(blob),
        "strings": len(ss),
        "class": elf_class(path),
        "device_path": "/" + os.path.relpath(path, base).replace(os.sep, "/"),
        "mixer_dyn": dyn[:2], "mixer_default": dflt[:2],
        "platform_refs": sorted({s for s in ss if "audio_platform_info" in s})[:3],
        "acdb_hits": has("acdb"), "vivo_hits": has("vivo"), "sndcard_hits": has("snd-card"),
        "devices": len(devices), "hifi_device": HIFI_DEVICE in devices,
        "dsd": {k: has(k) for k in DSD_TOKENS + SELF_PARAMS},
        "controls_named": len(ctl_names), "controls_backed": backed,
        "controls_unbacked_count": len(unbacked),
        "needed": needed_libs(path),
    }


def load_live_and_board():
    routes = os.path.join(ROOT, "art/audio-6.0.1/route-states.tsv")
    live = {l.split("\t")[0] for l in open(routes, encoding="utf-8").read().splitlines()[1:]} \
        if os.path.exists(routes) else set()
    mixdir = os.path.join(ROOT, "art/audio-6.0.1/shipped/system/etc")
    board = set()
    if os.path.exists(os.path.join(mixdir, "mixer_paths_tasha.PD1610.xml")):
        t = open(os.path.join(mixdir, "mixer_paths_tasha.PD1610.xml"),
                 encoding="utf-8", errors="replace").read()
        board = set(re.findall(r'<ctl name="([^"]+)"', t))
    return live, board


TSV_COLUMNS = ["device_path", "elf_class", "live_mapped", "bytes", "strings", "snd_device_names",
               "hifi_declared", "acdb_hits", "vivo_hits", "controls_named", "controls_backed",
               "control_names_backed", "dsd_counts", "mixer_pair", "platform_paths", "needed"]


def tsv_cells(a):
    """One implementation of the row shape: --tsv writes it, --check-tsv compares against it.
    A second copy that drifts is how a stale table passes its own check (ledger 391)."""
    return [a["device_path"], a["class"], a["live_mapped"], a["bytes"], a["strings"], a["devices"],
            a["hifi_device"], a["acdb_hits"], a["vivo_hits"], a["controls_named"],
            len(a["controls_backed"]), " ".join(a["controls_backed"]),
            " ".join(f"{k}={v}" for k, v in sorted(a["dsd"].items()) if v),
            "present", " ".join(a["platform_refs"]), ",".join(a["needed"])]


def report(base=None, out=None, quiet=False, live=None):
    base = base or os.path.join(ROOT, "art/audio-6.0.1/shipped")
    live = live or os.path.join(ROOT, "art/audio-6.0.1/live")
    found = find_hal(base)
    if not found:
        sys.exit(f"gate: no {HAL_NAME} under {base} in {CANDIDATE_DIRS} -- before concluding it is "
                 "absent, check the candidate list itself (this project already got that wrong once)")
    mapped = live_hal_paths(live)
    live, board = load_live_and_board()
    rows = []
    for p in found:
        a = analyse(p, live, board, base)
        a["live_mapped"] = a["device_path"] in mapped
        rows.append(a)
        if not quiet:
            print(f"# {a['device_path']}  {a['class']}  {a['bytes']} B  strings={a['strings']}  "
                  f"mapped-by-loaders={a['live_mapped']}")
            print(f"   mixer selection: dyn={a['mixer_dyn']} default={a['mixer_default']}")
            print(f"   platform file refs: {a['platform_refs']}")
            print(f"   hits: acdb={a['acdb_hits']} vivo={a['vivo_hits']} snd-card={a['sndcard_hits']}")
            print(f"   SND_DEVICE_* names: {a['devices']} (Hi-Fi device declared: {a['hifi_device']})")
            print(f"   DSD/Hi-Fi strings: " +
                  " ".join(f"{k}={v}" for k, v in a["dsd"].items() if v))
            print(f"   control-like names: {a['controls_named']}, backed by live/board files: "
                  f"{len(a['controls_backed'])} ({', '.join(a['controls_backed'][:6])}), "
                  f"unbacked: {a['controls_unbacked_count']}")
            print(f"   NEEDED: {a['needed']}")
    if not any(r["live_mapped"] for r in rows):
        sys.exit("gate: none of the HAL copies found in the extract is a path the live maps named -- "
                 "so I cannot say this HAL is the one the device loads, and the layer must not be "
                 "quoted as the decision maker (pull the maps capture, or the right bitness)")
    if out:
        import csv
        with open(out, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f, delimiter="\t")
            w.writerow(TSV_COLUMNS)
            for a in rows:
                w.writerow(tsv_cells(a))
        print(f"# wrote {out}: {len(rows)} rows")
    return rows


def check_tsv(path, base=None, live=None):
    """Re-derive every cell from the binary and compare with the file on disk.  This is the only
    mode that must be run against the baseline directory: it writes nothing."""
    import csv
    if not os.path.exists(path):
        sys.exit(f"gate: {path} is not there -- generate it first (`--tsv {path}`), do not check "
                 "a remembered table")
    got = [[str(c) for c in row] for row in csv.reader(open(path, encoding="utf-8"), delimiter="\t")]
    if not got or got[0] != TSV_COLUMNS:
        sys.exit(f"gate: {path} header is {got[0] if got else 'empty'}, not the current row shape "
                 f"{TSV_COLUMNS} -- the tool changed; re-supply rather than compare columns by luck")
    fresh = report(base=base, out=None, quiet=True, live=live)
    body = got[1:]
    if len(body) != len(fresh):
        sys.exit(f"gate: {path} holds {len(body)} data rows, the extract now yields {len(fresh)} "
                 "HAL(s) -- a bitness was added or removed and this layer has to say which")
    bad = 0
    for cells, a in zip(body, fresh):
        want = [str(c) for c in tsv_cells(a)]
        for name, old, new in zip(TSV_COLUMNS, cells, want):
            if old != new:
                print(f"  MISMATCH {name}: table={old!r} recomputed={new!r}")
                bad += 1
    if bad:
        print(f"check-tsv: {bad} column(s) differ -- the table is stale, not the binary")
        return 1
    print(f"check-tsv: {len(body)} row(s) agree with the binary, {len(TSV_COLUMNS)} columns each")
    return 0


def selftest():
    """Prove each gate can fire, on doctored copies -- the strings are the evidence, so a scanner
    that cannot notice their removal is worse than no scanner."""
    bad = 0
    base = os.path.join(ROOT, "art/audio-6.0.1/shipped")
    arms = [
        ("ok: 6.0.1 HAL reports normally", None),
        ("gate: Hi-Fi device string removed", "SND_DEVICE_OUT_HEADPHONE_HIFI", "SND_DEVICE_OUT_HEADPHONE_XXX"),
        ("gate: mixer-selection fallback removed", "Loading default mixer file", "Loading XXX mixer file"),
        ("gate: no live-mapped HAL copy in the extract", None, None),
        ("gate: no live loaders.txt to decide bitness", None, None),
    ]
    import shutil, tempfile
    for label, *pair in arms:
        tmp = tempfile.mkdtemp()
        src = find_hal(base)
        dst_dir = os.path.join(tmp, "system/lib64/hw")
        live_dir = os.path.join(tmp, "live")
        os.makedirs(dst_dir, exist_ok=True)
        os.makedirs(live_dir, exist_ok=True)
        open(os.path.join(live_dir, "loaders.txt"), "w", encoding="utf-8").write(
            "== pid 716 /system/bin/mediaserver \n/system/lib64/hw/" + HAL_NAME + "\n")
        if not src:
            print("  FAIL no HAL to doctor -- baseline itself is unreadable")
            bad += 1
            shutil.rmtree(tmp, ignore_errors=True)
            continue
        b = bytearray(open(src[0], "rb").read())
        if pair and pair[0] is not None:
            old, new = pair
            ob, nb = old.encode(), new.encode()
            if ob not in b:
                print(f"  FAIL {label}: anchor {old!r} absent -- vacuous arm")
                bad += 1
                shutil.rmtree(tmp, ignore_errors=True)
                continue
            i = b.find(ob)
            b[i:i + len(ob)] = nb + b"\x00" * (len(ob) - len(nb))
        open(os.path.join(dst_dir, HAL_NAME), "wb").write(bytes(b))
        if label.startswith("gate: no live-mapped"):
            open(os.path.join(live_dir, "loaders.txt"), "w", encoding="utf-8").write(
                "== pid 716 /system/bin/mediaserver \n/system/lib/libaudioflinger.so\n")
        elif label.startswith("gate: no live loaders"):
            os.remove(os.path.join(live_dir, "loaders.txt"))
        env = dict(os.environ)
        r = subprocess.run([sys.executable, os.path.join(ROOT, "tools", "audio_hal_surface.py"),
                            "--root", tmp, "--live", live_dir],
                           capture_output=True, text=True, env=env)
        out = r.stdout + r.stderr
        if label.startswith("ok:"):
            ok = r.returncode == 0 and "SND_DEVICE_* names" in out
            print(("  ok   " if ok else "  FAIL ") + label)
            bad += 0 if ok else 1
        else:
            stopped = r.returncode != 0 and "gate:" in out
            print(("  ok   " if stopped else "  FAIL ") + label +
                  ("" if stopped else f" (rc={r.returncode})"))
            bad += 0 if stopped else 1
        shutil.rmtree(tmp, ignore_errors=True)
    bad += check_tsv_arms()
    print(f"selftest: {bad} arm(s) failed")
    return 1 if bad else 0


def check_tsv_arms():
    """The check arm must be able to fail: a comparison that only ever prints 'agree' is not a
    witness that the table is current."""
    staged = os.path.join(ROOT, "art/audio-6.0.1/hal-surface.PD1610.tsv")
    import tempfile
    bad = 0
    if not os.path.exists(staged):
        print("  FAIL check-tsv arms: " + staged + " is not staged -- the layer has no table to check")
        return 1
    r = subprocess.run([sys.executable, os.path.join(ROOT, "tools", "audio_hal_surface.py"),
                        "--check-tsv", staged], capture_output=True, text=True)
    ok = r.returncode == 0 and "agree" in (r.stdout + r.stderr)
    print(("  ok   " if ok else "  FAIL ") + "check-tsv: staged table agrees with the binary")
    bad += 0 if ok else 1

    lines = open(staged, encoding="utf-8").read().splitlines()
    head = lines[0].split("\t")
    col = head.index("strings")
    body = [l.split("\t") for l in lines[1:]]
    if len(body) < 2:
        print("  FAIL check-tsv arm: staged table has " + str(len(body)) +
              " data rows -- the census found two HAL copies, so this arm would test nothing")
        bad += 1
    else:
        body[0][col] = str(int(body[0][col]) + 1)
        tmp = os.path.join(tempfile.mkdtemp(), "doctored.tsv")
        text = "\n".join(["\t".join(head)] + ["\t".join(r) for r in body]) + "\n"
        open(tmp, "w", encoding="utf-8").write(text)
        if text == "\n".join(lines) + "\n":
            print("  FAIL check-tsv arm: the mutation did not land -- vacuous arm")
            bad += 1
        else:
            r = subprocess.run([sys.executable, os.path.join(ROOT, "tools", "audio_hal_surface.py"),
                                "--check-tsv", tmp], capture_output=True, text=True)
            out = r.stdout + r.stderr
            ok = r.returncode == 1 and "MISMATCH strings" in out
            print(("  ok   " if ok else "  FAIL ") + "check-tsv: a doctored column is caught" +
                  ("" if ok else f" (rc={r.returncode})"))
            bad += 0 if ok else 1
    return bad


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        sys.exit(selftest())
    if "--check-tsv" in sys.argv:
        chk = sys.argv[sys.argv.index("--check-tsv") + 1]
        base = sys.argv[sys.argv.index("--root") + 1] if "--root" in sys.argv else None
        live = sys.argv[sys.argv.index("--live") + 1] if "--live" in sys.argv else None
        sys.exit(check_tsv(chk, base=base, live=live))
    rep = {"--root"} <= set(sys.argv)
    base = sys.argv[sys.argv.index("--root") + 1] if "--root" in sys.argv else None
    live = sys.argv[sys.argv.index("--live") + 1] if "--live" in sys.argv else None
    out = sys.argv[sys.argv.index("--tsv") + 1] if "--tsv" in sys.argv else None
    report(base=base, out=out, live=live)
