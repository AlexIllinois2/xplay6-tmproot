#!/usr/bin/env python3
"""Runtime audio event skeleton, read out of the device log buffer (ledger 415).

Why this is a separate layer: everything else in this deliverable describes a STATE (control values,
files, calibration tables, code).  Only the log shows the sequence the HAL actually ran -- which
snd_device was enabled, which route path names were touched, which ACDB commands were issued and with
what return code.  A 7-port can match every state and still fail, because the sequence or a command
returned differently; and conversely a state difference that shows up in the log is explainable.

The ACDB error lines matter most: `-19` on AUDPROC_COMMON_TABLE means the calibration stage that
should follow a Hi-Fi session declined to answer, and it happens ON 6.0.1 -- so it is baseline
behaviour to compare against, not a port defect.
"""
import argparse, glob, os, re, sys

ROOT = os.environ.get("AUDIO_PORT_ROOT") or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EVENT = re.compile(r"^([VDFIW])/([A-Za-z0-9_.\-]+) *\(( *)?(\d+)\): (.*)$")
PATTERNS = {
    "select_devices": re.compile(r"select_devices: out_snd_device\((\d+): ([^)]+)\)"),
    "enable_snd_device": re.compile(r"enable_snd_device: snd_device\((\d+): ([^)]+)\)"),
    "disable_snd_device": re.compile(r"disable_snd_device: snd_device\((\d+): ([^)]+)\)"),
    # the HAL prints the two directions with DIFFERENT wording (verified against the stored dump):
    # enable says "apply mixer and update path", disable says "reset and update mixer path".  One
    # pattern covering both would have matched only the reset line -- i.e. the ruler would have read
    # the undo and called it the application.
    "route_path_enable": re.compile(r"enable_audio_route: apply mixer and update path: (.+)"),
    "route_path_reset": re.compile(r"disable_audio_route: reset and update mixer path: (.+)"),
    "app_type_cfg": re.compile(r"PLAYBACK app_type (\d+), acdb_dev_id (\d+), sample_rate (\d+)"),
    "send_audio_cal": re.compile(r"ACDB -> send_audio_cal, acdb_id = (\d+), path = (\d+), "
                                 r"app id = (0x[0-9a-f]+), sample rate = (\d+)"),
    "acdb_cmd": re.compile(r"ACDB -> (ACDB_CMD_[A-Z_0-9]+)"),
    "acdb_error": re.compile(r"Error: (ACDB[^\n]*?) = (-?\d+)"),
    "hifi_support": re.compile(r"isHifiSupport, reply ret:(\d+), value:(\d+)"),
    "topology": re.compile(r"ACDB -> send_(asm|adm|audtable|afe|lsm|topology)[a-z_]*"),
    # the misspelling IS the key: same family as HAL's `DSDEnbale` (ledger 408).  A 7-side that fixed
    # the typo would silently lose this event, so the pattern names it exactly as the device prints it.
    "dolby_endpoint": re.compile(r"audio_extn_dolby_ds2_set_endpoint: Dolby set endpint :(0x[0-9a-fA-F]+)"),
}
GROUPS = {k: v for k, v in PATTERNS.items()}


AUDIO_TAGS = re.compile(r"^(?:audio_hw_[a-z_]*|audio_extn[a-z_]*|audio_policy|audio_primary|"
                        r"ACDB-LOADER|ACDB|AudioFlinger|AudioService|hardware_info|"
                        r"msm8974_platform|FeatureService_Native|audio_hw_hal|HAL*)")
LOG_LEVELS = os.environ.get("AUDIO_LOG_LEVELS", "VDFIWEA")   # overridable ONLY so a selftest arm can
                                                              # prove the E guard bites; E was missing
                                                              # from an early version of this filter, and the
                                # only lines it dropped were the ACDB errors -- the interesting ones
TAG = re.compile(r"^([" + LOG_LEVELS + r"])/([^ (]+) *\( *\d+\): (.*)$")


THREADTIME = re.compile(r"^\d\d-\d\d \d\d:\d\d:\d\d\.\d+\s+(\d+)\s+(\d+)\s+"
                        r"([VDIFWEA])\s+([^ :]+):\s(.*)$")


def normalize(raw):
    """§463: `logcat -v threadtime` lines carry the level/tag AFTER the pids, so the brief-only matcher
    dropped every line of a threadtime ring and then reported 'no audio activity'.  Rewrite the shape
    into the brief form this ruler parses; brief lines pass through untouched."""
    m = THREADTIME.match(raw.strip())
    if not m:
        return raw
    return "%s/%s(%s): %s" % (m.group(3), m.group(4), m.group(1), m.group(5))


def scan(paths, keep_slice=None):
    """Filter the raw dump by TAG SET (never by a hand-made slice: the slice is where the E lines went
    missing), count events, and optionally write the kept slice so the artefact matches the ruler."""
    hits = {k: [] for k in PATTERNS}
    lines = kept = 0
    levels = {c: 0 for c in LOG_LEVELS}
    kept_levels = {c: 0 for c in LOG_LEVELS}
    # a level that is not in LOG_LEVELS never matches TAG at all, so the "raw" side of the guard has
    # to be counted with a class-free pattern -- otherwise excluding E from the filter also erases the
    # evidence that E lines were there (which is exactly how the first version hid the ACDB errors)
    ANY_LEVEL = re.compile(r"^([A-Z])/([^ (]+) *\( *\d+\): (.*)$")
    audio_levels = {}          # per-level counts of AUDIO-TAGGED lines, independent of LOG_LEVELS
    out = open(keep_slice, "w", encoding="utf-8") if keep_slice else None
    for p in paths:
        for line in open(p, encoding="utf-8", errors="replace"):
            lines += 1
            raw = normalize(line.rstrip("\n"))
            am = ANY_LEVEL.match(raw)
            if am and AUDIO_TAGS.search(am.group(2)):
                audio_levels[am.group(1)] = audio_levels.get(am.group(1), 0) + 1
                if am.group(1) not in LOG_LEVELS:
                    m = None            # a level the filter would silently swallow
                else:
                    m = TAG.match(raw)
            else:
                m = TAG.match(raw)
            if not m:
                continue
            lvl, tag, msg = m.group(1), m.group(2), m.group(3)
            if lvl in levels:
                levels[lvl] += 1
            if not AUDIO_TAGS.search(tag):
                continue
            kept += 1
            if lvl in kept_levels:
                kept_levels[lvl] += 1
            if out:
                out.write(line)
            for k, rx in GROUPS.items():
                g = rx.search(msg)
                if g and all(x is not None for x in g.groups()):
                    # a pattern whose alternation matches without filling its groups would otherwise
                    # store None and blow up the sort downstream -- or worse, print a blank event
                    hits[k].append((os.path.basename(p), tag, g.groups()))
    if out:
        out.close()
    return hits, lines, kept, audio_levels, kept_levels


def mixer_paths_table(board_xml):
    """path name -> the controls that path writes, from the board mixer file itself.

    The point of joining the log to the file is that it settles a question neither answers alone:
    the log proves a route path was APPLIED, the file proves which controls that path writes, and
    together they explain why a control can read Off while the feature is switched on -- the switch
    is only asserted for the duration of the stream.
    """
    import xml.etree.ElementTree as ET
    if not os.path.exists(board_xml):
        sys.exit("gate: " + board_xml + " is not in the extract -- the log/file join cannot be made")
    root = ET.parse(board_xml).getroot()
    out = {}
    for node in root.iter("path"):
        nm = node.get("name")
        ctls = [(c.get("name"), c.get("value")) for c in node.iter("ctl") if c.tag == "ctl"]
        if nm and ctls:
            out.setdefault(nm, []).extend(ctls)
    if not out:
        sys.exit("gate: no <path name=...> with <ctl> children parsed from " + board_xml +
                 " -- the parse is blind")
    return out


DECISIVE_CTLS = ("SmartPA Switch", "HiFi Mode Switch", "DSD SampleRate Switch")


def ctl_writers(table, ctls=DECISIVE_CTLS):
    """which route paths in THIS file can write each decisive control -- the file-side enumeration of
    the question the DAPM graph answered from the other side (§298: 外放只差一格 `SmartPA Switch`)."""
    out = {}
    for ctl in ctls:
        out[ctl] = sorted({nm for nm, cl in table.items() for n, v in cl if n == ctl})
    if not all(out.values()):
        sys.exit("gate: no path in this mixer file writes " +
                 "・".join(k for k, v in out.items() if not v) +
                 " -- either the enumeration is blind or this is not the board file; the DAPM-side "
                 "conclusion (which single control gates 外放 / Hi-Fi) then has no file counterpart")
    return out


def route_paths(hits):
    """every route path name the log mentions, from EITHER direction, sorted.

    Both are used because a rolling buffer may hold only one of them; which direction was seen is
    reported separately so nobody reads a reset as an application.
    """
    return sorted({g[0] for k in ("route_path_enable", "route_path_reset")
                   for _, _, g in hits[k] if g[0]})


def mixer_family(etc_dir):
    """every mixer-family file in the extract -- the candidate set has to be enumerated from the disk,
    not from what I remember (a hand-picked pair made this leg 'prove' the board file was loaded,
    while `mixer_paths_tasha.xml` and the four FTM files explain the same route)."""
    return sorted(glob.glob(os.path.join(etc_dir, "mixer_paths*.xml")) +
                  glob.glob(os.path.join(etc_dir, "ftm-mixerpath*.xml")))


def resolve_route_paths(paths, table, exact_only=False):
    """route path names from the log -> the paths that file actually defines.

    The whole string is tried first because the board file defines COMPOSITE names (`deep-buffer-
    playback headphone-hifi` writes the backend-specific MultiMedia1 switch) -- falling back to the
    tokens only when the composite is absent keeps the parent path from being mistaken for the whole
    route.  Returns {} for a file that cannot explain any of the log's routes.
    """
    out = {}
    for p in paths:
        if p in table:
            out.setdefault(p, []).append((p, table[p]))
        elif not exact_only:
            for token in p.split():
                if token in table:
                    out.setdefault(p, []).append((token, table[token]))
    return out


def discriminate(hits, boards):
    """How many of the log's applied routes each candidate mixer file can explain.

    This is the runtime-side leg for §412's "which mixer file is loaded": the generic file defines
    `deep-buffer-playback` but no `headphone-hifi` at all, so a Hi-Fi route seen in the log could not
    have been applied from it.  Nothing is claimed unless exactly ONE candidate explains every route.
    """
    paths = route_paths(hits)
    if not paths:
        return None
    per = {}
    for b in boards:
        if not os.path.exists(b):
            sys.exit("gate: candidate mixer file " + b + " is missing -- a discrimination needs every "
                     "candidate present, otherwise 'not explained' just means 'not read'")
        exact = resolve_route_paths(paths, mixer_paths_table(b), exact_only=True)
        loose = resolve_route_paths(paths, mixer_paths_table(b))
        per[os.path.basename(b)] = (len(exact), len(paths), sorted(set(paths) - set(exact)),
                                    len(loose))
    winners = [k for k, v in per.items() if v[0] == v[1]]
    return paths, per, winners


def backend_chain(hits, platform_info, table):
    """the log's enabled snd_device -> platform-info backend + interface -> that path's controls.

    One log line has to agree with THREE files, which is why it is a good port test: a 7-side that
    keeps the same device number but renames the backend, or maps it to another interface, breaks the
    chain visibly even when every individual control value still matches.
    """
    names = sorted({g[1] for _, _, g in hits["enable_snd_device"]})
    if not names:
        return None
    if not os.path.exists(platform_info):
        sys.exit("gate: " + platform_info + " is not in the extract -- the log->platform-info leg "
                 "cannot be made")
    txt = open(platform_info, encoding="utf-8", errors="replace").read()
    out = []
    for nm in names:
        dev = "SND_DEVICE_OUT_" + nm.upper().replace("-", "_")
        m = re.search(r'<device name="' + re.escape(dev) + r'"[^>]*?backend="([^"]+)"'
                      r'[^>]*?interface="([^"]+)"', txt)
        be = m.group(1) if m else None
        out.append((nm, dev, be, m.group(2) if m else None, table.get(be, []) if be else [],
                    be in table if be else False))
    if out and all(o[2] is None for o in out):
        sys.exit("gate: none of the log's enabled devices (" + "・".join(names) + ") has a <device "
                 "name=...> entry in " + os.path.basename(platform_info) + " -- either the wrong "
                 "platform-info file was compared or the name mapping is mine, not the device's")
    resolved = [o for o in out if o[2]]
    if resolved and not any(o[5] for o in resolved):
        sys.exit("gate: " + os.path.basename(platform_info) + " maps every device the log enabled to a "
                 "backend that NO candidate mixer path defines (" +
                 "・".join(f"{o[0]}->{o[2]}" for o in resolved) + ") -- the log, the platform info and "
                 "the mixer file are not from the same world; refusing to print a chain that is "
                 "impossible")
    return out


def cross_check(hits, table, board_xml):
    paths = route_paths(hits)
    if not paths:
        return None
    resolved = resolve_route_paths(paths, table)
    if not resolved:
        sys.exit("gate: none of the route path names in the log (" + "・".join(paths) +
                 ") exists in " + os.path.basename(board_xml) + " -- the log and the extract are not "
                 "from the same world (or the wrong mixer file was compared)")
    return paths, resolved


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--log", nargs="+", default=[os.path.join(ROOT, "art/audio-6.0.1/live/logcat-raw.txt")])
    ap.add_argument("--slice", default=None, help="write the audio-tag slice here (the stored artefact)")
    a = ap.parse_args()
    for p in a.log:
        if not os.path.exists(p):
            sys.exit("gate: " + p + " is missing -- capture it with `adb exec-out \"su -c 'logcat -d -v brief'\"` "
                                     "and filter the audio tags; this layer is runtime evidence, not memory")
    hits, lines, kept, levels, kept_levels = scan(a.log, keep_slice=a.slice)
    total = sum(len(v) for v in hits.values())
    if total == 0:
        sys.exit("gate: 0 audio events in %d log lines -- the buffer held no audio activity, which is "
                 "not evidence of absence; reproduce by playing something and re-capturing" % lines)
    for k in ("select_devices", "send_audio_cal", "app_type_cfg"):
        if not hits[k]:
            sys.exit(f"gate: the log has no {k} lines though it has {total} other audio events -- the "
                     "tag filter or the parse is blind; refusing to report a partial skeleton")
    print(f"log lines: {lines} raw, {kept} kept by the audio tag set, {total} events; "
          f"levels in dump={ {k: v for k, v in sorted(levels.items()) if v} } "
          f"kept={ {k: v for k, v in kept_levels.items() if v} }")
    if levels.get("E", 0) and kept_levels.get("E", 0) == 0:
        sys.exit("gate: %d audio-tagged E-level lines are in the dump and none survived the filter -- "
                 "error lines are exactly what this layer exists to catch; check LOG_LEVELS before "
                 "trusting this skeleton" % levels["E"])
    for k, v in sorted(hits.items(), key=lambda kv: -len(kv[1])):
        uniq = sorted({tuple(x[2]) for x in v})
        print(f"   {k:<18} {len(v):4d}  distinct {len(uniq)}   " +
              "; ".join("・".join(str(y) for y in u[:3]) for u in uniq[:4]))
    board = os.environ.get("AUDIO_PORT_BOARD_MIXER") or os.path.join(
        ROOT, "art/audio-6.0.1/shipped/system/etc/mixer_paths_tasha.PD1610.xml")
    xc = cross_check(hits, mixer_paths_table(board), board)
    if xc:
        paths, resolved = xc
        print("   log x mixer-file join: route paths seen in the log that the board file defines: " +
              str(len(resolved)) + "/" + str(len(paths)))
        for p, toks in sorted(resolved.items()):
            for tok, ctls in toks:
                sw = " ".join(f"{n}={v}" for n, v in ctls if "Switch" in n or "Mode" in n)
                print(f"      {p}  ->  path {tok}: {sw or '(no switch/mode controls)'}")
    cands = [c.strip() for c in os.environ.get("AUDIO_MIXER_CANDIDATES", "").split(",") if c.strip()]
    if not cands:
        # ALL mixer-family files in the extract, not the two I happened to think of -- with a
        # hand-picked pair the leg would have "proved" the board file was loaded while the unsuffixed
        # tasha file and the FTM files explain the very same route
        cands = mixer_family(os.path.join(ROOT, "art/audio-6.0.1/shipped/system/etc"))
    writers = ctl_writers(mixer_paths_table(board))
    print("   which paths in " + os.path.basename(board) + " can write the decisive controls:")
    for k, v in sorted(writers.items()):
        print(f"      {k:<22} {len(v)} path(s): " + "・".join(v))
    disc = discriminate(hits, cands)
    if disc:
        paths, per, winners = disc
        losers = sorted(k for k, v in per.items() if v[0] != v[1])
        print("   which mixer file can apply these routes (key = the WHOLE name the HAL passes, e.g. "
              "`deep-buffer-playback headphone-hifi`; +token-level = the weaker fallback): " +
              " | ".join(f"{k} {n}/{m} exact, {tok} token-level" +
                         ("" if not miss else " (unexplained: " + "・".join(miss) + ")")
                         for k, (n, m, miss, tok) in sorted(per.items())) +
              "  ->  " + ("DISCRIMINATING: only " + winners[0] + " explains every route the log applied"
                          if len(winners) == 1 else
                          ("the loaded file is not in the set I was given (no candidate explains every "
                           "route) -- refusing to name one" if not winners else
                           "refutes " + str(len(losers)) + " of " + str(len(per)) +
                           " (" + "・".join(losers) + ") -- those CANNOT be the loaded file; " +
                           str(len(winners)) + " survivors the log cannot tell apart, so this leg "
                           "alone names none")))
    pinf = os.environ.get("AUDIO_PLATFORM_INFO") or os.path.join(
        ROOT, "art/audio-6.0.1/shipped/system/etc/audio_platform_info.xml")
    chain = backend_chain(hits, pinf, mixer_paths_table(board))
    if chain:
        print("   log -> platform-info -> mixer path chain (device, backend, interface, controls the "
              "backend path writes):")
        for nm, dev, be, iface, ctls, known in chain:
            sw = " ".join(f"{a}={b}" for a, b in ctls if "Switch" in a or "Mode" in a)
            print(f"      {nm}  [{dev}]  backend={be} interface={iface}  " +
                  (f"{len(ctls)} ctl(s)" if known else "backend NOT defined by any mixer path") +
                  (("  " + sw) if sw else ""))
    err = sorted({tuple(x[2]) for x in hits["acdb_error"]})
    if err:
        print("   ACDB ERRORS (baseline behaviour on 6.0.1, to be compared not fixed blindly): " +
              "; ".join("=・".join(e) for e in err))
    if not hits["acdb_error"]:
        print("   (no ACDB error lines in this buffer -- the -19 set seen on 2026-10-17 was during a "
              "headphone-hifi session, so absence here is about buffer timing, not health)")
    return 0


def selftest():
    """Synthetic dumps: one that must summarise, one with the error level excluded from the filter
    (the guard must catch it), one with an unknown route path, one with the ACDB lines removed (a
    required group must abort), and one where the Dolby line's misspelling is corrected (the event
    must then NOT be reported -- the key is that exact string)."""
    import subprocess
    import tempfile
    tool = os.path.abspath(__file__)
    repo = os.environ.get("AUDIO_PORT_ROOT") or "/home/v/.local/project/xplay6"
    real_mixer = os.path.join(repo, "art/audio-6.0.1/shipped/system/etc/mixer_paths_tasha.PD1610.xml")
    generic_mixer = os.path.join(repo, "art/audio-6.0.1/shipped/system/etc/mixer_paths.xml")
    real_platform = os.path.join(repo, "art/audio-6.0.1/shipped/system/etc/audio_platform_info.xml")
    good = ("D/audio_hw_primary(  737): select_devices: out_snd_device(43: headphone-hifi) in_snd_device(0: )\n"
            "I/audio_hw_utils(  737): audio_extn_utils_send_app_type_cfg PLAYBACK app_type 69937, acdb_dev_id 150, sample_rate 44100\n"
            "D/ACDB-LOADER(  737): ACDB -> send_audio_cal, acdb_id = 150, path = 0, app id = 0x11131, sample rate = 44100\n"
            "E/ACDB-LOADER(  737): Error: ACDB audproc returned = -19\n"
            "E/audio_hw_dolby(  737): audio_extn_dolby_ds2_set_endpoint: Dolby set endpint :0x4\n"
            "D/audio_hw_primary(  737): enable_snd_device: snd_device(43: headphone-hifi)\n"
            "D/audio_hw_primary(  737): enable_audio_route: apply mixer and update path: deep-buffer-playback headphone-hifi\n"
            "V/audio_hw_primary(  737): disable_audio_route: reset and update mixer path: deep-buffer-playback headphone-hifi\n"
            "W/PackageManager(  500): some unrelated warning\n")
    arms = [("ok: a normal audio dump summarises", good,
             {"AUDIO_PORT_BOARD_MIXER": real_mixer} if os.path.exists(real_mixer) else {},
             ("send_audio_cal", "acdb_error", "dolby_endpoint", "0x4", "log x mixer-file join",
             "route_path_enable", "can write the decisive controls", "SmartPA Switch"), ()),
            ("gate: the error level excluded from the filter is caught", good, {"AUDIO_LOG_LEVELS": "VDFIWA"},
             ("none survived the filter",), ()),
            ("gate: a route path the board mixer file does not define cannot pass the join",
             "D/audio_hw_primary(  737): enable_audio_route: apply mixer and update path: made-up-playback x\n"
             "D/ACDB-LOADER(  737): ACDB -> send_audio_cal, acdb_id = 150, path = 0, app id = 0x11131, sample rate = 44100\n"
             "I/audio_hw_utils(  737): audio_extn_utils_send_app_type_cfg PLAYBACK app_type 69937, acdb_dev_id 150, sample_rate 44100\n"
             "D/audio_hw_primary(  737): select_devices: out_snd_device(43: headphone-hifi) in_snd_device(0: )\n",
             {"AUDIO_PORT_BOARD_MIXER": "__GENERATED_EMPTY_MIXER__"},
             ("none of the route path names in the log",), ()),
            ("gate: a dump with the ACDB lines removed cannot pass as a skeleton",
             "\n".join(l for l in good.splitlines() if "ACDB" not in l), {},
             ("the log has no send_audio_cal lines",), ()),
            # the Dolby event is keyed on the device's own misspelling: fix the typo in the fixture and
            # the event must disappear -- proof that the key is the string, not a fuzzy tag match
            ("ok: a corrected-typo Dolby line is NOT matched",
             good.replace("Dolby set endpint", "Dolby set endpoint"),
             {"AUDIO_PORT_BOARD_MIXER": real_mixer} if os.path.exists(real_mixer) else {},
             ("select_devices",), ("0x4",)),
            # the discrimination leg must be able to say BOTH things: it may only name a loaded file when
            # exactly one candidate explains the route, so the arm set needs the negative shape too
            ("report: exactly one candidate explaining the route is what makes the claim",
             good,
             {"AUDIO_MIXER_CANDIDATES": real_mixer + "," + generic_mixer,
              "AUDIO_PORT_BOARD_MIXER": real_mixer},
             ("DISCRIMINATING: only " + os.path.basename(real_mixer),), ("NOT discriminating",)),
            ("report: a candidate set in which nothing explains the route claims nothing",
             good,
             {"AUDIO_MIXER_CANDIDATES": generic_mixer, "AUDIO_PORT_BOARD_MIXER": real_mixer},
             ("the loaded file is not in the set I was given",),
             ("DISCRIMINATING",)),
            # a rolling buffer may hold only the reset half of the story; the leg must still work, and
            # with neither direction present it must NOT name a loaded file
            ("report: a dump holding only the reset line still discriminates",
             "\n".join(l for l in good.splitlines() if "apply mixer and update path" not in l),
             {"AUDIO_MIXER_CANDIDATES": real_mixer + "," + generic_mixer,
              "AUDIO_PORT_BOARD_MIXER": real_mixer},
             ("DISCRIMINATING: only " + os.path.basename(real_mixer),), ()),
            ("report: with no route evidence at all the leg names no file",
             "\n".join(l for l in good.splitlines() if "audio_route" not in l),
             {"AUDIO_MIXER_CANDIDATES": real_mixer + "," + generic_mixer,
              "AUDIO_PORT_BOARD_MIXER": real_mixer},
             ("select_devices",), ("DISCRIMINATING", "the loaded file is not in the set")),
            # with the WHOLE mixer family as candidates the leg can only refute -- claiming a single
            # loaded file here would be the classic over-read (tasha.xml and the FTM files explain it)
            ("report: over the whole mixer family the leg refutes but names nothing", good,
             {"AUDIO_PORT_BOARD_MIXER": real_mixer},
             ("refutes 3 of 10",), ("DISCRIMINATING",)),
            ("gate: a mixer file where the decisive control is renamed cannot carry the enumeration",
             good, {"AUDIO_PORT_BOARD_MIXER": "__GENERATED_RENAMED_MIXER__"},
             ("no path in this mixer file writes",), ()),
            ("gate: a platform-info file naming none of the log's devices cannot carry the chain leg",
             good, {"__gen_platform": "missing-device"}, ("none of the log's enabled devices",), ()),
            ("gate: a backend no mixer path defines cannot be printed as a chain",
             good, {"__gen_platform": "unknown-backend"},
             ("backend that NO candidate mixer path defines",), ()),
            ]
    bad = 0

    # §463 arm: the SAME session captured in both logcat shapes must summarise identically.  The two
    # rings are the delivered artefact (the B-arm in-play snapshot), so this arm runs on what the
    # acceptance procedure actually stores -- before the normaliser the threadtime copy of this very
    # ring produced 0 events and the tool told the operator to go play something again.
    pair = os.path.join(repo, "art/audio-6.0.1/live/inplay-barm-calfileprefix-20261018-1137")
    tt_p, br_p = os.path.join(pair, "logcat-ring.txt"), os.path.join(pair, "logcat-ring-brief.txt")
    if not (os.path.exists(tt_p) and os.path.exists(br_p)):
        print("  FAIL the two-shape ring pair is missing under %s -- the §463 arm cannot compare" % pair)
        bad += 1
    else:
        def ev(run):
            m = re.search(r"(\d+) events", run.stdout)
            return (run.returncode, m.group(1) if m else None)
        t_ev = ev(subprocess.run([sys.executable, tool, "--log", tt_p], capture_output=True, text=True))
        b_ev = ev(subprocess.run([sys.executable, tool, "--log", br_p], capture_output=True, text=True))
        if t_ev[0] != 0 or b_ev[0] != 0 or t_ev[1] != b_ev[1] or t_ev[1] is None:
            print("  FAIL threadtime -> rc=%s events=%s / brief -> rc=%s events=%s (the normaliser is "
                  "not shape-neutral)" % (t_ev[0], t_ev[1], b_ev[0], b_ev[1]))
            bad += 1
        else:
            print("  ok   the same session in threadtime and in brief both give %s events" % t_ev[1])

    for label, text, extra, must_have, must_not in arms:
        d = tempfile.mkdtemp()
        if extra.get("AUDIO_PORT_BOARD_MIXER") == "__GENERATED_RENAMED_MIXER__":
            mx = os.path.join(d, "renamed.xml")
            # route names kept so the join passes -- the only change is that `SmartPA Switch` no longer
            # exists, which is what this leg, and only this leg, must catch
            open(mx, "w", encoding="utf-8").write(
                "<mixer>"
                '<path name="deep-buffer-playback headphone-hifi">'
                '<ctl name="TERT_MI2S_RX Audio Mixer MultiMedia1" value="1"/></path>'
                '<path name="headphone-hifi"><ctl name="HiFi Mode Switch" value="HiFi"/></path>'
                '<path name="headphone-hifi-DSD"><ctl name="DSD SampleRate Switch" value="On"/></path>'
                '<path name="speaker"><ctl name="SmartPA Renamed" value="1"/></path>'
                "</mixer>\n")
            extra = dict(extra)
            extra["AUDIO_PORT_BOARD_MIXER"] = mx
        if extra.get("__gen_platform"):
            kind = extra["__gen_platform"]
            pin = os.path.join(d, "audio_platform_info.xml")
            if kind == "missing-device":
                open(pin, "w", encoding="utf-8").write(
                    '<root><device name="SND_DEVICE_OUT_HANDSET" backend="handset" '
                    'interface="SLIMBUS_0_RX"/></root>\n')
            else:
                open(pin, "w", encoding="utf-8").write(
                    '<root><device name="SND_DEVICE_OUT_HEADPHONE_HIFI" backend="nonexistent-backend" '
                    'interface="TERT_MI2S_RX"/></root>\n')
            extra = dict(extra)
            extra.pop("__gen_platform")
            extra["AUDIO_PLATFORM_INFO"] = pin
            if not os.path.exists(real_mixer):
                extra["AUDIO_PORT_BOARD_MIXER"] = real_mixer
        if extra.get("AUDIO_PORT_BOARD_MIXER") == "__GENERATED_EMPTY_MIXER__":
            mx = os.path.join(d, "mixer.xml")
            open(mx, "w", encoding="utf-8").write(
                "<mixer><path name=\"other-path\"><ctl name=\"Foo\" value=\"1\"/></path></mixer>\n")
            extra = dict(extra)
            extra["AUDIO_PORT_BOARD_MIXER"] = mx
        p = os.path.join(d, "logcat-raw.txt")
        open(p, "w", encoding="utf-8").write(text)
        env = dict(os.environ)
        env["AUDIO_PORT_ROOT"] = repo      # the tool must not resolve its defaults against /tmp
        env.update(extra)
        r = subprocess.run([sys.executable, tool, "--log", p], capture_output=True, text=True, env=env)
        out = r.stdout + r.stderr
        if label.startswith(("ok:", "report:")):
            ok = (r.returncode == 0 and all(s in out for s in must_have)
                  and not any(s in out for s in must_not))
        else:
            # a gate arm must name WHICH gate fired -- otherwise it can pass because some unrelated
            # leg could not read a file, which is how a selftest stops testing anything
            ok = (r.returncode != 0 and "gate:" in out and all(s in out for s in must_have))
        print(("  ok   " if ok else "  FAIL ") + label + ("" if ok else f" (rc={r.returncode})"))
        bad += 0 if ok else 1
    print("selftest: %d arm(s) failed" % bad)
    return 1 if bad else 0


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        sys.exit(selftest())
    sys.exit(main())
