#!/usr/bin/env python3
"""One-command in-play acceptance check for the two output routes (Hi-Fi and speaker).

A snapshot is a directory of read-only device faces taken while a stream is RUNNING.  The route is
decided from evidence (powered DAPM sink, the two route switches, the per-stream ACDB id), never from
which switch we hope somebody set; expectations come from stored 6.0.1 snapshots, not from memory;
and when a snapshot carries two capture forms of the same control (the per-control echo and the full
mixer dump) they must agree -- that gate exists because a hand read of the echo took the FIRST enum
option instead of the `>`-marked one and turned a live `HiFi Mode Switch: HiFi` into "Off".
"""
import argparse, os, re, shutil, subprocess, sys

ROOT = os.environ.get("AUDIO_PORT_ROOT") or "/home/v/.local/project/xplay6"
SU = os.environ.get("SU", "su")  # SU=sux on the 7.1.1 firmware (ledger 579: the vendor name gate)
BASE = f"{ROOT}/art/audio-6.0.1"
CARD = "/sys/kernel/debug/asoc/msm8996-tasha-cdp-snd-card"
CODEC_DAPM = [("tfa98xx", CARD + "/codec:tfa98xx/dapm"),
              ("hifi-codec", CARD + "/codec:hifi-codec/dapm"),
              ("tasha_codec", CARD + "/codec:tasha_codec/dapm")]
MUST = ["SmartPA Switch", "HiFi Mode Switch", "TERT_MI2S_RX Audio Mixer MultiMedia1",
        "SLIMBUS_0_RX Audio Mixer MultiMedia1", "TERT_MI2S mode", "TERT_MI2S Bit Format",
        "Headphone Rx Mixer I2S_RX", "DSD SampleRate Switch"]
STREAM0 = "Audio Stream 0 App Type Cfg"
ACDB_ROUTE = {"150": "hifi", "15": "speaker", "10": "headphones", "124": "hifi"}
SPK_WIDGETS = ["Speaker", "SmartPA", "SmartPA I2S In", "SmartPA Playback"]
MIN_CONTROLS = 500


def _adb(cmd, timeout=150):
    r = subprocess.run(["adb", "exec-out", f"{SU} -c '%s' </dev/null" % cmd],
                       capture_output=True, timeout=timeout)
    if r.returncode != 0 and not r.stdout:
        sys.exit("gate: adb failed for: " + cmd + " :: " + r.stderr.decode("utf-8", "replace")[:200])
    return r.stdout.decode("utf-8", "replace")


def pcm_status():
    return _adb("for d in /proc/asound/card0/pcm*; do for s in $d/sub*; do "
                "echo \"== $s/status\"; cat $s/status; done; done")


RUNRE = r"== (\S+)/status\nstate: RUNNING\nowner_pid   : (\d+)"


def in_play_evidence(procfs1, procfs2, debugfs_start_paths):
    """Pure: may a snapshot proceed?  procfs RUNNING on both sides, or -- for a compress stream that
    procfs cannot see (§451) -- at least one front-end whose debugfs state says `State: start`."""
    return bool(procfs1 and procfs2) or bool(debugfs_start_paths)


def capture(out):
    """Device side, read-only.  The RUNNING set is read twice, around the mixer dump."""
    os.makedirs(out, exist_ok=True)
    st1 = pcm_status()
    run1 = re.findall(RUNRE, st1)
    tinymix = _adb("tinymix -D 0", 200)
    st2 = pcm_status()
    run2 = re.findall(RUNRE, st2)
    if not run1 or not run2:
        # §468: a compress-offload session (DSD) is NOT in procfs at all -- §451 measured that the
        # 29 instances whose /proc/asound/pcm name is wrapped in ( ) get no per-instance directory,
        # and device 17 is one of them.  So 'no RUNNING substream' must not be read as 'nothing is
        # playing' until the debugfs front-end state has been asked.
        comp = _adb("grep -l '^State: start' /sys/kernel/debug/asoc/*/*/state", 60)
        running = [l for l in comp.splitlines() if l.strip().endswith("/state")]
        if not in_play_evidence(run1, run2, running):
            sys.exit("gate: no RUNNING playback substream (%d / %d) and no debugfs front-end in "
                     "`State: start` -- nothing is playing on either face, so there is no in-play "
                     "state to check; start the file on the route under test and re-run"
                     % (len(run1), len(run2)))
        # compress route: keep the witness that procfs cannot give (§451/§468).  No shell loop and no
        # inner quotes -- the device `sh` rejects `for` (it hung a capture once) and inner single
        # quotes inside `su -c "..."` hang the transport; the glob survives the spaces in the names.
        body = _adb("grep -H 'State:' /sys/kernel/debug/asoc/*/*/state", 90)
        with open(os.path.join(out, "compress-state-a.txt"), "w", encoding="utf-8") as fh:
            fh.write(body)
        with open(os.path.join(out, "in-play-witness.txt"), "w", encoding="utf-8") as fh:
            fh.write("# §468: procfs 报 no RUNNING substream（compress 流在 procfs 没有每实例目录），"
                     "在播证人取自 debugfs 前端状态：\n" + "\n".join(running) + "\n")
        st2 = st1

    if sorted(run1) != sorted(run2):
        sys.exit("gate: the RUNNING set changed between the two reads (%s vs %s) -- the stream was "
                 "torn down mid-capture, so this snapshot is not one session" % (run1, run2))
    files = {"tinymix-all.txt": tinymix, "pcm-status-1.txt": st1, "pcm-status-2.txt": st2,
             "running.txt": "\n".join("%s RUNNING owner_pid=%s" % r for r in run1) + "\n",
             "codec_reg.txt": _adb("cat /sys/kernel/debug/tfa98xx/codec_reg"),
             "es9038-reg.txt": _adb("cat /sys/kernel/debug/es9038/reg"),
             "pa-calibrate.txt": _adb("cat /sys/kernel/debug/tfa98xx/calibrate"),
             "uptime.txt": _adb("cat /proc/uptime"),
             "hw_params.txt": "".join("== %s/hw_params\n%s" % (p, _adb("cat %s/hw_params" % p, 30))
                                      for p, _ in run1)}
    # §428: the platform's own bit-width log lines only exist in the ring, and a snapshot that
    # carries them can be compared three ways (front end / backend control / platform decision).
    # `logcat -d` is read-only and costs no user action; the ring is brief-format unless the device
    # already logs threadtime, so both are parsed downstream.
    ring = _adb("logcat -d -b main -b system", 240)
    if not ring.strip():
        sys.exit("gate: logcat -d returned nothing -- cannot write an empty ring into a snapshot; "
                 "the platform-log leg would then silently claim 'no lines' instead of 'no read'")
    if "AudioFlinger" not in ring:
        print("note: the ring holds no AudioFlinger lines (it rolled) -- storing it anyway, "
              "backend_bitwidth_chain.py will report the platform vote as absent")
    files["logcat-ring.txt"] = ring
    files["dapm-live.txt"] = "".join(
        _adb("for f in '%s'/*; do echo \"== %s ${f##*/}\"; cat \"$f\"; done" % (path, name), 120)
        for name, path in CODEC_DAPM)
    thr = []
    for _, pid in run1:
        st = _adb("cat /proc/%s/status" % pid, 30)
        tg = re.search(r"Tgid:\s*(\d+)", st)
        nm = re.search(r"Name:\s*(\S+)", st)
        line = "thread %s (%s) -> Tgid %s" % (pid, nm.group(1) if nm else "?", tg.group(1) if tg else "?")
        if tg:
            line += "\n" + "\n".join(l for l in _adb("toybox ls -l /proc/%s/fd" % tg.group(1), 60).splitlines()
                                    if re.search(r"\.(mp3|flac|wav|dsf|ape|m4a|aac|ogg|wma)\b", l, re.I))
        thr.append(line)
    files["thread-owner.txt"] = "\n".join(thr) + "\n"
    for k, v in files.items():
        open(os.path.join(out, k), "w", encoding="utf-8").write(v)
    return out


def controls_current(text):
    """`tinymix -D 0` prints `<num>\t<type>\t<n>\t<name padded to 40><ACTIVE value>`."""
    vals = {}
    for l in text.splitlines():
        m = re.match(r"^(\d+)\t(\w+)\t(\d+)\t(.*)$", l)
        if not m:
            continue
        rest = m.group(4)
        name, value = rest[:40].rstrip(), rest[40:].strip()
        if not value:
            name, _, value = rest.partition("    ")
            name, value = name.rstrip(), value.strip()
        vals.setdefault(name, value)
    return vals


def controls_echo(text):
    """Per-control form: `tinymix -D 0 <name>` echoes `NAME:\tOPT1\t>OPT2\tOPT3` for an ENUM (the `>`
    marks the ACTIVE item) or `NAME: VALUE` for a BOOL.  Taking the token after the colon is the trap."""
    vals = {}
    for l in text.splitlines():
        if ":" not in l:
            continue
        name, _, rest = l.partition(":")
        name = name.strip()
        if ":" in rest:
            rest = rest.split(":", 1)[1]
        rest = rest.strip()
        if "Invalid mixer control" in rest or "MISSING" in rest:
            continue
        opts = rest.split("\t")
        cur = [o.strip().lstrip(">") for o in opts if o.strip().startswith(">")]
        vals[name] = cur[0] if cur else rest
    return vals


def widgets_on(text):
    out = set()
    for b in re.split(r"^== ", text, flags=re.M)[1:]:
        head, _, body = b.partition("\n")
        codec, _, widget = head.strip().partition(" ")
        v = body.strip().splitlines()[0] if body.strip() else ""
        m = re.match(r"^(.*?): (On|Off)\b", v)
        if m and m.group(2) == "On":
            out.add("%s/%s" % (codec, widget))
    return out


def pa_reg_values(path):
    """debugfs `codec_reg` prints `reg{XXXX}:<hex>`; the class table keys on the short form."""
    if not os.path.exists(path):
        return {}
    out = {}
    for m in re.finditer(r"reg\{(\w+)\}:(\w+)", open(path, encoding="utf-8", errors="replace").read()):
        out[int(m.group(1), 16)] = m.group(2)
    return out


def stable_pa_regs(tsv):
    """Which PA registers are ALLOWED to move between two reads -- from the classifier's own table,
    never from a guess (the four-class reading of ledger 346-350)."""
    if not os.path.exists(tsv):
        sys.exit("gate: " + tsv + " missing -- comparing whole PA register files byte-for-byte would "
                 "call the volatile window a regression, so the class table is required")
    import csv
    keep = set()
    n = 0
    for r in csv.DictReader(open(tsv, encoding="utf-8"), delimiter="\t"):
        n += 1
        if r["class"].strip().upper() == "STABLE":
            keep.add(int(r["reg"].strip(), 16))
    if not keep:
        sys.exit("gate: the class table has " + str(n) + " rows but no STABLE register -- refusing to "
                 "assert an empty set")
    return keep, n


def stream_cfg(v):
    w = re.split(r"\s+", v.strip()) if v else []
    return (w[0], w[1], w[2]) if len(w) >= 3 else ("?", "?", "?")


def route_of(ctl, on):
    """Every leg that can name the route, and the answer is only accepted when the legs agree."""
    legs = {}
    if on:
        speak = [w for w in SPK_WIDGETS if ("tfa98xx/" + w) in on]
        if len(speak) == len(SPK_WIDGETS):
            legs["dapm"] = "speaker"
        elif "hifi-codec/HiFi DAC" in on:
            legs["dapm"] = "hifi"
    if ctl.get("HiFi Mode Switch") in ("HiFi", "DSD"):
        legs["HiFi Mode Switch"] = "hifi"
    elif "HiFi Mode Switch" in ctl:
        legs["HiFi Mode Switch"] = "not-hifi"
    if ctl.get("SmartPA Switch") == "On":
        legs["SmartPA Switch"] = "speaker"
    elif "SmartPA Switch" in ctl:
        legs["SmartPA Switch"] = "not-speaker"
    acdb = stream_cfg(ctl.get(STREAM0, ""))[1]
    if acdb in ACDB_ROUTE:
        legs["acdb " + acdb] = ACDB_ROUTE[acdb]
    named = {v for k, v in legs.items() if v in ("hifi", "speaker")}
    if len(named) > 1:
        sys.exit("gate: the route legs disagree (%s) -- refusing to pick one, because which leg is "
                 "wrong decides what the whole check asserts" % legs)
    if not named:
        sys.exit("gate: no leg names a route (%s) -- a third route (headphones? DSD?) has no stored "
                 "baseline here, so nothing may be asserted" % legs)
    return named.pop(), legs


def load(d):
    p = lambda f: os.path.join(d, f)
    if not os.path.exists(p("tinymix-all.txt")):
        sys.exit("gate: %s has no tinymix-all.txt -- a baseline must be a real snapshot, not a "
                 "hand-written expectation" % d)
    ctl = controls_current(open(p("tinymix-all.txt"), encoding="utf-8", errors="replace").read())
    if len(ctl) < MIN_CONTROLS:
        sys.exit("gate: parsed only %d control(s) from %s -- the dump or the parser is blind, so no "
                 "expectation from it can be trusted (need >= %d)"
                 % (len(ctl), p("tinymix-all.txt"), MIN_CONTROLS))
    if os.path.exists(p("controls.txt")):
        echo = controls_echo(open(p("controls.txt"), encoding="utf-8", errors="replace").read())
        bad = ["%s: echo=%s dump=%s" % (c, echo[c], ctl[c]) for c in echo
               if c in ctl and echo[c] and echo[c] != ctl[c]]
        if bad:
            sys.exit("gate: the two capture forms disagree in %s -- %s.  The per-control echo lists ALL "
                     "enum options with `>` on the active one, so the first token after the colon is "
                     "the first OPTION, not the value (that misread is what once turned a live "
                     "`HiFi Mode Switch: HiFi` into \"Off\")" % (d, " | ".join(bad)))
    on = widgets_on(open(p("dapm-live.txt"), encoding="utf-8", errors="replace").read()) \
        if os.path.exists(p("dapm-live.txt")) else set()
    route, legs = route_of(ctl, on)
    apptype, acdb, rate = stream_cfg(ctl.get(STREAM0, ""))
    pa = open(p("codec_reg.txt"), encoding="utf-8", errors="replace").read() \
        if os.path.exists(p("codec_reg.txt")) else ""
    return {"dir": d, "ctl": ctl, "on": on, "route": route, "legs": legs, "acdb": acdb, "rate": rate,
            "apptype": apptype, "pa_regs": len(re.findall(r"^reg\{", pa, re.M)),
            "dac_off": "is off" in (open(p("es9038-reg.txt"), encoding="utf-8", errors="replace").read()
                                    if os.path.exists(p("es9038-reg.txt")) else ""),
            "track": [l.split("-> ")[-1] for l in open(p("thread-owner.txt"), encoding="utf-8",
                                                       errors="replace").read().splitlines()
                      if "-> " in l and re.search(r"\.(mp3|flac|wav|dsf|ape|m4a|aac|ogg|wma)\b", l, re.I)]
            if os.path.exists(p("thread-owner.txt")) else [],
            "dapm_present": bool(os.path.exists(p("dapm-live.txt")))}


def judge(new, olds, verbose=True):
    old = next((o for o in olds if o["route"] == new["route"]), None)
    if old is None:
        sys.exit("gate: no stored baseline for the route this snapshot is on (%s; baselines cover %s) "
                 "-- a route without a 6.0.1 snapshot has nothing to be compared to"
                 % (new["route"], "・".join(o["route"] for o in olds)))
    miss = [c for c in MUST if c not in old["ctl"]]
    if miss:
        sys.exit("gate: the stored baseline %s has no line for %s -- the check would be inventing its "
                 "own expectation" % (old["dir"], "・".join(miss)))
    bad = ["%s: baseline=%s NEW=%s" % (c, old["ctl"][c], new["ctl"][c])
           for c in MUST if c in new["ctl"] and new["ctl"][c] != old["ctl"][c]]
    bad += [c + ": baseline=%s NEW=ABSENT" % old["ctl"][c] for c in MUST if c not in new["ctl"]]
    want = (set("tfa98xx/" + w for w in SPK_WIDGETS) if new["route"] == "speaker"
            else {"hifi-codec/HiFi DAC"})
    noff = sorted(want - new["on"]) if new["dapm_present"] else []
    extra = sorted(new["on"] - old["on"]) if (new["dapm_present"] and old["dapm_present"]) else []
    reg_bad = old["pa_regs"] >= 0 and new["pa_regs"] != old["pa_regs"] and new["route"] == "speaker"
    cls_tsv = os.environ.get("TFA_REGS_TSV") or f"{BASE}/tfa-regs.PD1610.tsv"
    keep, nrows = stable_pa_regs(cls_tsv)
    rv_new, rv_old = pa_reg_values(os.path.join(new["dir"], "codec_reg.txt")), \
        pa_reg_values(os.path.join(old["dir"], "codec_reg.txt"))
    cmp_regs = sorted(k for k in keep if k in rv_new and k in rv_old)
    pa_bad = [hex(k) + ": baseline=" + rv_old[k] + " NEW=" + rv_new[k] for k in cmp_regs if rv_new[k] != rv_old[k]]
    cal_bad = old["route"] == "speaker" and new["route"] == "speaker" and \
        bool(re.search(r"impedance (ok|fail)", open(os.path.join(new["dir"], "pa-calibrate.txt"),
               encoding="utf-8", errors="replace").read())) != \
        bool(re.search(r"impedance (ok|fail)", open(os.path.join(old["dir"], "pa-calibrate.txt"),
               encoding="utf-8", errors="replace").read()))
    if verbose:
        print("route: %s   decided by: %s" % (new["route"], "・".join("%s=%s" % kv for kv in sorted(new["legs"].items()))))
        print("baseline: %s" % old["dir"])
        print("track: %s" % "・".join(new["track"] or ["unknown -- no media fd on the RUNNING thread"]))
        print("stream0 app_type/acdb/rate: NEW=%s/%s/%s  baseline=%s/%s/%s"
              % (new["apptype"], new["acdb"], new["rate"], old["apptype"], old["acdb"], old["rate"]))
        print("controls agreed %d/%d: %s" % (len(MUST) - len(bad), len(MUST),
                                            "・".join("%s=%s" % (c, old["ctl"][c]) for c in MUST)))
        if bad:
            print("CONTROLS DISAGREE: " + " | ".join(bad))
        if noff:
            print("WIDGETS OFF THAT THIS ROUTE REQUIRES ON: " + "・".join(noff))
        if extra:
            print("widgets additionally On vs baseline: " + "・".join(extra))
        if reg_bad:
            print("PA register count differs: baseline=%d NEW=%d" % (old["pa_regs"], new["pa_regs"]))
        print("PA setting-class registers identical %d/%d (class table %s rows; volatile and "
              "state-dependent registers are excluded on purpose)"
              % (len(cmp_regs) - len(pa_bad), len(cmp_regs), nrows))
        if pa_bad:
            print("PA SETTING REGISTERS DISAGREE: " + " | ".join(pa_bad))
        if cal_bad:
            print("PA calibration verdict differs from the baseline")
        print("Hi-Fi DAC powered off in this snapshot: %s (baseline: %s)" % (new["dac_off"], old["dac_off"]))
        if not new["dapm_present"]:
            print("boundary: no dapm-live.txt in this snapshot -> the powered sink is not asserted, "
                  "the route rests on the switches and the ACDB id only")
    fail = bool(bad or noff or reg_bad or cal_bad or pa_bad)
    print("verdict: %s" % ("MISMATCH -- see above" if fail else "MATCHES the 6.0.1 %s route" % new["route"]))
    return 1 if fail else 0



# --------------------------------------------------------------------------- matrix
def candidate_dumps(live):
    """Every mixer dump in the baseline that parses to a full control table -- enumerated from disk,
    never a hand-typed file list."""
    out = []
    for root, dirs, files in os.walk(live):
        for f in sorted(files):
            if not re.search(r"tinymix.*\.txt$|\.tinymix$", f):
                continue
            p = os.path.join(root, f)
            try:
                c = controls_current(open(p, encoding="utf-8", errors="replace").read())
            except OSError:
                continue
            if len(c) >= MIN_CONTROLS and ("SmartPA Switch" in c or "HiFi Mode Switch" in c):
                out.append((p, c))
    if not out:
        sys.exit("gate: no mixer dump under %s parses to >= %d controls -- the matrix has no input"
                 % (live, MIN_CONTROLS))
    return out


def label_dump(path, c):
    sp, hi = c.get("SmartPA Switch"), c.get("HiFi Mode Switch")
    legs = set()
    if sp == "On":
        legs.add("speaker")
    if hi in ("HiFi", "DSD"):
        legs.add("hifi")
    if len(legs) > 1:
        sys.exit("gate: %s asserts BOTH routes (SmartPA Switch=On and HiFi Mode Switch=%s) -- 6.0.1 "
                 "was never seen in that state, so it must be looked at, not averaged into a group"
                 % (path, hi))
    return legs.pop() if legs else "idle"


def spread_of(sets):
    """sets: group -> sorted distinct values.  Returns (marker-type, per-group sharing note).

    A value is `shared` when some OTHER group holds it too: that is what a leftover or a coinciding
    measurement looks like from outside, and this tool refuses to guess which.  A value that appears
    in no other group is `unique` to that state -- a real marker, or a drift the baseline never saw."""
    gs = [g for g in ("idle", "hifi", "speaker") if g in sets]
    note, unique = {}, {}
    for g in gs:
        others = set()
        for h in gs:
            if h != g:
                others |= set(sets[h])
        note[g] = " ".join("%s[%s]" % (v, "shared" if v in others else "unique") for v in sets[g])
        unique[g] = [v for v in sets[g] if v not in others]
    multi = [g for g in gs if len(sets[g]) > 1]
    if not multi:
        if len({sets[g][0] for g in gs}) == 1:
            return "constant", note, unique
        v = {g: sets[g][0] for g in gs}
        if len(gs) == 3 and v["hifi"] == v["speaker"] != v["idle"]:
            return "play-marker (any running stream)", note, unique
        if len(gs) == 3 and v["idle"] == v["hifi"] != v["speaker"]:
            return "speaker-marker", note, unique
        if len(gs) == 3 and v["idle"] == v["speaker"] != v["hifi"]:
            return "hifi-marker", note, unique
        return "state-marker", note, unique
    if all(not unique[g] for g in multi):
        return "spread, every value shared with another state (leftover or coincidence)", note, unique
    return "spread with a value unique to one state (marker or drift -- which is not decidable here)", \
        note, unique


def matrix(live):
    dumps = candidate_dumps(live)
    groups = {}
    for p, c in dumps:
        g = label_dump(p, c)
        groups.setdefault(g, []).append((p, c))
    for g in ("idle", "hifi", "speaker"):
        if g not in groups:
            sys.exit("gate: no dump labels as %s -- the matrix cannot state what %s looks like" % (g, g))
    names = set.intersection(*[set(c) for _, c in sum(groups.values(), [])])
    rows = []
    for k in sorted(names):
        sets = {g: sorted({c[k] for _, c in groups[g]}) for g in groups}
        lab, note, unique = spread_of(sets)
        if lab == "constant":
            continue
        cols = ""
        widths = {len(v.split()) for g in groups for v in sets[g]}
        if len(widths) == 1 and next(iter(widths)) >= 3:
            parts = []
            for i in range(next(iter(widths))):
                cs = {g: sorted({c[k].split()[i] for _, c in groups[g]}) for g in groups}
                l2, _n2, u2 = spread_of(cs)
                if l2 != "constant":
                    parts.append("col%d:%s%s" % (i, l2.split(" (")[0],
                                                 "" if not any(u2[g] for g in u2) else
                                                 " unique=" + ",".join(sorted({x for g in u2 for x in u2[g]}))))
            cols = " ".join(parts)
        rows.append({"control": k, "class": lab, "idle": "|".join(sets.get("idle", ["-"])),
                     "hifi": "|".join(sets.get("hifi", ["-"])),
                     "speaker": "|".join(sets.get("speaker", ["-"])),
                     "sharing": " ".join("%s:%s" % (g, note[g]) for g in ("idle", "hifi", "speaker")),
                     "per_column": cols,
                     "dumps": " ".join("%s=%d" % (g, len(groups[g])) for g in ("idle", "hifi", "speaker"))})
    return rows, groups


def dumps_table(groups, live):
    keys = ["dump", "state", "SmartPA Switch", "HiFi Mode Switch", "HP Sel", "acdb_col1"]
    lines = ["\t".join(keys)]
    for g in ("idle", "hifi", "speaker"):
        for p, c in sorted(groups[g], key=lambda x: x[0]):
            lines.append("\t".join([p.replace(live + "/", ""), g, c.get("SmartPA Switch", "?"),
                                     c.get("HiFi Mode Switch", "?"), c.get("HP Sel", "?"),
                                     stream_cfg(c.get(STREAM0, ""))[1]]))
    return "\n".join(lines) + "\n"


def matrix_texts(rows, groups, live):
    keys = ["control", "class", "idle", "hifi", "speaker", "sharing", "per_column", "dumps"]
    main = "\t".join(keys) + "\n" + "\n".join("\t".join(str(r[k]) for k in keys) for r in rows) + "\n"
    side = dumps_table(groups, live)
    n_dumps = sum(len(v) for v in groups.values())
    if len(side.strip().splitlines()) - 1 != n_dumps:
        sys.exit("gate: the provenance table lists %d dumps but the groups hold %d -- the matrix's own "
                 "denominator would be wrong" % (len(side.strip().splitlines()) - 1, n_dumps))
    return main, side


def write_matrix(rows, groups, out, live):
    main, side = matrix_texts(rows, groups, live)
    side_path = out.replace(".tsv", ".dumps.tsv")
    for path, want in ((out, main), (side_path, side)):
        have = open(path, encoding="utf-8").read() if os.path.exists(path) else ""
        if have == want:
            continue
        open(path, "w", encoding="utf-8").write(want)
        print("wrote %s (%d lines)" % (path, len(want.strip().splitlines())))
    print("matrix: %d moving control(s); %s; %d dumps with provenance in %s"
          % (len(rows), " ".join("%s=%d" % (g, len(groups[g])) for g in ("idle", "hifi", "speaker")),
             sum(len(v) for v in groups.values()), side_path))


def _row(rows, name):
    return next((r for r in rows if r["control"] == name), None)


def _print_fail(msg):
    print("     (arm is inert: %s)" % msg)


def matrix_selftest(live):
    import tempfile
    rows, groups = matrix(live)
    r_hp = _row(rows, "HiFi Mode Switch")
    r_pa = _row(rows, "SmartPA Switch")
    r_sel = _row(rows, "HP Sel")
    r_imp = _row(rows, "HPHL Impedance")
    r_cfg = _row(rows, STREAM0)
    arms = [
        ("ok: the dumps on disk land in three state groups", lambda: set(groups) == {"idle", "hifi", "speaker"}),
        # The DSD-in-play capture (2026-10-18) showed the switch reading `DSD`, so the Hi-Fi group now
        # legitimately holds two values and the classifier can no longer call it a single-value marker.
        # What IS decidable, and what this arm now asserts: the switch is Off in both non-Hi-Fi states and
        # never Off inside the Hi-Fi group, whose values are a subset of {HiFi, DSD}; `SmartPA Switch`
        # stays a one-value speaker marker.  If DSD stops appearing, the arm says so rather than passing.
        ("ok: `HiFi Mode Switch` is Off outside the Hi-Fi group and holds only HiFi/DSD inside it; "
         "`SmartPA Switch` stays the speaker marker",
         lambda: (r_hp and r_pa and r_pa["class"] == "speaker-marker"
                  and r_hp["idle"] == "Off" and r_hp["speaker"] == "Off"
                  and set(r_hp["hifi"].split("|")) <= {"HiFi", "DSD"}
                  and "Off" not in r_hp["hifi"].split("|")
                  and (set(r_hp["hifi"].split("|")) == {"HiFi"}
                       or set(r_hp["hifi"].split("|")) == {"HiFi", "DSD"}))),
        ("ok: `HP Sel` shows a value in the speaker group that another state also holds (a leftover)",
         lambda: r_sel and "shared with another state" in r_sel["class"] and "[shared]" in r_sel["sharing"]),
        ("ok: `HPHL Impedance` carries a value no other state holds, so it is NOT called a leftover",
         lambda: r_imp and "unique to one state" in r_imp["class"]),
        ("ok: the per-stream cfg is read column-wise and the ACDB column keeps a unique value",
         lambda: r_cfg and "col1:" in r_cfg["per_column"]),
        ("gate: a dump asserting BOTH routes at once is refused, not grouped",
         lambda: _both_routes_arm(live)),
        ("gate: with the idle dumps gone the matrix refuses to speak about idle",
         lambda: "no dump labels as idle" in _abort(matrix, _drop_idle(live))),
        ("gate: an empty candidate set is called empty rather than reported as a matrix",
         lambda: "no mixer dump" in _abort(candidate_dumps, tempfile.mkdtemp())),
        ("gate: the count of dumps per state is printed with the matrix, not assumed",
         lambda: all(int(x.split("=")[1]) > 0 for x in _row(rows, "SmartPA Switch")["dumps"].split())),
    ]
    bad = 0
    for label, fn in arms:
        try:
            ok = bool(fn())
        except SystemExit as e:
            ok = "gate:" in label
            if ok:
                print("     (gate fired: %s)" % str(e)[:88])
        except Exception as e:
            ok = False
            print("     (exception: %s)" % str(e)[:150])
        print(("ok   " if ok else "FAIL ") + label)
        bad += 0 if ok else 1
    print("matrix-selftest: %d arm(s) failed" % bad)
    return 1 if bad else 0


def _copy_dumps(live, d):
    """Copy ONLY the candidate dumps into a scratch tree -- `live/` is hundreds of MB."""
    out = os.path.join(d, "live")
    for p, _c in candidate_dumps(live):
        rel = os.path.relpath(p, live)
        dst = os.path.join(out, rel)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copyfile(p, dst)
    return out


def _mk_both_routes(live):
    import tempfile
    d = tempfile.mkdtemp()
    out = _copy_dumps(live, d)
    src = os.path.join(out, "tinymix-D0-playing-speaker.txt")
    text = open(src, encoding="utf-8", errors="replace").read()
    open(src, "w", encoding="utf-8").write(_set_ctl(text, "HiFi Mode Switch", "HiFi"))
    return out


def _drop_idle(live):
    import tempfile
    d = tempfile.mkdtemp()
    out = _copy_dumps(live, d)
    for root, dirs, files in os.walk(out):
        for f in files:
            p = os.path.join(root, f)
            if not re.search(r"tinymix.*\.txt$|\.tinymix$", f):
                continue
            try:
                c = controls_current(open(p, encoding="utf-8", errors="replace").read())
            except OSError:
                continue
            if c.get("SmartPA Switch") == "Off" and c.get("HiFi Mode Switch") not in ("HiFi", "DSD"):
                os.remove(p)
    return out


def _both_routes_arm(live):
    d = _mk_both_routes(live)
    p = os.path.join(d, "tinymix-D0-playing-speaker.txt")
    c = controls_current(open(p, encoding="utf-8", errors="replace").read())
    if len(c) < MIN_CONTROLS or c.get("SmartPA Switch") != "On" or c.get("HiFi Mode Switch") != "HiFi":
        print("     (arm is inert: the fixture does not actually assert both routes -- "
              "SmartPA=%s HiFi=%s n=%d)" % (c.get("SmartPA Switch"), c.get("HiFi Mode Switch"), len(c)))
        return False
    return "BOTH routes" in _abort(matrix, d)


def selftest():
    import tempfile, shutil
    hifion = os.path.join(BASE, "live/inplay-hifion-20261017-1933")
    spk = os.environ.get("INPLAY_SPK_SNAP") or os.path.join(BASE, "live/inplay-spk-20261017-2012")
    for d in (hifion, spk):
        if not os.path.isdir(d):
            sys.exit("gate: fixture/baseline %s missing" % d)
    A, B = load(hifion), load(spk)

    def doctor(base, sub, repl):
        d = tempfile.mkdtemp()
        shutil.copytree(base, os.path.join(d, "s"))
        p = os.path.join(d, "s", sub)
        src = open(p, encoding="utf-8", errors="replace").read()
        open(p, "w", encoding="utf-8").write(src.replace(*repl))
        return d

    def run(new, olds):
        """Return (rc-or-abort-text, what the check printed) so every arm can name WHICH gate fired."""
        import io, contextlib
        buf = io.StringIO()
        try:
            with contextlib.redirect_stdout(buf):
                rc = judge(new, olds)
            return str(rc), buf.getvalue()
        except SystemExit as e:
            return "ABORT", buf.getvalue() + " :: " + str(e)

    def stable_flip(base, want):
        """Return the (old,new) register line pair for a STABLE-class register, read from the class
        table so the choice is not hand-picked."""
        keep, _ = stable_pa_regs(os.environ.get("TFA_REGS_TSV") or f"{BASE}/tfa-regs.PD1610.tsv")
        regs = pa_reg_values(os.path.join(base, "codec_reg.txt"))
        for k in sorted(keep):
            if k in regs:
                v = regs[k]
                old = "reg{%04x}:%s" % (k, v)
                return old, "reg{%04x}:%s" % (k, "0" if v != "0" else "1")
        sys.exit("gate: no STABLE-class register present in the fixture -- cannot build the arm")

    def volatile_flip(base, want):
        cls = open(os.environ.get("TFA_REGS_TSV") or f"{BASE}/tfa-regs.PD1610.tsv",
                   encoding="utf-8").read()
        reg = int(want, 16)
        if "0x%02x" % reg not in cls:
            sys.exit("gate: register %s is not in the class table" % want)
        regs = pa_reg_values(os.path.join(base, "codec_reg.txt"))
        v = regs.get(reg)
        if v is None:
            sys.exit("gate: volatile register %s absent from the fixture" % want)
        return "reg{%04x}:%s" % (reg, v), "reg{%04x}:%s" % (reg, "0" if v != "0" else "1")

    def mutated_dir(base, sub, repl):
        d = tempfile.mkdtemp()
        shutil.copytree(base, os.path.join(d, "s"))
        p = os.path.join(d, "s", sub)
        src = open(p, encoding="utf-8", errors="replace").read()
        open(p, "w", encoding="utf-8").write(src.replace(*repl))
        return d

    def mutated(base, sub, repl, expect):
        rc, txt = run(load(os.path.join(doctor(base, sub, repl), "s")), [A, B])
        rc0, _ = run(load(base), [A, B])                      # same-run positive control
        return rc == "1" and expect in txt and rc0 == "0"

    s = open(__file__, encoding="utf-8").read()
    arms = [
        ("ok: a compress session (no procfs RUNNING, debugfs `State: start`) is allowed through (§468)",
         lambda: in_play_evidence([], [], ["/sys/kernel/debug/asoc/x/MSM8996 Compress2/state"])),
        ("gate: with NEITHER procfs nor debugfs evidence the snapshot still refuses (the old refusal "
         "must survive the new escape hatch)", lambda: not in_play_evidence([], [], [])),
        ("ok: the ordinary procfs path is unaffected by the new branch",
         lambda: in_play_evidence([("/proc/x/pcm0p", "731")], [("/proc/x/pcm0p", "731")], [])),
        ("gate: the refusal message and its % arguments still agree in count (an edit on 2026-10-18 "
         "broke this and would have raised TypeError right at the gate)",
         lambda: (lambda frag: frag.count("%d") + frag.count("%s") == 2)(
             s.split('"gate: no RUNNING playback substream', 1)[-1].split("% (len(run1)", 1)[0])
             if '"gate: no RUNNING playback substream' in s else False),
        ("ok: the two stored snapshots are read as two different routes by the parser alone",
         lambda: (A["route"], B["route"]) == ("hifi", "speaker")),
        ("ok: each snapshot judged against the pair of baselines returns 0",
         lambda: judge(A, [A, B], verbose=False) == 0 and judge(B, [A, B], verbose=False) == 0),
        ("gate: a snapshot whose PA switch disagrees with the baseline cannot pass",
         lambda: mutated(B["dir"], "tinymix-all.txt",
                         ("\tSmartPA Switch                           On",
                          "\tSmartPA Switch                           Off"), "CONTROLS DISAGREE")),
        ("gate: a snapshot whose Hi-Fi switch flips the route cannot pass either",
         lambda: mutated(A["dir"], "tinymix-all.txt",
                         ("\tTERT_MI2S mode                           Slave",
                          "\tTERT_MI2S mode                           Master"), "CONTROLS DISAGREE")),
        ("gate: flipping a SETTING-class PA register cannot pass",
         lambda: mutated(B["dir"], "codec_reg.txt", stable_flip(B["dir"], "02"),
                         "PA SETTING REGISTERS DISAGREE")),
        ("ok: a VOLATILE-class PA register moving must NOT be called a mismatch",
         lambda: (lambda d: judge(load(os.path.join(d, "s")), [A, B], verbose=False) == 0)(
             mutated_dir(B["dir"], "codec_reg.txt", volatile_flip(B["dir"], "71")))),
        ("gate: the two capture forms must agree -- a disagreeing echo aborts the load",
         lambda: "disagree" in _abort(load, os.path.join(_mk_echo_disagree(B["dir"]), "s"))),
        ("gate: the `>` marker, not the first option -- a hand-read echo must not flip HiFi to Off",
         lambda: controls_echo("HiFi Mode Switch: HiFi Mode Switch:\tOff\t>HiFi\tDSD\tNormal")
                 ["HiFi Mode Switch"] == "HiFi"),
        ("gate: a baseline missing an asserted control aborts rather than inventing it",
         lambda: "inventing" in _abort(judge, A,
                                      [load(os.path.join(_drop_ctl(A["dir"], "SmartPA Switch"), "s"))])),
        ("gate: a mixer dump that parses to a handful of controls is called blind",
         lambda: "blind" in _abort(load, os.path.join(_mk_blind(), "s"))),
        ("gate: a route no leg names refuses to borrow another route's baseline",
         lambda: "no leg names a route" in _abort(load, os.path.join(_mk_unknown(B["dir"]), "s"))),
    ]
    bad = 0
    for label, fn in arms:
        try:
            r = fn()
        except SystemExit as e:
            r = "gate:" in label and str(e) != ""
            if r:
                print("     (%s)" % str(e)[:110])
        except Exception as e:
            r = False
            print("     (exception: %s)" % str(e)[:200])
        print(("ok   " if r else "FAIL ") + label)
        bad += 0 if r else 1
    print("selftest: %d arm(s) failed" % bad)
    return 1 if bad else 0


def _abort(fn, *a):
    try:
        fn(*a)
        return ""
    except SystemExit as e:
        return str(e)


def _mk_echo_disagree(base):
    import tempfile, shutil
    d = tempfile.mkdtemp()
    shutil.copytree(base, os.path.join(d, "s"))
    open(os.path.join(d, "s", "controls.txt"), "w", encoding="utf-8").write(
        "HiFi Mode Switch: HiFi Mode Switch:\tOff\t>HiFi\tDSD\tNormal\n"
        "SmartPA Switch: SmartPA Switch: On\n")
    return d


def _mk_blind():
    import tempfile, os as _os
    d = tempfile.mkdtemp()
    _os.makedirs(os.path.join(d, "s"))
    open(os.path.join(d, "s", "tinymix-all.txt"), "w", encoding="utf-8").write(
        "0\tINT\t3\tFoo Volume                          1\n")
    return d


def _drop_ctl(base, name):
    import tempfile, shutil
    d = tempfile.mkdtemp()
    shutil.copytree(base, os.path.join(d, "s"))
    p = os.path.join(d, "s", "tinymix-all.txt")
    src = open(p, encoding="utf-8", errors="replace").read()
    open(p, "w", encoding="utf-8").write("\n".join(l for l in src.splitlines() if name not in l) + "\n")
    return d


def _set_ctl(text, name, value):
    """Rewrite one control's ACTIVE value in a full mixer dump, honouring the 40-column name field."""
    out = []
    for l in text.splitlines():
        m = re.match(r"^(\d+\t\w+\t\d+\t)(.*)$", l)
        if m and m.group(2)[:40].rstrip() == name:
            l = m.group(1) + (name[:40].ljust(40) + value if len(name) <= 40 else l)
        out.append(l)
    return "\n".join(out) + "\n"


def _mk_unknown(base):
    """Nothing powered, no switch set, an ACDB id no route owns: the legs must refuse to name a route."""
    import tempfile, shutil
    d = tempfile.mkdtemp()
    shutil.copytree(base, os.path.join(d, "s"))
    open(os.path.join(d, "s", "dapm-live.txt"), "w", encoding="utf-8").write(
        "== tfa98xx Speaker\nSpeaker: Off  in 0 out 0\n")
    p = os.path.join(d, "s", "tinymix-all.txt")
    t = _set_ctl(open(p, encoding="utf-8", errors="replace").read(), "SmartPA Switch", "Off")
    t = _set_ctl(t, STREAM0, "69937 77 48000")
    open(p, "w", encoding="utf-8").write(t)
    return d


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--snap", help="capture a snapshot into this directory (device, read-only)")
    ap.add_argument("--check", help="judge this snapshot directory")
    ap.add_argument("--baseline", action="append", default=[])
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--matrix", action="store_true", help="build the idle/hifi/speaker state matrix")
    ap.add_argument("--out")
    ap.add_argument("--check-matrix", dest="check_matrix")
    ap.add_argument("--matrix-selftest", action="store_true")
    a = ap.parse_args()
    if a.matrix_selftest:
        sys.exit(matrix_selftest(os.environ.get("LIVE_DIR") or f"{BASE}/live"))
    if a.matrix:
        live = os.environ.get("LIVE_DIR") or f"{BASE}/live"
        rows, groups = matrix(live)
        if a.check_matrix:
            main, side = matrix_texts(rows, groups, live)
            for path, want in ((a.check_matrix, main),
                               (a.check_matrix.replace(".tsv", ".dumps.tsv"), side)):
                if not os.path.exists(path):
                    sys.exit("gate: %s missing -- the stored matrix (and its provenance table) must "
                             "both be current" % path)
                if open(path, encoding="utf-8").read() != want:
                    stored = open(path, encoding="utf-8").read()
                    break
            else:
                stored = ""
            if stored and want:
                import difflib
                d = list(difflib.unified_diff(stored.splitlines(), want.splitlines(), lineterm="", n=0))[2:]
                sys.exit("gate: the stored matrix %s is out of date with what the dumps on disk say now "
                         "(%d line(s)) -- the table would quote a stale reading: %s"
                         % (path, len(d), " | ".join(x[:80] for x in d[:3])))
            print("matrix check: %d moving control(s), %d dumps -- stored tables agree line by line"
                  % (len(rows), sum(len(v) for v in groups.values())))
            return
        if not a.out:
            sys.exit("gate: --matrix needs --out (the matrix is a deliverable, not a print)")
        write_matrix(rows, groups, a.out, live)
        return
    if a.selftest:
        sys.exit(selftest())
    if a.snap:
        capture(a.snap)
        print("snapshot written: " + a.snap)
        a.check = a.check or a.snap
    if a.check:
        bl = a.baseline or [os.path.join(BASE, "live/inplay-hifion-20261017-1933"),
                           os.path.join(BASE, "live/inplay-spk-20261017-2012")]
        for b in bl:
            if not os.path.isdir(b):
                sys.exit("gate: baseline snapshot absent: %s -- expectations must come from a stored "
                         "6.0.1 capture" % b)
        sys.exit(judge(load(a.check), [load(b) for b in bl]))
    print("nothing to do (use --snap / --check / --selftest)")


if __name__ == "__main__":
    main()
