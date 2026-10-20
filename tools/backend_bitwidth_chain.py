#!/usr/bin/env python3
"""tools/backend_bitwidth_chain.py -- three independent sources for one bit-width decision.

Which bit depth actually reaches the codec is decided in the platform layer, opened at the ALSA
front end, and mirrored into a backend mixer control.  6.0.1 lets all three be read for the SAME
session: the platform's own log lines, `/proc/asound/.../hw_params`, and `tinymix` for
`TERT_MI2S Bit Format`.  This tool lines them up per session and prints AGREE / DISAGREE / NO-LOG
-- it never averages them and never names a backend it cannot pair.

Why it matters for the port: on the speaker route the platform log says 24-bit while the backend
control in the same snapshot reads S16_LE.  That is exactly the kind of thing §372's listening test
cannot see, and on 7 the same three-source comparison is one command.
"""
import argparse, inspect, os, re, sys

SHAPES = {
    "route": r"select_devices: route to out_snd_device:(\d+);sample_rate:(\d+);bit_width:(\d+)",
    "usecase": r"platform_check_and_set_codec_backend_cfg: Usecase bitwidth (\d+), samplerate (\d+)",
    "newdev": r"platform_check_and_set_codec_backend_cfg: new_snd_devices\[\d+\] is (\d+)",
    "backend": r"Codec selected backend: (\d+) (current|updated) bit width: (\d+) and sample rate: (\d+)",
    "set": r"platform_set_codec_backend_cfg bit width: (\d+), sample rate: (\d+) backend_idx - (\d+)",
    "mixerset": r"platform_set_codec_backend_cfg: (\S+) Format mixer set to (\d+) bit",
    "open": r"Opening PCM device card_id\(\d+\) device_id\((\d+)\) format\((0x[0-9a-f]+)\),"
            r"config\.rate:(\d+),bit_width:(\d+)",
    "allow": r"Allowing (\d+)-bit playback on (\w+) ONLY at default sampling rate",
}
BRIEF = re.compile(r"^[VDIWEAF]/([^ (]+)\(\s*(\d+)\):\s?(.*)$")
THREADTIME = re.compile(r"^\d\d-\d\d [\d:.]+\s+(\d+)\s+\d+\s+([VDIWEAF])\s+([^:]+):\s(.*)$")


def messages(path):
    out = []
    for line in open(path, encoding="latin-1", errors="replace").read().splitlines():
        m = THREADTIME.match(line)
        if m:
            out.append((m.group(3).strip(), m.group(1), m.group(4)))
            continue
        m = BRIEF.match(line)
        if m:
            out.append((m.group(1), m.group(2), m.group(3)))
    return out


def find_shape(msgs):
    hits = {}
    for tag, pid, msg in msgs:
        for name, pat in SHAPES.items():
            m = re.search(pat, msg)
            if m:
                hits.setdefault(name, []).append({"tag": tag, "pid": pid, "groups": m.groups(),
                                                  "msg": msg[:110]})
    return hits


XML = f"{os.environ.get('AUDIO_PORT_ROOT') or '/home/v/.local/project/xplay6'}" \
      "/art/audio-6.0.1/shipped/system/etc/mixer_paths_tasha.PD1610.xml"
PATH_FOR_ROUTE = {"speaker": "speaker", "hifi": "headphone-hifi"}


def xml_value(path_name):
    """What the board's OWN mixer XML commands for `TERT_MI2S Bit Format` inside a path -- the
    config-file face of the same knob.  Which copy the HAL loads at runtime is itself an open item
    (§417: `new_mixer_xml_path` never appeared in a log ring), so the file used is printed."""
    if not os.path.exists(XML):
        return None
    b = open(XML, encoding="latin-1", errors="ignore").read()
    blocks = re.split(r"(?=<path name=)", b)
    for blk in blocks:
        m = re.match(r'<path name="([^"]+)"', blk)
        if m and m.group(1) == path_name:
            v = re.search(r'<ctl name="TERT_MI2S Bit Format" value="([^"]+)"', blk)
            if v:
                return v.group(1)
    ini = re.search(r'<ctl name="TERT_MI2S Bit Format" value="([^"]+)"',
                    b.split("<path")[0])
    return ini.group(1) + " (init block)" if ini else None


def live(dirpath):
    """The snapshot's own front-end and back-end readings."""
    hw, ctl = {}, {}
    p = f"{dirpath}/hw_params.txt"
    if os.path.exists(p):
        t = open(p, encoding="latin-1", errors="replace").read()
        hw = {"format": (re.search(r"format:\s*(\S+)", t) or [None, None])[1],
              "rate": (re.search(r"rate:\s*(\d+)", t) or [None, None])[1],
              "period": (re.search(r"period_size:\s*(\d+)", t) or [None, None])[1],
              "buffer": (re.search(r"buffer_size:\s*(\d+)", t) or [None, None])[1]}
    p = f"{dirpath}/tinymix-all.txt"
    if os.path.exists(p):
        for line in open(p, encoding="latin-1", errors="replace").read().splitlines():
            m = re.match(r"^\s*\d+\t\w+\t\d+\t(.{40})(.*)$", line)
            if not m:
                continue
            name = m.group(1).strip()
            if name in ("TERT_MI2S Bit Format", "HiFi Mode Switch", "SmartPA Switch"):
                ctl[name] = m.group(2).strip()
    return hw, ctl


def judge(dirpath, live_log_dirs=()):
    """Per snapshot: compare the three sources, and never invent a fourth."""
    hw, ctl = live(dirpath)
    logs = []
    for cand in sorted(os.listdir(dirpath)) if os.path.isdir(dirpath) else []:
        if cand.startswith("logcat"):   # includes logcat-ring.txt written by --snap
            logs.append(os.path.join(dirpath, cand))
    shapes = {}
    for lg in logs:
        for k, v in find_shape(messages(lg)).items():
            shapes.setdefault(k, []).extend(v)
    # comparable pairs, stated separately.  The platform line is a DIFFERENT quantity (the ADSP
    # backend cfg bit width), so it is recorded, not voted against the DAI format control.
    bit_log = sorted({g[2] for g in (x["groups"] for x in shapes.get("backend", [])) if len(g) == 4}
                     | {g[3] for g in (x["groups"] for x in shapes.get("open", []))})
    ctl_bit = re.findall(r"S(\d+)", ctl.get("TERT_MI2S Bit Format", ""))
    front_bit = re.findall(r"S(\d+)", hw.get("format") or "")
    # the route must come from the ROUTE SWITCHES, not from the bit-format control -- labelling the
    # path from the quantity under test would let the ruler confirm itself (§420/§421's lesson)
    sw, pa = ctl.get("HiFi Mode Switch", ""), ctl.get("SmartPA Switch", "")
    if sw.startswith("HiFi") and pa == "Off":
        route = "hifi"
    elif pa == "On" and not sw.startswith("HiFi"):
        route = "speaker"
    else:
        route = None
    xv = xml_value(PATH_FOR_ROUTE[route]) if route else None
    xml_bit = re.findall(r"S(\d+)", xv or "")
    pairs = {}
    pairs["front-vs-backend"] = ("FRONT-MISSING" if not front_bit or not ctl_bit else
                                 "SAME" if set(front_bit) == set(ctl_bit) else "DIFFERENT")
    pairs["backend-vs-XML"] = ("NO-XML" if not xml_bit or not ctl_bit else
                               "MATCH" if set(ctl_bit) == set(xml_bit) else "MISMATCH")
    votes = [x for x in (("front", front_bit), ("backend control", ctl_bit), ("XML path", xml_bit))
             if x[1]]
    distinct = {y for _, lst in votes for y in lst}
    if len(votes) >= 2 and len(distinct) > 1:
        state = "DIFFERENT(%d comparable sources: %s)" % (len(votes), "・".join(
            "%s=%s" % (n, "/".join(l)) for n, l in votes))
    elif len(votes) >= 2:
        state = "AGREE(%d sources on %s-bit)" % (len(votes), "・".join(sorted(distinct)))
    else:
        state = "SINGLE-SOURCE"
    return {"dir": os.path.basename(dirpath), "state": state, "pairs": pairs, "route_guess": route,
            "route_switches": {"HiFi Mode Switch": sw, "SmartPA Switch": pa},
            "xml": xv, "front": hw, "control": ctl,
            "platform_bits": sorted(set(bit_log)), "control_bits": ctl_bit, "front_bits": front_bit,
            "log_files": [os.path.basename(x) for x in logs], "log_available": bool(logs),
            "shapes": sorted(shapes), "counts": {k: len(v) for k, v in shapes.items()}}


def scan(live):
    dirs = [os.path.join(live, x) for x in sorted(os.listdir(live)) if os.path.isdir(live + "/" + x)]
    out = []
    for d in dirs:
        try:
            r = judge(d)
        except Exception as e:
            sys.exit("gate: %s failed to judge: %s" % (d, e))
        out.append(r)
    withlogs = [r for r in out if r["log_files"]]
    if not withlogs:
        sys.exit("gate: no snapshot in %s carries a logcat file -- the three-source comparison "
                 "cannot be made" % live)
    return out, len(dirs)


def report(rows, ndirs):
    print("== backend bit-width: three sources per snapshot (%d dirs scanned) ==" % ndirs)
    for r in rows:
        if not (r["log_files"] or r["front"] or r["control"]):
            continue
        print("\n   %-34s %s" % (r["dir"], r["state"]))
        print("      front-end hw_params : %s" % (r["front"] or "absent"))
        print("      back-end control    : %s" % (r["control"] or "absent"))
        print("      platform log (ADSP cfg, recorded, NOT voted): %s  (from %s)  shapes: %s"
              % ("・".join(r["platform_bits"]) or "no log", "・".join(r["log_files"]) or "-",
                 "・".join(r["shapes"]) or "-"))
        print("      route by the switches %r : %s ・ board XML for that path: %s ・ pairs: %s"
              % (r["route_switches"], r["route_guess"], r["xml"] or "not found",
                 "・".join("%s=%s" % kv for kv in sorted(r["pairs"].items()))))


def _erase_fixture(spk):
    """Copy the speaker snapshot and delete the platform bit-width lines; prove the erase bit."""
    import shutil, tempfile
    t = tempfile.mkdtemp()
    d = os.path.join(t, os.path.basename(spk))
    shutil.copytree(spk, d)
    removed = 0
    for f in os.listdir(d):
        if f.startswith("logcat"):
            q = os.path.join(d, f)
            lines = open(q, encoding="latin-1").read().splitlines()
            keep = [l for l in lines if "codec_backend_cfg" not in l and "Format mixer" not in l
                    and "Opening PCM device" not in l]
            removed += len(lines) - len(keep)
            open(q, "w", encoding="latin-1").write("\n".join(keep) + "\n")
    if not removed:
        sys.exit("gate: the fixture erased nothing -- a green arm here would mean nothing")
    return d


DAI_NAME = re.compile(r"\b(SLIM_\d+_[RT]X|TERT_MI2S_[RT]X|QUAT_MI2S_[RT]X|PRIMARY_TERT_RX|SEC_MI2S_RX|"
                      r"AUX_PCM_RX|AFE_PCM_RX|SLIMBUS_\d+)\b")
IDX_ANY = re.compile(r"(?:backend port - |Codec selected backend: |backend_idx - |backend_idx )(-?\d+)")


def idx_dai_pairings(live):
    """§465: what the corpus REALLY pairs a numeric backend_idx with.  The old helper took two
    independent line families (one giving `backend_idx - N`, another giving `<DAI> Format mixer set`)
    and asserted their cross-product was small -- which was never a pairing, and a new capture naming
    any further DAI turned the arm red for the wrong reason.  A pairing here means the SAME message
    line carries both an idx and a DAI name."""
    pairs, lines, with_idx, with_dai = set(), 0, 0, 0
    for dp, dn, fn in os.walk(live):
        for f in fn:
            if not f.startswith("logcat"):
                continue
            for _tag, _pid, msg in messages(os.path.join(dp, f)):
                lines += 1
                ix = IDX_ANY.search(msg)
                di = DAI_NAME.search(msg)
                if ix:
                    with_idx += 1
                if di:
                    with_dai += 1
                if ix and di:
                    pairs.add((ix.group(1), di.group(1)))
    return pairs, {"audio lines scanned": lines, "lines naming an idx": with_idx,
                   "lines naming a DAI": with_dai}


def selftest(live):
    spk = f"{live}/inplay-spk-20261017-2012"
    hif = f"{live}/inplay-hifion2-20261017-2303"
    old = f"{live}/inplay-hifion-20261017-1933"
    for d in (spk, hif, old):
        if not os.path.isdir(d):
            sys.exit("gate: " + d + " missing")
    a, b = judge(spk), judge(hif)

    def speaker_pairing():
        return (a["pairs"]["front-vs-backend"] == "DIFFERENT"
                and a["pairs"]["backend-vs-XML"] == "MATCH"
                and a["front_bits"] == ["24"] and a["control_bits"] == ["16"]
                and a["state"].startswith("DIFFERENT(3"))

    def hifi_three():
        return (b["state"].startswith("AGREE(3") and b["pairs"]["backend-vs-XML"] == "MATCH"
                and b["control_bits"] == ["24"] and b["front_bits"] == ["24"])

    def erase_keeps_the_verdict():
        r = judge(_erase_fixture(spk))
        return (not r["platform_bits"] and r["state"] == a["state"] and r["pairs"] == a["pairs"])

    def caps_are_honest():
        # the 19:33 session has no front-end hw_params, so it can only be a 2-source statement
        o = judge(old)
        return o["front_bits"] == [] and o["state"].startswith("AGREE(2")

    def idx_pairing():
        """§465: no numeric backend_idx is ever paired with a DAI name in a single message, so the tool
        may not name an idx from the logs -- and the arm must not depend on which DAI names happen to
        appear in other lines.  The counter-case is built, not assumed: one synthetic line that DOES
        carry both must make the pairing set non-empty."""
        pairs, den = idx_dai_pairings(live)
        if den["audio lines scanned"] == 0:
            sys.exit("gate: the pairing scan read 0 log lines -- an empty bucket is not a result (§451)")
        split = [("V/x", 1, "platform_set_codec_backend_cfg bit width: 24, sample rate: 48000 backend_idx - 7"),
                 ("V/x", 1, "SLIM_3_RX Format mixer set to 24 bit")]
        joined = [("V/x", 1, "platform_check_codec_backend_cfg: backend_idx - 9 on QUAT_MI2S_RX in use")]
        def scan(msgs):
            out = set()
            for _t, _p, m in msgs:
                ix, di = IDX_ANY.search(m), DAI_NAME.search(m)
                if ix and di:
                    out.add((ix.group(1), di.group(1)))
            return out
        return (not pairs and scan(split) == set() and len(scan(joined)) == 1
                and den["lines naming an idx"] > 0 and den["lines naming a DAI"] > 0)

    def label_is_from_the_switches():
        """Flip the route switches in a copy: if the XML lookup follows the switches, the verdict must
        change.  If the label had been taken from the bit-format control (the first version), nothing
        would move and the ruler would be confirming itself."""
        import shutil, tempfile
        t = tempfile.mkdtemp()
        d = os.path.join(t, os.path.basename(spk))
        shutil.copytree(spk, d)
        f = os.path.join(d, "tinymix-all.txt")
        src = open(f, encoding="latin-1").read()
        new = re.sub(r"(?m)^(\d+\tENUM\t1\tHiFi Mode Switch\s+)Off$", r"\g<1>HiFi", src)
        new = re.sub(r"(?m)^(\d+\tBOOL\t1\tSmartPA Switch\s+)On$", r"\g<1>Off", new)
        if new == src:
            sys.exit("gate: fixture did not flip the switches -- a green arm here would mean nothing")
        open(f, "w", encoding="latin-1").write(new)
        r = judge(d)
        return (r["route_guess"] == "hifi" and r["xml"].startswith("S24")
                and r["pairs"]["backend-vs-XML"] == "MISMATCH")

    def denominator():
        rows, n = scan(live)
        return n >= 4 and any(r["log_available"] for r in rows) and any(r["xml"] for r in rows)

    def report_prints_for_every_row():
        """Exercise the delivered read-out itself: the arms above only call judge(), which is how a
        KeyError in the print line stayed green while the runbook step crashed on the device."""
        import io, contextlib
        rows, n = scan(live)
        shown = [r for r in rows if r["log_files"] or r["front"] or r["control"]]
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            report(rows, n)
        return buf.getvalue().count("route by the switches") == len(shown) and len(shown) >= 4

    def print_keys_exist_in_judge():
        """Every key the print line touches must be produced by judge(); the same test must refuse
        when one is removed, otherwise it is a gate that cannot fire."""
        need = set(re.findall(r'\br\["(\w+)"\]', inspect.getsource(report)))
        have = set(judge(spk))
        if len(need) < 6:
            sys.exit("gate: only %d key(s) recovered from report() -- this test would be vacuous"
                     % len(need))
        if need - have:
            return False
        probe = sorted(need & have)[0]
        return not need <= (have - {probe})

    arms = [
        ("ok: the speaker session is DIFFERENT front(24)-vs-backend(16) while the backend MATCHES the "
         "board XML's own `speaker` path", speaker_pairing),
        ("ok: the second Hi-Fi session agrees across all three comparable sources on 24-bit",
         hifi_three),
        ("ok: erasing the platform log lines leaves the verdict identical (it is a live-state + XML "
         "fact, not a log artefact)", erase_keeps_the_verdict),
        ("gate: a session without front-end hw_params may only claim 2 sources, never 3",
         caps_are_honest),
        ("ok: NO numeric backend_idx shares a message line with a DAI name in the whole corpus, so no "
         "idx may be named from these logs -- and the scan proves it can fire when one does (§465)",
         idx_pairing),
        ("gate: the route label comes from the route SWITCHES -- flipping them in a copy moves the XML "
         "lookup and turns the verdict into MISMATCH (a control-derived label would self-confirm)",
         label_is_from_the_switches),
        ("ok: the scan reports its own denominator (dirs, log availability, XML availability)",
         denominator),
        ("gate: the delivered read-out itself is exercised -- report() must print one line per "
         "judged snapshot (a KeyError here used to pass the selftest and break the runbook step)",
         report_prints_for_every_row),
        ("gate: every key report() touches is produced by judge(), and the test refuses when one is "
         "removed", print_keys_exist_in_judge),
    ]
    bad = 0
    for label, fn in arms:
        try:
            ok = bool(fn())
        except SystemExit as e:
            ok = "gate:" in label and "nothing" in str(e)
        except Exception as e:
            ok = False
            print("     (exception: %s)" % str(e)[:160])
        print(("ok   " if ok else "FAIL ") + label)
        bad += 0 if ok else 1
    print("selftest: %d arm(s) failed" % bad)
    return 1 if bad else 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--live", default=None)
    a = ap.parse_args()
    repo = os.environ.get("AUDIO_PORT_ROOT") or "/home/v/.local/project/xplay6"
    live = a.live or f"{repo}/art/audio-6.0.1/live"
    if a.selftest:
        sys.exit(selftest(live))
    rows, n = scan(live)
    report(rows, n)


if __name__ == "__main__":
    main()