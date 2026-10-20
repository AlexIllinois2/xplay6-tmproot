#!/usr/bin/env python3
"""Derive the carry-list expectations from the shipped audio CONFIGURATION FILES, not by reading them.

Why this layer exists: the audit that produced ledger 402 found 27 xml/conf files captured on disk but
`port-target.PD1610.tsv` had essentially no rows for them -- so the procedure could not check them on
7.  These files are the *input* that produces much of what the live readings show:

  * `mixer_paths_tasha.PD1610.xml` -- the board file that defines `SmartPA Switch` (the single route
    cell ledger 298/299 proved 外放 needs) and `HiFi Mode Switch`; the generic `mixer_paths.xml`
    defines neither, so WHICH FILE the HAL picks is itself a port-critical fact.
  * `audio_platform_info.xml` -- `SND_DEVICE_OUT_SPEAKER -> acdb_id 15` (the id the live ACDB reading
    reported), a 24-bit speaker width, and the vivo `HEADPHONE_HIFI` / `HEADPHONE_HIFI_DSD` devices.
  * `audio_policy.conf` -- the `direct_pcm` profile with rates to 192000, i.e. the Hi-Fi path.

Every number printed here is parsed from the file in this run; a gate aborts when a claim the
procedure depends on is not actually in the file (e.g. if `SmartPA Switch` disappeared from the board
mixer file, the route rows would lose their file-level provenance and the runbook must say so).

Usage:
  python3 tools/audio_cfg_files.py                 # report
  python3 tools/audio_cfg_files.py --tsv OUT.tsv   # also write the summary table
  python3 tools/audio_cfg_files.py --selftest      # prove the gates can fire
"""
import os, re, subprocess, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# Overridable so the SAME tool runs against an extracted Android 7 system/etc -- this layer exists to
# compare the file-level contract byte-for-byte across versions, not to re-read it by hand.
ETC = os.environ.get("AUDIO_CFG_ETC") or os.path.join(ROOT, "art/audio-6.0.1/shipped/system/etc")
ROUTES = os.environ.get("AUDIO_CFG_ROUTES") or os.path.join(ROOT, "art/audio-6.0.1/route-states.tsv")
CARDS = os.environ.get("AUDIO_CFG_CARDS") or os.path.join(ROOT, "art/audio-6.0.1/live/cards.txt")
GETPROP = os.environ.get("AUDIO_CFG_GETPROP") or os.path.join(ROOT, "art/audio-6.0.1/live/getprop.txt")
BOARD_MIX = "mixer_paths_tasha.PD1610.xml"
GENERIC_MIX = "mixer_paths.xml"
PLATFORM = "audio_platform_info.xml"
POLICY = "audio_policy.conf"
CRITICAL_CTLS = ("SmartPA Switch", "HiFi Mode Switch")
HIFI_DEVICES = ("SND_DEVICE_OUT_HEADPHONE_HIFI", "SND_DEVICE_OUT_HEADPHONE_HIFI_DSD")


def read(path):
    if not os.path.exists(path):
        sys.exit(f"gate: {path} is not in the extract -- this layer is derived from these files, "
                 "so a missing one is a capture gap, not a zero")
    return open(path, encoding="utf-8", errors="replace").read()


def mixer_summary(path):
    t = read(path)
    paths = re.findall(r'<path name="([^"]+)"', t)
    ctls = re.findall(r'<ctl name="([^"]+)"', t)
    return {"paths": len(paths), "distinct_paths": len(set(paths)), "ctls": len(ctls),
            "distinct_ctls": len(set(ctls)), "ctl_set": set(ctls),
            "critical": {c: t.count(f'"{c}"') for c in CRITICAL_CTLS},
            "size": os.path.getsize(path)}


def platform_summary(path):
    t = read(path)
    acdb = dict(re.findall(r'<device name="([^"]+)" acdb_id="(\d+)"', t))
    bits = dict(re.findall(r'<device name="([^"]+)" bit_width="(\d+)"', t))
    devices = re.findall(r'<device name="([^"]+)"', t)
    # backends are ATTRIBUTES on <device .../> inside <backend_names> -- a `<backend name=` search
    # finds nothing in a file that plainly declares eight of them, so parse the real shape.
    back = re.findall(r'<device name="([^"]+)"\s+backend="([^"]+)"\s+interface="([^"]+)"', t)
    section = re.search(r"<backend_names>(.*?)</backend_names>", t, re.S)
    if section and not back:
        sys.exit("gate: backend_names has content but no device/backend/interface triple was parsed "
                 "-- the parser is blind, and '0 backends' would be a false claim")
    return {"acdb": acdb, "bits": bits, "devices": len(devices), "distinct_devices": len(set(devices)),
            "backends": len(back), "backend_rows": back,
            "hifi": {h: (h in devices) for h in HIFI_DEVICES},
            "params": dict(re.findall(r'<param key="([^"]+)"\s+value="([^"]*)"', t)),
            "native": re.findall(r'<feature name="([^"]+)"', t), "size": os.path.getsize(path)}


def effects_summary(path):
    """audio_effects.conf -- brace-depth tokenizer, NOT a lazy regex: an earlier draft stopped at the
    first line-initial `}` and reported 1 library of 7.  The internal control is structural: every
    library element carries exactly one `path` line, so libraries must equal the path-line count."""
    import re as _re
    t = _re.sub(r"#[^\n]*", "", read(path))
    depth = 0
    section = None
    pending = None
    prev = None
    libs, effs = [], []
    for m in _re.finditer(r"[{}]|[A-Za-z][\w.]*", t):
        s2 = m.group(0)
        if s2 == "{":
            depth += 1
            if depth == 1 and pending:
                section, pending = pending, None
            elif depth == 2 and section == "libraries":
                libs.append(prev)
            elif depth == 2 and section == "effects":
                effs.append(prev)
        elif s2 == "}":
            depth -= 1
            if depth == 0:
                section = None
        else:
            prev = s2
            if depth == 0 and s2 in ("libraries", "effects"):
                pending = s2
    npath = len(_re.findall(r"\bpath\b", t))
    nuuid = len(_re.findall(r"\buuid\b", t))
    # compare the RAW list, not the set: a file may declare the same library name twice, and deduping
    # here hid exactly that on the vendor copy (14 unique names, 15 `path` lines).
    if len(libs) != npath:
        sys.exit(f"gate: {path} parses {len(set(libs))} libraries but declares {npath} `path` lines "
                 "-- the tokenizer is blind; fix it rather than quoting a wrong count")
    dupes = sorted({x for x in libs if libs.count(x) > 1})
    return {"libs": sorted(set(libs)), "effects": sorted(set(effs)), "paths": npath, "uuids": nuuid,
            "declared_lib_entries": len(libs), "duplicate_lib_names": dupes,
            "size": os.path.getsize(path)}


def policy_summary(path):
    t = read(path)
    # profiles are `name {` blocks; keep the sampling_rates of each (comments kept as evidence)
    prof = {}
    for m in re.finditer(r"^\s{0,8}([a-zA-Z_][\w]*)\s*\{\s*$((?:[^\n]*\n)*?)\s*\}", t, re.M):
        body = m.group(2)
        rates = re.findall(r"sampling_rates\s+([0-9|]+)", body)
        flags = re.findall(r"flags\s+(.+)", body)
        if rates:
            prof[m.group(1)] = {"rates": rates, "flags": flags,
                                "commented_rates": len(re.findall(r"#\s*sampling_rates", body))}
    return prof


def live_controls():
    if not os.path.exists(ROUTES):
        return None
    rows = [l.split("\t") for l in open(ROUTES, encoding="utf-8").read().splitlines() if l.strip()]
    return {r[0] for r in rows[1:]}



def live_card_token2():
    """Second '-' token of the sound-card name, from the live capture (cards.txt line for card 0)."""
    p = CARDS
    if not os.path.exists(p):
        sys.exit("gate: live/cards.txt missing -- the composed mixer filename needs the card name, "
                 "and guessing it from the board model is exactly the mistake this function exists "
                 "to prevent")
    txt = open(p, encoding="utf-8", errors="replace").read()
    for line in txt.splitlines():
        if ":" not in line:
            continue
        tail = line.split(":", 1)[1].strip()
        name = tail.split("-snd-card")[0] + "-snd-card" if "-snd-card" in tail else tail.split()[0]
        toks = name.split("-")
        if len(toks) >= 2:
            return toks[1], name
    sys.exit("gate: no card line parsed out of cards.txt -- reader is blind")


def live_model_prop():
    p = GETPROP
    if not os.path.exists(p):
        sys.exit("gate: live/getprop.txt missing -- ro.vivo.product.model is the second half of the "
                 "composed mixer filename")
    m = re.search(r"\[ro\.vivo\.product\.model\]: \[(.*?)\]",
                  open(p, encoding="utf-8", errors="replace").read())
    if m and m.group(1).strip():
        return m.group(1).strip()
    for line in open(p, encoding="utf-8", errors="replace"):
        pass
    sys.exit("gate: ro.vivo.product.model not found in getprop.txt -- the suffix leg has no value")


def loaded_file_evidence(cands, live):
    """Which mixer file the HAL loaded, from two legs that must agree -- stated at the strength the
    evidence actually has.

    Leg 1 (controls) is a REFUTATION test, not a proof: if a file defines a control that no other
    candidate defines and that control is NOT live, the file was not loaded.  A file that survives is
    only *compatible* -- `mixer_paths_tasha.PD1610LG4.xml` shares every control with PD1610, so it has
    zero unique controls and cannot be refuted by controls at all.  Leg 1 also names the positive
    control that makes it bite: PD1610's `MultiMedia5 Mixer AUX_PCM_TX` is live and is defined by no
    other candidate, so some file that defines it was read.
    Leg 2 (the composed name): the HAL builds "/system/etc/mixer_paths" + "_" + <card name token 2>
    + ".xml", then inserts "." + ro.vivo.product.model before the last dot (ledger 411/412 read off
    the instructions at 0x16074-0x160c4 and the helper at 0x140ec).  That is what separates siblings.
    The answer is the intersection: compatible AND equal to the composed name.  Anything else aborts.
    """
    per = {n: set(re.findall(r'<ctl name="([^"]+)"', text)) for n, text in cands.items()}
    if not per:
        sys.exit("gate: no mixer candidates parsed -- nothing can explain the live controls")
    compatible, refuted, discriminating = [], [], []
    for name, cs in per.items():
        others = set().union(*[v for k, v in per.items() if k != name]) if len(per) > 1 else set()
        uniq = sorted(cs - others)
        dead = [c for c in uniq if c not in live]
        if dead:
            refuted.append((name, len(uniq), dead))
        else:
            compatible.append((name, len(uniq)))
        if uniq and not dead:
            discriminating.append((name, uniq))
    if not refuted:
        sys.exit("gate: no candidate was refuted by its own unique controls -- the test cannot bite "
                 "(the live capture is missing every control every file defines)")
    if not discriminating:
        sys.exit("gate: no candidate has a unique control that IS live, so leg 1 proves nothing "
                 "about which file was read -- only its refutations")
    tok2, card = live_card_token2()
    model = live_model_prop()
    composed = "mixer_paths_%s.%s.xml" % (tok2, model)
    comp_names = [n for n, _ in compatible]
    if composed not in comp_names:
        sys.exit("gate: the composed name %s (card %r token 2 = %r, model = %r) is not compatible "
                 "with the live controls (%s) -- rule and evidence disagree, so neither may be quoted"
                 % (composed, card, tok2, model, ", ".join(comp_names)))
    if composed in [n for n, _, _ in refuted]:
        sys.exit("gate: %s was refuted yet matched the composed name -- internal contradiction"
                 % composed)
    return composed, compatible, refuted, discriminating, card, tok2, model


def report():
    board = mixer_summary(os.path.join(ETC, BOARD_MIX))
    generic = mixer_summary(os.path.join(ETC, GENERIC_MIX))
    plat = platform_summary(os.path.join(ETC, PLATFORM))
    pol = policy_summary(os.path.join(ETC, POLICY))
    live = live_controls()

    # gates: claims the rest of the procedure leans on must actually be in these files
    for c in CRITICAL_CTLS:
        if not board["critical"][c]:
            sys.exit(f"gate: `{c}` is not in {BOARD_MIX} -- the route rows lose their file-level "
                     "provenance; check the capture before quoting route cells")
    if generic["critical"]["SmartPA Switch"]:
        sys.exit(f"gate: {GENERIC_MIX} also defines SmartPA Switch -- the claim that the BOARD file "
                 "must be selected is no longer true; rewrite the row, do not leave it stale")
    if "SND_DEVICE_OUT_SPEAKER" not in plat["acdb"]:
        sys.exit("gate: audio_platform_info.xml has no acdb_id for SND_DEVICE_OUT_SPEAKER, so the "
                 "live acdb_dev_id reading has no file-side partner")

    print(f"# {BOARD_MIX}: {board['paths']} paths ({board['distinct_paths']} distinct), "
          f"{board['ctls']} ctl refs ({board['distinct_ctls']} distinct), {board['size']} B")
    print(f"   critical controls in the board file: "
          + " ".join(f"{k}={v}" for k, v in board["critical"].items()))
    print(f"# {GENERIC_MIX}: {generic['paths']} paths, {generic['distinct_ctls']} distinct ctls, "
          f"{generic['size']} B -- SmartPA Switch present: {generic['critical']['SmartPA Switch']} "
          "(so HAL file selection matters)")
    if live is not None:
        in_live = len(board["ctl_set"] & live)
        only_file = board["ctl_set"] - live
        only_live = live - board["ctl_set"]
        print(f"# live control cross-check ({os.path.basename(ROUTES)}: {len(live)} controls): "
              f"file-and-live = {in_live}, file-only {len(only_file)}, live-only {len(only_live)} "
              f"({100*len(only_live)/len(live):.1f}% of live controls are NOT in the board mixer file "
              "= driver-built controls)")
        for k in CRITICAL_CTLS:
            print(f"     {k}: in-file {board['critical'][k]}, in-live {k in live}")
        print("     live-only examples (driver-built, not from this file): "
              + ", ".join(sorted(only_live)[:6]))

        cands = {}
        for nm in sorted(os.listdir(ETC)):
            if nm.startswith("mixer_paths") and nm.endswith(".xml"):
                cands[nm] = open(os.path.join(ETC, nm), encoding="utf-8", errors="replace").read()
        composed, compatible, refuted, discriminating, card, tok2, model = loaded_file_evidence(cands, live)
        print(f"   loaded-file evidence: {composed} (card {card!r} -> token2 {tok2!r}, model {model!r}) "
              f"is the composed name AND survives the control test; "
              f"compatible={[n for n, _ in compatible]}, refuted={[n for n, _, _ in refuted]}")
        print(f"      leg-1 positive control: {discriminating[0][0]} uniquely defines "
              f"{', '.join(discriminating[0][1][:3])} and those ARE live")
        print("     file-only examples (declared but not enumerated live): "
              + ", ".join(sorted(only_file)[:6]))
    print(f"# {PLATFORM}: {plat['devices']} device entries ({plat['distinct_devices']} distinct), "
          f"{plat['backends']} backends, {plat['size']} B")
    print(f"   acdb_id map: " + " ".join(f"{k.replace('SND_DEVICE_OUT_','')}={v}" for k, v in plat["acdb"].items()))
    print(f"   bit_width:   " + " ".join(f"{k.replace('SND_DEVICE_OUT_','')}={v}" for k, v in plat["bits"].items()))
    print(f"   Hi-Fi devices declared: " + " ".join(f"{k.replace('SND_DEVICE_OUT_','')}={v}" for k, v in plat["hifi"].items()))
    if plat["native"]:
        print(f"   native configs: {plat['native']}  params: {plat['params']}")
    print(f"   backend rows (device -> backend@interface): {plat['backends']}")
    for d, b, i in plat["backend_rows"]:
        print(f"     {d.replace('SND_DEVICE_OUT_',''):34s} {b} @ {i}")
    eff_pairs = []
    for name in ("audio_effects.conf",):
        a = os.path.join(ETC, name)
        b = os.path.join(ROOT, "art/audio-6.0.1/shipped/vendor/etc", name)
        for f in (a, b):
            if os.path.exists(f):
                eff_pairs.append((f, effects_summary(f)))
    if len(eff_pairs) == 2:
        (pa, ea), (pb, eb) = eff_pairs
        print(f"# audio_effects.conf: system {len(ea['libs'])} libs / {len(ea['effects'])} effects "
              f"({ea['size']} B) vs vendor {len(eb['libs'])} libs / {len(eb['effects'])} effects "
              f"({eb['size']} B)")
        print(f"   only in vendor: libs={sorted(set(eb['libs']) - set(ea['libs']))[:6]} "
              f"effects={sorted(set(eb['effects']) - set(ea['effects']))[:6]}")
        print(f"   only in system: effects={sorted(set(ea['effects']) - set(eb['effects']))[:6]}")
    hi = [p for p, v in pol.items() if any(len(r.split('|')) > 4 for r in v["rates"])]
    print(f"# {POLICY}: {len(pol)} profiles with rates -- profiles declaring >4 rates: {hi}")
    for p in hi:
        v = pol[p]
        print(f"   {p}: rates={v['rates'][0][:64]} flags={v['flags'][:1]} "
              f"commented-out rate lines={v['commented_rates']}")
    return board, generic, plat, pol, live


def selftest():
    """Each arm mutates a COPY of the extract and requires this tool to abort on that mutation."""
    import shutil
    import tempfile
    bad = 0
    src = os.path.join(ROOT, "art/audio-6.0.1/shipped/system/etc")
    tmp = tempfile.mkdtemp()
    etc = os.path.join(tmp, "etc")
    shutil.copytree(src, etc)
    mix = os.path.join(etc, BOARD_MIX)
    gen = os.path.join(etc, GENERIC_MIX)
    pla = os.path.join(etc, PLATFORM)
    original = {f: open(f, encoding="utf-8", errors="replace").read() for f in (mix, gen, pla)}
    gt = open(gen, encoding="utf-8", errors="replace").read()
    import re as _re
    mm = _re.search(r"<path name=" + chr(34) + r"[^" + chr(34) + r"]+" + chr(34) + ">", gt)
    if not mm:
        print("  FAIL generic file has no <path name=...> to anchor on -- arms would be vacuous")
        return 1
    FIRST_GENERIC_PATH = mm.group(0)
    arms = [
        # replace EVERY occurrence: the control appears 4 times, and mutating one of them leaves the
        # gate satisfied -- an arm that only breaks what it counted once proves nothing.
        ("SmartPA Switch is removed from the board mixer file", mix, chr(34) + "SmartPA Switch" + chr(34),
         chr(34) + "SmartX Switch" + chr(34), "all"),
        ("HiFi Mode Switch is removed from the board mixer file", mix, chr(34) + "HiFi Mode Switch" + chr(34),
         chr(34) + "HiFi Mode X" + chr(34), "all"),
        # anchor on the first <path name="..."> the generic file really contains (the old draft used
        # a path name from the other file and the arm silently did nothing)
        ("SmartPA Switch is added to the generic mixer file", gen, FIRST_GENERIC_PATH,
         "<ctl name=" + chr(34) + "SmartPA Switch" + chr(34) + " value=" + chr(34) + "1" + chr(34) + "/>\n    "
         + FIRST_GENERIC_PATH),
        ("the SPEAKER acdb_id line is renamed", pla,
         "SND_DEVICE_OUT_SPEAKER" + chr(34) + " acdb_id=", "SND_DEVICE_OUT_SPEAKER_Q" + chr(34) + " acdb_id="),
    ]
    tool = os.path.join(ROOT, "tools", "audio_cfg_files.py")
    for arm in arms:
        name, path, old, new = arm[:4]
        every = len(arm) > 4 and arm[4] == "all"
        for f, txt in original.items():
            open(f, "w", encoding="utf-8").write(txt)
        t = open(path, encoding="utf-8", errors="replace").read()
        if t.count(old) < 1:
            print("  FAIL " + name + ": anchor absent in the copy -- vacuous arm")
            bad += 1
            continue
        open(path, "w", encoding="utf-8").write(t.replace(old, new) if every else t.replace(old, new, 1))
        env = dict(os.environ)
        env["AUDIO_CFG_ETC"] = etc
        env["AUDIO_CFG_ROUTES"] = "/nonexistent-routes"
        r = subprocess.run([sys.executable, tool], capture_output=True, text=True, env=env)
        out = (r.stdout + r.stderr).strip().splitlines()
        if r.returncode != 0 and any("gate:" in l for l in out):
            print("  ok   gate fires when " + name)
        else:
            print("  FAIL " + name + ": rc=" + str(r.returncode) + " :: " + (out[-1][:70] if out else "no output"))
            bad += 1
    for f, txt in original.items():
        open(f, "w", encoding="utf-8").write(txt)

    # ---- arms for the loaded-file evidence: one positive, two negatives ----
    live_routes = os.path.join(ROOT, "art/audio-6.0.1/route-states.tsv")
    cards_real = os.path.join(ROOT, "art/audio-6.0.1/live/cards.txt")
    prop_real = os.path.join(ROOT, "art/audio-6.0.1/live/getprop.txt")
    if not (os.path.exists(live_routes) and os.path.exists(cards_real) and os.path.exists(prop_real)):
        print("  FAIL evidence arms: a live input is missing (routes/cards/getprop) -- arms would be vacuous")
        bad += 1
    else:
        cards = os.path.join(tmp, "cards.txt")
        prop = os.path.join(tmp, "getprop.txt")
        shutil.copyfile(cards_real, cards)
        shutil.copyfile(prop_real, prop)

        def run_env(extra_routes=None, etc_dir=None):
            env = dict(os.environ)
            env["AUDIO_CFG_ETC"] = etc_dir if etc_dir is not None else etc
            env["AUDIO_CFG_ROUTES"] = extra_routes or live_routes
            env["AUDIO_CFG_CARDS"] = cards
            env["AUDIO_CFG_GETPROP"] = prop
            r = subprocess.run([sys.executable, tool], capture_output=True, text=True, env=env)
            return r.returncode, (r.stdout + r.stderr)

        rc, out = run_env()
        ok = rc == 0 and "loaded-file evidence: mixer_paths_tasha.PD1610.xml" in out
        print(("  ok   " if ok else "  FAIL ") + "positive: the evidence names the board file the live controls support")
        bad += 0 if ok else 1

        base = open(prop, encoding="utf-8").read()
        # mutate the MODEL line specifically: [PD1610] also appears as the value of
        # ro.product.device earlier in the file, and replacing the first occurrence would leave the
        # property this ruler reads untouched (an arm that changes text but not meaning)
        mutated = re.sub(r"(\[ro\.vivo\.product\.model\]: \[)PD1610(\])", r"\g<1>PD1516A\g<2>", base, count=1)
        if mutated == base:
            print("  FAIL model line not found in getprop -- vacuous arm")
            bad += 1
        else:
            open(prop, "w", encoding="utf-8").write(mutated)
            rc2, out2 = run_env()
            ok2 = rc2 != 0 and "gate:" in out2 and "not compatible" in out2
            print(("  ok   " if ok2 else "  FAIL ") + "gate fires when ro.vivo.product.model says another board")
            bad += 0 if ok2 else 1
        open(prop, "w", encoding="utf-8").write(base)

        cb = open(cards, encoding="utf-8").read()
        open(cards, "w", encoding="utf-8").write(cb.replace("msm8996-tasha", "msm8996-fluid", 1))
        if open(cards, encoding="utf-8").read() == cb:
            print("  FAIL card mutation did not land -- vacuous arm")
            bad += 1
        else:
            rc3, out3 = run_env()
            ok3 = rc3 != 0 and "gate:" in out3 and "not compatible" in out3
            print(("  ok   " if ok3 else "  FAIL ") + "gate fires when the sound-card token says another codec")
            bad += 0 if ok3 else 1
        open(cards, "w", encoding="utf-8").write(cb)

        # and the empty-live-input case must NOT be silently treated as evidence
        rc4, out4 = run_env(extra_routes="/nonexistent-routes")
        ok4 = "loaded-file evidence" not in out4
        print(("  ok   " if ok4 else "  FAIL ") + "no live capture -> no loaded-file claim")
        bad += 0 if ok4 else 1

    shutil.rmtree(tmp, ignore_errors=True)
    print("selftest: " + str(bad) + " arm(s) failed")
    return 1 if bad else 0
if __name__ == "__main__":
    if "--selftest" in sys.argv:
        sys.exit(selftest())
    report()
