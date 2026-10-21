#!/usr/bin/env python3
"""The user-facing tuning surface: vivo's audio UI (com.vivo.audiofx) decides WHICH apps get an
effects/Hi-Fi session and stores the owner's own switch state.  Nothing in the kernel, HAL or ACDB
layers shows this, and a port that ignores it can reproduce every control value and still sound
different -- because the app playing was never eligible, or the owner's toggle was not carried.

Reads only captured artifacts:
  live/data_com.vivo.audiofx.tgz   (files/com.vivo.audiofx.hifi_whitelist.xml, shared_prefs/...)
  live/packages_sys.txt, live/packages_3rd.txt   (what is actually installed)
Gates abort rather than printing a confident zero.  --selftest proves each gate can fire.
"""
import argparse, os, re, sys, tarfile, tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KEYS = ("enabled", "key", "prevkey", "prevhifi")


def load_members(base):
    tgz = os.path.join(base, "live/data_com.vivo.audiofx.tgz")
    if not os.path.exists(tgz):
        sys.exit("gate: " + tgz + " is not in the extract -- this layer is derived from the owner's "
                 "app state, do not quote it from memory (ledger 212)")
    out = {}
    with tarfile.open(tgz) as tf:
        for m in tf.getmembers():
            if m.isfile() and m.size:
                out[os.path.basename(m.name)] = tf.extractfile(m).read().decode("utf-8", "replace")
    if not out:
        sys.exit("gate: the audiofx tgz unpacked to zero files -- reader is blind")
    return out


def parse_whitelist(text):
    ver = re.search(r"<version>\s*(\d+)\s*</version>", text)
    if not ver:
        sys.exit("gate: no <version> in the Hi-Fi whitelist -- the file changed shape; the version "
                 "matters because the UI ships it per ROM")
    apps = re.findall(r"<app>(.*?)</app>", text, re.S)
    if len(apps) < 10:
        sys.exit(f"gate: only {len(apps)} <app> entries parsed from an 8.9 KB whitelist -- the parse "
                 "is blind, not the file empty")
    rows, bad = [], []
    for i, a in enumerate(apps):
        pkg = re.search(r"<package_name>\s*([^<\s]+)\s*</package_name>", a)
        fx = re.search(r"<audio_fxsession_name>\s*([^<\s]+)\s*</audio_fxsession_name>", a)
        cm = re.search(r"<!--\s*(.*?)\s*-->", a, re.S)
        if not (pkg and fx):
            bad.append(i)
            continue
        rows.append({"package": pkg.group(1), "fx_session": fx.group(1),
                     "comment": (cm.group(1).strip() if cm else ""),
                     "extra_tags": sorted({t for t in re.findall(r"<([a-z_A-Z]+)>", a)} -
                                          {"package_name", "audio_fxsession_name", "app"})})
    if bad:
        sys.exit(f"gate: {len(bad)} <app> entries lack package_name or audio_fxsession_name "
                 f"(indices {bad[:5]}) -- the whitelist grammar differs from what this tool claims")
    return int(ver.group(1)), rows


def parse_prefs(text):
    vals = {}
    for m in re.finditer(r'<(boolean|string|int)\s+name="([^"]+)"(?:\s+value="([^"]*)")?\s*/?>', text):
        vals[m.group(2)] = {"kind": m.group(1), "value": m.group(3)}
    missing = [k for k in KEYS if k not in vals]
    if missing:
        sys.exit(f"gate: the owner-state prefs lack {missing} -- either the app version differs or the "
                 "capture came from another app; this layer names those four keys")
    return vals


def installed(base):
    names = set()
    for f in ("packages_sys.txt", "packages_3rd.txt"):
        p = os.path.join(base, "live", f)
        if not os.path.exists(p):
            sys.exit("gate: " + p + " missing -- the whitelist can only be checked against the "
                     "installed-package capture")
        for line in open(p, encoding="utf-8", errors="replace"):
            line = line.strip()
            if "=" in line:                      # `package:/data/app/x-1/base.apk=com.x`
                names.add(line.rsplit("=", 1)[1])
            elif line.startswith("package:"):
                names.add(line.split(":", 1)[1])
            elif re.fullmatch(r"[a-zA-Z0-9_.]+", line):
                names.add(line)
    if len(names) < 50:
        sys.exit(f"gate: only {len(names)} packages parsed from the two captures -- the reader is "
                 "blind (this ROM lists 206); eligibility numbers would be meaningless")
    return names


def eligibility(rows, inst, prefs_pkg="com.android.bbkmusic"):
    """How many whitelisted apps are actually installed -- reported, not gated on a ratio.

    The list is aspirational by design: 46 entries, most of them third-party music apps that a given
    device does not carry (here exactly 2 are installed: the stock BBK music player and the stock
    video player).  A ratio gate would have been an invented expectation; what IS checkable is that
    the parse works, so the positive control is: the package that owns the captured prefs file must
    show up in the installed captures.
    """
    present = [r["package"] for r in rows if r["package"] in inst]
    if not present:
        sys.exit("gate: no whitelisted package appears in the installed captures -- either the "
                 "captures or the parse is broken; refusing to report eligibility")
    if prefs_pkg not in inst:
        sys.exit(f"gate: {prefs_pkg} owns the captured shared_prefs but is not in the installed "
                 "captures -- the two captures disagree about the machine, so neither number here is "
                 "trustworthy")
    return present


def summarize(base):
    members = load_members(base)
    wl_name = "com.vivo.audiofx.hifi_whitelist.xml"
    alt_name = "hifi_whitelist.from.secure.xml"
    if wl_name not in members:
        sys.exit("gate: no " + wl_name + " inside the tgz -- the app state layout changed")
    version, rows = parse_whitelist(members[wl_name])
    prefs = parse_prefs(members.get("com.android.bbkmusic.xml", ""))
    inst = installed(base)
    present = eligibility(rows, inst)
    rate = len(present) / len(rows)
    drift = ""
    if alt_name in members:
        v2, r2 = parse_whitelist(members[alt_name])
        same = (v2 == version and [x["package"] for x in r2] == [x["package"] for x in rows])
        drift = (f"the /data/secure copy agrees byte-shape ({v2}, {len(r2)} apps)" if same else
                 f"the /data/secure copy DIFFERS (version {v2}, {len(r2)} apps) -- two whitelists are "
                 "live and the UI's fallback order decides which one applies")
    return {"version": version, "apps": len(rows), "present": len(present), "rate": rate,
            "installed_names": present, "rows": rows, "prefs": prefs, "drift": drift,
            "extras": sorted({t for r in rows for t in r["extra_tags"]})}



# --- the consumer, read out of the app's own code (this APK ships no classes.dex: the code is the
#     sibling .odex, so the strings that name the reader live there) ---
NEEDED_IN_CODE = {
    "bbkcore path": b"/data/bbkcore/com.vivo.audiofx.hifi_whitelist.xml",
    "whitelist class": b"Lcom/vivo/audiofx/whitelist/hifi/HiFiWhiteList;",
    "app list class": b"Lcom/vivo/audiofx/whitelist/hifi/AppList;",
    "session key tag": b"audio_fxsession_name",
    "settings key": b"hifi_settings_music",
    "update time key": b"hifi_online_update_list_update_time",
    "create session log": b"updateAudioEffectEnable : create session : key = ",
}
OPTIONAL_IN_CODE = {
    "video settings key": b"hifi_settings_video",
    # matched WITHOUT the apostrophe: the source string carries a typographic U+2019 there, and
    # bytes literals do not decode \u escapes -- a prefix is the robust form of this test
    "bbkcore-missing log": b"bbkcore dir doesn",
    "model-gated log": b"this model can",
    "online update log": b"hifi whitelist update file not exists",
    "DSD listener": b"com.vivo.audiofx.IDSDStateListener",
    "Maxx effect": b"com.vivo.audiofx.maxxaudio.effect",
}
ODEX = "shipped/system/app/AudioEffect/oat/arm64/AudioEffect.odex"
APK = "shipped/system/app/AudioEffect/AudioEffect.apk"


def code_surface(base):
    """What the app code itself names: the difference between 'a file that looks like a gate' and
    'the class that reads it'.  Every string here is a literal the compiler kept."""
    p = os.path.join(base, ODEX)
    if not os.path.exists(p):
        sys.exit("gate: " + ODEX + " is not in the extract -- the app\u2019s code is there and nowhere "
                 "else (the APK is resources only), so this leg cannot run at all")
    blob = open(p, "rb").read()
    found = {k: (blob.count(v) if v in blob else 0) for k, v in NEEDED_IN_CODE.items()}
    missing = [k for k, n in found.items() if n == 0]
    if missing:
        sys.exit("gate: the ODEX no longer contains " + str(missing) + " -- either the app changed or "
                 "the pull was truncated; the consumer claim must be re-read, not carried over")
    opt = {k: ("yes" if v in blob else "no") for k, v in OPTIONAL_IN_CODE.items()}
    apk = os.path.join(base, APK)
    dex = "APK absent"
    if os.path.exists(apk):
        import zipfile
        names = zipfile.ZipFile(apk).namelist()
        dex = ("%d dex in %d entries (%d png, %d xml)" %
               (len([x for x in names if x.endswith(".dex")]), len(names),
                len([x for x in names if x.endswith(".png")]), len([x for x in names if x.endswith(".xml")])))
    return {"found": found, "optional": opt, "apk": dex, "bytes": len(blob)}


def copy_agreement(base):
    """The three copies of the whitelist the app could read.  The code names /data/bbkcore first, so
    agreement is not what decides behaviour -- but a disagreement would mean the machine holds two
    live answers, and the row has to say that instead of quoting one list."""
    import hashlib
    import tarfile
    dig = {}
    bb = os.path.join(base, "shipped/bbkcore/com.vivo.audiofx.hifi_whitelist.xml")
    if os.path.exists(bb):
        dig["bbkcore"] = hashlib.md5(open(bb, "rb").read()).hexdigest()
    tgz = os.path.join(base, "live/data_com.vivo.audiofx.tgz")
    if os.path.exists(tgz):
        with tarfile.open(tgz) as tf:
            for n in ("./files/com.vivo.audiofx.hifi_whitelist.xml", "./files/hifi_whitelist.from.secure.xml"):
                try:
                    dig[n.split("/")[-1]] = hashlib.md5(tf.extractfile(n).read()).hexdigest()
                except KeyError:
                    dig[n.split("/")[-1]] = "MISSING"
    if not dig:
        sys.exit("gate: no whitelist copy is readable -- refuse to report agreement")
    same = len(set(dig.values())) == 1 and "MISSING" not in dig.values()
    return dig, same



APK_MANIFEST = "AndroidManifest.xml"
MANIFEST_NEEDED = {
    "bound service": "com.vivo.audiofx.AudioFxService",
    "intent receiver": "com.vivo.audiofx.AudioFxIntentReceiver",
    "enable action": "com.vivo.audiofx.vivo_sound.enable",
    "request action": "com.vivo.audiofx.vivo_sound.request",
    "hifi state action": "com.vivo.action.HIFI_APP_STATE_CHANGED",
    "hifi panel action": "bbk.media.action.DISPLAY_HIFI_CONTROL_PANEL",
    "bbe console": "com.vivo.audiofx.AudioFxBBEConsole",
    "hifi settings activity": "com.vivo.audiofx.HifiSettings",
    "audio permission": "android.permission.MODIFY_AUDIO_SETTINGS",
    "write settings permission": "android.permission.WRITE_SETTINGS",
    "boot receiver permission": "android.permission.RECEIVE_BOOT_COMPLETED",
}
MANIFEST_OPTIONAL = {
    "maxx effect service": "com.vivo.audiofx.maxxaudio.effect",
    "waves activity": "com.vivo.audiofx.waves.MaxSoundSettingActivity",
    "force-stop action": "android.intent.action.FORCE_STOP_PACKAGE",
    "sticky broadcast": "android.permission.BROADCAST_STICKY",
    "overlay permission": "android.permission.SYSTEM_ALERT_WINDOW",
    "logsystem read": "com.bbk.iqoo.logsystem.permission.READ_DATA",
    "component enable permission": "android.permission.CHANGE_COMPONENT_ENABLED_STATE",
    "dsd about activity": "com.vivo.audiofx.AboutDSD",
    "hpx enable": "com.vivo.audiofx.hpx.enable",
}


def axml_strings(raw):
    """Android's binary manifest keeps its string pool as UTF-16LE runs, each preceded by a length
    unit that is itself printable -- so an entry may start with one junk character and every match
    has to be a substring test, not startswith().  No aapt/apkanalyzer exists on this machine; the
    interface names are what matters here, not the tag tree."""
    out, buf = [], ""
    for i in range(0, len(raw) - 1, 2):
        ch = raw[i] | (raw[i + 1] << 8)
        if 0x20 <= ch < 0x7F:
            buf += chr(ch)
        else:
            if len(buf) >= 4:
                out.append(buf)
            buf = ""
    if len(buf) >= 4:
        out.append(buf)
    return out


def manifest_surface(base):
    """The app's OUTER interface, read from its binary manifest: which service is bound, which
    receiver wakes on boot, which intent actions can reach it from outside, and which permissions a
    caller would need.

    It closes the loose end left by the code leg: `IAudioFxService` is absent from `service list`
    (which does list `audio`, `media.audio_flinger`, `media.audio_policy`) because it is a BOUND
    service, so the outside-reachable surface is the broadcasts named here.
    """
    import zipfile
    apk = os.path.join(base, APK)
    if not os.path.exists(apk):
        sys.exit("gate: " + APK + " is not in the extract -- the manifest leg cannot run")
    raw = zipfile.ZipFile(apk).read(APK_MANIFEST)
    if len(raw) < 2000:
        sys.exit("gate: %s is only %d B -- not the binary manifest this leg expects"
                 % (APK_MANIFEST, len(raw)))
    strs = axml_strings(raw)
    joined = "\x00".join(strs)
    found = {k: ("yes" if v in joined else "no") for k, v in MANIFEST_NEEDED.items()}
    missing = [k for k, v in found.items() if v == "no"]
    if missing:
        sys.exit("gate: the manifest no longer declares " + str(missing) + " -- either the app "
                 "interface changed or the string-pool scan went blind; re-read before quoting it")
    opt = {k: ("yes" if v in joined else "no") for k, v in MANIFEST_OPTIONAL.items()}
    perms = sorted({m.group() for s in strs
                    for m in re.finditer(r"android\.permission\.[A-Z_]+|com\.bbk\.[A-Za-z0-9_.]+", s)})
    names = sorted({m.group() for s in strs
                    for m in re.finditer(r"(?:com|android)\.(?:vivo|bbk)\.[A-Za-z0-9_.]+", s)})
    return {"bytes": len(raw), "strings": len(strs), "found": found, "optional": opt,
            "perms": perms, "names": names}


def report(base, as_tsv=None):
    s = summarize(base)
    inst = installed(base)
    print(f"Hi-Fi whitelist: version={s['version']} apps={s['apps']} installed-on-device={s['present']} "
          f"({100*s['rate']:.1f}% of the list -- the list is aspirational: it names third-party "
          "music apps this device does not carry)")
    print(f"   installed among the list: {' '.join(s['installed_names'])}")
    print(f"   tags beyond package_name/audio_fxsession_name: {' '.join(s['extras']) or '(none)'}")
    print(f"   owner state (shared_prefs/com.android.bbkmusic.xml): " +
          " ".join(f"{k}={v['kind']}:{v['value']}" for k, v in sorted(s["prefs"].items())))
    print(f"   second copy: {s['drift'] or '(no hifi_whitelist.from.secure.xml in the tgz)'}")
    print("   sample entries: " + "; ".join(f"{r['comment'] or r['package']}->{r['fx_session']}"
                                            for r in s["rows"][:6]))
    cs = code_surface(base)
    print("   consumer (read from " + ODEX + ", " + str(cs["bytes"]) + " B): " +
          " ".join(k + "=x" + str(v) for k, v in sorted(cs["found"].items())))
    print("      APK code layout: " + cs["apk"])
    print("      optional strings present: " + " ".join(k + "=" + v for k, v in sorted(cs["optional"].items())))
    ms = manifest_surface(base)
    print("   manifest interface (" + str(ms["bytes"]) + " B AXML, " + str(ms["strings"]) +
          " strings): all " + str(len(ms["found"])) + " required names present")
    print("      permissions: " + " ".join(ms["perms"]))
    print("      optional: " + " ".join(k + "=" + v for k, v in sorted(ms["optional"].items())))
    dig, same = copy_agreement(base)
    print("   whitelist copies: " + " ".join(k + "=" + v[:10] for k, v in sorted(dig.items())) +
          ("  ALL AGREE" if same else "  DISAGREE -- this machine holds two live answers"))
    if as_tsv:
        with open(as_tsv, "w", encoding="utf-8") as f:
            f.write("index\tpackage\tfx_session\tcomment\tinstalled\textra_tags\n")
            for i, r in enumerate(s["rows"]):
                f.write(f"{i}\t{r['package']}\t{r['fx_session']}\t{r['comment']}\t"
                        f"{'yes' if r['package'] in inst else 'no'}\t"
                        f"{'|'.join(r['extra_tags'])}\n")
        print(f"wrote {as_tsv}: {s['apps']} rows")
    return s


def selftest():
    """Arms mutate a COPY of the tgz; each must make the tool refuse rather than report a number."""
    bad = 0
    base = os.environ.get("AUDIOFX_BASE") or os.path.join(ROOT, "art/audio-6.0.1")
    tool = os.path.abspath(__file__)
    import shutil, subprocess
    tmp = tempfile.mkdtemp()
    tmp2 = tempfile.mkdtemp()
    shutil.copytree(os.path.join(base, "live"), os.path.join(tmp, "live"))
    # the report path now also reads the app code, so the arms fixture needs those files too
    for sub in (os.path.dirname(ODEX), "shipped/bbkcore"):
        os.makedirs(os.path.join(tmp, sub), exist_ok=True)
    for f in (ODEX, APK, "shipped/bbkcore/com.vivo.audiofx.hifi_whitelist.xml"):
        shutil.copyfile(os.path.join(base, f), os.path.join(tmp, f))
    tgt = os.path.join(tmp, "live/data_com.vivo.audiofx.tgz")
    wd = os.path.join(tmp, "un")
    os.makedirs(wd, exist_ok=True)
    with tarfile.open(tgt) as tf:
        tf.extractall(wd)
    wl = os.path.join(wd, "files", "com.vivo.audiofx.hifi_whitelist.xml")
    pf = os.path.join(wd, "shared_prefs", "com.android.bbkmusic.xml")
    orig_wl = open(wl, encoding="utf-8", errors="replace").read()
    orig_pf = open(pf, encoding="utf-8", errors="replace").read()

    def repack():
        with tarfile.open(tgt, "w:gz") as tf:
            tf.add(wd, arcname=".")

    arms = [
        ("ok: the captured state summarises", None, None, None),
        ("whitelist version removed", wl, r"<version>\s*6\s*</version>", ""),
        ("audio_fxsession_name dropped", wl, r"<audio_fxsession_name>com\.android\.bbkmusic</audio_fxsession_name>", ""),
        ("owner-state prefs emptied", pf, r"<boolean name=", r"<booleanZ name="),
    ]
    for label, path, old, new in arms:
        open(wl, "w", encoding="utf-8").write(orig_wl)
        open(pf, "w", encoding="utf-8").write(orig_pf)
        if path is not None:
            cur = open(path, encoding="utf-8", errors="replace").read()
            if old is not None and re.search(old, cur) is None:
                print("  FAIL " + label + ": anchor absent -- vacuous arm")
                bad += 1
                continue
            open(path, "w", encoding="utf-8").write(re.sub(old, new, cur, count=1))
            if open(path, encoding="utf-8", errors="replace").read() == cur:
                print("  FAIL " + label + ": mutation did not land -- vacuous arm")
                bad += 1
                continue
        repack()
        env = dict(os.environ)
        r = subprocess.run([sys.executable, tool, "--base", tmp], capture_output=True, text=True, env=env)
        out = r.stdout + r.stderr
        if label.startswith("ok:"):
            ok = r.returncode == 0 and "whitelist: version=" in out
        else:
            ok = r.returncode != 0 and "gate:" in out
        print(("  ok   " if ok else "  FAIL ") + label + ("" if ok else f" (rc={r.returncode})"))
        bad += 0 if ok else 1
    def arm_manifest(tmpdir):
        """Blank the receiver's UTF-16 name in the fixture manifest -- same length, so the AXML
        offsets survive -- require the abort, restore, require green again."""
        import zipfile
        # the earlier arms rewrite the tgz (prefs mutation) and do not restore it, so start from the
        # pristine capture -- otherwise this arm inherits a broken owner-state and fails for a reason
        # that has nothing to do with the manifest
        shutil.copyfile(os.path.join(base, "live/data_com.vivo.audiofx.tgz"),
                        os.path.join(tmpdir, "live/data_com.vivo.audiofx.tgz"))
        apk = os.path.join(tmpdir, APK)
        bak = os.path.join(tmpdir, "..", "AudioEffect.apk.orig")
        shutil.copyfile(apk, bak)
        zin = zipfile.ZipFile(apk)
        items = [(i, zin.read(i.filename)) for i in zin.infolist()]
        zin.close()
        needle = "com.vivo.audiofx.AudioFxIntentReceiver".encode("utf-16-le")
        out = []
        hit = False
        for info, data in items:
            if info.filename == APK_MANIFEST:
                raw = bytearray(data)
                pos = bytes(raw).find(needle)
                if pos < 0:
                    shutil.copyfile(bak, apk)
                    return "vacuous"
                hit = True
                for k in range(len(needle)):
                    raw[pos + k] = 0x58
                data = bytes(raw)
            out.append((info, data))
        with zipfile.ZipFile(apk, "w") as zo:
            for info, data in out:
                zo.writestr(info, data)
        r2 = subprocess.run([sys.executable, tool, "--base", tmpdir], capture_output=True, text=True)
        o2 = r2.stdout + r2.stderr
        ok2 = r2.returncode != 0 and "intent receiver" in o2
        print(("  ok   " if ok2 else "  FAIL ") + "gate fires when the receiver is removed from the manifest" +
              ("" if ok2 else " (rc=%d :: %s)" % (r2.returncode, o2.strip().splitlines()[-1][:150])))
        shutil.copyfile(bak, apk)
        r3 = subprocess.run([sys.executable, tool, "--base", tmpdir], capture_output=True, text=True)
        ok3 = r3.returncode == 0
        print(("  ok   " if ok3 else "  FAIL ") + "restoring the manifest makes the leg green again" +
              ("" if ok3 else " (rc=%d :: %s)" % (r3.returncode, (r3.stdout + r3.stderr).strip().splitlines()[-1][:150])))
        return ("vacuous" if not hit else (0 if ok2 else 1) + (0 if ok3 else 1))

    res = arm_manifest(tmp)
    if res == "vacuous":
        print("  FAIL manifest arm: receiver name absent from the fixture manifest")
        bad += 1
    else:
        bad += res

    # ---- arms for the consumer leg: a real fixture tree, one positive and one mutation ----
    fx = os.path.join(tmp2, "base")
    for sub in ("shipped/system/app/AudioEffect/oat/arm64", "shipped/bbkcore", "live"):
        os.makedirs(os.path.join(fx, sub), exist_ok=True)
    real = os.path.join(ROOT, "art/audio-6.0.1")
    shutil.copyfile(os.path.join(real, ODEX), os.path.join(fx, ODEX))
    shutil.copyfile(os.path.join(real, APK), os.path.join(fx, APK))
    shutil.copyfile(os.path.join(real, "shipped/bbkcore/com.vivo.audiofx.hifi_whitelist.xml"),
                    os.path.join(fx, "shipped/bbkcore/com.vivo.audiofx.hifi_whitelist.xml"))
    shutil.copyfile(os.path.join(real, "live/data_com.vivo.audiofx.tgz"),
                    os.path.join(fx, "live/data_com.vivo.audiofx.tgz"))
    for f in ("packages_sys.txt", "packages_3rd.txt"):
        shutil.copyfile(os.path.join(real, "live", f), os.path.join(fx, "live", f))
    r = subprocess.run([sys.executable, tool, "--base", fx], capture_output=True, text=True)
    okc = r.returncode == 0 and "consumer (read from" in (r.stdout + r.stderr)
    print(("  ok   " if okc else "  FAIL ") + "positive: the app code names the reader (class, path, keys)")
    bad += 0 if okc else 1
    ob = bytearray(open(os.path.join(fx, ODEX), "rb").read())
    needle = b"Lcom/vivo/audiofx/whitelist/hifi/HiFiWhiteList;"
    pos = ob.find(needle)
    if pos < 0:
        print("  FAIL fixture ODEX lacks the class literal -- vacuous arm")
        bad += 1
    else:
        ob[pos:pos + len(needle)] = b"X" * len(needle)
        open(os.path.join(fx, ODEX), "wb").write(bytes(ob))
        r2 = subprocess.run([sys.executable, tool, "--base", fx], capture_output=True, text=True)
        ok2 = r2.returncode != 0 and "whitelist class" in (r2.stdout + r2.stderr)
        print(("  ok   " if ok2 else "  FAIL ") + "gate fires when the class reference is stripped from the code")
        bad += 0 if ok2 else 1

    shutil.rmtree(tmp, ignore_errors=True)
    print("selftest: %d arm(s) failed" % bad)
    return 1 if bad else 0


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        sys.exit(selftest())
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default=os.path.join(ROOT, "art/audio-6.0.1"))
    ap.add_argument("--tsv", default=None)
    a = ap.parse_args()
    report(a.base, a.tsv)
