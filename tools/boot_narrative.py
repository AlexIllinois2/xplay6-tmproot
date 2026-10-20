#!/usr/bin/env python3
"""Driver-side boot narrative (ledger 417).

Why a layer of its own: every other row describes a state I read while the machine was already up.
The kernel ring buffer holds what happened exactly once -- which .cnt the DT picked, what the PA
measured during its boot calibration, which ASoC routes the machine driver failed to add, which card
string got registered.  Those are the only witnesses of the boot sequence, they roll out of the
1 MB logcat ring within ~30 s of boot (measured: `logcat -g` says main = 1 Mb, and the earliest
audio_hw_primary line at uptime 60 s was already ~30 s late), and they are the things a 7 port can
get wrong without any control value changing.

Nothing here is typed from memory: every fact is read out of a stored capture, and a fact the parser
cannot find aborts the run.
"""
import argparse, os, re, sys

ROOT = os.environ.get("AUDIO_PORT_ROOT") or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DMESG = os.environ.get("BOOT_DMESG") or "live/dmesg-boot-20261017-0956.txt"
LOGCAT = os.environ.get("BOOT_LOGCAT") or "live/logcat-boot-20261017-0956.txt"

# label -> (regex, group names).  A missing label is an abort: these strings are printed by the
# drivers on every boot of this machine, so absence means my capture or my parse broke.
FACTS = {
    "cnt_file":            re.compile(r"tfa98xx_dts_phrase: use the (\S+\.cnt)"),
    "f0_window_hz":        re.compile(r"tfa98xx_dts_phrase: frequence range from (\d+) to (\d+) Hz"),
    "imped_window_ohm":    re.compile(r"calibration's value range from ([\d.]+) to ([\d.]+) Ohm"),
    "cnt_load":            re.compile(r"tfa98xx_cnt_loadfile: loaded (\S+) - size: (\d+)"),
    "cnt_member":          re.compile(r"tfa98xx_cnt_loadfile: \[(\d+)\] (file|profile): (\S+)"),
    "chip_id":             re.compile(r"tfa98xx \S+: ID revision (0x[0-9a-fA-F]+)"),
    "fw_ic_rev":           re.compile(r"tfa98xx_check_ic_rom_version: FW rev: (\d+), IC rev (\d+)"),
    "cal_measured_ohm":    re.compile(r"tfa98xx_init:calibration impedence ([\d.]+)"),
    "mtp_count":           re.compile(r"tfa98xx_StoreMtpSettings: count=(\d+)"),
    "patch_len":           re.compile(r"tfa98xx_process_patch_file: len (\d+)"),
    "spk_params":          re.compile(r"tfa98xx_dsp_write_speaker_parameters: (\d+)"),
    "boot_attenuation":    re.compile(r"tfa98xx_set_volume: \d+, attenuation (-?\d+) dB"),
    "card_registered":     re.compile(r"Sound card (\S+) registered"),
    "hifi_codec_node":     re.compile(r"(hifi-codec-\w+) hifi-codec:"),
    "jack_poles":          re.compile(r"This hardware has (\d+) pole jack"),
    "dsp_regs":            re.compile(r"tfa98xx_dsp_start Read (System Ctrl|Status|Audio) Reg value (0x[0-9a-f]+)"),
}
ROUTE_FAIL = re.compile(r"ASoC: (?:no sink widget found for|no source widget found for|"
                        r"Failed to add route|no dapm match for|mux \S+ has no paths|unknown pin|"
                        r"CODEC DAI \S+ not registered|platform \(null\) not registered)(.*)")
MANDATORY = ("cnt_file", "f0_window_hz", "imped_window_ohm", "cnt_load", "chip_id", "fw_ic_rev",
             "cal_measured_ohm", "mtp_count", "patch_len", "card_registered", "hifi_codec_node",
             "boot_attenuation")
LOG_FACTS = {
    "boot_session":   re.compile(r"select_devices: out_snd_device\((\d+): ([^)]+)\)"),
    "boot_route":     re.compile(r"enable_audio_route: apply mixer and update path: (.+)"),
    "boot_app_type":  re.compile(r"send_app_type_cfg PLAYBACK app_type (\d+), acdb_dev_id (\d+), sample_rate (\d+)"),
    "hifi_support":   re.compile(r"isHifiSupport, reply ret:(\d+), value:(\d+)"),
    "whitelist_read": re.compile(r"HiFiInfoServer\w*\(\)\(\s*\d+\): parseFileToGetList: (\S+)"),
    "have_hifi":      re.compile(r"AudioFxService.*HAVE_HIFI"),
    "dlopen_fail":    re.compile(r'dlopen failed: library "(\S+)" not found'),
}


def parse(text):
    out = {}
    for name, rx in FACTS.items():
        out[name] = [m.groups() for m in rx.finditer(text)]
    out["route_fail"] = sorted({" ".join(m.group(0).split())[:90] for m in ROUTE_FAIL.finditer(text)})
    out["probe_repeats"] = len(re.findall(r"msm8996_asoc_machine_probe", text))
    return out


def impedance_verdict(f):
    """The measured calibration impedance against the window the DT declares -- computed, not read.

    This is the acceptance check that survives a version change: 7 may print a different window (a
    different DT) and a different measurement (a different speaker), but the pair has to be coherent
    or the PA is running uncalibrated.
    """
    win = f["imped_window_ohm"][0]
    got = f["cal_measured_ohm"][0][0]
    lo, hi, meas = float(win[0]), float(win[1]), float(got)
    if not (lo <= meas <= hi):
        return f"OUT-OF-WINDOW measured={got} window={lo}..{hi}"
    return f"inside window: measured {got} Ohm in {lo}..{hi} (DT-declared)"


def parse_log(text):
    out = {}
    for name, rx in LOG_FACTS.items():
        out[name] = [m.groups() for m in rx.finditer(text)]
    return out


def report(base, dmesg_rel, logcat_rel):
    dp = os.path.join(base, dmesg_rel)
    lp = os.path.join(base, logcat_rel)
    for p, what in ((dp, "dmesg"), (lp, "logcat")):
        if not os.path.exists(p):
            sys.exit(f"gate: the {what} boot capture {p} is missing -- capture it right after a boot "
                     "(`adb exec-out \"su -c 'dmesg'\"` / `logcat -d -v brief`); boot facts are not "
                     "something to write from memory")
    dtext = open(dp, encoding="utf-8", errors="replace").read()
    ltext = open(lp, encoding="utf-8", errors="replace").read()
    if len(dtext.splitlines()) < 200:
        sys.exit(f"gate: {dp} has {len(dtext.splitlines())} lines -- a real boot dmesg runs to "
                 "thousands; this is not the boot segment")
    f = parse(dtext)
    missing = [k for k in MANDATORY if not f[k]]
    if missing:
        sys.exit("gate: these boot facts are absent from the dmesg capture: " + " ".join(missing) +
                 " -- either the parse is blind or the buffer did not hold the boot (kernel_log should "
                 "survive; check `dmesg` first line is near [    0.000000])")
    lf = parse_log(ltext)
    if not lf["boot_session"]:
        sys.exit("gate: no select_devices line in the boot logcat -- the HAL session is the reason "
                 "this layer exists")
    if not lf["whitelist_read"]:
        sys.exit("gate: HiFiInfoServer's parseFileToGetList line is gone -- that line is the runtime "
                 "witness naming who reads the Hi-Fi whitelist (ledger 414 left it unverified)")
    first = dtext.splitlines()[0]
    print(f"dmesg: {len(dtext.splitlines())} lines, first {first[:16]!r}; "
          f"logcat: {len(ltext.splitlines())} lines")
    print("  .cnt                 : " + " ".join(str(x) for x in f["cnt_file"][0]) +
          " ; members " + "・".join(f"[{a}]{b}={c}" for a, b, c in f["cnt_member"]))
    print("  chip/FW/IC           : " + f["chip_id"][0][0] + " FW " + f["fw_ic_rev"][0][0] +
          " IC " + f["fw_ic_rev"][0][1])
    print("  f0 window (DT)       : " + " Hz .. ".join(f["f0_window_hz"][0]) + " Hz")
    imp = impedance_verdict(f)
    print("  impedance            : " + imp)
    if imp.startswith("OUT-OF-WINDOW"):
        # not a curiosity: the PA runs uncalibrated when the measurement misses the window the DT
        # declares, and that is audible -- so a 7 boot that fails this does not get to print a table
        sys.exit("gate: OUT-OF-WINDOW -- " + imp + " -- the boot calibration did not land inside the "
                 "device-tree window; treat this as a failed acceptance check, not a reading")
    print("  MTP settings count   : " + f["mtp_count"][0][0] + " ; patch len " + f["patch_len"][0][0] +
          " ; speaker params " + f["spk_params"][0][0] + " ; boot attenuation " +
          f["boot_attenuation"][0][0] + " dB")
    print("  card registered      : " + f["card_registered"][0][0] + " ; Hi-Fi codec node " +
          f["hifi_codec_node"][0][0] + " ; jack " + (f["jack_poles"][0][0] if f["jack_poles"] else "?") +
          " pole ; machine probe repeats " + str(f["probe_repeats"]))
    print("  ASoC route failures at boot (baseline set): " + str(len(f["route_fail"])))
    for r in f["route_fail"][:8]:
        print("      - " + r)
    print("  boot session         : " + "・".join(" ".join(g) for g in lf["boot_session"][:2]) +
          " ; app_type " + "・".join(" ".join(g) for g in lf["boot_app_type"][:1]))
    print("  route applied        : " + "・".join(g[0] for g in lf["boot_route"][:2]))
    print("  isHifiSupport (boot) : " + "・".join(f"ret{a}=value{b}" for a, b in lf["hifi_support"]) +
          "   (the in-play capture of the same line reads value:1 -- ledger 415)")
    print("  whitelist reader     : " + "・".join(g[0] for g in lf["whitelist_read"][:1]) +
          " named by " + str(len(lf["whitelist_read"])) + " line(s)")
    print("  dlopen failures      : " + "・".join(sorted({g[0] for g in lf["dlopen_fail"]})) +
          "  (baseline on 6.0.1: Widevine is not installed)")
    return 0


ARMS = [
    ("ok: the stored boot captures parse", None, None),
    ("gate: a measured impedance outside the DT window must be called out",
     lambda t: t.replace("calibration impedence 07.15", "calibration impedence 05.00"), None),
    ("gate: dropping the .cnt load line aborts (a fact must not silently vanish)",
     lambda t: "\n".join(l for l in t.splitlines() if "cnt_loadfile: loaded" not in l), None),
    ("gate: a dmesg that is not the boot segment aborts",
     lambda t: "\n".join(t.splitlines()[-50:]), None),
    ("gate: a logcat without the HiFiInfoServer line aborts", None,
     lambda t: "\n".join(l for l in t.splitlines() if "HiFiInfoServer" not in l)),
]


def selftest():
    import tempfile
    base_real = ROOT
    dmesg_rel, logcat_rel = DMESG, LOGCAT
    bad = 0
    for label, dmut, lmut in ARMS:
        with tempfile.TemporaryDirectory() as tmp:
            for rel, mut in ((dmesg_rel, dmut), (logcat_rel, lmut)):
                src = os.path.join(base_real, "art/audio-6.0.1", rel)
                dst = os.path.join(tmp, rel)
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                text = open(src, encoding="utf-8", errors="replace").read()
                open(dst, "w", encoding="utf-8").write(mut(text) if mut else text)
            env = dict(os.environ)
            r = __import__("subprocess").run([sys.executable, os.path.abspath(__file__), "--base", tmp],
                                             capture_output=True, text=True, env=env)
            out = r.stdout + r.stderr
            if label.startswith("ok:"):
                ok = r.returncode == 0 and "whitelist reader" in out and "impedance" in out
            else:
                want = ("OUT-OF-WINDOW" if "outside" in label else "gate:")
                ok = r.returncode != 0 and want in out
            print(("  ok   " if ok else "  FAIL ") + label + ("" if ok else
                  f" (rc={r.returncode}) :: " + (out.strip().splitlines() or ["-"])[-1][:70]))
            bad += 0 if ok else 1
    print("selftest: %d arm(s) failed" % bad)
    return 1 if bad else 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default=os.path.join(ROOT, "art/audio-6.0.1"))
    ap.add_argument("--dmesg", default=DMESG)
    ap.add_argument("--logcat", default=LOGCAT)
    a = ap.parse_args()
    return report(a.base, a.dmesg, a.logcat)


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        sys.exit(selftest())
    sys.exit(main())
