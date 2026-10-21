#!/usr/bin/env python3
"""The DSD / Hi-Fi source surface (ledger 418).

§408 read the DSD strings inside the audio HAL and §414 read the app's own toggle, but the middle of
the chain -- who decodes DSD and which property tells the stack to send it to the DAC raw -- lived in
libraries that were only captured after §417 widened the denominator.  This tool closes that middle
from three independent artefacts: the framework/HAL binaries, the codec registration file, and the
live property capture.  Each leg aborts if its own evidence is missing, because a Hi-Fi port that
quietly loses `audio/dsd` changes the audible path for DSD files without any control value moving.
"""
import argparse, os, re, sys

ROOT = os.environ.get("AUDIO_PORT_ROOT") or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASE = os.path.join(ROOT, "art/audio-6.0.1")

BINARIES = {
    "shipped/system/lib/hw/audio.primary.msm8996.so":
        ("HAL", ("AUDIO_OUTPUT_FLAG_HW_DSD", "DSDEnable", "DSDEnbale", "HiFi DSD Volume Switch",
                 "headphone-hifi-DSD")),
    "shipped/system/lib/libmediaplayerservice.so":
        ("framework player service", ("DSDEnable return", "isResetDSDFinished", "performResetDSD",
                                      "audio.dsd.hw.out")),
    "shipped/system/lib/libmars-service.so":
        ("vivo mars service", ("audio.dsd.hw.out",)),
    "shipped/system/lib/libmediacore4g_vivo_public.so":
        ("vivo media core (software DSD)", ("OMX.vivo.dsd.decoder", "omx.vivo.dsd.decoder",
                                            "dsd2pcm_init", "dsd2pcm_translate", "ff_dsd_lsbf_decoder",
                                            "ff_dsd_msbf_decoder", "DSDIFF Version", "audio/dsd")),
}
CODEC_XML = "shipped/system/etc/media_codecs_vivo_audio.xml"
PROPS = "live/getprop.txt"
PROP_KEYS = ("audio.dsd.hw.out", "persist.vivo.phone.hifi", "ro.config.hifi_config_state")


def strings(path):
    return [s.decode("utf-8", "replace").rstrip("\x00")
            for s in re.findall(rb"[ -~]{5,}\x00", open(path, "rb").read())]


def read(base=BASE):
    out = {"bins": {}, "missing": [], "codec": None, "props": {}}
    for rel, (role, toks) in BINARIES.items():
        p = os.path.join(base, rel)
        if not os.path.exists(p):
            out["missing"].append(rel)
            continue
        ss = strings(p)
        blob = "".join(ss)
        out["bins"][os.path.basename(rel)] = {
            "role": role,
            "found": {t: blob.count(t) for t in toks if t in blob},
            "strings": len(ss)}
    if out["missing"]:
        sys.exit("gate: these binaries that carry the DSD chain are not in the extract: " +
                 "・".join(out["missing"]) + " -- §417 established the capture denominator from the live "
                 "maps, so a missing one means the capture regressed, not that the mechanism is gone")
    cp = os.path.join(base, CODEC_XML)
    if not os.path.exists(cp):
        sys.exit("gate: " + cp + " missing -- the codec registration leg has no source")
    txt = open(cp, encoding="utf-8", errors="replace").read()
    m = re.search(r'<MediaCodec name="([^"]*dsd[^"]*)"\s+type="([^"]+)"', txt, re.I)
    if not m:
        sys.exit("gate: no <MediaCodec name=*dsd* type=...> registration in " + CODEC_XML +
                 " -- either vivo dropped the DSD decoder here or my pattern is blind")
    out["codec"] = {"name": m.group(1), "type": m.group(2)}
    pp = os.path.join(base, PROPS)
    if not os.path.exists(pp):
        sys.exit("gate: " + pp + " missing -- the property half of the chain has to be read from the "
                 "device, not from the binaries")
    for l in open(pp, encoding="utf-8", errors="replace"):
        k = re.match(r"\[([^\]]+)\]: \[([^\]]*)\]", l.strip())
        if k and k.group(1) in PROP_KEYS:
            out["props"][k.group(1)] = k.group(2)
    lost = [k for k in PROP_KEYS if k not in out["props"]]
    if lost:
        sys.exit("gate: the property capture has no line for " + "・".join(lost) +
                 " -- the capture predates this leg's key list; re-capture `getprop`")
    return out


def report(base=BASE):
    d = read(base)
    tot = sum(len(v["found"]) for v in d["bins"].values())
    print(f"DSD/Hi-Fi source surface: {len(d['bins'])} binaries, {tot} distinct evidence strings")
    for name, v in sorted(d["bins"].items()):
        print(f"   {name:38s} [{v['role']}] {v['strings']} strings :: " +
              "・".join(f"{k}x{n}" for k, n in sorted(v["found"].items())))
    print(f"   codec registration: {d['codec']['name']} <- type {d['codec']['type']} ({CODEC_XML})")
    print("   live properties: " + "・".join(f"{k}={v!r}" for k, v in sorted(d["props"].items())))
    sw = sorted({k for v in d["bins"].values() for k in v["found"] if k.startswith(("dsd2pcm", "ff_dsd",
                                                                                    "OMX.vivo.dsd"))})
    hw = sorted({k for v in d["bins"].values() for k in v["found"] if k.startswith(("AUDIO_OUTPUT_FLAG_HW_DSD",
                                                                                    "audio.dsd.hw.out"))})
    print(f"   hardware route markers: {hw}")
    print(f"   software (dsd2pcm/ffmpeg) markers: {sw}")
    if not (hw and sw):
        sys.exit("gate: only one of the two DSD routes is evidenced -- reporting 'both exist' would be "
                 "a guess")
    return d


ARMS = [
    ("ok: the stored extract reports both DSD routes", None, None),
    ("gate: a binary of the chain missing from the extract aborts",
     lambda b: os.remove(os.path.join(b, "shipped/system/lib/libmediacore4g_vivo_public.so")), None),
    ("gate: deleting the dsd MediaCodec line aborts the registration leg", None,
     lambda b: _patch(os.path.join(b, CODEC_XML), 'name="OMX.vivo.dsd.decoder"', 'name="OMX.vivo.xsd.decoder"')),
    ("gate: a property capture without audio.dsd.hw.out aborts", None,
     lambda b: _drop_prop(os.path.join(b, PROPS), "audio.dsd.hw.out")),
]


def _patch(path, old, new):
    t = open(path, encoding="utf-8").read()
    assert old in t, "anchor present in fixture"
    open(path, "w", encoding="utf-8").write(t.replace(old, new, 1))


def _drop_prop(path, key):
    lines = open(path, encoding="utf-8").read().splitlines()
    open(path, "w", encoding="utf-8").write("\n".join(l for l in lines if not l.startswith("[" + key)) + "\n")


def selftest():
    import shutil, subprocess, tempfile
    tool = os.path.abspath(__file__)
    bad = 0
    r = subprocess.run([sys.executable, tool], capture_output=True, text=True)
    if r.returncode == 0 and "hardware route markers" in r.stdout:
        print("  ok   ok: the stored extract reports both DSD routes")
    else:
        print("  FAIL ok: the stored extract reports both DSD routes :: " +
              (r.stdout + r.stderr).strip()[-160:])
        bad += 1
    for label, pre, post in ARMS[1:]:
        d = tempfile.mkdtemp(prefix="dsdsurf-")
        # only the files this leg reads -- the whole extract is 164 MB and /tmp is a ramdisk
        for rel in list(BINARIES) + [CODEC_XML, PROPS]:
            src = os.path.join(BASE, rel)
            dst = os.path.join(d, rel)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copyfile(src, dst)
        try:
            if pre:
                pre(d)
            if post:
                post(d)
        except Exception as e:
            print(f"  FAIL {label} :: fixture setup failed: {e}")
            bad += 1
            shutil.rmtree(d, ignore_errors=True)
            continue
        env = dict(os.environ)
        r2 = subprocess.run([sys.executable, tool, "--base", d], capture_output=True, text=True, env=env)
        out = r2.stdout + r2.stderr
        if r2.returncode != 0 and "gate:" in out:
            print("  ok   " + label)
        else:
            print(f"  FAIL {label} (rc={r2.returncode}) :: " + (out.strip().splitlines() or ["-"])[-1][:150])
            bad += 1
        shutil.rmtree(d, ignore_errors=True)
    print("selftest: %d arm(s) failed" % bad)
    return 1 if bad else 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default=BASE)
    a = ap.parse_args()
    report(a.base)
    return 0


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        sys.exit(selftest())
    sys.exit(main())
