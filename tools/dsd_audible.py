#!/usr/bin/env python3
"""「DSD 能出响」的可复跑判据（机主口径：不评听感，只要响）——读一份在播留底，给逐条判决。
用法：python3 tools/dsd_audible.py <baseline>/live/<dsd-inplay-目录> [--report]　・　--selftest 跑臂

判据（§467 之后）：
  ⓪ debugfs 里前端与后端都读到 `State: start`（§451：procfs 对 device 17 结构上没有每实例目录，
     所以在播证人只有 `/sys/kernel/debug/asoc/…/MSM8996 Compress2/state` 这一处）。
  ① PCM 被打开　② 路由被 enable　③ DSD 状态被置 1
  ④ **DSD 进料方式有证据**：`FLAG_OFFLOAD_DOP`（DoP）**或** debugfs 的 `FE S8 → BE S24_LE @176400`（硬件直解）。
     旧版只认 DoP，于是硬件直解那一发被误判（14:16 那发实测：直解、无 DoP 标志）。
  ⑤ 没有「打开即 EOS」
  ⑥ **孤立** UNDERRUN 的密度（不是"有没有低于阈值"）：与状态事件（`dsd state change`／`Opening PCM device`／
     standby）相隔 <100 ms 的 underrun 算换档伴随；环里带时标（threadtime）才判得出这件事——brief 环无时标 ⇒ 明说「不可判」。
     ①–④ 证管线建立，⑤⑥ 才证它在持续供数据。"""
import argparse, os, re, sys, glob

STATE_RE = r"(?:dsd state change|start_output_stream: Opening PCM device|out_standby|standby here since)"
UND_RE = r"pause because of UNDERRUN, framesReady = (\d+)"
LINE_TS = re.compile(r"^\d\d-\d\d (\d\d):(\d\d):(\d\d)\.(\d\d\d)")


def _ms(line):
    m = LINE_TS.match(line)
    if not m:
        return None
    h, mi, s, f = (int(x) for x in m.groups())
    return ((h * 60 + mi) * 60 + s) * 1000 + f


def supply(text, window_ms=100, per_min=1.0):
    """Classify underruns against the state events in the same ring, and report the denominators.

    Pure so the selftest can hand it either shape without needing a capture that happens to contain
    one.  `timed=False` means the ring carries no clock (logcat -v brief) -- then the density is
    NOT ASSESSED, which is a different statement from 'no underruns'."""
    und = [(x[0], int(re.search(UND_RE, x[1]).group(1))) for x in
           (( _ms(l), l) for l in text.splitlines() if "UNDERRUN" in l) if x[0] is not None]
    ev = [x for x in (_ms(l) for l in text.splitlines() if re.search(STATE_RE, l)) if x is not None]
    raw = len(re.findall(UND_RE, text))
    if raw == 0:
        return {"ok": True, "coincident": 0, "isolated": 0, "span_s": 0.0, "timed": True, "raw": 0,
            "untimed": 0}
    untimed = raw - len(und)
    if not und:
        return {"ok": False, "coincident": "-", "isolated": "-", "span_s": "-", "timed": False,
                "raw": raw, "untimed": untimed}
    near = [min((abs(u - v) for v in ev), default=None) for u, _fr in und]
    coincident = sum(1 for x in near if x is not None and x < window_ms)
    isolated = len(und) - coincident
    lo, hi = min([u for u, _ in und] + ev), max([u for u, _ in und] + ev)
    span_s = (hi - lo) / 1000.0
    dens = isolated / (span_s / 60.0) if span_s > 0 else (99.0 if isolated else 0.0)
    return {"ok": isolated == 0 or dens <= per_min, "coincident": coincident, "isolated": isolated,
            "span_s": round(span_s, 1), "per_min": round(dens, 2), "timed": True, "raw": raw,
            "untimed": untimed,
            "min_framesReady": min(f for _u, f in und), "window_ms": window_ms}


def branch(dop, fe_text):
    """How is the DSD actually getting into the DSP?  DoP leaves S8-in/S24_LE-out at 176400 as well,
    so the debugfs byte face is reported as its own evidence rather than as a substitute."""
    if "FLAG_OFFLOAD_DOP" in dop:
        return "dop"
    if re.search(r"Format\s*=\s*S8", fe_text) and re.search(r"Format\s*=\s*S24_LE", fe_text) \
            and "176400" in fe_text:
        return "hw-direct (FE S8 -> BE S24_LE @176400)"
    return ""


def judge(d):
    # each `logcat -d` dump re-contains what the previous one held, so the denominator must come
    # from unique lines: summing per file inflated every event count ~5x in this round's capture
    seen, lines = set(), []
    for f in sorted(glob.glob(f"{d}/logcat-ring*.txt")):
        for l in open(f, encoding="latin-1", errors="replace").read().splitlines():
            if l not in seen:
                seen.add(l)
                lines.append(l)
    txt = "\n".join(lines)
    fe_files = sorted(glob.glob(f"{d}/compress-state*.txt"))
    fe_txt = "\n".join(open(f, encoding="latin-1", errors="replace").read() for f in fe_files)
    n = lambda p: len(re.findall(p, txt))
    open_pcm, enable, state1 = (n(r"start_output_stream: Opening PCM device"),
                                n(r"enable_audio_route: apply mixer"), n(r"dsd state change from 0 to 0x1"))
    eos, trunc = n(r'"EOS\.\.\."'), n(r"incomplete dsf file")
    fe_start = len(re.findall(r"^State: start", fe_txt, re.M))
    be_start = len(re.findall(r"^\s+State: start", fe_txt, re.M))
    sup = supply(txt)
    br = branch(txt, fe_txt)
    early = trunc and trunc >= eos and eos > 0 and open_pcm and eos >= open_pcm
    if sup.get("timed"):
        extra = "" if not sup.get("untimed") else "・另有 %d 条无时标未参与判定" % sup["untimed"]
        und_line = ("UNDERRUN %d 条：与状态事件 <%dms 内 %s 条、孤立 %s 条・窗口 %.1fs・密度 %s/分钟%s"
                    % (sup["raw"], sup.get("window_ms", 100), sup["coincident"], sup["isolated"],
                       sup["span_s"], sup.get("per_min", "-"), extra))
    else:
        und_line = ("%d 条 UNDERRUN 全部无时标（brief 环）⇒ 密度不可判，请用 threadtime 环重采" % sup["raw"])
    return [
        ("FE+BE really streaming (debugfs)", bool(fe_files) and fe_start > 0 and be_start > 0,
         f"FE start={fe_start} BE start={be_start} over {len(fe_files)} state file(s)"),
        ("PCM opened", open_pcm > 0, open_pcm),
        ("route enabled", enable > 0, enable),
        ("DSD state set", state1 > 0, state1),
        ("DSD feed evidence (DoP or hw-direct)", bool(br), br or "既无 FLAG_OFFLOAD_DOP，也无 FE S8→BE S24_LE@176400"),
        ("no open-then-immediate-EOS", not early, f"EOS={eos} truncated={trunc}"),
        ("no isolated underruns", bool(sup["ok"]), und_line)]


def selftest():
    import tempfile
    bad = 0
    def line(ts, body):
        return "10-18 %s  731  999 W AudioFlinger: %s" % (ts, body)
    u = lambda ts: line(ts, "pause because of UNDERRUN, framesReady = 0,minFrames = 7072, mFormat = 0x3")
    ev = lambda ts: line(ts, "dsd state change from 0 to 0x1")[:-len("W ")] + "D AudioFlinger: x"
    transition = "\n".join([ev("14:14:10.000"), u("14:14:10.010"), ev("14:17:45.000"), u("14:17:45.020")])
    starving = "\n".join([ev("14:14:10.000")] + [u("14:%02d:%02d.000" % (14 + i // 6, i % 6)) for i in range(6)]
                         + ["10-18 14:16:40.000  731  999 W AudioFlinger: EOS..."])
    s1, s2 = supply(transition), supply(starving)
    for label, got, want in (("underruns coincident with a state transition pass", s1["ok"], True),
                             ("isolated underruns mid-stream fail", s2["ok"], False)):
        if bool(got) is not want:
            print(f"  FAIL {label}: got {got} want {want} ({s1 if want else s2})")
            bad += 1
        else:
            print(f"  ok   {label}")
    if supply("\n".join([line("14:14:10.000", "x")] * 0 + [u("14:14:10.000"), u("14:15:10.000")]))["ok"]:
        print("  FAIL an underrun with NO state event at all is called fine")
        bad += 1
    else:
        print("  ok   gate: with no state event nearby, an underrun is isolated (not excused)")
    if supply("10-18 14:14:10.000  1 1 W x: dsd state change\npause because of UNDERRUN, framesReady = 0,minFrames = 7\n")["timed"]:
        print("  FAIL an untimed underrun line was counted as timed")
        bad += 1
    else:
        print("  ok   gate: a brief-format ring (no clock) is reported as 不可判, not as clean")
    fe_dop = "State: start\nHardware Params: Format = S8, Channels = 0, Rate = 176400\n - X\n   State: start\n   Format = S24_LE\n"
    for label, txt_, fe, want in (("DoP flag counts as feed evidence", "FLAG_OFFLOAD_DOP", "", "dop"),
                                 ("hardware direct decode counts too", "", fe_dop, "hw"),
                                 ("neither one is not accepted", "", "State: start\n", "")):
        got = branch(txt_, fe)
        ok = (got == "") if want == "" else got.startswith(want)
        if not ok:
            print(f"  FAIL {label}: got {got!r}")
            bad += 1
        else:
            print(f"  ok   {label}")
    d = tempfile.mkdtemp()
    open(os.path.join(d, "logcat-ring1.txt"), "w", encoding="latin-1").write(transition)
    rows = judge(d)
    if len(rows) != 7:
        print("  FAIL judge() returned %d checks, not 7" % len(rows))
        bad += 1
    if not any(r[0].startswith("FE+BE") and r[1] is False for r in rows):
        print("  FAIL judge() on a ring without a debugfs file let the ⓪ witness pass")
        bad += 1
    else:
        print("  ok   judge() still refuses the ⓪ witness when no debugfs state file was captured")
    print(f"selftest: {bad} arm(s) failed")
    return 1 if bad else 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("capture", nargs="?")
    ap.add_argument("--report", action="store_true",
                    help="exit 0 as long as a verdict was reached (do NOT pin the answer of today's "
                         "material -- the acceptance leg must not turn red the day a complete file is "
                         "played)")
    ap.add_argument("--selftest", action="store_true", help="prove the underrun window, the feed-evidence "
                         "alternative and the untimed-ring refusal all bite")
    a = ap.parse_args()
    if a.selftest:
        sys.exit(selftest())
    if not a.capture:
        sys.exit("gate: need a capture directory (or --selftest)")
    rows = judge(a.capture)
    for name, ok, val in rows:
        print("  %-30s %s  (%s)" % (name, "OK " if ok else "FAIL", val))
    verdict = all(bool(r[1]) for r in rows)
    print("\nVERDICT: %s" % ("响了（管线建立且持续供数据）" if verdict else
          "尚不能判「响了」——见上面 FAIL 项；素材截断（incomplete dsf file）就换一枚完整 DSD 再跑同一条"))
    if a.report:
        print("report mode: the verdict is stated above; rc does not encode it")
        return 0
    return 0 if verdict else 1


if __name__ == "__main__":
    sys.exit(main())
