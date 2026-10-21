#!/usr/bin/env python3
"""The controls a Hi-Fi session actually asserts, as a diff of two FULL control dumps (ledger 419).

Everything else in the deliverable compares states at one instant.  This compares the whole mixer
table of the same card in two instants -- idle, and playing with Hi-Fi on -- because the useful
acceptance list for Android 7 is not "does `HiFi Mode Switch` read HiFi" but "which of the 1518
controls move, and to what".  A port that reaches the same target value through a different set of
auxiliary controls (impedance, app-type cfg, bit format, clock role) can still sound different.

Both inputs are `tinymix -D 0` captures stored in the baseline; nothing is typed from memory, and the
comparison refuses to run on dumps that are not the same card (name sets must agree).
"""
import argparse, os, re, sys

ROOT = os.environ.get("AUDIO_PORT_ROOT") or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASE = os.path.join(ROOT, "art/audio-6.0.1")
LINE = re.compile(r"^\s*(\d+)\t(\w+)\t(\d+)\t(.+?)\s{2,}(.*)$")
MIN_CONTROLS = 500
# controls that MUST move in a Hi-Fi session; a 7 that asserts a different set is a different mechanism
MUST_MOVE = ("HiFi Mode Switch", "TERT_MI2S_RX Audio Mixer MultiMedia1", "Headphone Rx Mixer I2S_RX",
             "Audio Stream 0 App Type Cfg", "TERT_MI2S Bit Format")
# controls whose VALUES carry mechanism facts (not just on/off)
NAMED = ("HP Sel", "HPH Type", "HPHL Impedance", "HPHR Impedance", "HiFi Mute", "TERT_MI2S mode",
         "Audio Stream 0 App Type Cfg")


def parse(path):
    if not os.path.exists(path):
        sys.exit("gate: " + path + " missing -- capture `tinymix -D 0` on the device; this leg is a "
                 "diff of two real dumps, not a remembered list")
    out = {}
    for line in open(path, encoding="utf-8", errors="replace"):
        m = LINE.match(line.rstrip("\n"))
        if m:
            out[m.group(4).strip()] = m.group(5).strip()
    if len(out) < MIN_CONTROLS:
        sys.exit(f"gate: {path} parsed to {len(out)} controls, below {MIN_CONTROLS} -- the dump is "
                 "truncated or the line format changed, so a diff of it would be a fiction")
    return out


def diff(idle, active):
    only_a = sorted(set(idle) - set(active))
    only_b = sorted(set(active) - set(idle))
    if len(only_a) + len(only_b) > 50:
        sys.exit(f"gate: the two dumps disagree about {len(only_a)+len(only_b)} control NAMES -- they "
                 "are not the same card/state, so 'what changed' is unanswerable here")
    ch = {k: (idle[k], active[k]) for k in idle if k in active and idle[k] != active[k]}
    return ch, only_a, only_b


def report(idle_p, active_p, strict=True):
    a, b = parse(idle_p), parse(active_p)
    ch, only_a, only_b = diff(a, b)
    print(f"controls: idle={len(a)} active={len(b)}  changed={len(ch)}  "
          f"name-only-in-idle={len(only_a)} name-only-in-active={len(only_b)}")
    for k in sorted(ch):
        av, bv = ch[k]
        print(f"   {k:40s} {av[:34]!r:38s} -> {bv[:34]!r}")
    for k in NAMED:
        if k in ch:
            print(f"   fact[{k}] {ch[k][0]!r} -> {ch[k][1]!r}")
    missing = [m for m in MUST_MOVE if m not in ch]
    if missing:
        msg = ("gate: these controls did NOT change between the two dumps: " + "・".join(missing) +
               " -- either the active capture is not a Hi-Fi session, or the port changed mechanism")
        if strict:
            sys.exit(msg)
        print("NOTE " + msg.replace("gate:", ""))
    return ch


def selftest():
    import tempfile
    real_idle = os.path.join(BASE, "live/tinymix-D0.txt")
    real_act = os.environ.get("AUDIO_ACTIVE_DUMP") or os.path.join(BASE, "live/inplay-hifion-20261017-1933/tinymix-all.txt")
    bad = 0
    for label, args, want_rc, want_txt in [
        ("ok: the stored pair reports the asserted control set", (real_idle, real_act), 0, "changed=14"),
        ("control: a self-diff reports 0 changes, and the must-move gate then fires",
         (real_act, real_act), 1, "changed=0"),
        ("gate: a must-move control missing aborts the acceptance read", (real_idle, real_idle), 1, "did NOT change"),
        ("gate: a truncated dump aborts instead of reporting a small diff", None, 1, "below 500"),
    ]:
        if args is None:
            d = tempfile.mkdtemp()
            p = os.path.join(d, "short.txt")
            open(p, "w", encoding="utf-8").write("0\tINT\t1\tFoo          1\n")
            args = (p, p)
        try:
            rc, txt = 0, ""
            import io, contextlib
            buf = io.StringIO()
            try:
                with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
                    report(*args)
            except SystemExit as e:
                rc = e.code if isinstance(e.code, int) else 1
                buf.write(str(e) + "\n")
            txt = buf.getvalue()
        except Exception as e:      # a raise that is not SystemExit is a failure, not a pass
            rc, txt = 99, repr(e)
        ok = (rc == want_rc) and (want_txt in txt)
        print(("  ok   " if ok else "  FAIL ") + label +
              ("" if ok else f" (rc={rc} want {want_rc}) :: " + txt.strip().splitlines()[-1][:130] if txt.strip() else ""))
        bad += 0 if ok else 1
    # the doctored-value arm: flipping one extra control must be visible in the count
    d = tempfile.mkdtemp()
    src = open(real_act, encoding="utf-8", errors="replace").read().splitlines()
    n_doctor = 0
    for i, l in enumerate(src):
        m = re.match(r"^(\s*\d+\t\w+\t\d+\tHiFi Mute\s+)None$", l)
        if m:
            src[i] = m.group(1) + "Both"
            n_doctor += 1
    if n_doctor != 1:
        print("  FAIL gate: un-doing one asserted value must reduce the change count "
              f":: the fixture matched {n_doctor} HiFi Mute lines, expected 1")
        bad += 1
        print("selftest: %d arm(s) failed" % bad)
        return 1 if bad else 0
    p = os.path.join(d, "act.txt")
    open(p, "w", encoding="utf-8").write("\n".join(src) + "\n")
    import io, contextlib
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        report(real_idle, p)
    ok = "changed=13" in buf.getvalue()
    print(("  ok   " if ok else "  FAIL ") + "gate: un-doing one asserted value must reduce the change count")
    bad += 0 if ok else 1
    print("selftest: %d arm(s) failed" % bad)
    return 1 if bad else 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--idle", default=os.path.join(BASE, "live/tinymix-D0.txt"))
    ap.add_argument("--active", required=False,
                    default=os.path.join(BASE, "live/inplay-hifion-20261017-1933/tinymix-all.txt"))
    ap.add_argument("--no-strict", action="store_true",
                    help="report a missing must-move control instead of aborting (for exploratory pairs)")
    a = ap.parse_args()
    report(a.idle, a.active, strict=not a.no_strict)
    return 0


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        sys.exit(selftest())
    sys.exit(main())
