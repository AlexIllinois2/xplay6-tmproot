#!/usr/bin/env python3
"""Install an APK on this vivo ROM and click its confirmation, which times out in ~14 s.

Why the click is the hard part (all measured on device 2026-10-20):
  · the ROM's `VivoAdbInstallUtils` holds every adb-side install (legacy AND the session API) until the
    on-screen confirm comes back; unattended it answers `Failure [-200]` and logcat shows
    `INSTALL_CALLBACK_TIMEOUT`.
  · `input tap` used to be unable to do the click: as uid 2000 the InputDispatcher refused cross-uid
    injection, and as root the process is SIGKILLed (rc=137) -- it is an app_process.  Raw evdev writes
    (sendevent to the fts panel) reach the kernel but never Android's pipeline (ledger 604-607).  What
    worked was a real touchscreen built on /dev/uinput (tools/uinput_tap), which needs root (ledger 611-612).
    ★That is only true while the ROM's own 「USB模拟点击」 developer option is off: the refusal is
    `VivoPackageManagerSerivceUtils.preCheckUidPermission` withholding INJECT_EVENTS from uid 2000
    (ledger 691/696).  With that flag on, `TAPBACKEND=adb` (the default now) clicks it with no root at all;
    `TAPBACKEND=uinput` keeps the old route for a boot where the flag is still 0.
    ★`TAPBACKEND=chan` clicks through the daemon's raw root shell (TCP 12345) instead of through `su`:
    needed on a boot where the flag is off AND adb's uid is not on the su allow list, where the uinput
    route answers `ERR unknown service` and the click never happens (2026-10-21, installing 1.9.22).
  · A second dialog -- vivo's 「您的IMEI或MEID是无效的」 warning -- shows up over the installer on some
    boots and swallows the first tap.  It is dismissed here, not remembered as a human step.

usage: install_tap.py <device-apk-path> [ser]     (push + chcon are done by install_and_verify.sh)
"""
import os
import re
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SER = sys.argv[2] if len(sys.argv) > 2 else "3e5a38a5"
APK = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith("--") else ""
if not APK and "--selftest" not in sys.argv:
    sys.exit("usage: install_tap.py <device-apk-path> [ser] -- no default on purpose: the installed "
             "build and the applied artifact move every release. Use tools/install_and_verify.sh, "
             "which picks the newest release/*/APK and checks it before installing. A stale default "
             "would silently install an old file.")
ADB = ["adb", "-s", SER]
WANT = re.compile(r"(继续安装|安装|确定|允许|同意|下一步|立即安装|Install|Continue|Allow)")
NOISE = re.compile(r"(知道了|我知道了|好)$")


def sh(args, t=40):
    return subprocess.run(ADB + ["shell"] + args, capture_output=True, text=True, timeout=t).stdout


SU = os.environ.get("SU7", "/data/local/tmp/sux")
# 2026-10-21 (ledger 696): with the ROM's own 「USB模拟点击」 flag on, framework injection from uid 2000 is
# allowed, so the taps no longer need root or a /dev/uinput touchscreen.  The uinput backend stays because
# it is the only route on a boot where that vendor flag is still 0.
BACKEND = os.environ.get("TAPBACKEND", "adb")


def tap_via_channel(cx, cy):
    """Click through the daemon's raw root shell (TCP 12345) instead of through `su`.

    Why a third backend exists (measured 2026-10-21 installing 1.9.22): the uinput backend asks the su
    channel, and the su channel answers `ERR unknown service` for a caller that is not on the allow
    list -- so on a boot where `vivo_adb_simulate_input` is off AND adb's uid is not granted, the tool
    reported `landed=0 refused=1` while the real reason was that its own click never ran. The raw
    channel is root already and needs no grant."""
    import socket
    subprocess.run(ADB + ["forward", "tcp:12345", "tcp:12345"], capture_output=True, text=True)
    try:
        s = socket.create_connection(("127.0.0.1", 12345), timeout=20)
    except OSError as e:
        return "channel connect failed: %s" % e, "chan"
    try:
        s.sendall(("/data/local/tmp/uinput_tap %d %d\nexit\n" % (cx, cy)).encode())
        s.settimeout(20)
        buf = b""
        while True:
            try:
                d = s.recv(4096)
            except socket.timeout:
                break
            if not d:
                break
            buf += d
    finally:
        s.close()
    return buf.decode("utf-8", "replace").strip(), "chan"


def tap(cx, cy):
    """Send one click; returns (ack_text, kind).

    `adb` has NO ack -- `input tap` prints nothing whether or not the click was consumed, so a landed tap
    must be judged by its effect by the caller (the button disappearing).  Claiming "landed" from rc=0
    would be the same false accounting as reading `pm install ... Success` as proof of the tap (1.9.8)."""
    if BACKEND == "adb":
        p = subprocess.run(ADB + ["shell", "input", "tap", str(cx), str(cy)],
                           capture_output=True, text=True, timeout=60)
        return ((p.stdout or "") + (p.stderr or "")).strip(), "adb"
    if BACKEND == "chan":
        return tap_via_channel(cx, cy)
    # the uinput route: create a touchscreen on /dev/uinput as root and click once.
    # The command has to reach the device shell as ONE quoted argument: adb joins its argv with
    # spaces, so passing -c and the command separately made sux see the coordinates as extra argv
    # and sud answered "ERR target uid not allowed" (measured on 1.9.7, ledger 629).
    p = subprocess.run(ADB + ["shell", '%s -c "/data/local/tmp/uinput_tap %d %d"' % (SU, cx, cy)],
                       capture_output=True, text=True, timeout=120)
    ack = ((p.stdout or "") + (p.stderr or "")).strip()
    if "ERR unknown service" in ack:
        # the click did not even reach the screen: this caller is not granted. Say which, so the next
        # move is obvious instead of reading `landed=0` as a device problem (2026-10-21).
        ack += "  [the su path refused this uid -- retry with TAPBACKEND=chan, which uses the daemon's raw root shell]"
    return ack, "uinput"


def candidates(xml):
    """(kind, text, cx, cy) for every node this script would click -- a pure function so --selftest can
    hold the same rule the delivered loop holds (a rule only tested through the loop cannot be tested
    offline, and both of its defects were found only by running them against the real screen)."""
    out = []
    for m in re.finditer(r'<node[^>]*?text="([^"]*)"[^>]*?clickable="(\w+)"[^>]*?bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"', xml):
        txt, clickable, x1, y1, x2, y2 = m.group(1), m.group(2), *map(int, m.groups()[2:])
        if not txt or clickable != "true" or (x2 - x1) < 30:
            continue
        kind = "noise" if NOISE.search(txt) else ("confirm" if WANT.search(txt) else None)
        if kind is None:
            continue
        out.append((kind, txt, (x1 + x2) // 2, (y1 + y2) // 2))
    return out


if "--selftest" in sys.argv:
    # Each arm is a defect this script actually had (ledger 697) plus a check that the fixture can still
    # catch it -- an arm that passes on a fixture which never contained the trap is not a ruler.
    def node(txt, clickable, x1, y1, x2, y2):
        return ('<node text="%s" resource-id="android:id/button1" class="android.widget.TextView" '
                'package="com.android.packageinstaller" checkable="false" checked="false" clickable="%s" '
                'enabled="true" bounds="[%d,%d][%d,%d]" />' % (txt, clickable, x1, y1, x2, y2))

    BODY = "外部来源应用，未经vivo安全性和兼容性检测，请谨慎安装。"
    d1 = node(BODY, "false", 93, 600, 987, 744) + node("继续安装", "true", 420, 1620, 660, 1704)
    d2 = node("安装", "true", 420, 1620, 660, 1704)
    d3 = node("知道了", "true", 93, 1091, 987, 1229)
    d4 = node("开发模式(易卡顿)，点击关闭", "true", 100, 0, 900, 60) + node("12:30", "false", 40, 40, 200, 90)
    arms = []
    got = [t for _k, t, _x, _y in candidates(d1)]
    arms.append(("body text is not a button (only the clickable one)", got == ["继续安装"], got))
    arms.append(("the fixture really carries the trap (body text contains 安装 but clickable=false)",
                 (BODY in d1) and ("安装" in BODY) and ('clickable="false"' in d1), None))
    seen, kept = [], []
    for _k, t, x, y in candidates(d1) + candidates(d2):
        if (t, x, y) not in seen:
            seen.append((t, x, y)); kept.append(t)
    arms.append(("two dialog stages at one centre both get tapped", kept == ["继续安装", "安装"], kept))
    got = [(k, t) for k, t, _x, _y in candidates(d3)]
    arms.append(("the IMEI warning is noise, not a confirm", got == [("noise", "知道了")], got))
    arms.append(("a launcher screen yields nothing to tap", candidates(d4) == [], candidates(d4)))
    bad = [a for a in arms if not a[1]]
    for name, ok, extra in arms:
        print("  %-62s %s%s" % (name, "ok" if ok else "MISBEHAVED", "" if ok else " -> %r" % (extra,)))
    print("install_tap selftest: %d/%d arms ok" % (len(arms) - len(bad), len(arms)))
    sys.exit(1 if bad else 0)


flags = os.environ.get("PMFLAGS", "-r -t")
# Pre-condition, measured (ledger 618): with the display asleep, or with the keyguard/StatusBar still
# holding focus, this ROM does NOT render the vivo confirm window at all -- uiautomator keeps dumping
# the launcher's clock/battery for 26 s and the install dies in `Failure [-200]`.  A dump with
# contents therefore does not prove the dialog is on screen, so ask before spending the 14 s window.
wake = sh(["dumpsys", "power"])
asleep = "mWakefulness=Awake" not in wake
focus = [l for l in sh(["dumpsys", "window"]).splitlines() if "mCurrentFocus" in l]
focus = focus[0].strip() if focus else "no mCurrentFocus line"
if asleep or "StatusBar" in focus:
    print("REFUSE: the confirm dialog would not be rendered yet -- %s / %s" % (
        "screen ASLEEP" if asleep else "screen awake", focus))
    print("  fix it first (needs the root channel, or a hand on the phone):")
    print("    adb -s %s shell svc power stayon true" % SER)
    print("    adb -s %s shell <su> -c 'input keyevent KEYCODE_WAKEUP'" % SER)
    print("    adb -s %s shell <su> -c 'wm dismiss-keyguard'" % SER)
    print("  and require mCurrentFocus to name a real window before rerunning this.")
    sys.exit(2)
print("pre-condition ok: %s / %s" % ("awake", focus), flush=True)
# the read-out must be single-run: measured 2026-10-21, a previous attempt's `pm install` was still alive
# and appended `[-200]` after this run's `Success`, so the file held two runs' verdicts at once.
sh(["rm -f /data/local/tmp/pminst.out"], t=30)
subprocess.run(ADB + ["shell", "nohup sh -c 'pm install %s %s > /data/local/tmp/pminst.out 2>&1' "
                         ">/dev/null 2>&1 &" % (flags, APK)], capture_output=True, timeout=40)
tapped = []
landed = refused = 0
for i in range(14):
    time.sleep(1.2)
    sh(["uiautomator", "dump", "/data/local/tmp/ui.xml"], t=25)
    xml = sh(["cat", "/data/local/tmp/ui.xml"], t=25)
    if "Application not responding" in xml:
        break
    for kind, txt, cx, cy in candidates(xml):
        # dedupe on (text, point), not on the point: vivo's confirm is TWO stages whose buttons sit at the
        # same centre -- measured 2026-10-21, 「继续安装」 then 「安装」 both at (540,1662), and a point-only
        # rule skipped the second one so the install died in `Failure [-200]` with landed=1 refused=0.
        if (txt, cx, cy) in tapped:
            continue
        tapped.append((txt, cx, cy))
        r, backend = tap(cx, cy)
        # A refused tap must never be read as a landed one: measured on 1.9.8, all three taps
        # answered ERR while pm install still printed Success, so Success alone says nothing
        # about the tap path (art/ledger-20261016.md 629).
        if backend in ("uinput", "chan"):
            ok = "UINPUT_TAP_DONE" in r
            note = r
        else:
            # no ack exists for `input tap`, so the witness is the effect: that button must be off the screen
            time.sleep(1.5)
            sh(["uiautomator", "dump", "/data/local/tmp/ui.xml"], t=25)
            gone = txt not in re.findall(r'text="([^"]*)"', sh(["cat", "/data/local/tmp/ui.xml"], t=25))
            ok = gone
            note = "button %r gone=%s" % (txt, gone)
        if ok:
            landed += 1
        else:
            refused += 1
        print("tap %s %r at %d,%d -> %s" % (kind, txt, cx, cy, note), flush=True)
        time.sleep(2.5)
time.sleep(4)
print("install output:", sh(["cat", "/data/local/tmp/pminst.out"]).strip()[:200], flush=True)
code = re.findall(r"versionCode=(\d+)", sh(["dumpsys", "package", "com.xplay6.temproot"]))
print("installed versionCode:", code[0] if code else "none", flush=True)
print("taps: landed=%d refused=%d" % (landed, refused), flush=True)
if refused:
    print("INCOMPLETE: %d tap(s) never reached the screen -- the install outcome above did not come "
          "from this script's taps" % refused, flush=True)
    sys.exit(3)
