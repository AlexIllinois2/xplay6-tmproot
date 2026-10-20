#!/usr/bin/env python3
"""Install an APK on this vivo ROM and click its confirmation, which times out in ~14 s.

Why the click is the hard part (all measured on device 2026-10-20):
  · the ROM's `VivoAdbInstallUtils` holds every adb-side install (legacy AND the session API) until the
    on-screen confirm comes back; unattended it answers `Failure [-200]` and logcat shows
    `INSTALL_CALLBACK_TIMEOUT`.
  · `input tap` cannot do the click: as uid 2000 the InputDispatcher refuses cross-uid injection, and
    as root the process is SIGKILLed (rc=137) -- it is an app_process.  Raw evdev writes (sendevent to
    the fts panel) reach the kernel but never Android's pipeline (ledger 604-607).  What works is a real
    touchscreen built on /dev/uinput (tools/uinput_tap): InputReader registers SOURCE_TOUCHSCREEN and
    the vendor dialog answers it (ledger 611-612).  Building it needs root, so this script goes through
    the daemon's channel: SU7=<path to the su client> and tools/uinput_tap pushed to /data/local/tmp.
  · A second dialog -- vivo's 「您的IMEI或MEID是无效的」 warning -- shows up over the installer on this
    boot and swallows the first tap.  It is dismissed here, not remembered as a human step.

usage: install_tap.py <device-apk-path> [ser]     (push + chcon are done by install_and_verify.sh)
"""
import os
import re
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SER = sys.argv[2] if len(sys.argv) > 2 else "3e5a38a5"
APK = sys.argv[1] if len(sys.argv) > 1 else ""
if not APK:
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


def tap(cx, cy):
    """the only tap that works here: create a touchscreen on /dev/uinput as root and click once.
    It runs through the daemon's channel because building the device needs root.
    The command has to reach the device shell as ONE quoted argument: adb joins its argv with
    spaces, so passing -c and the command separately made sux see the coordinates as extra argv
    and sud answered "ERR target uid not allowed" (measured on 1.9.7, ledger 629)."""
    p = subprocess.run(ADB + ["shell", '%s -c "/data/local/tmp/uinput_tap %d %d"' % (SU, cx, cy)],
                       capture_output=True, text=True, timeout=120)
    return ((p.stdout or "") + (p.stderr or "")).strip()


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
    for m in re.finditer(r'<node[^>]*?text="([^"]*)"[^>]*?bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"', xml):
        txt, x1, y1, x2, y2 = m.group(1), *map(int, m.groups()[1:])
        if not txt or (x2 - x1) < 30:
            continue
        kind = "noise" if NOISE.search(txt) else ("confirm" if WANT.search(txt) else None)
        if kind is None:
            continue
        cx, cy = (x1 + x2) // 2, (y1 + y2) // 2
        if (cx, cy) in tapped:
            continue
        tapped.append((cx, cy))
        r = tap(cx, cy)
        # A refused tap must never be read as a landed one: measured on 1.9.8, all three taps
        # answered ERR while pm install still printed Success, so Success alone says nothing
        # about the tap path (art/ledger-20261016.md 629).
        if "UINPUT_TAP_DONE" in r:
            landed += 1
        else:
            refused += 1
        print("tap %s %r at %d,%d -> %s" % (kind, txt, cx, cy, r), flush=True)
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
