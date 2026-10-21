#!/usr/bin/env python3
"""Drive the official 「USB模拟点击」 switch and judge it by the Secure value only.

Why this needs its own ruler (measured on-device 2026-10-21, ledger 691-692):
  * The verdict is `Settings.Secure vivo_adb_simulate_input` -- PKMS keeps it live through a
    ContentObserver, so a landed write shows up in the very next read, no reboot.
  * `uiautomator` on this ROM reports `checkable="true"` for ZERO nodes on both the developer-options
    page and DisplaySettings -- the switch's own state is unreadable there, so "the tap did nothing"
    must never be concluded from a dump.  The only witness is the value.
  * Root cannot write that value: the daemon's root shell has no servicemanager lookup at all
    (`dumpsys window` -> `Can't find service: window`, `settings put` -> null IActivityManager).
    So the write must come out of a process that has binder AND WRITE_SECURE_SETTINGS -- Settings itself.
  * Clicking the row opens a dialog with a 6 s countdown; the positive button writes 1 when
    `readVerifiedRecord()` (Settings' own `account_verified_ok` pref) is true, and BOTH the expiry and
    every verification failure branch write 0 back.  That gives two independent arms for one ruler:
    let it expire -> value must stay 0; tap positive -> value must become 1.
  * Taps go through /dev/uinput (tools/uinput_tap, --drag for the scroll) because the framework refuses
    adb-side injection until this very flag is on -- which is the thing being flipped.

usage: simulate_input_toggle.py [--arm both|positive|negative] [--dry] [ser]
Exits: 0 judged, 2 REFUSED (a coordinate or a node could not be read -- nothing was concluded),
       3 the arms disagree with the model (real red).
"""
import os
import re
import subprocess
import sys
import time

SER = "3e5a38a5"
ARM = "both"
DRY = False
args = sys.argv[1:]
while args:
    a = args.pop(0)
    if a == "--arm":
        ARM = args.pop(0)
    elif a == "--dry":
        DRY = True
    else:
        SER = a
ADB = ["adb", "-s", SER]
KEY = "vivo_adb_simulate_input"
ROW_TEXT = re.compile(r"USB模拟点击")
BUTTON = re.compile(r"^(同意|继续|确定|允许|立即|开启)$")
REFUSE_BUTTON = re.compile(r"(不同意|取消|关闭)")
NODE = re.compile(r'<node[^>]*?text="([^"]*)"[^>]*?bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"')


def sh(cmd, t=60, stdin=None):
    return subprocess.run(ADB + ["shell"] + cmd, capture_output=True, text=True, timeout=t,
                          input=stdin).stdout


def value():
    v = sh(["settings", "get", "secure", KEY]).strip()
    return v


def root(cmd, wait=6):
    """one command through the daemon's raw root shell (port 12345).
    The pipeline shape is copied from tools/verify_approot.sh's rootsh(): the daemon does not close the
    socket, so the read side has to be cut off by `timeout` -- without it this hangs until the caller's
    own timeout and the collected output is lost."""
    subprocess.run(["adb", "-s", SER, "forward", "tcp:12345", "tcp:12345"], capture_output=True)
    script = ('{ printf "%s\\n" "$1"; sleep "$2"; } '
              '| timeout "$3" bash -c "exec 3<>/dev/tcp/127.0.0.1/12345; cat >&3; cat <&3" 2>/dev/null '
              '| tr -d "\\r"')
    p = subprocess.run(["bash", "-c", script, "_", cmd, str(wait), str(wait + 8)],
                       capture_output=True, text=True, timeout=90)
    return ((p.stdout or "") + (p.stderr or "")).strip()


def tap(x, y, wait=2):
    # the dialog only lives 6 s (CountDownTimer(6000)), so a tap must not sit on the socket reading its
    # own echo for longer than that -- measured: with wait=6 the dump always landed after onFinish dismissed it
    return root("/data/local/tmp/uinput_tap %d %d" % (x, y), wait=wait)


def drag(x1, y1, x2, y2):
    return root("/data/local/tmp/uinput_tap --drag %d %d %d %d 12" % (x1, y1, x2, y2), wait=4)


def nodes(tag="ui"):
    path = "/data/local/tmp/%s.xml" % tag
    sh(["uiautomator", "dump", path], t=40)
    xml = sh(["cat", path], t=40)
    return [(m.group(1), ((int(m.group(2)) + int(m.group(4))) // 2,
                          (int(m.group(3)) + int(m.group(5))) // 2),
             (int(m.group(4)) - int(m.group(2))) * (int(m.group(5)) - int(m.group(3))))
            for m in NODE.finditer(xml)]


def find_row(ns):
    for t, c, area in ns:
        if t and ROW_TEXT.search(t):
            return c
    return None


def open_page():
    sh(["am", "start", "-a", "android.settings.APPLICATION_DEVELOPMENT_SETTINGS"], t=40)
    time.sleep(3)


def refuse(why):
    print("REFUSED: %s" % why)
    print("  nothing is concluded about the switch -- the ruler could not see what it must read.")
    sys.exit(2)


if ARM not in ("both", "positive", "negative"):
    sys.exit("bad --arm")
pre = value()
print("pre-run %s = %r" % (KEY, pre), flush=True)
if pre not in ("0", "1", "null"):
    refuse("the value read itself is unparseable: %r" % pre)

open_page()
row = find_row(nodes("row1"))
if row is None:  # the row sits below the fold; scroll with the one real touchscreen we can build
    r = drag(540, 1400, 540, 500)
    print("scroll -> %s" % r.splitlines()[-1] if r else "scroll: no answer", flush=True)
    if "UINPUT_TAP_DONE" not in r:
        refuse("the scroll drag never came back done: %r" % r)
    row = find_row(nodes("row2"))
if row is None:
    refuse("no 「USB模拟点击」 row in the dump (page not rendered / focus elsewhere)")
print("row center from the dump: %d,%d" % row, flush=True)
if DRY:
    print("DRY: would tap the row and judge by the value")
    sys.exit(0)

results = []

def dialog_buttons():
    ns = nodes("dlg")
    yes = [c for t, c, a in ns if t and BUTTON.match(t.strip()) and a > 400]
    if not yes:
        refuse("the confirm dialog's positive button was not in the dump (texts seen: %r)"
               % ([t for t, _c, _a in ns if t][:14],))
    print("dialog positive candidates from this dump: %r" % yes, flush=True)
    return yes[0]

def learn_buttons():
    """open the dialog once ONLY to read its geometry off the device -- the 6 s countdown runs while we read"""
    r = tap(*row)
    if "UINPUT_TAP_DONE" not in r:
        refuse("the row tap was not acknowledged: %r" % r)
    return dialog_buttons()

if ARM in ("both", "negative"):
    if value() != "0":
        refuse("negative arm needs the flag at 0 first (it reads %r)" % value())
    pos = learn_buttons()
    time.sleep(6)
    v = value()
    results.append(("negative: dialog left to expire", v, v == "0"))
    print("  -> value %s" % v, flush=True)
elif value() != "0":
    refuse("positive arm needs the flag at 0 first, so this click is the only possible witness (it reads %r)"
           % value())

if ARM == "positive":
    pos = learn_buttons()                      # throwaway dialog: geometry only
    time.sleep(6)
    if value() != "0":
        refuse("the throwaway dialog already moved the value (%r) -- the arm is no longer clean" % value())

if ARM in ("both", "positive"):
    # ONE channel round trip: the row, then its positive button inside the countdown window
    out = root("/data/local/tmp/uinput_tap %d %d; sleep 1; /data/local/tmp/uinput_tap %d %d"
               % (row[0], row[1], pos[0], pos[1]), wait=8)
    print("tap pair -> %s" % out.replace("\n", " | ")[:180], flush=True)
    if out.count("UINPUT_TAP_DONE") != 2:
        refuse("expected two acknowledged taps, got %d: %r" % (out.count("UINPUT_TAP_DONE"), out))
    time.sleep(3)
    v = value()
    results.append(("positive: row + confirm tapped", v, v == "1"))
    print("  -> value %s" % v, flush=True)

bad = [r for r in results if not r[2]]
print("== verdict ==")
for name, v, ok in results:
    print("  %-32s value=%s  %s" % (name, v, "as modelled" if ok else "MISBEHAVED"))
if bad:
    print("RED: the value did not follow the clicks -- %r" % ([b[0] for b in bad],))
    sys.exit(3)
print("JUDGED: pre-run %s = %r, now %r -- %d arm(s) reported." % (KEY, pre, value(), len(results)))
