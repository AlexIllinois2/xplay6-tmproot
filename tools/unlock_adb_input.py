#!/usr/bin/env python3
"""One-time unlock of this ROM's ADB input gate, and the check that it held.

What the gate is (evidence: art/ledger-20261021.md 691-701):
  system_server's `VivoPackageManagerSerivceUtils.preCheckUidPermission` withholds INJECT_EVENTS from
  uid 2000 unless `Settings.Secure vivo_adb_simulate_input` == 1.  The vendor UI only lets that flag be
  turned on after a vivo-account check, but the check lives entirely in Settings: the dialog's positive
  button first reads `SharedPreferences("development").getBoolean("account_verified_ok")` and, when true,
  writes the flag without asking for an account.  PKMS watches the Secure URI with a ContentObserver, so
  the flip is live immediately, and it survives reboot (measured: 1 -> adb reboot -> 1, no observer write).

Two things this script does NOT do, both measured:
  * it cannot write the flag itself -- the daemon's root shell has no servicemanager access at all
    (`dumpsys window` -> "Can't find service: window", `settings put` -> null IActivityManager), so the
    last move is a finger on 开发者选项 -> USB模拟点击;
  * it must not use /data/data for the pref: Settings' manifest sets `defaultToDeviceProtectedStorage=true`,
    so its SharedPreferences live under /data/user_de -- writing the CE path reads back false silently.

usage: unlock_adb_input.py [--check|--feed] [ser]
  --check  read-only: is the flag on, is the pref in place (needs the root channel for that half)
  --feed   write the pref through the daemon's root shell, then print the human step
exit: 0 ok / 2 REFUSED (a witness was unreachable -- nothing concluded) / 3 red (flag off after the step)
"""
import os
import subprocess
import sys

PREF_DIR = "/data/user_de/0/com.android.settings/shared_prefs"
PREF = PREF_DIR + "/development.xml"
XML = ("<?xml version='1.0' encoding='utf-8' standalone='yes' ?>\n<map>\n"
       '    <boolean name="account_verified_ok" value="true" />\n</map>\n')
KEY = "vivo_adb_simulate_input"
SER = "3e5a38a5"
MODE = "--check"
for a in sys.argv[1:]:
    if a.startswith("--"):
        MODE = a
    else:
        SER = a
ADB = ["adb", "-s", SER]


def sh(args, t=60):
    return subprocess.run(ADB + ["shell"] + args, capture_output=True, text=True, timeout=t).stdout


def root(cmd, wait=6):
    """the daemon's raw root shell on TCP 12345 (same pipeline shape as verify_approot.sh's rootsh,
    which needs the `timeout` because the daemon never closes the socket itself)"""
    subprocess.run(["adb", "-s", SER, "forward", "tcp:12345", "tcp:12345"], capture_output=True)
    script = ('{ printf "%s\\n" "$1"; sleep "$2"; } '
              '| timeout "$3" bash -c "exec 3<>/dev/tcp/127.0.0.1/12345; cat >&3; cat <&3" 2>/dev/null '
              '| tr -d "\\r"')
    p = subprocess.run(["bash", "-c", script, "_", cmd, str(wait), str(wait + 8)],
                       capture_output=True, text=True, timeout=120)
    subprocess.run(["adb", "-s", SER, "forward", "--remove", "tcp:12345"], capture_output=True)
    return ((p.stdout or "") + (p.stderr or "")).strip()


def gate():
    return sh(["settings", "get", "secure", KEY]).strip()


def pref_state():
    """returns (ok, raw) -- ok None means the witness itself was unreachable, which is REFUSED, not false"""
    out = root("ls -lZ %s 2>&1 | tail -2; grep -ac 'account_verified_ok\" value=\"true\"' %s 2>/dev/null"
               % (PREF, PREF))
    if not out or "No such file" in out or "Permission denied" in out:
        return (None if not out else False), out
    return out.splitlines()[-1].strip() == "1", out


g = gate()
print("%s = %r" % (KEY, g))
if MODE == "--feed":
    ok, raw = pref_state()
    if ok is True:
        print("pref already in place, nothing to write")
    else:
        out = root("mkdir -p %s; chown 1000:1000 %s; chmod 771 %s; "
                   "printf %%s %r > %s; chown 1000:1000 %s; chmod 660 %s; restorecon -R %s; "
                   "ls -lZ %s | tail -1; grep -ac 'value=\"true\"' %s"
                   % (PREF_DIR, PREF_DIR, PREF_DIR, XML, PREF, PREF, PREF, PREF_DIR, PREF, PREF))
        print(out)
    print("\n下一步（脚本做不到，实测成因见文件头）：手机上 设置 -> 更多设置 -> 开发者选项 -> "
          "「USB模拟点击」 拨开；弹框按正按钮。喂了这枚 pref 之后不应再要 vivo 账号。")
    print("拨完回来跑： python3 tools/unlock_adb_input.py --check %s" % SER)
    sys.exit(0)

ok, raw = pref_state()
if ok is None:
    print("pref witness: REFUSED (root channel not up this boot) -- %r" % raw[:80])
else:
    print("pref witness: %s -- %s" % ("account_verified_ok=true present" if ok else "MISSING", raw[-90:]))
if g == "1":
    print("UNLOCKED: adb injection is allowed. Proof of the functional face:")
    print("  adb -s %s shell input tap 950 <row-y>   # 打在行的开关侧，标题区不吃点击" % SER)
    sys.exit(0)
print("STILL LOCKED: the flag reads 0.")
sys.exit(3 if ok is True else 2)
