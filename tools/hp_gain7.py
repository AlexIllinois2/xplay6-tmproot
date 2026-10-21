#!/usr/bin/env python3
"""The §592 one-byte HP knob: make 7's headphone gain match 6.0.1's, in RAM only.

What was established (art/ledger-20261016.md §589/§592, offline disassembly; DT side re-confirmed
live on this phone 2026-10-20 by `--read`, no root needed):
  · 7's `tasha_codec_probe` overwrites `wcd_hph_gain[0..3]` from DT `vivo,wcd-hph-gain`, one byte at a
    time (`strb` at 0xffffffc000bbbbec), so the DT's {4,3,1,1} replaces the compiled {4,1,1,1}.
  · Both boards consume that array in the SAME exported function `wcd_hph_gain_config`, which picks a
    column from the measured impedance and writes the byte into codec registers 0x6d3 and 0x6d6 with
    mask 0x1f.  6.0.1 hard-codes the column thresholds as compares; 7 reads them from `wcd_imped_defs`
    (whose DT value equals the compiled default, so that one changes nothing).
  · §326/§327 measured 34 ohm -> column 1 on this phone, and column 1 is exactly where the two
    firmware lines differ (6.0.1: 1, 7: 3).  This tool moves that one byte.

Transports -- each one is only here because it was measured to work (or not work):
  READ  pre-state  = the live DT property, as big-endian u32 cells, through plain adb shell.  Works
                      today, no root, no needle.
  WRITE            = `clobber <rounds> kern <addr> hex:<4B> 4 0` through the daemon's root channel --
                      the same primitive that landed the modprobe_path / selinux_enforcing writes in
                      §599.  Needs the channel up, i.e. the app-side escalation.
  READBACK        = NONE, deliberately admitted here (see WITNESS in the report): arbitrary kernel read
                      is judged dead (§492), tools/kread.c is a documented negative result, /dev/mem is
                      compiled out and there is no /proc/kcore (§375), and `codec:tasha_codec/codec_reg`
                      is 0 bytes on this card.  So `--apply` can prove the write fired, not the value.

Honesty rules baked in:
  - RAM write only.  No partition is touched, and a reboot restores whatever the DT says.
  - Default is DRY RUN; `--apply` is required to write, same rule as §375/§376.
  - The address comes from the recovered kallsyms table AND the running kernel's UTS release must match
    the profile that table was recovered for; otherwise refuse, exactly like run_temproot.sh.
  - The tool refuses unless the DT supplies one of the two shapes it can explain.  A third value means
    this build's DT is not the one §592 disassembled against, and writing blindly would be an
    experiment disguised as a port.
  - No dB claim anywhere: the only scale we have is "a 5-bit field (mask 0x1f) written to 0x6d3/0x6d6".

usage:
  tools/hp_gain7.py --read            # live DT pre-state + the plan            (works with no root)
  tools/hp_gain7.py --apply           # write the 6.0.1 value                  (needs the root channel)
  tools/hp_gain7.py --restore         # write the DT value back (also: reboot)  (needs the root channel)
  tools/hp_gain7.py --selftest        # decision table + delivered read-out, no device
"""
import argparse
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SER = os.environ.get("SER", "3e5a38a5")
ADB = ["adb", "-s", SER]
KALL = os.path.join(ROOT, "art/kallsyms-7-real.txt")
PROFILE_RELEASE = "3.18.31-perf-g9dce1fbc9"     # the build §592/§599 were measured against
DT_GAIN = "/proc/device-tree/soc/sound-9335/vivo,wcd-hph-gain"
DT_IMPED = "/proc/device-tree/soc/sound-9335/vivo,wcd-imped-defs"
CLOBBER = "/data/local/tmp/clobber"
OBJ_LEN = 8                                     # wcd_hph_gain spans to soc_codec_dev_tasha at +8
REG_FACE = ("0x6d3", "0x6d6")                   # written with mask 0x1f by wcd_hph_gain_config
COMPILED = bytes([4, 1, 1, 1])                  # default of BOTH firmware lines == 6.0.1's steady value
DT_SHAPE = bytes([4, 3, 1, 1])                  # what 7's DT overwrites the array with
TARGET = COMPILED                               # what we want while 6.0.1 is the reference
KNOWN = {COMPILED: "compiled default of both firmware lines (6.0.1's steady value)",
         DT_SHAPE: "7's DT value from vivo,wcd-hph-gain"}

WITNESS = """# witness boundary -- measured, not assumed:
#   RAM readback of wcd_hph_gain: NONE on this build.  Arbitrary kernel read was judged dead
#     (ledger 492: the leak window only covers the kmalloc-512 family); tools/kread.c is a documented
#     negative result (access_ok on the user iovec at entry); /dev/mem is compiled out and there is no
#     /proc/kcore (ledger 375, six faces all ABSENT).
#   Register face for %s: the codec node that carries wcd_hph_gain_config writes them, and BOTH
#     candidate codec dirs under /sys/kernel/debug/asoc/msm8996-tasha-cdp-snd-card/ print nothing:
#     codec:tasha_codec/codec_reg and codec:hifi-codec/codec_reg are each 0 bytes
#     (art/audio-6.0.1/MANIFEST.txt:389 and :1107, md5 e3b0c44298fc1c14... = the empty file).
#     Only codec:tfa98xx/codec_reg ever produced a dump, and that is the SmartPA, not this codec.
#   So what --apply CAN prove: the write primitive fired at that address (`CLOBBER OK`, the same
#     primitive that landed modprobe_path and selinux_enforcing writes in ledger 599).
#   What is left as the effect face: the listener.  A/B with the ledger 372/374 rig -- the runbook's
#     "要人配合" cell.  Do not write "verified" in any column this tool cannot read back.
""" % (" / ".join(REG_FACE),)


def die(msg, code=1):
    print("REFUSE: %s" % msg)
    sys.exit(code)


def sym(name, table=None):
    table = table or open(KALL, errors="replace").read()
    m = re.search(r"^([0-9a-f]{16}) d %s$" % re.escape(name), table, re.M)
    return int(m.group(1), 16) if m else None


def release_ok(rel):
    """pure so the arm and the live run share one verdict (a copied predicate drifts)"""
    return rel.strip() == PROFILE_RELEASE


def parse_od(text):
    """`od -An -tu1` output -> the byte list, or None if it is not four big-endian u32 cells."""
    n = [int(x) for x in re.findall(r"\b\d+\b", text.split("--imped--")[0])]
    return n if len(n) == 16 else None


def cells_from_od(text):
    """live DT bytes -> the 4 gain values -> the 4-byte RAM shape the probe would leave behind."""
    b = parse_od(text)
    if b is None:
        return None
    return bytes([b[3], b[7], b[11], b[15]])


def plan(cur, want=TARGET):
    """(action, payload, note) -- the whole decision table, testable with no device."""
    if cur is None or len(cur) < 4:
        return ("refuse", None,
                "short read: %r for a 4-cell field -- the DT node was not parsed, nothing was measured"
                % (None if cur is None else list(cur)))
    head = bytes(cur[:4])
    if head not in KNOWN:
        return ("refuse", None, "DT bytes %s match nothing this line explains; the shapes it knows are %s"
                % (list(head), " / ".join(str(list(k)) for k in KNOWN)))
    if head == want:
        return ("noop", None, "already %s = %s" % (list(head), KNOWN[head]))
    return ("write", want, "from %s (%s) to %s (%s)"
            % (list(head), KNOWN[head], list(want), KNOWN[want]))


def decide(cur, want, force):
    """plan()'s verdict, plus the one correction an unwitnessable target forces on it.

    `cur` can only ever be the DT reading (arbitrary kernel read is dead on this build, so the tool has
    no way to see the array).  Left alone, that makes `--restore` answer "noop" forever: DT still says
    what DT says no matter what is in RAM.  A write of a known 4-byte value is idempotent, so when the
    operator asked for an explicit action the request wins over the comparison -- while a shape this
    line cannot explain still refuses (writing blindly would be an experiment, not a port).
    """
    act, pay, note = plan(cur, want)
    if act == "refuse":
        return act, pay, note
    if force and act == "noop":
        return ("write", want,
                "DT already says %s -- forced write anyway: the array cannot be read back, so that "
                "match is not a reading of RAM" % list(want))
    return act, pay, note


def byte_diff(cur, pay):
    return [(i, cur[i], pay[i]) for i in range(len(pay)) if cur[i] != pay[i]]


def clobber_landed(out):
    """the only write witness this transport offers, and it is a *fired* witness, not a value witness"""
    return "CLOBBER OK" in out


def report(addr, nxt, cur, act, pay, note, mode):
    """the delivered read-out; selftest arm 8 runs THIS text, not just plan()"""
    lines = ["# wcd_hph_gain @ 0x%x (bounded by soc_codec_dev_tasha at 0x%x, %d B)" % (addr, nxt, nxt - addr),
             "# DT pre-state %s -> %s" % ("unread" if cur is None else list(cur), note),
             "# registers this feeds: %s (mask 0x1f) written by wcd_hph_gain_config; column chosen from "
             "the measured impedance (34 ohm -> column 1, ledger 326/327)" % (", ".join(REG_FACE),)]
    if act == "write":
        diff = byte_diff(cur, pay)
        if not diff:
            other = next((k for k in KNOWN if k != pay), pay)
            lines.append("# bytes that actually move (against the other documented value %s, since RAM "
                         "cannot be read): %s" % (list(other), ", ".join("[%d] %d->%d" % d
                                                                        for d in byte_diff(other, pay))))
        else:
            lines.append("# bytes that actually move: %s"
                         % ", ".join("[%d] %d->%d" % d for d in diff))
    lines.append(WITNESS.rstrip("\n"))
    if act == "refuse":
        lines.append("REFUSE: " + note)
    elif act == "noop":
        lines.append("nothing to do")
    elif mode == "dry":
        lines.append("DRY RUN: would write %s (4 B) at 0x%x  --  pass --apply to do it "
                     "(--restore to write the DT value back)" % (list(pay), addr))
    elif mode == "apply":
        lines.append("APPLY: writing %s (4 B) at 0x%x through the root channel" % (list(pay), addr))
    return "\n".join(lines)


def sh(args, timeout=40):
    return subprocess.run(ADB + ["shell"] + args, capture_output=True, text=True,
                          timeout=timeout).stdout.replace("\r", "")


def rsh(cmd, timeout=30):
    """one command through the daemon's raw root channel.

    Protocol copied from the recorded shape (tools/verify_approot.sh:122 rootsh and
    tools/sendevent_tap_install.sh rootsh): forward, write the command, close stdin, read to EOF.
    `exit` is what makes the daemon's shell close the socket, so the read terminates by itself.
    Never raises -- a dead channel must become a REFUSE line, not a traceback, because this is the
    one code path that will be run unsupervised when the channel is back.
    """
    subprocess.run(ADB + ["forward", "tcp:12345", "tcp:12345"], capture_output=True)
    try:
        p = subprocess.Popen(["bash", "-c",
                              'exec 3<>/dev/tcp/127.0.0.1/12345; cat >&3; cat <&3'],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, text=True)
        out, _ = p.communicate(cmd + "\nexit\n", timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            p.kill()
            out, _ = p.communicate(timeout=5)
        except Exception:
            out = ""
        return "<<TIMEOUT>> " + (out or "")
    except Exception as e:
        return "<<ERROR:%s>>" % e
    return (out or "").replace("\r", "")


def channel_says_root(out):
    """pure so the arm and the live pre-flight share one verdict: an unread channel is NEVER up"""
    if out.startswith(("<<TIMEOUT", "<<ERROR")):
        return False
    return out.strip().splitlines()[-1:] == ["0"]


def channel_up():
    return channel_says_root(rsh("id -u"))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--read", action="store_true")
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--restore", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        sys.exit(selftest())

    if not release_ok(live_release := sh(["uname", "-r"])):
        die("running kernel is %r but the kallsyms profile is for %r -- refusing to write an "
            "address recovered for another build" % (live_release.strip(), PROFILE_RELEASE))
    addr = sym("wcd_hph_gain")
    nxt = sym("soc_codec_dev_tasha")
    if addr is None or nxt is None or nxt - addr < OBJ_LEN:
        die("cannot bound wcd_hph_gain in %s (addr=%s next=%s) -- writing an unbounded object is "
            "how you corrupt a neighbour" % (KALL, addr, nxt))
    if addr + 4 > nxt:
        die("a 4-byte word at 0x%x would end past the object bound 0x%x" % (addr, nxt))
    cur = cells_from_od(sh(["od", "-An", "-tu1", DT_GAIN]))
    want = DT_SHAPE if a.restore else TARGET
    mode = "apply" if (a.apply or a.restore) else "dry"
    act, pay, note = decide(cur, want, force=(mode == "apply"))
    print(report(addr, nxt, cur, act, pay, note, mode))
    if act == "refuse":
        sys.exit(1)
    if act != "write" or mode == "dry":
        return 0
    if not channel_up():
        die("the root channel is not up (port 12345 must answer `id -u` == 0). Nothing was written. "
            "This tool does not fall back to a user-memory path: the target is a kernel .data address.")
    out = rsh("%s 40 kern 0x%x hex:%s 4 0"
              % (CLOBBER, addr, "".join("%02x" % b for b in pay)))
    print(out.strip()[-400:])
    if not clobber_landed(out):
        die("clobber reported no hit in this batch -- the write did NOT land; the array is unchanged "
            "(rounds=40 because ledger 599 measured rounds=10 missing 3/3 on this boot)")
    print(fired_report(addr))
    print("reversibility: reboot re-applies the DT value; --restore writes %s back" % list(DT_SHAPE))
    return 0


def fired_report(addr):
    """The line the operator reads as "it fired here" -- kept as a function so the selftest arm runs
    the delivered text itself instead of a paraphrase of it."""
    return ("fired: clobber OK at 0x%x.  UNWITNESSED by design: the value in RAM.  Effect face = A/B."
            % addr)


def selftest():
    bad = 0

    def arm(name, cond):
        nonlocal bad
        print("  %s %s" % ("ok  " if cond else "FAIL", name))
        if not cond:
            bad += 1

    dt = "   0   0   0   4   0   0   0   3   0   0   0   1   0   0   0   1\n"
    act, pay, _ = plan(cells_from_od(dt))
    arm("the recorded live od text parses to the DT shape and gets a plan to write 6.0.1's value",
        act == "write" and pay == TARGET)
    act, pay, d = plan(cells_from_od(dt), TARGET)
    arm("only ONE byte moves, and it moves 3->1 at index 1", d is not None and
        byte_diff(cells_from_od(dt), pay) == [(1, 3, 1)])
    act, _, _ = plan(bytes([4, 1, 1, 1, 0, 0, 0, 0]))
    arm("already-there is a NOOP, not a rewrite", act == "noop")
    act, _, _ = plan(bytes([4, 9, 1, 1]))
    arm("an unexplained shape REFUSES (this is a port, not an experiment)", act == "refuse")
    act, _, _ = plan(None)
    arm("a failed parse REFUSES -- no read is never a value", act == "refuse")
    act, _, n2 = plan(cells_from_od("   0   0   0   4   0   0   0   9   0   0   0   1   0   0   0   1\n"))
    arm("the refusal NAMES both the observed bytes and the shapes it knows",
        act == "refuse" and "[4, 9, 1, 1]" in n2 and "[4, 3, 1, 1]" in n2)
    act, pay, _ = plan(bytes([4, 1, 1, 1]), want=DT_SHAPE)
    arm("--restore is the mirror decision (DT shape gets planned back from the compiled one)",
        act == "write" and pay == DT_SHAPE)
    arm("the trap that made --restore dead is still described, not silently allowed to return",
        plan(DT_SHAPE, want=DT_SHAPE)[0] == "noop")
    arm("but an explicit --restore forces the write, because DT is not a reading of RAM",
        decide(DT_SHAPE, DT_SHAPE, force=True)[0] == "write"
        and decide(DT_SHAPE, DT_SHAPE, force=True)[1] == DT_SHAPE)
    arm("--read keeps the plain verdict (a forced write is only for the commands that ask for one)",
        decide(DT_SHAPE, DT_SHAPE, force=False)[0] == "noop")
    arm("force must not outrank the shape gate -- an unexplained DT still refuses",
        decide(bytes([4, 9, 1, 1]), DT_SHAPE, force=True)[0] == "refuse")
    arm("the release gate is a real verdict, and a stale build refuses",
        release_ok(PROFILE_RELEASE + "\n") and not release_ok("3.18.20-perf-g0000")
        and not release_ok(PROFILE_RELEASE + "-dirty"))
    t = "ffffffc001bb82c8 d wcd_hph_gain\nffffffc001bb82d0 d soc_codec_dev_tasha\n"
    arm("address derivation reads a table by name", sym("wcd_hph_gain", t) == 0xffffffc001bb82c8)
    arm("and the bound check sees the 8-byte span", 0xffffffc001bb82d0 - 0xffffffc001bb82c8 == OBJ_LEN)
    arm("a table where the neighbour is 4 B away must not pass the bound rule",
        not (sym("wcd_hph_gain", t) is not None and 0xffffffc001bb82cc - 0xffffffc001bb82c8 >= OBJ_LEN))
    a7, b7 = sym("wcd_hph_gain"), sym("soc_codec_dev_tasha")
    arm("the REAL recovered table for this build still holds both symbols and the same span",
        a7 is not None and b7 is not None and b7 - a7 == OBJ_LEN and a7 + 4 <= b7)
    arm("the fired-witness gate has teeth: no CLOBBER OK is not a landing",
        clobber_landed("RESULT: no hit in this batch\n") is False
        and clobber_landed("  *** CLOBBER OK ***\n") is True)
    fired = fired_report(0xffffffc001bb82c8)
    arm("the fired line names the address it wrote (an unformatted directive printed the address away once)",
        "0xffffffc001bb82c8" in fired and not re.search(r"%[a-z]", fired))
    txt = report(0xffffffc001bb82c8, 0xffffffc001bb82d0, cells_from_od(dt), "write", TARGET,
                 "from [4, 3, 1, 1] (7's DT value) to [4, 1, 1, 1]", "dry")
    arm("the DELIVERED read-out is run here: address, byte diff, and the witness boundary all print",
        "0xffffffc001bb82c8" in txt and "[1] 3->1" in txt
        and "RAM readback of wcd_hph_gain: NONE" in txt and "DRY RUN" in txt
        and "codec:tasha_codec/codec_reg and codec:hifi-codec/codec_reg are each 0 bytes" in txt)
    refused = report(0xffffffc001bb82c8, 0xffffffc001bb82d0, None, "refuse", None,
                     "short read: None for a 4-cell field", "dry")
    arm("the read-out says REFUSE rather than inventing a plan when nothing was measured",
        refused.startswith("#") and "REFUSE:" in refused and "DRY RUN" not in refused)
    arm("the channel pre-flight is not a maybe: banner+0 is up, but timeout/error/empty/2000 are not",
        channel_says_root("id -u\n0\n") is True
        and channel_says_root("<<TIMEOUT>> partial") is False
        and channel_says_root("<<ERROR:ConnectionRefusedError>>") is False
        and channel_says_root("") is False and channel_says_root("2000\n") is False)
    print("hp_gain7 selftest: %d arm(s) failed" % bad)
    return 1 if bad else 0


if __name__ == "__main__":
    main()
