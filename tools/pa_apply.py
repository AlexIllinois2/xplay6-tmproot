#!/usr/bin/env python3
"""tools/pa_apply.py -- the §252 write-back procedure for the TFA9890, implemented and gated.

What it is for: on 7, the PA register layer has to be brought back to the 6.0.1 values.  On 6.0.1 the
only legitimate use is the *idempotent* one -- write each register the value it already holds, prove the
write door round-trips, and leave the chip identical -- because there is no second machine to restore
yet.  Default mode is therefore --dry-run (no device writes at all); --verify does the idempotent
round-trip; --restore writes baseline values that differ and needs one explicit token per register it
would actually change.

Gates, in the order they are checked (all denominators read from artifacts, none hand-typed):
  1  the door answers 26 registers (`cat /sys/kernel/debug/tfa98xx/codec_reg`, §249: the whitelist is
     `tfa98xx_regs` in .rodata and the loop bound is 0x1a -- 26, not 27)
  2  the table supplies exactly one row per register with a class in its `use_case` column (§346/§361)
  3  the speaker route is actually on: `SmartPA Switch` must read the value route-states.tsv gives for
     the speaker column -- off-path the amp sits on its reset values and writing them back is an
     actuation, not a restore (§285's lesson about reading the wrong section)
  4  only class == STABLE is ever written; the 8 non-STABLE registers (state-dependent 3 + volatile 3 +
     cross-session 2) are excluded by the table, not by a hard-coded list
  5  write -> read back -> must equal, or the whole run rolls back in reverse order to the snapshot
  6  the snapshot (all 26) is taken and kept before the first write, and re-verified after the last one

The door itself is `echo '<reg> <val>' > /sys/kernel/debug/tfa98xx/codec_reg`: sscanf "%x %x" then
do_reg_write_check (write-reads-compares, up to 5 retries) -- a WHOLE-register regmap_write with no mask,
so one line can move bits nobody intended to touch.  That is why every mode prints the field decode
(genregs name + the fields that hold the value) next to each register it would write.
"""
import argparse
import csv
import os
import re
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ART = os.path.join(ROOT, "art", "audio-6.0.1")
REGS = os.path.join(ART, "tfa-regs.PD1610.tsv")
TARGET = os.path.join(ART, "port-target.PD1610.tsv")
FIELDS = os.path.join(ART, "tfa-reg-fields.PD1610.tsv")
ROUTES = os.path.join(ART, "route-states.tsv")
DOOR = "/sys/kernel/debug/tfa98xx/codec_reg"
ADB = os.environ.get("ADB", "adb")
SU = os.environ.get("SU", "su")  # SU=sux on 7.1.1: the vendor gate refuses execve of a path whose last component is "su" (ledger 579)

LINE_RE = re.compile(r"reg\{([0-9a-f]+)\}:([0-9a-f]+)", re.I)


def sim():
    """the door is overridable at run time (not import time) so --selftest can point it at a fixture"""
    return os.environ.get("SIM_DOOR")


def sim_reject():
    return {int(x, 16) for x in os.environ.get("SIM_REJECT", "").replace(",", " ").split() if x}


def device_read():
    """the read door: `cat /sys/kernel/debug/tfa98xx/codec_reg` (26 lines).  With SIM_DOOR set the
    fixture is read instead, so the write loop and the rollback path can be tested without a phone."""
    if sim():
        return open(sim(), encoding="utf-8", errors="replace").read()
    p = subprocess.run([ADB, "exec-out", f"{SU} -c 'cat {DOOR}'"], capture_output=True, timeout=60)
    if p.returncode != 0:
        sys.exit(f"gate: reading {DOOR} failed rc={p.returncode} :: "
                 f"{p.stderr.decode('utf-8', 'replace')[:160]}")
    return p.stdout.decode("utf-8", "replace")


def device_write(reg, val):
    if sim():
        a, v = int(reg, 16), int(val, 16)
        if a in sim_reject():
            # a chip that NACKs the write: the door itself returns fine, the value simply does not stick
            return 0, f"sim: {a:#06x} did not take"
        cur = parse_door(open(sim(), encoding="utf-8", errors="replace").read())
        cur[a] = v
        # SIM_SIDE_EFFECT="0x4:0x5" makes a write to 0x04 also move 0x05 -- the crosstalk the sibling
        # gate is supposed to catch, so that gate has to be provable able to fire
        for spec in os.environ.get("SIM_SIDE_EFFECT", "").replace(",", " ").split():
            src, _, dst = spec.partition(":")
            if int(src, 16) == a and int(dst, 16) in cur:
                cur[int(dst, 16)] ^= 0x01
        with open(sim(), "w", encoding="utf-8") as fh:
            fh.write("\n".join(f"reg{{{k:04x}}}:{x:04x}" for k, x in sorted(cur.items())) + "\n")
        return 0, ""
    p = subprocess.run([ADB, "exec-out", f"{SU} -c 'echo {reg} {val} > {DOOR}'"],
                       capture_output=True, timeout=60)
    return p.returncode, (p.stdout + p.stderr).decode("utf-8", "replace").strip()


def parse_door(text):
    """physical-address-shaped reg{hex}:hex lines; both chips print this shape, so the caller must hand
    this function ONE section only (§285: parsing both let the DAC bytes overwrite 12 PA registers)."""
    out = {}
    for a, v in LINE_RE.findall(text):
        out[int(a, 16)] = int(v, 16)
    return out


def load_tables():
    regs = {int(r["reg"], 16): r for r in csv.DictReader(open(REGS, encoding="utf-8"), delimiter="\t")}
    tgt = {}
    for r in csv.DictReader(open(TARGET, encoding="utf-8"), delimiter="\t"):
        if r["layer"] == "PA/TFA9890":
            m = re.search(r"codec_reg 0x([0-9a-f]+)", r["item"])
            if m:
                tgt[int(m.group(1), 16)] = r
    fields = {int(r["reg"], 16): r for r in csv.DictReader(open(FIELDS, encoding="utf-8"), delimiter="\t")}
    return regs, tgt, fields


def plan(mode, live, regs, tgt, approvals, enforcing=False, allow_unknown=False):
    """which registers this run would write, with the reason for every exclusion.  Approval tokens are
    parsed as numbers, not matched as text: `0x4`, `0x04` and `0x0004` all mean register 4.

    Two gates beyond §252's class rule, both learned from the first dry run on this machine: class STABLE
    means the VALUE never moved between sessions, which says nothing about whether writing it is safe --
    the 18 STABLE rows include `DEVICE_REVISION` (a read-only identity) and nine registers with no decoded
    field names at all (the driver's bitfield table was trimmed, §329).  So a register is only written
    when it is named by token, and an unnamed one additionally needs --allow-unknown."""
    appr = {int(x, 16) for x in approvals}
    rows, skipped = [], []
    for addr in sorted(live):
        if addr not in regs:
            skipped.append((addr, "not in the 26-register baseline table"))
            continue
        row = regs[addr]
        if row["class"] != "STABLE":
            skipped.append((addr, f"class {row['class']} -- §252 gate 4"))
            continue
        named = bool(row["play_fields"].strip()) or bool(row["idle_fields"].strip())
        if not named and not allow_unknown:
            skipped.append((addr, "no decoded field names (§329 trimmed driver table) -- semantics "
                                  "unknown, needs --allow-unknown"))
            continue
        if enforcing and addr not in appr:
            skipped.append((addr, "would be written but has no --approve token"))
            continue
        want = live[addr] if mode != "restore" else int(row["play"], 16)
        cur = live[addr]
        if mode == "restore" and want == cur:
            skipped.append((addr, "already equal to the baseline, nothing to restore"))
            continue
        if mode == "restore" and addr not in appr:
            skipped.append((addr, f"WOULD CHANGE {cur:#06x} -> {want:#06x} but no approval token"))
            continue
        baseline = int(row["play"], 16)
        drift = "" if cur == baseline else f"  (live differs from baseline {baseline:#06x})"
        rows.append({"addr": addr, "now": cur, "want": want, "name": row["name"],
                     "fields": row["play_fields"].strip(), "class": row["class"], "drift": drift})
    return rows, skipped


def run(args):
    regs, tgt, fields = load_tables()
    if len(regs) != 26 or len(tgt) != 26:
        sys.exit(f"gate: the baseline supplies {len(regs)} tfa-regs rows and {len(tgt)} PA rows in "
                 "port-target -- both must be 26 (§249: the whitelist is 26, the loop bound is 0x1a); "
                 "refusing to plan a write against a partial denominator")
    stable = sorted(a for a, r in regs.items() if r["class"] == "STABLE")
    print(f"  table: 26 registers, {len(stable)} STABLE (write candidates), "
          f"{26 - len(stable)} excluded by class")

    if args.device == "off":
        if not args.fixture:
            sys.exit("gate: --device off needs --fixture with door text -- planning a write against a "
                     "guessed register map is exactly what §285 was about")
        live = parse_door(open(args.fixture, encoding="utf-8").read())
        sw = "fixture"
    else:
        live = parse_door(device_read())
        sw = read_smartpa()
        print(f"  door: {len(live)} register(s) read from {DOOR}; `SmartPA Switch` reads {sw!r}")
    if len(live) != 26:
        sys.exit(f"gate: {len(live)} register values, want 26 (gate 1) -- with the amp off-path the dump "
                 "is reset-shape and a different chip bound to this door prints a different count; "
                 "neither may be planned against")

    want_on = speaker_value(ROUTES, "SmartPA Switch")
    if want_on is None:
        sys.exit("gate: route-states.tsv has no `SmartPA Switch` row -- gate 3 cannot be checked, and "
                 "§298/§299 make that control exactly the one edge the speaker path needs")
    on_path = sw.strip().lower() == want_on.strip().lower()
    if not on_path:
        print(f"  NOTE gate 3: the speaker route is NOT on (`SmartPA Switch`={sw!r}, route-states.tsv "
              f"wants {want_on!r}) -- these values are off-path/reset shape.  A dry run may still show "
              "the plan; --commit is refused until the route is on.")

    rows, skipped = plan(args.mode, live, regs, tgt, set(args.approve or []),
                         enforcing=(not args.dry_run) or args.preview_enforcing,
                         allow_unknown=args.allow_unknown)
    print(f"  mode={args.mode} dry_run={args.dry_run} "
          f"enforcing={(not args.dry_run) or args.preview_enforcing}: "
          f"would write {len(rows)} register(s)")
    print("  ★`writable` in port-target only ever says the DEBUGFS DOOR accepts a write (0644, sscanf "
          "'%x %x', whole-register regmap_write with no mask).  No artifact here states CHIP-side "
          "writeability -- the TFA9890 datasheet is unreachable (§350) -- so a register named in a "
          "committed plan is a decision the operator makes, not a capability this tool verified.")
    for r in rows:
        print(f"    {r['addr']:#06x} {r['name']:<22} now={r['now']:#06x} want={r['want']:#06x} "
              f"[{r['class']}] {r['fields'][:52]}{r['drift']}")
    for a, why in skipped:
        print(f"    skip {a:#06x} {regs[a]['name']:<20} {why}")

    stamp = time.strftime("%Y%m%d-%H%M%S")
    # §360: only a deliberate act may mint a file under art/ -- a rehearsal must not put a near-identical
    # "snapshot" next to the baseline where a later reader (or tfa_field_history) could take it for one
    snap = args.snapshot_out or os.path.join(
        ART if not args.dry_run else "/tmp",
        "live" if not args.dry_run else "", f"pa-snapshot-{stamp}.txt")

    if args.dry_run:
        with open(snap, "w", encoding="utf-8") as fh:
            fh.write("# dry run: read-only snapshot, no write issued\n" + "\n".join(
                f"{a:#06x} {v:#06x}" for a, v in sorted(live.items())) + "\n")
        print(f"  DRY RUN: zero writes issued.  Snapshot of all 26 -> {snap}")
        return 0

    if args.device == "off":
        sys.exit("gate: --commit against --device off would write nothing and prove nothing -- drop "
                 "--device off or drop --commit")
    if not on_path:
        sys.exit(f"gate 3 refuses --commit: `SmartPA Switch` reads {sw!r}, the speaker route needs "
                 f"{want_on!r}.  Off-path these registers hold reset-shape values, so writing them back "
                 "is an actuation on the audible path, not a restore.")
    print("  pre-staged rollback (what runs if any readback mismatches):")
    for r in reversed(rows):
        print(f"    echo {r['addr']:x} {live[r['addr']]:x} > {DOOR}")

    done = []
    try:
        for r in rows:
            rc, out = device_write(f"{r['addr']:x}", f"{r['want']:x}")
            now = parse_door(device_read())
            back = now.get(r["addr"])
            # siblings = registers the RUN did not write whose value moved.  Registers this run already
            # wrote legitimately differ from the pre-snapshot; counting those as crosstalk aborted a
            # clean restore at its second register (the fixture caught it on 2026-10-17).
            written = {x["addr"] for x in done} | {r["addr"]}
            siblings = [a for a in now if a in live and now[a] != live[a] and a not in written
                        and regs.get(a, {}).get("class") == "STABLE"]
            ok = rc == 0 and back == r["want"] and not siblings
            print(f"    write {r['addr']:#06x} -> {r['want']:#06x}: rc={rc} readback="
                  f"{'-' if back is None else hex(back)} "
                  f"{'OK' if ok else 'BAD ' + (out[:60] + (' ' + str(siblings) if siblings else ''))}")
            done.append(r)
            if not ok:
                if siblings:
                    print(f"    ★the door moved {', '.join(f'{a:#06x}' for a in siblings)} as well -- "
                          "regmap_write here has no mask (§248), so this register is not safely "
                          "writable one at a time")
                moved = [a for a in now if a in live and now[a] != live[a]]
                seq = [x["addr"] for x in done if x["addr"] in moved]
                seq += [a for a in sorted(moved) if a not in seq]
                raise SystemExit(rollback(seq, live, "readback mismatch or sibling movement"))
    finally:
        after = parse_door(device_read())
        written = {r["addr"] for r in done}
        unintended = [a for a in after if a in live and after[a] != live[a] and a not in written
                      and regs.get(a, {}).get("class") == "STABLE"]
        intended = [a for a in after if a in live and after[a] != live[a] and a in written]
        print(f"  post-verify: {len(after)} register(s) read; {len(intended)} moved as planned, "
              f"{len(unintended)} moved UNPLANNED -> "
              f"{', '.join(f'{a:#06x}' for a in unintended) or 'none'}")
        with open(snap, "w", encoding="utf-8") as fh:
            fh.write("# pre-snapshot and post state, all 26\n")
            for a in sorted(live):
                fh.write(f"{a:#06x} pre={live[a]:#06x} post={after.get(a, -1):#06x}\n")
        print(f"  snapshot+post -> {snap}")
    return 0


def read_smartpa():
    """tinymix prints `SmartPA Switch: On` -- the value is what follows the colon.  The name has a
    space, so it travels quoted with DOUBLE quotes: a single quote inside `su -c '…'` would break the
    wrapper and the remote shell would hang forever (tools/devmem_read.py)."""
    if sim():
        return os.environ.get("SIM_ROUTE", speaker_value(ROUTES, "SmartPA Switch") or "On")
    p = subprocess.run([ADB, "exec-out", f"{SU} -c 'tinymix -D 0 \"SmartPA Switch\"'"],
                       capture_output=True, timeout=30)
    out = p.stdout.decode("utf-8", "replace").strip()
    return out.split(":", 1)[1].strip() if ":" in out else out


def speaker_value(route_file, control):
    for r in csv.DictReader(open(route_file, encoding="utf-8"), delimiter="\t"):
        if r["control"] == control:
            return r.get("speaker")
    return None


def rollback(addrs, live, why):
    """restore every register whose value moved -- not only the ones this run wrote, because the door
    has no mask (§248) and can move a neighbour.  Reverse order, then re-read and report any residue."""
    order = list(reversed(addrs))
    lines = [f"rollback because {why}: {len(order)} register(s) in reverse write order"]
    for a in order:
        lines.append(f"  echo {a:x} {live[a]:x} > {DOOR}")
    text = "\n".join(lines)
    for a in order:
        device_write(f"{a:x}", f"{live[a]:x}")
    after = parse_door(device_read())
    left = [a for a in after if a in live and after[a] != live[a]]
    text += ("\n  after rollback: "
             + (", ".join(f"{a:#06x} still at {after[a]:#06x} (was {live[a]:#06x})" for a in left)
                if left else "every register is back where it was found"))
    return text


# -------------------------------- selftest --------------------------------
def selftest():
    """offline arms with a fake door: the gates must be able to refuse."""
    bad, notes = [], []
    regs, tgt, fields = load_tables()
    if len(regs) != 26 or len(tgt) != 26:
        bad.append(f"table denominators {len(regs)}/{len(tgt)} != 26/26")
    fake = {a: int(r["play"], 16) for a, r in regs.items()}
    named = sorted(a for a, r in regs.items() if r["class"] == "STABLE"
                   and (r["play_fields"].strip() or r["idle_fields"].strip()))
    unnamed_stable = sorted(a for a, r in regs.items() if r["class"] == "STABLE" and a not in named)
    rows, skipped = plan("verify", fake, regs, tgt, set())
    if [r["addr"] for r in rows] != named:
        bad.append(f"verify planned {[r['addr'] for r in rows]} but the named STABLE set is {named}")
    if any(regs[r["addr"]]["class"] != "STABLE" for r in rows):
        bad.append("a non-STABLE register reached the write plan -- gate 4 is decorative")
    if len(skipped) + len(named) != 26:
        bad.append(f"{len(skipped)} skips + {len(named)} planned != 26: every exclusion needs a printed "
                   "reason or a reader cannot audit the run")
    if not unnamed_stable:
        bad.append("no STABLE register lacks a decode -- the dry run that motivated this gate is then "
                   "not reproducible here, say so instead of implying coverage")
    if not any(a == unnamed_stable[0] and "semantics unknown" in w for a, w in skipped):
        bad.append("an unnamed STABLE register was excluded without naming the semantics rule")
    rows_u, _ = plan("verify", fake, regs, tgt, set(), allow_unknown=True)
    if len(rows_u) != len(named) + len(unnamed_stable):
        bad.append(f"--allow-unknown planned {len(rows_u)}, expected {len(named) + len(unnamed_stable)}")
    rows_e, skipped_e = plan("verify", fake, regs, tgt, set(), enforcing=True)
    if rows_e:
        bad.append(f"a committed run planned {len(rows_e)} write(s) with no token -- the per-register "
                   "approval gate would be a formality")
    if not all("no --approve token" in w for a, w in skipped_e
               if regs[a]["class"] == "STABLE" and a in named):
        bad.append("token-less skips in a committed run lost their reason")
    rows_t, _ = plan("verify", fake, regs, tgt, {f"{a:#x}" for a in named}, enforcing=True)
    if [r["addr"] for r in rows_t] != named:
        bad.append(f"with every token a committed run planned {[r['addr'] for r in rows_t]}, want {named}")

    # end-to-end through the door, with a fixture instead of a phone: a write that does not stick must
    # leave every register exactly where it was found (the net-zero property the rollback exists for)
    import argparse as _ap
    import contextlib as _cl
    import io as _io
    import tempfile as _tf
    drive = sorted(named)[:3]
    if len(drive) < 2:
        bad.append(f"only {drive} named STABLE register(s) exist -- the end-to-end arm cannot exercise "
                   "a rollback of more than one write")
    drift = {a: int(regs[a]["play"], 16) for a in regs}
    for a in drive:
        drift[a] ^= 0x11                      # the machine is off the baseline on these three
    for reject_expected in (True, False):
        with _tf.TemporaryDirectory() as td:
            door = os.path.join(td, "door.txt")
            snap = os.path.join(td, "snap.txt")
            before = "\n".join(f"reg{{{a:04x}}}:{v:04x}" for a, v in sorted(drift.items())) + "\n"
            open(door, "w").write(before)
            reject = drive[1] if reject_expected else -1
            os.environ["SIM_DOOR"] = door
            os.environ["SIM_REJECT"] = f"{reject:x}"
            ns = _ap.Namespace(selftest=False, mode="restore", dry_run=False, device="on", fixture=None,
                               snapshot_out=snap, approve={f"{a:#x}" for a in drive},
                               allow_unknown=False, preview_enforcing=False)
            buf, code = _io.StringIO(), None
            try:
                with _cl.redirect_stdout(buf):
                    run(ns)
            except SystemExit as e:
                code = str(e)
            finally:
                os.environ.pop("SIM_DOOR", None)
                os.environ.pop("SIM_REJECT", None)
            after = open(door).read()
            log = buf.getvalue()
            if reject_expected:
                if not code or "rollback" not in code:
                    bad.append("a rejected write did not raise the rollback message")
                if after != before:
                    moved = [a for a, v in parse_door(after).items() if drift[a] != v]
                    bad.append(f"after a failed restore the chip sits at {moved} -- rollback did not "
                               "return it to where it was found")
                if "reverse write order" not in code:
                    bad.append("the rollback plan does not state that it runs in reverse write order")
            else:
                if code is not None:
                    bad.append(f"a clean restore aborted: {code[:120]}")
                now = parse_door(after)
                if [now[a] for a in drive] != [int(regs[a]["play"], 16) for a in drive]:
                    bad.append("a clean restore left the registers off the baseline")
                if "moved UNPLANNED" not in log:
                    bad.append("no post-verify line -- a committed run that does not re-read all 26 is "
                               "not auditable")
    # a door that lost a register must abort, not silently plan one fewer write
    short = dict(fake)
    short.pop(min(short))
    if len(parse_door("\n".join(f"reg{{{a:x}}}:{v:04x}" for a, v in short.items()))) != 25:
        bad.append("parse_door miscounted a 25-line door")
    # §285's trap: feeding BOTH chip sections must not be possible through this parser
    both = "reg{0000}:025d\nreg{0014}:002e\n"
    if len(parse_door(both)) != 2:
        bad.append("parse_door dropped addresses -- sections cannot be told apart downstream")
    # reverse-order rollback must name the registers in the right order
    done = [{"addr": 0x03, "want": 0x80, "name": "x"}, {"addr": 0x04, "want": 0x1, "name": "y"}]
    order = [r["addr"] for r in list(reversed(done))]
    if order != [0x04, 0x03]:
        bad.append(f"rollback order {order} is not reverse write order")
    # restore mode without a token must refuse to change a value
    changed = dict(fake)
    changed[0x04] ^= 0x01
    rows2, skipped2 = plan("restore", changed, regs, tgt, set())
    if any(r["addr"] == 4 for r in rows2):
        bad.append("restore mode planned an unapproved value change for 0x04")
    if not any(a == 4 and "no approval token" in w for a, w in skipped2):
        bad.append("the unapproved change was skipped without a reason -- an operator could not see "
                   "what still needs a token")
    rows3, _ = plan("restore", changed, regs, tgt, {"0x04"})
    if [r["addr"] for r in rows3] != [4]:
        bad.append(f"with one token, restore planned {[r['addr'] for r in rows3]} instead of [4] -- the "
                   "approval door either over- or under-fires")
    if rows3 and rows3[0]["want"] != int(regs[4]["play"], 16):
        bad.append("the approved write does not carry the baseline value -- restore would restore "
                   "something else")
    # the bug this arm caught on its first run: `0x0004` and `0x4` are the same register
    for token in ("0x4", "4", "0x0004"):
        if [r["addr"] for r in plan("restore", changed, regs, tgt, {token})[0]] != [4]:
            bad.append(f"approval token {token!r} did not unlock register 4 -- tokens must be read as "
                       "numbers, the first version matched them as text and silently planned nothing")
    # the crosstalk gate has to be provable able to fire: a write that also moves a neighbour must
    # abort AND must roll the neighbour back (it was never written, so a write-list rollback would miss it)
    with _tf.TemporaryDirectory() as td:
        door = os.path.join(td, "door.txt")
        open(door, "w").write("\n".join(f"reg{{{a:04x}}}:{v:04x}"
                                         for a, v in sorted(fake.items())) + "\n")
        os.environ["SIM_DOOR"] = door
        os.environ["SIM_SIDE_EFFECT"] = f"0x{drive[0]:x}:0x{drive[1]:x}"
        ns = _ap.Namespace(selftest=False, mode="verify", dry_run=False, device="on", fixture=None,
                           snapshot_out=os.path.join(td, "snap.txt"),
                           approve={f"{a:#x}" for a in named}, allow_unknown=False,
                           preview_enforcing=False)
        buf, code = _io.StringIO(), None
        try:
            with _cl.redirect_stdout(buf):
                run(ns)
        except SystemExit as e:
            code = str(e)
        finally:
            os.environ.pop("SIM_DOOR", None)
            os.environ.pop("SIM_REJECT", None)
            os.environ.pop("SIM_SIDE_EFFECT", None)
        log = code or ""
        if "sibling movement" not in log:
            bad.append("a write that moved an unrelated register was NOT treated as crosstalk -- the "
                       "no-mask hazard (§248) would pass silently")
        if open(door).read() != "\n".join(f"reg{{{a:04x}}}:{v:04x}"
                                          for a, v in sorted(fake.items())) + "\n":
            bad.append("the rolled-back door is not the door that was found: the moved neighbour was "
                       "left behind")
        if "every register is back where it was found" not in log:
            bad.append(f"the rollback report does not confirm net-zero: {log[-200:]!r}")
    print(f"selftest: {len(bad)} arm(s) failed" + ("" if not bad else " -- " + "; ".join(bad)))
    return 1 if bad else 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--mode", choices=["verify", "restore"], default="verify",
                    help="verify = write each STABLE register the value it already holds")
    ap.add_argument("--dry-run", action="store_true", help="the default: no writes at all")
    ap.add_argument("--commit", dest="dry_run", action="store_false",
                    help="actually write (consent required; never on the baseline machine)")
    ap.add_argument("--device", choices=["on", "off"], default="on")
    ap.add_argument("--fixture", help="door text to judge when --device off")
    ap.add_argument("--snapshot-out", help="where to write the pre/post snapshot; default /tmp for a "
                                           "dry run and art/audio-6.0.1/live for a committed run")
    ap.add_argument("--approve", action="append", help="0xNN token, one per register a committed run "
                                                       "may write")
    ap.add_argument("--allow-unknown", action="store_true", help="permit registers with no decoded field "
                                                                 "names (§329) to be planned")
    ap.add_argument("--preview-enforcing", action="store_true", help="show the committed run's plan "
                    "(token gate active) while still writing nothing")
    ap.set_defaults(dry_run=True)
    a = ap.parse_args()
    if a.selftest:
        return selftest()
    return run(a)


if __name__ == "__main__":
    sys.exit(main())
