#!/usr/bin/env python3
"""tools/dsd_runtime_face.py -- the DSD decision as the RUNNING system logged it.

§422/§423/§424 settled how the player service stores the decision (a byte at NuPlayer+0xf0/+0xf1,
written per stream by a MIME test) but could not name the compared literal from the file, and never
said who tells the player about the hardware switch.  The stored logcat captures do: vivo's own
lines show the whole hand-off -- Java FeatureService (system_server) -> binder SET_PLAYER_FEATURE
-> FeatureService_Native (mediaserver) -> MediaPlayerService::notifytoplayer -> NuPlayerDriver
`DSD### setParameter`.  This tool extracts that chain from any capture, labels each capture by the
route its own mixer dump shows (never by directory name, §421), and reports the
`DSDHw_exist state=false` vs `return ... state=true` pair, which is a capability/state difference
inside ONE query.

Ordering comes from LINE ORDER: these captures were taken with `logcat -d` in brief format and
carry no timestamps, so "before/after" claims are only as good as the buffer order.
"""
import argparse, os, re, sys

BRIEF = re.compile(r"^([VDIWEAF])/([^ (]+)\(\s*(\d+)\):\s?(.*)$")
# threadtime: "MM-DD HH:MM:SS.mmm  PID  TID LEVEL Tag: message" -- newer captures taken with
# `logcat -d -b main -b system` use this, and it is the only one that carries timestamps.
THREADTIME = re.compile(r"^(\d\d-\d\d \d\d:\d\d:\d\d\.\d\d\d)\s+(\d+)\s+(\d+)\s+"
                        r"([VDIWEAF])\s+([^:]{1,40}?):\s?(.*)$")
DSD = re.compile(r"DSD|dsd|msgCode:\s*501|msgCode 501")


def events(path):
    """Parse a logcat dump in EITHER format and say which format produced each event: the stored
    6.0.1 captures are `brief` (no timestamps, so ordering is line order only) while newer dumps are
    `threadtime` (timestamps, which can then be checked for monotonicity).  Non-matching lines are
    continuations of the previous message and are counted, not dropped."""
    ev, cont, formats = [], 0, {}
    for line in open(path, encoding="latin-1", errors="replace").read().splitlines():
        m = THREADTIME.match(line)
        if m:
            ev.append({"level": m.group(4), "tag": m.group(5).strip(), "pid": m.group(2),
                       "tid": m.group(3), "ts": m.group(1), "msg": m.group(6), "format": "threadtime"})
            formats["threadtime"] = formats.get("threadtime", 0) + 1
            continue
        m = BRIEF.match(line)
        if m:
            ev.append({"level": m.group(1), "tag": m.group(2), "pid": m.group(3), "tid": None,
                       "ts": None, "msg": m.group(4), "format": "brief"})
            formats["brief"] = formats.get("brief", 0) + 1
        elif ev:
            ev[-1]["msg"] += " " + line.strip()
            cont += 1
    return ev, cont, formats


def ctl_values(text, want):
    """Read a control's value out of a full `tinymix` table dump by TWO forms and require agreement
    (§420: a single parse of an ENUM line once produced a delivered falsehood)."""
    out = {}
    for line in text.splitlines():
        m = re.match(r"^\s*(\d+)\t(\w+)\t(\d+)\t(.*)$", line)
        if not m:
            continue
        f = m.group(4)
        a_name, a_val = f[:40].rstrip(), f[40:].strip()
        mb = re.match(r"^(\S.*?)\s\s+(.*)$", f)
        if not mb:
            continue
        b_name, b_val = mb.group(1), mb.group(2).strip()
        if (a_name, a_val) != (b_name, b_val):
            sys.exit("gate: the two forms of the same line disagree (%r/%r vs %r/%r) -- the parser is "
                     "not reading this dump format, so no route may be named from it"
                     % (a_name, a_val, b_name, b_val))
        if a_name in want:
            out[a_name] = a_val.split()[0] if a_val else ""
    return out


def route_label(d):
    """Label the capture by the values in ITS OWN mixer dump -- SmartPA Switch On and
    HiFi Mode Switch Off => speaker; the reverse => Hi-Fi; anything else => unresolved."""
    cands = [f for f in os.listdir(d) if re.search(r"tinymix.*\.txt$|\.tinymix$", f)]
    if not cands:
        return None, []
    vals = {}
    used = []
    for c in sorted(cands):
        used.append(c)
        vals.update(ctl_values(open(os.path.join(d, c), encoding="latin-1", errors="replace").read(),
                               ("SmartPA Switch", "HiFi Mode Switch", "HP Sel")))
    spk, hifi = vals.get("SmartPA Switch"), vals.get("HiFi Mode Switch")
    if spk is None or hifi is None:
        return "unresolved:%s" % (vals or "no dump"), used
    if spk == "On" and hifi == "Off":
        return "speaker", used
    if hifi in ("HiFi", "DSD") and spk == "Off":
        return "hifi", used
    return "both/neither(%s,%s)" % (spk, hifi), used


def dsd_lines(ev):
    return [e for e in ev if DSD.search(e["msg"]) or DSD.search(e["tag"])]


CHAIN_TAGS = ("FeatureService", "IFeatureService", "FeatureService_Native", "MediaPlayerService",
              "NuPlayerDriver", "AudioFxService")
END_MSGS = ("onSendShowDSDIntent", "DSD### setParameter ---")


def chain_of(ev, start_msg, cap=12):
    """The ordered hand-off chain that starts at the given line.  It stops at the switch's own end
    marker OR after two consecutive lines from tags outside the chain vocabulary -- a chain is a
    sequence of participants, not "everything for the next 40 lines" (the first version slurped 40
    lines and 7 pids, which made the row look like a process census)."""
    for i, e in enumerate(ev):
        if start_msg in e["msg"]:
            break
    else:
        return None
    out, off = [], 0
    for e in ev[i:i + cap]:
        line = "%s/%s(%s) %s" % (e["level"], e["tag"], e["pid"], e["msg"][:70])
        if e["tag"] not in CHAIN_TAGS:
            off += 1
            if off >= 2:
                break
            continue
        off = 0
        out.append(line)
        if any(x in e["msg"] for x in END_MSGS):
            break
    return out


def feature_pairs(ev, window=4):
    """`getAudioFeature DSDHw_exist:state=X` and the matching `getAudioFeature return
    DSDHw_exist:return=RC;state=Y` -- one query, two states.  The two lines are NOT adjacent (an
    unrelated `tp.get` line sits between them), so pairing is by tag+pid within a bounded window,
    and an ask with two candidate returns (or a second ask first) is left unpaired rather than
    guessed."""
    out = []
    for k, a in enumerate(ev):
        ma = re.search(r"DSDHw_exist:state=(\w+)", a["msg"])
        if not (ma and a["tag"] == "FeatureService" and "getAudioFeature" in a["msg"]
                and "return" not in a["msg"]):
            continue
        cands = []
        for j in range(k + 1, min(len(ev), k + 1 + window)):
            b = ev[j]
            mb = re.search(r"return DSDHw_exist:return=(\w+);state=(\w+)", b["msg"])
            if b["tag"] == a["tag"] and b["pid"] == a["pid"] and mb:
                cands.append((j, b, mb))
            elif "DSDHw_exist:state=" in b["msg"]:
                break
        if len(cands) != 1:
            continue
        j, b, mb = cands[0]
        out.append({"asked": ma.group(1), "answered": mb.group(2), "rc": mb.group(1),
                    "service_pid": a["pid"], "caller": re.findall(r"calling from (\d+)", a["msg"]),
                    "gap": j - k})
    return out


def analyse(paths, route, how_route_known, require_chain=True, min_events=100):
    """The DSD face of one group of captures.  `route` must come from a mixer dump in the same
    directory; a group without one is labelled not-attributable and may not be tied to a route."""
    per = []
    for path in paths:
        ev, cont, formats = events(path)
        if not ev and os.path.getsize(path) > 200:
            sys.exit("gate: %s produced 0 events from %d bytes -- the parser is blind on this format, "
                     "so an empty DSD set here would mean nothing" % (os.path.basename(path),
                                                                      os.path.getsize(path)))
        dl = dsd_lines(ev)
        per.append({"file": os.path.basename(path), "events": len(ev), "continuations": cont,
                    "formats": formats, "ts_events": sum(1 for e in ev if e["ts"]),
                    "dsd": dl, "chain": chain_of(ev, "setDSDHWSwitch"), "pairs": feature_pairs(ev)})
    if sum(p["events"] for p in per) < min_events:
        sys.exit("gate: the whole group parsed into %d events -- too few to say anything about the "
                 "DSD face" % sum(p["events"] for p in per))
    if not any(p["dsd"] for p in per):
        sys.exit("gate: NO capture in this group has a DSD line (%d events parsed) -- report the "
                 "capture, not a conclusion about the DSD switch" % sum(p["events"] for p in per))
    if require_chain and not any(p["chain"] for p in per):
        sys.exit("gate: no setDSDHWSwitch chain although %d DSD line(s) were seen -- the hand-off leg "
                 "is missing from these captures, so the switch must not be described as observed "
                 "(pass --allow-absent on a build where absence is itself the finding)"
                 % sum(len(p["dsd"]) for p in per))
    return {"route": route, "how_route_known": how_route_known, "captures": per,
            "dsd_total": sum(len(p["dsd"]) for p in per),
            "no_dsd_captures": [p["file"] for p in per if not p["dsd"]]}


def read(d, require_chain=True):
    """One capture DIRECTORY: logcat files plus the mixer dump that names the route."""
    files = sorted(os.path.join(d, f) for f in os.listdir(d) if f.startswith("logcat"))
    if not files:
        sys.exit("gate: no logcat capture in %s -- there is no runtime face to read here" % d)
    route, used = route_label(d)
    if route is None:
        sys.exit("gate: %s has no mixer dump to label the route from values, so the switch state "
                 "could not be tied to a route" % d)
    if route.startswith("unresolved") or "both" in route:
        sys.exit("gate: route of %s is %s from its own dump values -- refusing to attribute a DSD "
                 "switch reading to an unnamed route" % (d, route))
    r = analyse(files, route, "・".join(used), require_chain=require_chain)
    r["dir"] = d
    return r


def read_group(name, files, require_chain=True):
    """Standalone captures that were taken without a mixer dump alongside (boot-time logcat)."""
    r = analyse(files, "not attributable", "no mixer dump beside this capture",
                require_chain=require_chain)
    r["dir"] = name
    return r


def _dt(ts):
    import datetime
    return datetime.datetime.strptime("2026-" + ts, "%Y-%m-%d %H:%M:%S.%f")


def time_leg(paths, needle_re=r"dsdvol_index.*out_set_parameters|out_set_parameters.*dsdvol_index"):
    """Ordering, timestamps and intervals.  A brief capture has NO timestamps, so the leg says so and
    refuses to quote intervals; a threadtime capture is checked for monotonicity first, because
    `logcat -d` concatenates buffers (and this device's ring carries a pre-NTP `01-12` segment), so a
    global time ordering would be false.  Intervals are therefore computed on the largest monotonic
    sub-run, and both the sub-run length and the number of violations are printed."""
    out = []
    for path in paths:
        ev, _c, formats = events(path)
        stamped = [e for e in ev if e["ts"]]
        if not stamped:
            out.append({"file": os.path.basename(path), "formats": formats, "timestamps": 0,
                        "verdict": "no timestamps (brief format) -- ordering is LINE ORDER only"})
            continue
        viol = [i for i in range(1, len(stamped)) if _dt(stamped[i]["ts"]) < _dt(stamped[i - 1]["ts"])]
        # largest monotonic run
        runs, start = [], 0
        for i in range(1, len(stamped)):
            if _dt(stamped[i]["ts"]) < _dt(stamped[i - 1]["ts"]):
                runs.append((start, i - 1))
                start = i
        runs.append((start, len(stamped) - 1))
        lo, hi = max(runs, key=lambda r: r[1] - r[0])
        sub = stamped[lo:hi + 1]
        hits = [e for e in sub if re.search(needle_re, e["msg"])]
        iv = [round((_dt(b["ts"]) - _dt(a["ts"])).total_seconds(), 3) for a, b in zip(hits, hits[1:])]
        # does the pattern ride on stream starts rather than on a timer?  Count the starts and measure
        # how far each key line sits from the nearest one -- "regular spacing" alone proves nothing.
        starts = [e for e in sub if e["tag"] == "AudioFlinger" and e["msg"].lstrip().startswith("start(")]
        near = [round(min((abs((_dt(h["ts"]) - _dt(x["ts"])).total_seconds()) for x in starts), default=0.0), 3)
                for h in hits]
        out.append({"file": os.path.basename(path), "formats": formats, "timestamps": len(stamped),
                    "violations": len(viol), "run": "%s..%s (%d events)" % (stamped[lo]["ts"],
                                                                            stamped[hi]["ts"], len(sub)),
                    "run_start": stamped[lo]["ts"], "run_end": stamped[hi]["ts"],
                    "run_events": len(sub),
                    "foreign": sorted({e["ts"][:5] for e in stamped} - {stamped[-1]["ts"][:5]}),
                    "key_lines": len(hits), "intervals": iv[:12], "starts": len(starts),
                    "nearest_start": near, "worst_start_delta": max(near) if near else None,
                    "pairs": sum(1 for x in iv if x <= 0.05),
                    "gaps": [x for x in iv if x > 1]})
    return out


def shapes(caps):
    seen = {}
    for d in caps:
        for p in d["captures"]:
            for e in p["dsd"]:
                key = (e["tag"], re.sub(r"0x[0-9a-f]+|\d+", "N", e["msg"])[:80])
                r = seen.setdefault(key, {"n": 0, "tags": set(), "files": set(), "pids": set()})
                r["n"] += 1
                r["files"].add(os.path.basename(d["dir"]) + "/" + p["file"])
                r["pids"].add(e["pid"])
    return seen


def report(r, require_chain=True):
    print("== %s  route=%s (%s)" % (r["dir"], r["route"], r["how_route_known"]))
    print("   ordering source = LINE ORDER (these captures are `logcat -d` in brief format, no "
          "timestamps); %d DSD line(s) total" % r["dsd_total"])
    for p in r["captures"]:
        print("   %-28s events=%-6d DSD lines=%-3d continuations=%d" % (
            p["file"], p["events"], len(p["dsd"]), p["continuations"]))
        for x in p["pairs"]:
            print("      feature query: caller %s asked state=%s -> service(%s) answered state=%s "
                  "(rc=%s, %d line(s) apart)" % ("・".join(x["caller"]), x["asked"], x["service_pid"],
                                                 x["answered"], x["rc"], x["gap"]))
        if p["chain"]:
            print("      chain (%d lines):" % len(p["chain"]))
            for j, c in enumerate(p["chain"]):
                print("        %2d. %s" % (j + 1, c))
        else:
            print("      chain: ABSENT in this capture (--allow-absent was given)")
    if r["no_dsd_captures"]:
        print("   captures with no DSD line: %s" % "・".join(r["no_dsd_captures"]))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--live", default=None, help="one capture directory")
    ap.add_argument("--all", action="store_true", help="every live capture that has a logcat file")
    ap.add_argument("--allow-absent", action="store_true",
                    help="on a build where the switch never logs, report absence as the finding "
                         "instead of refusing")
    ap.add_argument("--time", action="store_true",
                    help="timestamp/interval leg over the logcat corpus (ordering claims need it)")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    root = os.environ.get("AUDIO_PORT_ROOT") or "/home/v/.local/project/xplay6"
    live = f"{root}/art/audio-6.0.1/live"
    if a.selftest:
        sys.exit(selftest(live))
    if a.time:
        files = _corpus_files(live)
        for x in time_leg(files):
            print("   %-46s %s" % (x["file"], "・".join("%s=%d" % kv for kv in sorted(x["formats"].items()))
                                   or "no events"))
            if "verdict" in x:
                print("        %s" % x["verdict"])
                continue
            print("        timestamps=%d  monotonicity violations=%d  run=%s  foreign date prefixes=%s"
                  % (x["timestamps"], x["violations"], x["run"], x["foreign"]))
            print("        dsdvol/HAL lines=%d  pairs(<=0.05s)=%d  gaps>1s=%s" % (x["key_lines"],
                                                                                  x["pairs"],
                                                                                  [g for g in x["gaps"]][:8]))
        return
    groups = []
    if a.all:
        dirs = [os.path.join(live, x) for x in sorted(os.listdir(live))
                if os.path.isdir(os.path.join(live, x))
                and any(f.startswith("logcat") for f in os.listdir(os.path.join(live, x)))]
        for c in dirs:
            groups.append((c, lambda cc=c: read(cc, require_chain=not a.allow_absent)))
        lone = [os.path.join(live, f) for f in sorted(os.listdir(live))
                if f.startswith("logcat") and os.path.isfile(os.path.join(live, f))]
        if lone:
            groups.append(("boot: %d standalone logcat file(s)" % len(lone),
                           lambda: read_group("boot: %d standalone logcat file(s)" % len(lone), lone,
                                              require_chain=not a.allow_absent)))
        ok = []
        for name, fn in groups:
            try:
                ok.append(fn())
            except SystemExit as e:
                print("   skip %s: %s" % (str(name).replace(live, ""), str(e)[:88]))
        sh = shapes(ok)
        print("== DSD runtime shapes over %d usable capture group(s) of %d ==" % (len(ok), len(groups)))
        for (tag, shape), r in sorted(sh.items(), key=lambda kv: -kv[1]["n"]):
            print("   %-22s %-70s x%d  pids=%s  from %s" % (
                tag, shape, r["n"], "・".join(sorted(r["pids"])), "・".join(sorted(r["files"]))[:60]))
        for r in ok:
            report(r, require_chain=not a.allow_absent)
        return
    if not a.live:
        a.live = f"{live}/inplay-spk-20261017-2012"
    report(read(a.live, require_chain=not a.allow_absent), require_chain=not a.allow_absent)


def _reverse(ev):
    """Swap the ask line with its return line, and prove the swap happened."""
    e = list(ev)
    ia = next((i for i, x in enumerate(e) if re.search(r"DSDHw_exist:state=", x["msg"])
               and "return" not in x["msg"]), None)
    ib = next((i for i, x in enumerate(e) if "return DSDHw_exist" in x["msg"]), None)
    if ia is None or ib is None or e[ia]["msg"] == e[ib]["msg"]:
        sys.exit("gate: fixture has nothing to reverse")
    e[ia], e[ib] = e[ib], e[ia]
    if e[ia] is ev[ib]:
        return e
    sys.exit("gate: fixture did not swap")


def _first_chain(d):
    for p in read(d)["captures"]:
        if p["chain"]:
            return p["chain"]
    sys.exit("gate: no chain found in any capture of %s" % d)


def _abort(fn, *a):
    try:
        fn(*a)
        return ""
    except SystemExit as e:
        return str(e)


def _corpus_files(live):
    out = []
    for dp, dn, fn in os.walk(live):
        for f in fn:
            if f.startswith("logcat"):
                out.append(os.path.join(dp, f))
    return sorted(out)


def _stamped_files(live):
    return [p for p in _corpus_files(live) if any(e["ts"] for e in events(p)[0])
            and sum(1 for e in events(p)[0] if e["ts"]) >= 1000]


def _prints_group_denominator(live):
    """Run `--all` as a subprocess and require `over N usable capture group(s) of M` with N < M --
    a skipped capture must show up as a smaller numerator, never disappear from the denominator."""
    import subprocess
    root = live[: -len("/art/audio-6.0.1/live")]
    o = subprocess.run([sys.executable, os.path.abspath(__file__), "--all"], capture_output=True,
                       text=True, env=dict(os.environ, AUDIO_PORT_ROOT=root)).stdout
    m = re.search(r"over (\d+) usable capture group\(s\) of (\d+)", o)
    if not m:
        sys.exit("gate: --all did not print its group denominator: %r" % o[:120])
    return int(m.group(1)) < int(m.group(2))


def _threadtime_arm(live):
    st = _stamped_files(live)
    if not st:
        sys.exit("gate: no timestamped (threadtime) capture in the corpus yet -- this leg must be "
                 "run against a real one, not reported as passing")
    rows = [x for x in time_leg(st) if x["timestamps"] >= 1000]
    if not rows:
        return False
    withkeys = [r for r in rows if r["key_lines"] >= 4]
    if not withkeys:
        sys.exit("gate: the timestamped captures parse but none carries the dsdvol_index lines; the "
                 "interval claim has no subject")
    # §470: assert over EVERY timestamped capture that carries the key lines, not over whichever one
    # sorts first -- with the old `withkeys[0]` shape, simply capturing another session could flip this
    # arm red (it did, on 2026-10-18, when the complete-DSD capture sorted ahead of the older one).
    good = [r for r in withkeys if len(r["intervals"]) >= 3 and r["pairs"] >= 1
            and r["gaps"] and min(r["gaps"]) > 60]
    for r in withkeys:
        if r["violations"] and not r["run"]:
            sys.exit("gate: %s shows ordering violations with no monotonic run chosen" % r["file"])
    if not good:
        for r in withkeys[:6]:
            print("     (no claim from %s: intervals=%d pairs=%d min_gap=%s)"
                  % (r["file"], len(r["intervals"]), r["pairs"],
                     round(min(r["gaps"]), 1) if r["gaps"] else "-"))
    return bool(good)


def _both_formats_arm(live):
    files = _corpus_files(live)
    brief = [f for f in files if not any(e["ts"] for e in events(f)[0][:200])]
    stamped = _stamped_files(live)
    if not (brief and stamped):
        sys.exit("gate: the corpus must hold at least one brief AND one threadtime capture for this "
                 "cross-format control (%d/%d)" % (len(brief), len(stamped)))
    KEYS = ("dsdvol_index", "FeatureService", "out_set_parameters")
    def present(paths):
        txt = "".join(open(p, encoding="latin-1", errors="replace").read() for p in paths)
        return [k for k in KEYS if k in txt]
    b, t = present(brief[:8]), present(stamped[:4])
    return len(b) == len(KEYS) and len(t) == len(KEYS)


def selftest(live):
    import shutil, tempfile
    d = f"{live}/inplay-spk-20261017-2012"
    if not os.path.isdir(d):
        sys.exit("gate: " + d + " missing")
    arms = [
        ("ok: the running hand-off chain is present and ordered (binder -> native -> driver)",
         lambda: (lambda ch: ch and
                  any("setPlayerFeatures" in x for x in ch) and
                  any("notifytoplayer" in x for x in ch) and
                  [i for i, x in enumerate(ch) if "setPlayerFeatures" in x][0] <
                  [i for i, x in enumerate(ch) if "notifytoplayer" in x][0] and
                  [i for i, x in enumerate(ch) if "notifytoplayer" in x][0] <
                  [i for i, x in enumerate(ch) if "DSD### setParameter" in x][0])(_first_chain(d))),
        ("ok: the chain crosses a process boundary (system_server 1316 -> mediaserver 727)",
         lambda: (lambda ch: len({x.split("(")[1].split(")")[0] for x in ch}) >= 2
                  and any("FeatureService(" in x for x in ch)
                  and any("NuPlayerDriver(" in x for x in ch))(_first_chain(d))),
        ("ok: the feature query answers a DIFFERENT state than the caller's own copy (asked false / "
         "answered true), paired by tag+pid with the gap printed",
         lambda: (lambda ps: len(ps) == 1 and ps[0]["asked"] == "false" and
                  ps[0]["answered"] == "true" and ps[0]["rc"] == "OK" and
                  ps[0]["caller"] == ["3576"] and ps[0]["service_pid"] == "1398" and
                  ps[0]["gap"] > 1)(feature_pairs(events(f"{live}/logcat-boot-20261017-0956.txt")[0]))),
        ("gate: reversing ask and return must NOT produce a pair (the pairing rule is directional)",
         lambda: (lambda ev: len(feature_pairs(_reverse(ev))) == 0 and len(feature_pairs(ev)) == 1)(
                     events(f"{live}/logcat-boot-20261017-0956.txt")[0])),
        ("ok: the route label is taken from the capture's OWN mixer values",
         lambda: read(d)["route"] == "speaker"),
        ("gate: relabelling the dump (SmartPA Switch Off) must change the verdict, not keep it",
         lambda: "refusing to attribute" in _abort(*_flip_route(d))),
        ("gate: deleting the switch line must REFUSE the chain leg, not print an absent chain",
         lambda: "no setDSDHWSwitch chain" in _abort(read, _drop_lines(d, "setDSDHWSwitch"))),
        ("ok: the same fixture is readable with --allow-absent (the refusal is asymmetric)",
         lambda: (lambda p: all(x["chain"] is None for x in read(p, require_chain=False)["captures"])
                  and read(p, require_chain=False)["dsd_total"] > 0)(_drop_lines(d, "setDSDHWSwitch"))),
        ("gate: a capture directory without any logcat is refused, not reported as silent",
         lambda: "no logcat capture" in _abort(read, tempfile.mkdtemp())),
        ("gate: a capture too small to speak with is refused by the group floor, and a 0-event file "
         "is called blind rather than empty",
         lambda: ("too few" in _abort(read, _truncate(d))
                  and "blind" in _abort(read, _garble(d)))),
        ("ok: --all prints usable-of-candidate group counts, so a skipped capture shows up as a "
         "smaller numerator instead of vanishing",
         lambda: _prints_group_denominator(live)),
        ("gate: a brief capture must be reported as having NO timestamp backing, not given a fake "
         "interval list",
         lambda: any("no timestamps" in x["verdict"] for x in
                     time_leg([f"{live}/inplay-spk-20261017-2012/logcat-raw.txt"]))),
        ("ok: a threadtime capture yields real intervals, and the monotonicity check runs before any "
         "ordering claim (a corpus without one is refused, not skipped)",
         lambda: _threadtime_arm(live)),
        ("ok: the same DSD key set must be recoverable from BOTH log formats -- the parser is not "
         "format-blind",
         lambda: _both_formats_arm(live)),
    ]
    bad = 0
    for label, fn in arms:
        try:
            ok = bool(fn())
        except SystemExit as e:
            ok = "gate:" in label and any(k in str(e) for k in ("refuse", "no logcat", "blind",
                                                                "missing", "no setDSDHWSwitch",
                                                                "not reading this dump"))
        except Exception as e:
            ok = False
            print("     (exception: %s)" % str(e)[:160])
        print(("ok   " if ok else "FAIL ") + label)
        bad += 0 if ok else 1
    print("selftest: %d arm(s) failed" % bad)
    return 1 if bad else 0


def _copy(d):
    import tempfile, shutil
    t = tempfile.mkdtemp()
    p = os.path.join(t, os.path.basename(d))
    shutil.copytree(d, p)
    return p


def _flip_route(d):
    p = _copy(d)
    changed = 0
    for f in os.listdir(p):
        if re.search(r"tinymix.*\.txt$|\.tinymix$", f):
            q = os.path.join(p, f)
            s = open(q, encoding="latin-1").read()
            new = re.sub(r"(?m)^(\d+\tBOOL\t1\tSmartPA Switch\s+)On$", r"\g<1>Off", s)
            if new == s:
                sys.exit("gate: fixture did not change the dump -- a green arm here would mean nothing")
            open(q, "w", encoding="latin-1").write(new)
            changed += 1
    if not changed:
        sys.exit("gate: no mixer dump to flip")
    return (read, p)


def _drop_lines(d, needle):
    p = _copy(d)
    removed = 0
    for f in os.listdir(p):
        if f.startswith("logcat"):
            q = os.path.join(p, f)
            ls = open(q, encoding="latin-1").read().splitlines()
            keep = [l for l in ls if needle not in l]
            removed += len(ls) - len(keep)
            open(q, "w", encoding="latin-1").write("\n".join(keep) + "\n")
    if not removed:
        sys.exit("gate: fixture removed nothing")
    return p


def _truncate(d):
    p = _copy(d)
    for f in os.listdir(p):
        if f.startswith("logcat"):
            q = os.path.join(p, f)
            s = open(q, encoding="latin-1").read()
            open(q, "w", encoding="latin-1").write("\n".join(s.splitlines()[:20]))
    return p


def _garble(d):
    """Keep the bytes but destroy the `level/tag(pid):` shape -- the parser must call itself blind."""
    p = _copy(d)
    for f in os.listdir(p):
        if f.startswith("logcat"):
            q = os.path.join(p, f)
            s = open(q, encoding="latin-1").read().splitlines()
            open(q, "w", encoding="latin-1").write("\n".join(l[::-1] for l in s[:4000]) + "\n")
    return p


if __name__ == "__main__":
    main()
