#!/usr/bin/env python3
"""tools/dapmsnap.py -- regenerate the live DAPM widget/edge listings from a debugfs_asoc capture.

Written because art/audio-6.0.1/live/dapm-{files,edges}-<codec>.txt were hand-derived in a shell
one-liner with no tool of record.  Everything else in that directory is reproducible and
hash-registered; these were not, so comparing a 7-side capture would have meant hand-making the
other half again.

Input is a capture of /sys/kernel/debug/asoc (art/PORT-RUNBOOK-7.md step 5c):

    <dir>/codecs                                 one codec name per line
    <dir>/<card>/codec:<name>/dapm/<widget>      widget file, see format below
    <dir>/<card>/{platform,soc}:*/dapm/<widget>  machine/platform contexts, used only for the
                                                 path-symmetry cross-check

Widget file format, as printed by ASoC's show_widgets():

    "NAME: <bias>  in N out M"                     plain widget
    "NAME: <bias>  in N out M - R2609(0xa31) mask 0x20"   switch/value widget
    ' in  "path" "OTHER"'  /  ' out "path" "OTHER"'        one line per path (note the leading space)
    ' stream <FE name> active|inactive'                    DAI-link widget status, not a path

The 'in N out M' numbers are NOT path counts -- 'HP: Off  in 0 out 1' lists three 'in' lines -- so
this tool does not gate on them.  The invariant it does use is that every path is printed twice, as
an 'in' line on its sink and an 'out' line on its source, across all contexts of one card.

Output per codec (snd-soc-dummy and soc:* stubs are skipped, and the skip is reported):

    dapm-files-<codec>.txt    widget file names, bias_level excluded
    dapm-edges-<codec>.txt    source<TAB>sink<TAB>path, taken from the 'in' lines

usage: tools/dapmsnap.py CAPTURE_DIR [--out-prefix DIR] [--compare] [--strict-symmetry]
"""
import argparse
import os
import re
import sys

FIRST = re.compile(r"^(?P<name>.+?):\s+\S+\s+in\s+(?P<nin>\d+)\s+out\s+(?P<nout>\d+)"
                   r"(?:\s+-\s+R\d+\(0x[0-9a-f]+\)\s+mask\s+0x[0-9a-f]+)?\s*$")
LINE = re.compile(r'^\s*(?P<dir>in|out)\s+"(?P<path>[^"]*)"\s+"(?P<other>[^"]*)"\s*$')
STREAM = re.compile(r"^\s*stream\s+(?P<sname>.+?)\s+(?P<act>active|inactive)\s*$")
STUB_PREFIX = ("soc:", "snd-soc-dummy")


def contexts(cap):
    """every <something>/dapm directory under the capture, tagged with its owner name"""
    out = []
    for dp, _dn, fn in os.walk(cap):
        if os.path.basename(dp) != "dapm":
            continue
        out.append((os.path.basename(os.path.dirname(dp)), dp, sorted(fn)))
    return out


def parse(path, wf):
    """-> (nin_lines, nout_lines, stream_lines, errors).  Edges are returned, not counted."""
    txt = open(path, encoding="utf-8", errors="replace").read().splitlines()
    if not txt:
        return [], [], [], [f"{wf}: empty file"]
    errs, ins, outs, streams = [], [], [], []
    m = FIRST.match(txt[0])
    if not m:
        return [], [], [], [f"{wf!r}: first line {txt[0]!r} is not 'NAME: <bias> in N out M' "
                            "(and is not the bias_level context line)"]
    if m.group("name") != wf:
        errs.append(f"{wf}: header names the widget {m.group('name')!r} -- file/content mismatch")
    for ln in txt[1:]:
        if not ln.strip():
            continue
        lm = LINE.match(ln)
        if lm:
            (ins if lm.group("dir") == "in" else outs).append(
                (lm.group("other"), wf, lm.group("path")) if lm.group("dir") == "in"
                else (wf, lm.group("other"), lm.group("path")))
            continue
        sm = STREAM.match(ln)
        if sm:
            streams.append((wf, sm.group("sname"), sm.group("act")))
            continue
        errs.append(f"{wf}: unparsable line {ln!r}")
    return ins, outs, streams, errs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("capture")
    ap.add_argument("--out-prefix", default="")
    ap.add_argument("--compare", action="store_true",
                    help="diff against the files already in --out-prefix instead of writing")
    ap.add_argument("--strict-symmetry", action="store_true",
                    help="make unmatched paths an error instead of a report")
    ap.add_argument("--emit-all",
                    help="also write CONTEXT<TAB>widget for every widget file in every context "
                         "(codec:, platform:, soc:).  Widget names are NOT unique across contexts "
                         "-- HPHL exists in both codec:tasha_codec and codec:hifi-codec -- so this "
                         "is the only listing that lets a route endpoint be attributed to a context")
    a = ap.parse_args()
    if a.out_prefix and not a.compare:
        # The judging lines all print before the first write, so a missing directory used to crash
        # AFTER the readings were already on screen -- readings out, artifacts none (ledger 609).
        os.makedirs(a.out_prefix, exist_ok=True)

    cap = a.capture.rstrip("/")
    cp = f"{cap}/codecs"
    if not os.path.isdir(cap) or not os.path.exists(cp):
        sys.exit(f"gate: {cap} is not a debugfs_asoc capture (needs a 'codecs' file inside) -- "
                 "see art/PORT-RUNBOOK-7.md step 5c")
    codecs = [l.strip() for l in open(cp, encoding="utf-8", errors="replace") if l.strip()]
    if not codecs:
        sys.exit(f"gate: {cp} lists no codecs -- an empty capture is not a PASS, it is a failed pull")

    ctxs = contexts(cap)
    if not ctxs:
        sys.exit(f"gate: no */dapm directories anywhere under {cap} -- nothing was pulled")

    # parse everything once: the symmetry check needs the platform/machine contexts too, since a
    # codec widget's counterpart often lives in platform:soc:qcom,msm-pcm-routing
    per_ctx, all_in, all_out, errs = {}, set(), set(), []
    for owner, d, files in ctxs:
        widgets, ins, outs, streams = [], [], [], []
        for wf in files:
            if wf == "bias_level":
                continue
            i, o, s, e = parse(f"{d}/{wf}", wf)
            if e:
                errs.append(f"[{owner}] " + "\n  [".join(e))
            widgets.append(wf)
            ins += i
            outs += o
            streams += s
        per_ctx[owner] = (widgets, ins, outs, streams)
        all_in |= {(x, y) for x, y, _p in ins}
        all_out |= {(x, y) for x, y, _p in outs}
    if errs:
        sys.exit(f"gate: {len(errs)} parse error(s):\n  " + "\n  ".join(errs[:15]) +
                 "\n-- refusing to derive edges from a capture this tool cannot fully read")

    un_in = sorted(e for e in all_in if e not in all_out)
    un_out = sorted(e for e in all_out if e not in all_in)
    print(f"path symmetry over {len(ctxs)} contexts: {len(all_in)} distinct in-edges, "
          f"{len(all_out)} out-edges; unmatched in {len(un_in)}, unmatched out {len(un_out)}")
    for e in un_in[:6]:
        print(f"    in-only   {e[0]} -> {e[1]}")
    for e in un_out[:6]:
        print(f"    out-only  {e[0]} -> {e[1]}")
    if un_in or un_out:
        named = {w for owner, (ws, _i, _o, _s) in per_ctx.items() for w in ws}
        ghosts = [e for e in un_in + un_out if e[0] not in named or e[1] not in named]
        print(f"    of those, {len(ghosts)} name a widget that has no file in this capture -- "
              "those are contexts the pull missed, not paths that vanished")
        if a.strict_symmetry and (un_in or un_out):
            sys.exit("gate: --strict-symmetry and the capture is not symmetric")

    skipped = [c for c in codecs if c.startswith(STUB_PREFIX)]
    if a.emit_all:
        pairs = sorted({(o, w) for o, (ws, _i, _o, _s) in per_ctx.items() for w in ws})
        if len(pairs) < 100:
            sys.exit(f"gate: --emit-all produced {len(pairs)} context/widget pairs across "
                     f"{len(per_ctx)} contexts -- a live card exposes hundreds of widgets, so this "
                     "listing would be a silent truncation of the universe")
        with open(a.emit_all, "w", encoding="utf-8") as f:
            f.write("# context\twidget -- every DAPM widget file in the capture, all contexts\n")
            for o, w in pairs:
                f.write(f"{o}\t{w}\n")
        multi = {}
        for _o, w in pairs:
            multi[w] = multi.get(w, 0) + 1
        shared = {w: n for w, n in multi.items() if n > 1}
        print(f"emit-all: {len(pairs)} pairs, {len(shared)} names appear in more than one context "
              f"(e.g. {sorted(shared.items(), key=lambda kv: -kv[1])[:4]}) -- so an endpoint must be "
              "resolved against a context, not a bare name")
    wanted = [c for c in codecs if not c.startswith(STUB_PREFIX)]
    diffs = []
    for c in wanted:
        key = f"codec:{c}"
        if key not in per_ctx:
            sys.exit(f"gate: codec {c!r} is listed in {cp} but no <card>/codec:{c}/dapm directory "
                     "exists in the capture -- its widget list would be silently empty")
        widgets, ins, _outs, streams = per_ctx[key]
        if not widgets:
            sys.exit(f"gate: codec {c} has no widget files under its dapm directory")
        es = sorted({(s, k) for s, k, _p in ins})
        act = [s for s in streams if s[2] == "active"]
        total_w = len(widgets)
        fh = (f"# derived by tools/dapmsnap.py from {cap}\n"
              f"# one line per widget file; 'bias_level' is the DAPM context line, not a widget "
              f"(excluded by the gate)\n")
        eh = (f"# derived by tools/dapmsnap.py from {cap}\n"
              f"# one line per 'in' edge the running card printed: source<TAB>sink<TAB>path\n")
        fbody = "\n".join(sorted(widgets)) + "\n"
        ebody = "".join(f"{s}\t{k}\t{p}\n" for s, k, p in
                        sorted({(s, k, p) for s, k, p in ins}))
        print(f"  {c}: {total_w} widgets, {len(es)} distinct in-edges, "
              f"{len(act)}/{len(streams)} DAI streams active")
        for suffix, head, body in ((f"dapm-files-{c}.txt", fh, fbody),
                                   (f"dapm-edges-{c}.txt", eh, ebody)):
            target = os.path.join(a.out_prefix, suffix) if a.out_prefix else suffix
            if a.compare:
                if not os.path.exists(target):
                    diffs.append(f"{target}: MISSING on disk")
                    continue
                disk = [l.rstrip("\n") for l in open(target, encoding="utf-8", errors="replace")
                        if not l.startswith("#") and l.strip()]
                mine = [l for l in body.splitlines() if l.strip()]
                if disk != mine:
                    diffs.append(f"{target}: {len(disk)} lines on disk vs {len(mine)} derived -- "
                                 f"disk-only {[x for x in disk if x not in mine][:4]}, "
                                 f"derived-only {[x for x in mine if x not in disk][:4]}")
            else:
                with open(target, "w", encoding="utf-8") as f:
                    f.write(head + body)
                print(f"    wrote {target} ({len(body.splitlines())} lines)")
    if skipped:
        print(f"skipped stub/dummy codecs (name starts with one of {STUB_PREFIX}): {skipped}")
    print(f"{len(wanted)} codecs written/checked, {len(codecs)} listed, "
          f"{sum(len(v[0]) for v in per_ctx.values())} widget files across all "
          f"{len(ctxs)} contexts")
    if a.compare:
        if diffs:
            sys.exit("MISMATCH -- the files on disk are not what this capture yields:\n  "
                     + "\n  ".join(diffs))
        print("compare: every file on disk reproduced from the capture")


if __name__ == "__main__":
    main()
