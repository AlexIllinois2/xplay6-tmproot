#!/usr/bin/env python3
"""tools/tfa_reg_decode.py -- name the TFA9890 registers we read live off /sys/kernel/debug/tfa98xx/codec_reg.

Register/field definitions come from fw/tfa-ref/inc/tfa98xx_genregs_N1C_header (verbatim macro
table, not my transcription). Values come from the captured idle samples and the playing sample,
so stability is decided by measurement rather than by eye.
"""
import collections
import os
import re
import sys
from collections import defaultdict

GENREGS = "fw/tfa-ref/inc/tfa98xx_genregs_N1C.h"
IDLE = "art/audio-6.0.1/live/tfa98xx/tfasnap-idle.txt"
IDLE2 = "art/audio-6.0.1/live/tfa98xx/tfasnap-idle-session2.txt"
PLAY = "art/audio-6.0.1/live/tfa98xx/debugfs/tfa-live.txt"   # legacy single-shot
# a real speaker-playback session needs SmartPA Switch On; register 0x72 only shows its
# colours when several in-play samples exist (ledger 283), so play files are globbed too
PLAY_GLOB = "art/audio-6.0.1/live/tfa98xx/tfasnap-play-spk*.txt"


def field_map(path):
    text = open(path, encoding="utf-8", errors="replace").read()
    pos, ln = {}, {}
    for name, val in re.findall(r"^#define\s+(\w+)\s+([^\s/].*?)\s*$", text, re.M):
        m = re.fullmatch(r"TFA98XX_(\w+)_([A-Z0-9]+)_(POS|LEN)", name)
        if not m:
            continue
        reg, fld, kind = m.group(1), m.group(2), m.group(3)
        d = pos if kind == "POS" else ln
        d.setdefault((reg, fld), int(val, 0))
    regs = {}
    for name, val in re.findall(r"^#define\s+(TFA98XX_\w+)\s+(0x[0-9a-fA-F]{1,2})\s*$", text, re.M):
        base = name[len("TFA98XX_"):]
        # field-mask defines (…_MSK/_POS/_LEN/_MAX) also carry short hex values and would
        # silently overwrite the real register name at the same address
        if re.search(r"_(MSK|POS|LEN|MAX)$", base):
            continue
        regs[int(val, 16)] = base
    fields = defaultdict(list)
    for (reg, fld), p in pos.items():
        l = ln.get((reg, fld), 1)
        fields[reg].append((fld, p, l))
    for reg in fields:
        fields[reg].sort(key=lambda x: x[1])
    return regs, fields


def snap(path):
    txt = open(path, encoding="utf-8", errors="replace").read()
    out = []
    for b in re.split(r"===== sample \d+ [0-9.]+ =====|##### ", txt):
        d = {int(k, 16): int(v, 16) for k, v in re.findall(r"reg\{([0-9a-f]{4})\}:([0-9a-f]+)", b)}
        if d:
            out.append(d)
    return out


def route(path):
    """which amplifier path a play session actually used: tfasnap.sh writes 'SmartPA Switch: On/Off'
    as a witness per sample, and a session with the switch off shows reset values, not the tuning
    (ledger 283).  A capture predating the witness line says so instead of silently counting as off."""
    txt = open(path, encoding="utf-8", errors="replace").read()
    if "SmartPA Switch" not in txt:
        return "no-witness"
    return "amp-on" if re.search(r"SmartPA Switch:\s*On", txt) else "amp-off"


def cls_of(stable, cross, drift, state):
    """four classes, because 'the number does not travel' has four different reasons:
    STABLE         one value in every session and in playback
    cross-session  constant inside each session, differs between boots (DCDC REQ, 0x01)
    state-dependent differs between idle and playing (SYS_CONTROL0) -- reproducible per state
    volatile       changes inside a single session (0x71 steps every sample) -- no baseline number"""
    if stable:
        return "STABLE"
    if drift:
        return "volatile"
    if cross:
        return "cross-session"
    return "state-dependent" if state else "volatile"


def main():
    import glob
    regs, fields = field_map(GENREGS)
        # every idle capture is one session; STABLE has to mean "same across sessions", not "same within
    # one burst" -- DCDC_CONTROL0's REQ bit is steady inside a session yet differs between sessions
    # (ledger 260), and a within-session rule labelled it STABLE.  Sessions are globbed, so a later
    # `tools/port_check.sh pa-samples` file joins the derivation without editing this tool.
    extra = sorted(glob.glob(os.path.dirname(IDLE) + "/tfasnap-idle-session*.txt"))
    sessions = [snap(IDLE)] + [snap(pth) for pth in extra]
    # each file is ONE session: merging two captures' samples into one list would read a
    # between-capture difference as within-play drift (ledger 283 caught me doing exactly that)
    play_files = [PLAY] + sorted(glob.glob(PLAY_GLOB))
    play_sessions = [snap(pth) for pth in play_files]
    play = [d for s_ in play_sessions for d in s_]
    # the class of a register is only as good as the session inventory behind it, so the inventory
    # travels in the artifact itself -- port_manifest.py quotes it instead of re-typing a count
    # that would rot the day another capture joins these globs.
    prov = (f"idle {len(sessions)} session(s) [{'+'.join(str(len(s)) for s in sessions)} samples from "
            f"{', '.join(os.path.basename(p) for p in [IDLE] + extra)}]; "
            f"play {len(play_sessions)} session(s) [{'+'.join(str(len(s)) for s in play_sessions)} samples from "
            f"{', '.join(os.path.basename(p) + ' (' + route(p) + ')' for p in play_files)}]")
    print(f"header: {len(regs)} register addresses named, {len(fields)} with fields; "
          f"idle sessions={len(sessions)} samples/session={[len(s) for s in sessions]} "
          f"play samples={len(play)}\nprovenance: {prov}")
    allregs = sorted(set().union(*([set(d) for s in sessions for d in s] + [set(d) for d in play])))
    rows = []
    for r in allregs:
        iv = [sessions[0][k].get(r) for k in range(len(sessions[0]))]
        ivs = [[d.get(r) for d in s] for s in sessions]
        pv = [d.get(r) for d in play]
        vals = {x for s in ivs for x in s} | set(pv)
        within = len(vals) == 1
        idle_vals = {x for s in ivs for x in s if x is not None}
        pd = [[d.get(r) for d in s] for s in play_sessions]      # per-session, not pooled
        drift = any(len({x for x in s if x is not None}) > 1 for s in ivs + pd)
        cross = len(sessions) > 1 and not drift and len(idle_vals) > 1
        state = (not drift) and len(idle_vals) == 1 and len({x for x in pv if x is not None}) == 1 \
            and idle_vals != {x for x in pv if x is not None}
        stable = within and not cross and not drift
        name = regs.get(r)
        fl = fields.get(name, []) if name else []

        def nz(v):
            return " ".join(f"{fld}={(v >> p) & ((1 << l) - 1)}"
                            for fld, p, l in fl
                            if v is not None and ((v >> p) & ((1 << l) - 1)))
        vi = iv[0] if iv and iv[0] is not None else None
        vp = pv[0] if pv and pv[0] is not None else None
        rows.append((r, vi, vp, stable, cross, name, len(fl), nz(vi), nz(vp),
                     "idle=" + "|".join(",".join("-" if x is None else f"{x:04x}" for x in sn) for sn in ivs),
                     "play=" + ",".join("-" if x is None else f"{x:04x}" for x in pv),
                     cls_of(stable, cross, drift, state)))
    # the class census is only trustworthy if it covers the whole whitelist exactly once: 26 comes
    # from the binary's tfa98xx_regs list (ledger 249), not from a typed number here
    if len(rows) != 26:
        sys.exit(f"gate: class census has {len(rows)} registers, whitelist is 26 -- a row was lost")
    census = collections.Counter(x[11] for x in rows)
    print("class census: " + ", ".join(f"{k}={v}" for k, v in sorted(census.items())) +
          f"  (sum {sum(census.values())})")   # class census
    w = max(len(x[5] or "?") for x in rows)   # index 5 = name (tuple gained the cross-session flag at 4)
    print(f"\n{'reg':>4} {'idle':>4} {'play':>4} {'cls':<8} {'name':<{w}} {'#f':>3}  idle-fields | play-fields")
    for r, vi, vp, stable, cross, name, nf, a, b, is_, ps, cls in rows:
        print(f"{r:#04x} {format(vi,'04x') if vi is not None else '-':>4} "
              f"{format(vp,'04x') if vp is not None else '-':>4} {cls:<8} {(name or 'NO-NAME'):<{w}} {nf:>3}  "
              f"{a[:70]} | {b[:70]}  [{is_} {ps}]")
    out = sys.argv[1] if len(sys.argv) > 1 else None
    if out:
        with open(out, "w", encoding="utf-8") as fh:
            fh.write("reg\tidle\tplay\tclass\tname\tnfields\tidle_fields\tplay_fields\tidle_samples\tplay_samples"
                     "\tprovenance\n")
            for r, vi, vp, stable, cross, name, nf, a, b, is_, ps, cls in rows:
                fh.write(f"{r:#04x}\t{format(vi,'04x') if vi is not None else '-'}\t"
                         f"{format(vp,'04x') if vp is not None else '-'}\t"
                         f"{cls}\t{name or 'NO-NAME'}\t{nf}\t{a}\t{b}\t{is_}\t{ps}\t{prov}\n")
        print("wrote", out)


if __name__ == "__main__":
    main()
