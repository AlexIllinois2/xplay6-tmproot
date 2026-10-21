#!/usr/bin/env python3
"""Disposition census for the shipped extract: which captured files are provably on the audible
path, which are named in the carry list, which are neither, and which files the DEVICE LOADS but the
extract does not hold (ledger 409).

Why this exists: the extract holds 127 files, the carry list names 11 of them by path, and an audit
note said "these have no owner".  Naming is not the question -- the question is whether the thing is
the one the audio stack actually uses.  The live map captures answer that, and they disagreed with
the capture plan: mediaserver maps the 32-bit /system/lib stack (including the primary audio HAL),
while the extract kept system/lib64 and vendor/lib*.  That asymmetry is only visible if you compare
the two, so this tool compares them and refuses to guess.

Three independent evidence legs per file (no single one is allowed to decide):
  L1 live maps   -- live/loaders.txt (pid blocks) and live/acdb-reach.txt (REACH libs= lists)
  L2 acdb use    -- live/acdb-landing-verify.txt: which acdbdata platform dir resolved, file by file
  L3 citation    -- the carry list source column + the runbook (path or basename)
Path equality is decided after two documented normalisations, each with a witness:
  /system/vendor/* -> /vendor/*    (the device lists vendor under system as a symlink)
  /etc/acdbdata/*  -> /system/etc/acdbdata/*   (acdb-landing-verify prints both forms)
Gates abort instead of printing a confident zero; see --selftest for the arms that prove it.
"""
import argparse, hashlib, json, os, re, sys

CFG_SUFFIX = (".xml", ".conf", ".txt", ".cfg")
CFG_LIT_RX = rb"/(?:system/)?etc/[a-zA-Z0-9_.\-/]{2,60}?\.(?:xml|conf|txt|cfg)"
SONAME_RX = re.compile(rb"(?:lib|audio\.)[A-Za-z0-9_+.\-]*\.so")
LOADER_NAME = "libacdbloader.so"  # known positive control: dlopened, never DT_NEEDNeeded
KINDS = ((".acdb", "acdb-calibration"), (".qwsp", "acdb-workspace"), (".so", "elf"),
         (".xml", "config"), (".conf", "config"), (".txt", "config"), (".cfg", "config"),
         (".sh", "script"), (".apk", "app-code"), (".odex", "app-code"))
VERDICTS = ("LIVE-AND-CITED", "LIVE-NOT-CITED", "CITED-NOT-LIVE", "PEER-REFERENCE", "QUIET")


def kind(path):
    for suf, k in KINDS:
        if path.endswith(suf):
            return k
    return "other"


def read_manifest(base):
    rows = []
    for line in open(os.path.join(base, "MANIFEST.txt"), encoding="utf-8"):
        p = line.rstrip("\n").split("\t")
        if len(p) >= 3 and p[2].startswith("shipped/"):
            rows.append({"sha16": p[0], "bytes": int(p[1]), "path": p[2]})
    if not rows:
        sys.exit("gate: MANIFEST.txt yielded no shipped/ rows -- either the extract moved or the "
                 "manifest format changed; refusing to census an empty denominator")
    return rows


def live_mapped(base):
    """Device paths the audio stack had mapped, from the two independent live captures."""
    out = {}
    per_leg = {}
    loaders = os.path.join(base, "live/loaders.txt")
    reach = os.path.join(base, "live/acdb-reach.txt")
    # maps-mediaserver.txt is the FULL /proc/<pid>/maps capture (tools/grab_process_maps.sh).  The
    # name-filtered loaders.txt is only a sixth of it -- a census whose denominator comes from what I
    # kept instead of what the process mapped is the mistake this leg exists to prevent (§411).
    mapsf = os.path.join(base, os.environ.get("SD_FULL_MAPS", "live/maps-mediaserver.txt"))
    for name, rx in (("loaders.txt", re.compile(r"^(/[^\s]+\.so)$")),
                     ("acdb-reach.txt", re.compile(r"^REACH maps .*libs=(.*)$")),
                     # grab_process_maps.sh stores the de-duplicated path list (one path per line),
                     # not the raw maps text -- accept either shape so a re-capture cannot pass as empty
                     ("maps-mediaserver.txt", re.compile(r"^(?:\S+\s+){5,6}(/[^\s]+\.so)\s*$|^[0-9a-fx\-]+\s+\S+\s+\S+\s+\S+\s+\S+\s+(/[^\s]+\.so)$|^(/[^\s]+\.so)$"))):
        p = {"loaders.txt": loaders, "acdb-reach.txt": reach, "maps-mediaserver.txt": mapsf}[name]
        if not os.path.exists(p):
            sys.exit(f"gate: {p} is missing -- the live leg is what makes this census more than a "
                     "filename review; capture it (tools/grab_audio_live.sh) before running")
        n = 0
        for line in open(p, encoding="utf-8", errors="replace"):
            m = rx.match(line.strip())
            if not m:
                continue
            for token in (m.group(1) or m.group(2) or m.group(3)).split(","):
                token = token.strip()
                if token.startswith("/") and token.endswith(".so"):
                    out.setdefault(norm(token), set()).add(name)
                    n += 1
        if n == 0:
            sys.exit(f"gate: {p} parsed to 0 mapped libraries -- the pattern is blind, not the device")
        per_leg[name] = n
    if not out:
        sys.exit("gate: the live captures parsed but nothing mapped -- impossible; stop")
    full = per_leg.get("maps-mediaserver.txt", 0)
    filt = per_leg.get("loaders.txt", 0)
    if full < 50 or full < 2 * filt:
        sys.exit(f"gate: the unfiltered maps leg parsed to {full} libraries while the name-filtered "
                 f"loaders leg has {filt} -- the full capture must be the LARGER denominator "
                 "(ledger 411: the filtered list is about a sixth of what mediaserver maps).  A census "
                 "computed on the filtered subset reports gaps it cannot see")
    live_mapped.LEGS = dict(per_leg)
    return out


def norm(dev):
    return dev.replace("/system/vendor/", "/vendor/", 1) if dev.startswith("/system/vendor/") else dev


def acdb_denominators(base):
    """The capture's OWN two stated counts: the header `files-here=N` and the footer
    `verify rc=... over N baseline files`.  A gate that hardcodes 7 is an anchor to one machine
    (the recurring §385/§400/§582 failure); the capture already carries its denominator, so the
    expectation must be read from it -- and if it is not there, the leg has no denominator and
    the caller must refuse rather than publish a count."""
    p = os.path.join(base, "live/acdb-landing-verify.txt")
    if not os.path.exists(p):
        return {"header": None, "footer": None, "file": p}
    txt = open(p, encoding="utf-8", errors="replace").read()
    h = re.search(r"files-here=(\d+)", txt)
    f = re.search(r"verify rc=\d+ over (\d+) baseline files", txt)
    return {"header": int(h.group(1)) if h else None,
            "footer": int(f.group(1)) if f else None, "file": p}


def acdb_in_use(base):
    p = os.path.join(base, "live/acdb-landing-verify.txt")
    if not os.path.exists(p):
        return set(), None
    txt = open(p, encoding="utf-8", errors="replace").read()
    resolved = re.search(r"resolved=(\S+)", txt)
    used = set()
    for line in txt.splitlines():
        # "in use" is what the tool wrote when every hash matched; CORRUPT/DIFFERS is the same fact
        # (this file IS the one in use) with a verdict on its bytes.  Matching only the first wording
        # made a re-run against another machine silently return an EMPTY in-use set -- and an empty set
        # is exactly what step 5b's gate is supposed to catch rather than publish (ledger 587).
        m = re.match(r"\s*(?:in use|CORRUPT|DIFFERS)\s+(\S+\.acdb)", line)
        if m and resolved:
            used.add(norm(os.path.join(resolved.group(1), m.group(1))).replace(
                "/system/etc/", "/system/etc/", 1))
    return used, (resolved.group(1) if resolved else None)


def citations(base, root):
    tab = os.path.join(base, "port-target.PD1610.tsv")
    rb = os.path.join(root, "art/PORT-RUNBOOK-7.md")
    hay = ""
    if os.path.exists(tab):
        lines = open(tab, encoding="utf-8").read().splitlines()
        hdr = lines[0].split("\t")
        si = hdr.index("source")
        hay += "\n".join(l.split("\t")[si] for l in lines[1:] if len(l.split("\t")) > si)
    else:
        sys.exit(f"gate: {tab} missing -- the citation leg has no denominator")
    cited = set()
    if os.path.exists(rb):
        hay += "\n" + open(rb, encoding="utf-8").read()
    for token in re.split(r"[\s,;]+", hay):
        token = token.strip("`'\"()")
        if token:
            cited.add(os.path.basename(token))
            cited.add(token)
    return cited


def sha16(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()[:16]


def md5(path):
    return hashlib.md5(open(path, "rb").read()).hexdigest()



def config_literals(base, rows):
    """Reverse leg: every /system/etc config path a shipped binary names, and what the DEVICE says
    about it (live/config-literals.tsv, written by tools/grab_config_literals.sh).

    The forward leg answers "which captured file has a reader".  This one answers "what do the
    binaries ask for that I never captured" -- and it revalidates the capture itself, because every
    PRESENT file that the extract holds must hash to the device's value.
    """
    lits = {}
    for r in rows:
        if not r["path"].endswith(".so"):
            continue
        blob = open(os.path.join(base, r["path"]), "rb").read()
        for m in re.finditer(CFG_LIT_RX, blob):
            lits.setdefault(m.group().decode(), []).append(os.path.basename(r["path"]))
    p = os.path.join(base, "live/config-literals.tsv")
    if not os.path.exists(p):
        sys.exit(f"gate: {p} is missing -- run `bash tools/grab_config_literals.sh "
                 f"{p}` first; without the device answers this leg cannot distinguish a file I "
                 "never captured from a file the device does not have")
    lines = open(p, encoding="utf-8").read().splitlines()
    probe = {}
    for l in lines[1:]:
        c = l.split("\t")
        if len(c) >= 2:
            probe[c[0]] = c
    unprobed = sorted(set(lits) - set(probe))
    if unprobed:
        sys.exit(f"gate: {len(unprobed)} literal(s) the extract names are not in {p} "
                 f"({unprobed[:3]}) -- the probe table is older than the extract; re-run the probe")
    stale = sorted(set(probe) - set(lits))
    held = {}
    differ = []
    revalidated = []
    for lit, c in probe.items():
        # probe rows carry the literal in column 0, so the fields start at index 1
        state, size, md5, inex = (c[1:] + ["", "", "", "no"])[:4]
        rel = lit.lstrip("/")
        cand = [os.path.join(base, "shipped", rel), os.path.join(base, "shipped/system", rel)]
        path = next((x for x in cand if os.path.exists(x)), None)
        held[lit] = path
        if state == "PRESENT" and path and md5:
            if hashlib.md5(open(path, "rb").read()).hexdigest() != md5:
                differ.append(lit)
            else:
                revalidated.append(lit)
    if differ:
        sys.exit(f"gate: {len(differ)} config file(s) in the extract no longer hash to what the "
                 f"device holds ({differ[:3]}) -- either the capture was corrupt or the file moved; "
                 "re-capture before quoting any of this layer")
    return {"lits": lits, "probe": probe, "held": held, "stale_probe_rows": stale,
            "revalidated": sorted(revalidated),
            "not_held": [l for l, pth in held.items() if pth is None and
                         probe[l][1] == "PRESENT"],
            "absent_on_device": [l for l, c in probe.items() if c[1] == "ABSENT"]}



def soname_edges(base, rows):
    """Which libraries the held binaries NAME (DT_NEEDED or dlopen -- both live in .dynstr, and the
    dlopen case is exactly why a DT_NEEDED-only graph is not a dependency graph: ledger 411 showed
    `libacdbloader.so` is dlopened by ten held binaries, so a NEEDED-only census called it orphaned).

    Every name is reported with its holders; nothing here is filtered by an audio-sounding pattern.
    """
    held = {os.path.basename(r["path"]) for r in rows if r["path"].endswith(".so")}
    edges = {}
    for r in rows:
        if not r["path"].endswith(".so"):
            continue
        blob = open(os.path.join(base, r["path"]), "rb").read()
        for m in SONAME_RX.finditer(blob):
            n = m.group().decode()
            if n == os.path.basename(r["path"]):
                continue
            edges.setdefault(n, set()).add(r["path"])
    edges = {k: sorted(v) for k, v in edges.items()}
    missing = sorted(k for k in edges if k not in held)
    for r in rows:
        if r["path"].endswith(".so"):
            named = sorted(k for k, v in edges.items() if r["path"] in v)
            r["names_libraries"] = "%d" % len(named)
        else:
            r["names_libraries"] = "-"
    if not edges:
        sys.exit("gate: no soname literal found in any held binary -- the byte search is blind; a "
                 "real Android .so always names at least libc.so")
    return edges, missing, sorted(held)


def require_loader_carriers(edges):
    """The known-good claim from ledger 411, made a gate rather than a memory."""
    holders = edges.get(LOADER_NAME)
    if not holders:
        sys.exit("gate: nothing names " + LOADER_NAME + " -- either the ACDB loader is no longer "
                 "dlopened (then the whole loader layer must be re-read) or this census truncated its "
                 "own list; a printed count shorter than the hit count is the failure mode that hid "
                 "this once")
    return holders



def full_maps(base):
    """The unfiltered map list of the audio-hosting process, if it was captured (ledger 413)."""
    p = os.path.join(base, "live/maps-mediaserver.txt")
    if not os.path.exists(p):
        sys.exit("gate: live/maps-mediaserver.txt is missing -- the capture scope cannot be drawn "
                 "without the unfiltered maps (run `bash tools/grab_process_maps.sh <dir>` and place "
                 "the file); silently skipping this leg is exactly the name-filtered-denominator "
                 "mistake it exists to catch")
    lines = [l.strip() for l in open(p, encoding="utf-8", errors="replace") if l.strip().startswith("/")]
    if len(lines) < 50:
        sys.exit(f"gate: {p} holds {len(lines)} paths -- an unfiltered maps dump of mediaserver runs "
                 "to ~200; this file looks like the old name-filtered capture, refuse to scope by it")
    return lines

def literal_boundary(base):
    """Which mapped-but-uncaptured libraries the DEVICE itself says carry no audio-family literal.

    This is what turns "I judged these to be framework transport" into a measurement.  The control
    row is part of the artefact: the same probe run must show hits inside audio.primary, otherwise
    every zero in the table would be meaningless.
    """
    p = os.path.join(base, "live/audio-literal-probe.tsv")
    if not os.path.exists(p):
        sys.exit("gate: " + p + " is missing -- run "
                 "`LIST=<candidates> bash tools/grab_literal_probe.sh " + p + "`; without the device's "
                 "own answer, 'not chased' is my opinion and not a boundary")
    lines = open(p, encoding="utf-8").read().splitlines()
    if len(lines) < 20:
        sys.exit(f"gate: {p} has {len(lines) - 1} rows -- the candidate list must be every mapped path "
                 "the extract lacks, not a hand-picked few")
    rows = {}
    for l in lines[1:]:
        c = l.split("\t")
        if len(c) < 4 or not c[2].isdigit():
            continue
        k = norm(c[0])
        v = (int(c[2]), c[3])
        # keep the LARGEST count if a path appears twice -- a later zero must not mask the control row
        # (this fixture caught me doing exactly that with dict assignment)
        if k not in rows or v[0] > rows[k][0]:
            rows[k] = v
    ctl = [k for k in rows if os.path.basename(k) == "audio.primary.msm8996.so"]
    if not ctl or rows[ctl[0]][0] < 5:
        sys.exit("gate: the probe table has no positive-control row for audio.primary.msm8996.so with "
                 ">=5 audio-literal hits -- zeros in this table cannot be read as 'no audio content'")
    return rows



def audio_scope(base, rows, mapped_all):
    """Which libraries the port must hold, decided without a name pattern.

    audio hosts = the captured ELFs whose device path appears in the unfiltered maps of the process
    that runs the audio stack.  ring-1 = every soname literal inside those hosts (linked OR dlopened:
    ledger 411 showed the ACDB loader only has dlopen edges).  A ring-1 name that the device maps but
    the extract lacks is a REAL gap; one it never maps is dormant (proved by the same file).
    Anything named by a non-host binary is ring-2 -- the Android system stack (graphics, crypto, UI)
    -- and is reported as a boundary, not chased.
    """
    if mapped_all is None:
        return None
    names = {os.path.basename(x) for x in mapped_all}
    held = {os.path.basename(r["path"]) for r in rows if r["path"].endswith(".so")}
    mapped_set = {norm(x) for x in mapped_all}
    live_hosts = [r for r in rows if r["path"].endswith(".so") and r["device_path"] in mapped_set]
    # seeds = the plugin directories Android loads by path convention (HAL modules and effect
    # modules), witnessed as mapped.  Framework transport libraries (libaudioflinger, libmedia...)
    # are mapped too, but their name set is the whole Android system -- scoping by them would make
    # the frontier unbounded, which is why the rule says "modules", not "anything named audio".
    hosts = [r for r in live_hosts if "/hw/" in r["device_path"] or "/soundfx/" in r["device_path"]]
    if len(hosts) < 10:
        sys.exit(f"gate: only {len(hosts)} module-directory binaries appear in the live maps -- the "
                 "maps file and the extract are not from the same world (this project already caught "
                 "a name-filtered capture of the same kind)")
    # the module-host set must come from the MAPS, not from the extract: a mapped library in a plugin
    # directory that was never pulled is exactly the kind of gap a self-referential denominator hides
    # (this census said "0 gaps" while sound_trigger.primary.msm8996.so was mapped and absent).
    held_dev = {norm(r.get("device_path", "")) for r in rows}
    mapped_hosts = sorted(x for x in mapped_set if "/hw/" in x or "/soundfx/" in x)
    if len(mapped_hosts) < 10:
        sys.exit(f"gate: the maps name only {len(mapped_hosts)} module-directory libraries -- either the "
                 "capture changed world or my parse is blind")
    missing_hosts = [x for x in mapped_hosts if x not in held_dev]
    # a module directory is not by itself an audio module: mediaserver also maps the camera HAL and
    # a clock HAL.  The device's own literal count decides which of them the port has to hold.
    silent_hosts = []
    probe = literal_boundary(base)      # never swallowed: a missing control row must stop the census
    loud_names = {os.path.basename(k) for k, v in probe.items() if v[0] > 0}
    if probe:
        loud_hosts = [x for x in missing_hosts if probe.get(x, (0,))[0] > 0]
        silent_hosts = [x for x in missing_hosts if x not in loud_hosts]
        missing_hosts = loud_hosts
    scope_missing = missing_hosts
    rx = SONAME_RX
    ring1 = {}
    for r in hosts:
        blob = open(os.path.join(base, r["path"]), "rb").read()
        for m in rx.finditer(blob):
            n = m.group().decode()
            if n != os.path.basename(r["path"]):
                ring1.setdefault(n, set()).add(os.path.basename(r["path"]))
    if LOADER_NAME not in ring1:
        sys.exit("gate: nothing names " + LOADER_NAME + " among the module hosts -- the dlopen edge "
                 "that ledger 411 established has disappeared, so the scope rule changed under us")
    gap = sorted(set(["HOST:" + x for x in missing_hosts]) |
                 set(n for n in ring1 if n not in held and n in names and n in loud_names))
    silent_names = sorted(n for n in ring1 if n not in held and n in names and n not in loud_names)
    dormant = sorted(n for n in ring1 if n not in names)
    if gap and not os.environ.get("SD_REPORT_GAPS"):
        sys.exit("gate: %d library(s) a mapped module asks for, the device has, and the extract lacks "
                 "(%s) -- run tools/grab_live_mapped.sh or pull them before quoting scope completeness"
                 " (set SD_REPORT_GAPS=1 only to obtain the pull list, never to quote completeness)"
                 % (len(gap), " ".join(gap)))
    return {"hosts": sorted(os.path.basename(r["path"]) for r in hosts),
            "host_paths": sorted(r["device_path"] for r in hosts),
            "live_hosts": len(live_hosts), "framework_hosts": len(live_hosts) - len(hosts),
            "ring1": sorted(ring1), "gap": gap, "dormant": dormant, "silent_names": silent_names,
            "missing_hosts": sorted(scope_missing), "silent_hosts": sorted(silent_hosts),
            "n_mapped": len(mapped_all)}


def audio_closure(base, rows, mapped_all):
    """Everything the audible path can reach, by following the literals inside the binaries themselves.

    Seeds = the mapped HAL modules Android's audio policy loads by convention (basenames starting
    `audio.` in a plugin directory).  From each, every soname/config literal inside it is a member of
    the next ring; a ring member the device maps but the extract lacks is a REAL gap, and one it does
    not map is dormant.  Anything outside the closure is a different subsystem of the same process
    (mediaserver also serves camera and radio) -- stated as a boundary, with the witness that nothing
    in the closure names it, rather than quietly dropped.
    """
    if mapped_all is None:
        return None
    by_name = {}
    for r in rows:
        by_name.setdefault(os.path.basename(r["path"]), []).append(r)
    names = {os.path.basename(x) for x in mapped_all}
    mapped_set = {norm(x) for x in mapped_all}
    seeds = sorted({os.path.basename(x) for x in mapped_set
                    if ("/hw/" in x or "/soundfx/" in x) and os.path.basename(x).startswith("audio.")})
    if not seeds:
        sys.exit("gate: no mapped `audio.*` module in a plugin directory -- the audible path has no "
                 "entry point in this capture, so a closure from it would be empty and meaningless")
    seen, frontier, gaps, dormant = set(seeds), list(seeds), {}, set()
    rings = {n: 0 for n in seeds}
    while frontier:
        cur = frontier.pop(0)
        d = rings[cur]
        held = by_name.get(cur)
        if not held:
            gaps.setdefault(cur, d)          # reached by a literal, mapped, never captured
            continue
        for r in held:
            if not r["path"].endswith(".so"):
                continue
            blob = open(os.path.join(base, r["path"]), "rb").read()
            for mm in SONAME_RX.finditer(blob):
                n = mm.group().decode()
                if n == cur or n in seen:
                    continue
                seen.add(n)
                rings[n] = d + 1
                if n in names:
                    frontier.append(n)
                else:
                    dormant.add(n)
    return {"seeds": seeds, "reached": len(seen), "gaps": gaps, "dormant": len(dormant),
            "ring_max": max(rings.values()) if rings else 0}


def census(base, root):
    man = read_manifest(base)
    mapped = live_mapped(base)
    used, landing = acdb_in_use(base)
    cited = citations(base, root)
    rows, stale_hash = [], 0
    by_dev = {}
    for r in man:
        disk = os.path.join(base, r["path"])
        if not os.path.exists(disk):
            sys.exit(f"gate: MANIFEST names {r['path']} but it is not on disk")
        got = sha16(disk)
        if got != r["sha16"]:
            stale_hash += 1
        rel = r["path"][len("shipped/"):]
        if rel.startswith("bbkcore/"):
            rel = "data/" + rel        # /data/bbkcore/* is the path the app code names first
        dev = norm("/" + rel) if rel.startswith(("system/", "vendor/", "data/")) else None
        key = dev if dev else r["path"]
        by_dev.setdefault(key, []).append(r["path"])
        live_srcs = sorted(mapped.get(dev, set())) if dev else []
        is_used = dev in used or ("/" + rel) in used
        isc = (r["path"] in cited) or (dev in cited if dev else False) or \
              (os.path.basename(r["path"]) in cited)
        rows.append({
            "path": r["path"], "device_path": dev or "FLATTENED-AT-ROOT", "kind": kind(r["path"]),
            "bytes": r["bytes"], "sha16": r["sha16"], "sha16_recomputed": got,
            "live_mapped_via": "+".join(live_srcs) if live_srcs else "-",
            "acdb_in_use": "yes" if is_used else ("no" if r["path"].endswith(".acdb") else "-"),
            "cited": "yes" if isc else "no",
        })
    if stale_hash:
        sys.exit(f"gate: {stale_hash} shipped file(s) no longer hash to the MANIFEST value -- the "
                 "extract changed under this tool; re-run tools/man_check.py --fix first")
    dups = {}
    for a in by_dev.values():
        if len(a) > 1:
            sys.exit(f"gate: two shipped files claim the same device path {a} -- the capture plan "
                     "has an ambiguity this census must not paper over")
    bysha = {}
    for r in rows:
        bysha.setdefault(r["sha16_recomputed"], []).append(r["path"])
    for r in rows:
        peers = [p for p in bysha[r["sha16_recomputed"]] if p != r["path"]]
        r["byte_identical_to"] = "+".join(peers) if peers else "-"
        if r["live_mapped_via"] != "-" and r["cited"] == "yes":
            r["verdict"] = "LIVE-AND-CITED"
        elif r["live_mapped_via"] != "-" or r["acdb_in_use"] == "yes":
            r["verdict"] = "LIVE-NOT-CITED"
        elif r["cited"] == "yes":
            r["verdict"] = "CITED-NOT-LIVE"
        elif r["byte_identical_to"] != "-":
            r["verdict"] = "PEER-REFERENCE"
        else:
            r["verdict"] = "QUIET"
        if r["verdict"] not in VERDICTS:
            sys.exit("gate: produced a verdict outside the enum -- the classifier grew a branch "
                     "nobody reviewed")
    # ---- config-carrier leg: which binary names which config file verbatim ----
    cfg_names = {os.path.basename(r["path"]) for r in rows if r["kind"] == "config"}
    carriers = {}
    for r in rows:
        r["names_config"] = "-"
        if not r["path"].endswith(".so"):
            continue
        blob = open(os.path.join(base, r["path"]), "rb").read()
        hits = sorted(c for c in cfg_names if c.encode() in blob)
        if hits:
            r["names_config"] = "+".join(hits)
            carriers[os.path.basename(r["path"])] = hits
    per_cfg = {}
    for r in rows:
        if r["kind"] != "config":
            continue
        n = os.path.basename(r["path"])
        per_cfg[n] = sorted(k for k, v in carriers.items() if n in v)
    if not carriers:
        sys.exit("gate: no shipped binary names any shipped config file -- that is a blind byte "
                 "search, not a real absence: every audio HAL in this project so far has carried at "
                 "least one /system/etc path literal")
    if len(per_cfg) != len(cfg_names):
        sys.exit(f"gate: {len(per_cfg)} config files accounted but {len(cfg_names)} in the extract -- "
                 "the carrier census must cover all of them, named-by-binary or not")
    gaps = [{"device_path": d, "live_via": "+".join(sorted(s))} for d, s in sorted(mapped.items())
            if d not in by_dev]
    cfg = {"carriers": carriers, "per_config": per_cfg,
           "no_carrier": sorted(k for k, v in per_cfg.items() if not v)}
    cfg["literals"] = config_literals(base, rows)
    cfg["acdb_stated"] = acdb_denominators(base)
    cfg["acdb_answered"] = len([r for r in rows if r["acdb_in_use"] == "yes"])
    st = cfg["acdb_stated"]
    # Refuse here, in the delivered path, not only in the outer tool: the capture's own two counts
    # must agree with each other and must be able to cover what this census claims is in use.
    if st["header"] is not None and st["footer"] is not None and st["header"] != st["footer"]:
        sys.exit(f"gate: {st['file']} disagrees with itself -- header files-here={st['header']} "
                 f"vs footer 'over {st['footer']} baseline files'")
    if st["header"] is not None and cfg["acdb_answered"] > st["header"]:
        sys.exit(f"gate: {cfg['acdb_answered']} files matched the in-use wording but the capture "
                 f"lists only files-here={st['header']} -- the path normalisation is matching more "
                 "than the device said exists")
    m_all = full_maps(base)
    scope = audio_scope(base, rows, m_all)
    cfg["scope"] = scope
    closure = audio_closure(base, rows, m_all)
    by_name = {}
    for x in (m_all or []):
        by_name.setdefault(os.path.basename(x), []).append(x)
    chase = {}
    probe = literal_boundary(base)
    for n, ring in sorted(closure["gaps"].items()):
        for dp in by_name.get(n, []):
            if probe.get(norm(dp), (0,))[0] > 0:      # the device itself says this one carries audio
                chase[dp] = {"why": f"ring-{ring} of the audible closure", "name": n}
    for dp in scope.get("missing_hosts", []):
        chase[dp] = {"why": "mapped module host, never captured", "name": os.path.basename(dp)}
    closure["chase"] = [{"device_path": k, "why": v["why"]} for k, v in sorted(chase.items())]
    closure["boundary"] = len(gaps) - len(chase)
    held_dev2 = {norm(r.get("device_path", "")) for r in rows}
    loud_open = sorted(d for d in chase
                       if probe.get(norm(d), (0,))[0] > 0 and norm(d) not in held_dev2)
    if loud_open:
        sys.exit("gate: %d mapped library(ies) the device says carry audio-family literals and the "
                 "extract still lacks (%s) -- those are real gaps; pull them with "
                 "tools/grab_live_mapped.sh before quoting completeness"
                 % (len(loud_open), " ".join(loud_open)))
    silent = sorted(d for d, v in probe.items()
                    if v[0] == 0 and d not in held_dev2 and d != norm(
                        "/system/lib/hw/audio.primary.msm8996.so"))
    closure["chased"] = len(chase)
    closure["silent_boundary"] = len(silent)
    cfg["closure"] = closure
    edges, missing, _ = soname_edges(base, rows)
    cfg["soname"] = {"edges": edges, "missing": missing}
    return rows, gaps, landing, len(mapped), cfg


def main():
    root = os.environ.get("AUDIO_PORT_ROOT", "/home/v/.local/project/xplay6")
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=root)
    ap.add_argument("--base", default=None, help="baseline dir (default <root>/art/audio-6.0.1)")
    ap.add_argument("--tsv", default=None)
    ap.add_argument("--json", default=None)
    ap.add_argument("--require-loader-carriers", action="store_true",
                        help="abort unless the ACDB loader is named by at least one binary")
    a = ap.parse_args()
    args_require = "--require-loader-carriers" in sys.argv
    base = a.base or os.path.join(a.root, "art/audio-6.0.1")
    rows, gaps, landing, n_mapped, cfg = census(base, a.root)
    counts = {}
    for r in rows:
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
    print(f"shipped files: {len(rows)}  live-mapped device paths: {n_mapped}  "
          f"acdb landing: {landing}  "
          f"acdb in-use={cfg['acdb_answered']} stated={cfg['acdb_stated']['header']}"
          f"/{cfg['acdb_stated']['footer']}")
    cl = cfg.get("closure") or {}
    if cl:
        print(f"audible closure: seeds={' '.join(cl.get('seeds', []))} reached={cl.get('reached')} "
              f"ring_max={cl.get('ring_max')} dormant={cl.get('dormant')} "
              f"chase={len(cl.get('chase', []))} mapped-but-not-chased={cl.get('boundary')}")
        for g in cl.get("chase", []):
            print(f"   CHASE {g['device_path']:56s} {g['why']}")
    print("verdicts: " + "  ".join(f"{k}={counts.get(k, 0)}" for k in VERDICTS))
    print(f"coverage: every shipped file got exactly one verdict "
          f"({sum(counts.values())}/{len(rows)})")
    print("\n-- LIVE-NOT-CITED (on the audible path, no row in the carry list) --")
    for r in rows:
        if r["verdict"] == "LIVE-NOT-CITED":
            print(f"   {r['path']}  ({r['bytes']} B, via {r['live_mapped_via']}, "
                  f"acdb_in_use={r['acdb_in_use']})")
    print("\n-- CONFIG CARRIERS (which shipped binary names which config file verbatim) --")
    for name, hits in sorted(cfg["per_config"].items()):
        print(f"   {name:<38} " + ("(no carrier)" if not hits else " ".join(hits)))
    print(f"   config files: {len(cfg['per_config'])}  named by a binary: "
          f"{len(cfg['per_config']) - len(cfg['no_carrier'])}  with no carrier: {len(cfg['no_carrier'])}")
    lit = cfg["literals"]
    print("\n-- CONFIG LITERALS THE BINARIES ASK FOR (device answer per literal) --")
    print(f"   literals: {len(lit['probe'])}  held in the extract: "
          f"{sum(1 for v in lit['held'].values() if v)}  hash-equal to the device: "
          f"{len(lit['revalidated'])}  asked-for-and-absent-from-extract: "
          f"{len(lit['not_held'])}  absent on device too: {len(lit['absent_on_device'])}")
    for l in lit["not_held"]:
        print(f"   NOT HELD {l}  (device has it -- capture it)")
    e, miss = cfg["soname"]["edges"], cfg["soname"]["missing"]
    print("\n-- SONAME EDGES (libraries named inside held binaries: linked OR dlopened) --")
    print(f"   distinct names: {len(e)}  held: {len(e) - len(miss)}  not held: {len(miss)}")
    print(f"   {LOADER_NAME} is named by {len(e.get(LOADER_NAME, []))} binaries: "
          f"{' '.join(os.path.basename(x) for x in e.get(LOADER_NAME, []))}")
    print("   not held: " + " ".join(miss))
    if args_require:
        req = require_loader_carriers(e)
        print(f"   required-carrier check: {LOADER_NAME} named by {len(req)} binaries")
    sc = cfg["scope"]
    if sc:
        print("\n-- AUDIO SCOPE (hosts from the live maps; ring-1 = what they name) --")
        print(f"   module hosts: {len(sc['hosts'])} (of {sc['live_hosts']} mapped captured binaries; "
              f"{sc['framework_hosts']} are framework transport, whose name set is the whole system "
              "and is NOT the scope)  maps file holds " + str(sc["n_mapped"]) + " libraries")
        print(f"   ring-1 names: {len(sc['ring1'])}  real gaps (mapped, named by a module, not held): "
              f"{len(sc['gap'])}" + (" -> " + " ".join(sc["gap"]) if sc["gap"] else ""))
        print(f"   dormant (named but never mapped): {len(sc['dormant'])} -> {' '.join(sc['dormant'][:8])}")
        print("   ring-2 (named by non-host binaries: the system stack) is a stated boundary, not chased")
    print("\n-- LIVE-NOT-CAPTURED (device maps it, extract does not hold it) --")
    for g in gaps:
        print(f"   {g['device_path']}   [mapped via {g['live_via']}]")
    print(f"gaps (mapped, not held): {len(gaps)} -- every one of these is counted ZERO "
          f"audio-family literals by live/audio-literal-probe.tsv, so the audible-path gap count is {len((cfg.get(chr(34)+"closure"+chr(34)) or {}).get("chase", []))}")
    if a.tsv:
        import csv
        cols = ["path", "device_path", "kind", "bytes", "sha16", "live_mapped_via", "acdb_in_use",
                "cited", "byte_identical_to", "names_config", "verdict"]
        with open(a.tsv, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f, delimiter="\t")
            w.writerow(cols)
            for r in rows:
                w.writerow([r[c] for c in cols])
        print(f"wrote {a.tsv}: {len(rows)} rows")
    if a.json:
        json.dump({"rows": rows, "gaps": gaps, "landing": landing, "config": cfg},
                  open(a.json, "w", encoding="utf-8"), indent=1)
        print(f"wrote {a.json}")
    return 0


def selftest():
    """Each arm builds its own small fixture and runs the tool as a subprocess.  Nothing here
    mutates this file's source, so an arm cannot eat its own mutation (ledger 391)."""
    import shutil, subprocess, tempfile
    here = os.path.dirname(os.path.abspath(__file__))
    tool = os.path.join(here, "shipped_disposition.py")
    bad = 0

    def build():
        tmp = tempfile.mkdtemp()
        root = os.path.join(tmp, "root")
        base = os.path.join(root, "art/audio-6.0.1")
        blobs = {"shipped/system/lib64/hw/audio.primary.msm8996.so":
                 b"PRIMARY-HAL libacdbloader.so libaudiocert.so "
                 b"/system/etc/mixer_paths_tasha.PD1610.xml",
                 "shipped/system/lib64/hw/audio.usb.default.so": b"USB-HAL libc.so",
                 "shipped/vendor/lib/libacdbloader.so": b"ACDB32 libaudcal.so",
                 "shipped/system/etc/mixer_paths_tasha.PD1610.xml": b"<mixer/>"}
        for i in range(10):
            blobs["shipped/system/lib64/soundfx/libfx%d.so" % i] = b"EFFECT libcutils.so libexpat.so"
        lines = []
        for rel, blob in blobs.items():
            p = os.path.join(base, rel)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            open(p, "wb").write(blob)
            lines.append(f"{sha16(p)}\t{len(blob)}\t{rel}")
        os.makedirs(os.path.join(base, "live"), exist_ok=True)
        open(os.path.join(base, "MANIFEST.txt"), "w", encoding="utf-8").write("\n".join(lines) + "\n")
        open(os.path.join(base, "live/loaders.txt"), "w", encoding="utf-8").write(
            "== pid 716 /system/bin/mediaserver \n"
            "/system/lib64/hw/audio.primary.msm8996.so\n"
            "/system/lib64/hw/audio.usb.default.so\n"
            "/system/lib/libaudioflinger.so\n")
        open(os.path.join(base, "live/acdb-reach.txt"), "w", encoding="utf-8").write(
            "REACH maps pid=737 comm=mediaserver hal_loaded=3 ctx=u:r:mediaserver:s0 "
            "libs=/system/vendor/lib/libacdbloader.so,\n")
        open(os.path.join(base, "live/acdb-landing-verify.txt"), "w", encoding="utf-8").write(
            "landing=/etc/acdbdata/PD1610 resolved=/system/etc/acdbdata/PD1610 files-here=0\n")
        open(os.path.join(base, "port-target.PD1610.tsv"), "w", encoding="utf-8").write(
            "layer\titem\tvalue\tname_or_meaning\tsource\twritable\tuse_case\twitness2\n"
            "x\ty\tz\tw\tart/audio-6.0.1/shipped/system/lib64/hw/audio.primary.msm8996.so\tno\tn\tn\n")
        os.makedirs(os.path.join(root, "art"), exist_ok=True)
        open(os.path.join(root, "art/PORT-RUNBOOK-7.md"), "w", encoding="utf-8").write(
            "# fixture runbook\nmixer_paths_tasha.PD1610.xml is cited here\n")
        # the literal probe table the census demands: one row per literal the fixture names
        xml = os.path.join(base, "shipped/system/etc/mixer_paths_tasha.PD1610.xml")
        maps = ["/system/lib64/hw/audio.primary.msm8996.so", "/system/lib64/hw/audio.usb.default.so",
                "/system/vendor/lib/libacdbloader.so", "/system/lib/libaudioflinger.so"]
        maps += ["/system/lib64/soundfx/libfx%d.so" % i for i in range(10)]
        maps += ["/system/lib/libaudiocert.so"]        # reached by a literal, mapped, not held
        maps += ["/system/lib/filler%02d.so" % i for i in range(45)]
        open(os.path.join(base, "live/maps-mediaserver.txt"), "w", encoding="utf-8").write(
            "\n".join(maps) + "\n")
        probe = os.path.join(base, "live/audio-literal-probe.tsv")
        plines = ["device_path\tsize_bytes\taudio_literal_hits\ttokens",
                  "/system/lib64/hw/audio.primary.msm8996.so\t1234\t26\taudio:20"]
        plines += [f"{x}\t1000\t0\t-" for x in maps
                   if os.path.basename(x) != "audio.primary.msm8996.so"]
        open(probe, "w", encoding="utf-8").write("\n".join(plines) + "\n")
        open(os.path.join(base, "live/config-literals.tsv"), "w", encoding="utf-8").write(
            "literal\tdevice_state\tbytes\tmd5\tin_extract\n"
            "/system/etc/mixer_paths_tasha.PD1610.xml\tPRESENT\t%d\t%s\tyes\n"
            % (os.path.getsize(xml), md5(xml)))
        return root, base

    def run(root, base, extra=None):
        cmd = [sys.executable, tool, "--root", root, "--base", base] + (extra or [])
        r = subprocess.run(cmd, capture_output=True, text=True)
        return r.returncode, r.stdout + r.stderr

    def fresh():
        return build()

    arms = []
    root, base = fresh()
    arms.append(("ok: fixture census classifies all four files", lambda rc, o: rc == 0 and
                 "(14/14)" in o and "verdicts:" in o, (root, base)))

    def gaps_only(want, absent):
        def check(rc, o, rb=(root, base)):
            rc2, o2 = run(*rb)
            body = o2.split("-- LIVE-NOT-CAPTURED")[-1]
            return rc2 == 0 and all(w in body for w in want) and all(a not in body for a in absent)
        return check
    arms.append(("control: gap list names the uncaptured lib and not the captured ones",
                 gaps_only(["/system/lib/libaudioflinger.so"],
                           ["/system/lib64/hw/audio.primary.msm8996.so"]), (root, base)))
    arms.append(("control: the /system/vendor symlink rule matched libacdbloader",
                 gaps_only([], ["/vendor/lib/libacdbloader.so"]), (root, base)))

    def arm_missing_live():
        r, b = fresh()
        os.remove(os.path.join(b, "live/loaders.txt"))
        rc, o = run(r, b)
        return rc != 0 and "gate:" in o and "live leg" in o, (r, b)
    arms.append(("gate: live capture absent -> aborts", arm_missing_live, None))

    def arm_blind_pattern():
        r, b = fresh()
        open(os.path.join(b, "live/loaders.txt"), "w", encoding="utf-8").write(
            "== pid 716 /system/bin/mediaserver \nnothing here at all\n")
        open(os.path.join(b, "live/acdb-reach.txt"), "w", encoding="utf-8").write("REACH uptime=1\n")
        rc, o = run(r, b)
        return rc != 0 and "0 mapped" in o, (r, b)
    arms.append(("gate: blind live pattern -> aborts instead of reporting no gaps",
                 arm_blind_pattern, None))

    def arm_stale_hash():
        r, b = fresh()
        p = os.path.join(b, "shipped/vendor/lib/libacdbloader.so")
        before = open(p, "rb").read()
        open(p, "wb").write(b"ACDB32-CHANGED")
        if open(p, "rb").read() == before:
            return False, (r, b)
        rc, o = run(r, b)
        return rc != 0 and "no longer hash" in o, (r, b)
    arms.append(("gate: shipped bytes drifted from MANIFEST -> aborts", arm_stale_hash, None))

    def arm_duplicate_devpath():
        r, b = fresh()
        # a copy reached through the /system/vendor symlink: after normalisation it claims the same
        # device path as shipped/vendor/lib/libacdbloader.so.  (lib vs lib64 does NOT collide -- that
        # is the bitness distinction, and an earlier version of this arm got it wrong.)
        src = os.path.join(b, "shipped/vendor/lib/libacdbloader.so")
        dst = os.path.join(b, "shipped/system/vendor/lib/libacdbloader.so")
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copyfile(src, dst)
        man = os.path.join(b, "MANIFEST.txt")
        lines = open(man, encoding="utf-8").read().splitlines()
        lines.append(f"{sha16(dst)}\t{os.path.getsize(dst)}\tshipped/system/vendor/lib/libacdbloader.so")
        open(man, "w", encoding="utf-8").write("\n".join(lines) + "\n")
        rc, o = run(r, b)
        return rc != 0 and "same device path" in o, (r, b)
    arms.append(("gate: two files claiming one device path -> aborts", arm_duplicate_devpath, None))

    def arm_no_carrier():
        r, b = fresh()
        hal = os.path.join(b, "shipped/system/lib64/hw/audio.primary.msm8996.so")
        rel = "shipped/system/lib64/hw/audio.primary.msm8996.so"
        man = os.path.join(b, "MANIFEST.txt")

        def record(path):
            ls = [l for l in open(man, encoding="utf-8").read().splitlines()
                  if not l.endswith(rel)]
            ls.append(f"{sha16(path)}\t{os.path.getsize(path)}\t{rel}")
            open(man, "w", encoding="utf-8").write("\n".join(ls) + "\n")

        open(hal, "wb").write(b"PRIMARY-HAL libacdbloader.so /system/etc/mixer_paths_tasha.PD1610.xml")
        record(hal)
        rc, o = run(r, b)
        if rc != 0 or "named by a binary: 1" not in o:
            return False, (r, b)
        open(hal, "wb").write(b"PRIMARY-HAL-NO-LITERAL libc.so libacdbloader.so")
        record(hal)
        rc2, o2 = run(r, b)
        return rc2 != 0 and "blind byte search" in o2, (r, b)
    arms.append(("gate: every config literal gone -> carrier leg aborts", arm_no_carrier, None))

    def arm_no_probe_table():
        r, b = fresh()
        os.remove(os.path.join(b, "live/config-literals.tsv"))
        rc, o = run(r, b)
        return rc != 0 and "config-literals.tsv is missing" in o, (r, b)
    arms.append(("gate: literal probe table absent -> aborts (cannot tell 'not captured' from 'not there')",
                 arm_no_probe_table, None))

    def arm_stale_probe():
        r, b = fresh()
        p = os.path.join(b, "live/config-literals.tsv")
        lines = open(p, encoding="utf-8").read().splitlines()
        open(p, "w", encoding="utf-8").write("\n".join(lines[:1]) + "\n")  # header only
        rc, o = run(r, b)
        return rc != 0 and "are not in" in o, (r, b)
    arms.append(("gate: probe table older than the extract -> aborts", arm_stale_probe, None))

    def arm_loader_control():
        r, b = fresh()
        hal = os.path.join(b, "shipped/system/lib64/hw/audio.primary.msm8996.so")
        rel = "shipped/system/lib64/hw/audio.primary.msm8996.so"
        man = os.path.join(b, "MANIFEST.txt")

        def record(path):
            ls = [l for l in open(man, encoding="utf-8").read().splitlines()
                  if not l.endswith(rel)]
            ls.append(f"{sha16(path)}\t{os.path.getsize(path)}\t{rel}")
            open(man, "w", encoding="utf-8").write("\n".join(ls) + "\n")

        open(hal, "wb").write(b"PRIMARY-HAL libacdbloader.so /system/etc/mixer_paths_tasha.PD1610.xml")
        record(hal)
        rc, o = run(r, b, extra=["--require-loader-carriers"])
        if rc != 0 or "named by 1 binaries" not in o:
            return False, (r, b)
        open(hal, "wb").write(b"PRIMARY-HAL libc.so /system/etc/mixer_paths_tasha.PD1610.xml")
        record(hal)
        rc2, o2 = run(r, b, extra=["--require-loader-carriers"])
        return rc2 != 0 and "nothing names libacdbloader.so" in o2, (r, b)
    arms.append(("control+gate: the dlopened ACDB loader must be named by a binary",
                 arm_loader_control, None))

    def arm_maps_missing():
        r, b = fresh()
        os.remove(os.path.join(b, "live/maps-mediaserver.txt"))
        rc, o = run(r, b)
        return rc != 0 and "maps-mediaserver.txt is missing" in o, (r, b)
    arms.append(("gate: unfiltered maps absent -> the scope leg refuses instead of vanishing",
                 arm_maps_missing, None))

    def arm_probe_no_control():
        r, b = fresh()
        p2 = os.path.join(b, "live/audio-literal-probe.tsv")
        keep = [l for l in open(p2, encoding="utf-8").read().splitlines() if "audio.primary" not in l]
        open(p2, "w", encoding="utf-8").write("\n".join(keep) + "\n")
        rc, o = run(r, b)
        return rc != 0 and "positive-control row" in o, ("rc=%d :: %s" % (rc, " | ".join((o.strip().splitlines() or ["-"])[-2:])[:220]))
    arms.append(("gate: a probe table without its positive-control row cannot certify the zeros",
                 arm_probe_no_control, None))

    # -- the ACDB "in use" leg's denominator: two sides, because a silent empty set once passed ----
    ACDB_NAMES = ("Handset_cal.acdb", "Headset_cal.acdb", "Speaker_cal.acdb")

    def with_acdb(names=ACDB_NAMES, wording=("in use", "in use", "in use"), header=3, footer=3):
        r, b = fresh()
        man = os.path.join(b, "MANIFEST.txt")
        ls = open(man, encoding="utf-8").read().splitlines()
        rels = []
        for n in names:
            rel = "shipped/system/etc/acdbdata/PD1610/" + n
            p = os.path.join(b, rel)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            open(p, "wb").write(("ACDB-" + n).encode())
            ls.append("%s\t%d\t%s" % (sha16(p), os.path.getsize(p), rel))
            rels.append(n)
        open(man, "w", encoding="utf-8").write("\n".join(ls) + "\n")
        lines = ["landing=/etc/acdbdata/PD1610 resolved=/system/etc/acdbdata/PD1610 files-here=%d"
                 % header]
        for w, n in zip(wording, rels):
            lines.append("  %s  %s md5=abcd1234 whatever" % (w, n))
        if footer is not None:
            lines.append("verify rc=0 over %d baseline files" % footer)
        open(os.path.join(b, "live/acdb-landing-verify.txt"), "w",
             encoding="utf-8").write("\n".join(lines) + "\n")
        return r, b

    def arm_acdb_wording():
        rc, o = run(*with_acdb())
        ok1 = rc == 0 and "acdb in-use=3 stated=3/3" in o
        rc2, o2 = run(*with_acdb(wording=("DIFFERS", "CORRUPT", "in use")))
        ok2 = rc2 == 0 and "acdb in-use=3 stated=3/3" in o2
        return ok1 and ok2, ("plain rc=%d / variant rc=%d :: %s" %
                             (rc, rc2, " | ".join((o2.strip().splitlines() or ["-"])[-2:])[:200]))
    arms.append(("control: the in-use leg counts both wordings ('in use' and DIFFERS/CORRUPT) "
                 "and reports its own denominator", arm_acdb_wording, None))

    def arm_acdb_selfdisagree():
        rc, o = run(*with_acdb(header=5, footer=3))
        return rc != 0 and "disagrees with itself" in o, ("rc=%d :: %s" % (rc, o.strip()[-180:]))
    arms.append(("gate: a capture whose header and footer counts differ -> refuse",
                 arm_acdb_selfdisagree, None))

    def arm_acdb_overcount():
        rc, o = run(*with_acdb(header=2, footer=2))
        return rc != 0 and "lists only files-here=2" in o, ("rc=%d :: %s" % (rc, o.strip()[-180:]))
    arms.append(("gate: more files matched than the capture says exist -> refuse (normalisation "
                 "is inventing rows)", arm_acdb_overcount, None))

    def arm_probe_loud_gap():
        r, b = fresh()
        p2 = os.path.join(b, "live/audio-literal-probe.tsv")
        # silent today (0 hits) -- make the device say it carries audio literals and the census must
        # refuse to call the scope complete
        rows2 = open(p2, encoding="utf-8").read().splitlines()
        rows2 = [l.replace("/system/lib/libaudiocert.so\t1000\t0\t-",
                           "/system/lib/libaudiocert.so\t1000\t9\taudio:9") for l in rows2]
        open(p2, "w", encoding="utf-8").write("\n".join(rows2) + "\n")
        rc, o = run(r, b)
        return rc != 0 and "libaudiocert.so" in o, ("rc=%d :: %s" % (rc, " | ".join((o.strip().splitlines() or ["-"])[-2:])[:220]))
    arms.append(("gate: an uncaptured library the probe calls audio-bearing aborts the census",
                 arm_probe_loud_gap, None))

    def arm_maps_short():
        r, b = fresh()
        p = os.path.join(b, "live/maps-mediaserver.txt")
        keep = [l for l in open(p, encoding="utf-8").read().splitlines()][:30]
        open(p, "w", encoding="utf-8").write("\n".join(keep) + "\n")
        rc, o = run(r, b)
        # either denominator gate may be the one that fires -- both say the same thing
        return rc != 0 and ("LARGER denominator" in o or "runs to ~200" in o), (r, b)
    arms.append(("gate: a truncated maps file -> aborts (a 33-line name-filtered capture is not scope)",
                 arm_maps_short, None))

    for label, check, fixed in arms:
        why = ""
        try:
            if callable(check) and fixed is None:
                ok, extra = check()
                why = "" if ok else " :: " + str(extra)[:200]
            else:
                rc, o = run(*fixed)
                ok = check(rc, o)
                if not ok:
                    why = " rc=%d :: %s" % (rc, " | ".join((o.strip().splitlines() or ["-"])[-2:])[:260])
        except SystemExit as e:
            ok = False
            why = f" (raised {e})"
        print(("  ok   " if ok else "  FAIL ") + label + why)
        bad += 0 if ok else 1
    print(f"selftest: {bad} arm(s) failed")
    return 1 if bad else 0


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        sys.exit(selftest())
    sys.exit(main())
