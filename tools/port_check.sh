#!/usr/bin/env bash
# tools/port_check.sh -- verify a machine against the 6.0.1 audio baseline table.
#
# READ ONLY. Two doors exist on the PA debugfs (ledger 247/248): `i2c` is a raw passthrough
# (tfa98xx_debug_write: memdup_user -> i2c_master_send) and `codec_reg` is a parsed
# single-register write (sscanf "%x %x" -> regmap_write). Neither is used here -- applying values
# is a consent decision, so this script only ever reads.
#
# usage: tools/port_check.sh [check|snapshot|container|acdb|dir|reach|pa-samples] [out-file]
#   container = pull the .cnt named by DT and verify its DSP blocks against the 6.0.1 inventory
#   dir       = replay the loader's model/platform/hw_platform directory cascade live and judge it
#               against the table (this is the first thing to run after switching to 7)
set -uo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
TABLE=${TABLE:-$ROOT/art/audio-6.0.1/port-target.PD1610.tsv}
MODE=${1:-check}
OUT=${2:-}
ADB=${ADB:-adb}
# On the official 7.1.1 the vendor blocks execve of any path whose last component is `su` (ledger 571), while the
# same client under another name works: run the harness with SU=sux after the app has mounted it on PATH.
SU=${SU:-su}
# CAPTURE= judges an existing file, so an offline re-read must not mint a new 119 KB "capture" inside
# the ledger directory -- it did exactly that on 2026-10-16 and man_check --fix nearly registered the
# duplicate as an artifact.  Live runs still default to a timestamped file under art/.
if [ -z "$OUT" ]; then
    if [ -n "${CAPTURE:-}" ] || [ "$MODE" != check ]; then
        # ONLY `check` may mint a capture.  The other subcommands write reports, and the top-level
        # default put ACDB / REACH / .cnt dumps into art/audio-6.0.1/live/portcheck-<time>.txt, where a
        # reader -- or tfa_field_history's session denominator -- would take them for captures (§360).
        OUT=$(mktemp /tmp/portcheck-$MODE.XXXXXX)
    else
        OUT=$ROOT/art/audio-6.0.1/live/portcheck-$(date +%Y%m%d-%H%M%S).txt
    fi
fi

[ -f "$TABLE" ] || { echo "no table: $TABLE"; exit 2; }

sh_on() { $ADB shell "$SU -c '$1'" 2>&1; }

# one place that knows how to run the cascade probe, because both the dir gate and the acdb gate
# need the same landing answer (ledger 275)
run_acdbdir() {
    $ADB push "$ROOT/tools/acdbdir.sh" /data/local/tmp/acdbdir.sh >/dev/null 2>&1 ||
        { echo "acdbdir: cannot push tools/acdbdir.sh"; return 2; }
    $ADB exec-out "$SU -c 'sh /data/local/tmp/acdbdir.sh'" 2>/dev/null | tr -d '\r'
}

# acdb mode: which on-device calibration set is this machine actually using? decided by content
# (sha256 prefixes from the local 6.0.1 table), because the directory name is chosen by the HAL's
# board-id logic and is exactly the thing that changes across firmware versions.
if [ "$MODE" = acdb ]; then
    # this device has md5sum/sha1sum but NO sha256sum -- the baseline column follows the tool
    LIST=$(sh_on 'for f in /system/etc/acdbdata/*/*.acdb /vendor/etc/acdbdata/*/*.acdb; do [ -f "$f" ] && md5sum "$f"; done' \
            | tr -d '\r' | grep -E "^[0-9a-f]{32} +/")
    [ -n "$LIST" ] || { echo "acdb: no .acdb readable on device (or md5sum missing)"; exit 2; }
    echo "$LIST" > "$OUT"
    python3 - "$OUT" "$ROOT/art/audio-6.0.1/acdb-meta.PD1610.tsv" <<'PY'
import csv, sys
live = {}
for ln in open(sys.argv[1]):
    h, p = ln.split(None, 1)
    live[p.strip()] = h
base = {r["file"]: r["md5"] for r in csv.DictReader(open(sys.argv[2]), delimiter="\t") if r["dir"] == "PD1610"}
hit = {}
for p, sha in live.items():
    fn = p.rsplit("/", 1)[-1]
    if fn in base:
        hit.setdefault(fn, []).append((p.split("/")[-2] if "/" in p else "?", sha == base[fn]))
print(f"compared {len(base)} baseline files against {len(live)} device files")
nomatch = 0
for fn in sorted(base):
    matches = sorted({d for d, ok in hit.get(fn, []) if ok})
    anyhit = bool(hit.get(fn))
    print(f"  {'OK   ' if matches else 'NOMATCH' if anyhit else 'ABSENT'} {fn:22s} baseline md5={base[fn][:12]}… "
          f"dirs matching={','.join(matches) or '-'}")
    if not matches:
        nomatch += 1
if nomatch:
    # the exit code has to carry the content verdict too -- printing NOMATCH and returning 0 is
    # the same §260 defect this ledger already recorded once for another gate
    sys.exit(f"FAIL: {nomatch} of {len(base)} baseline cal files have no byte-identical copy on device")
PY
    rc1=$?
    # --- delta overlay (ledger 274): /data/misc/audio/acdbdata/delta/ carries ONE slot per cal
    # file the driver was handed, and libaudcal writes through acdbdata_ioctl -- a NON-ZERO slot
    # means the shipped .acdb is being patched at runtime, which is exactly the stale-copy risk
    # that §272 wrongly cleared (it only looked for '*.acdb', not for '*.acdbdelta').
    if [ -n "${DELTA:-}" ]; then
        [ -f "$DELTA" ] || { echo "acdb: DELTA=$DELTA missing"; exit 2; }
        DELTA_OURS=""
    else
        DELTA=/tmp/portcheck-delta.$$
        DELTA_OURS=1
        sh_on 'ls -la /data/misc/audio/acdbdata/delta' | tr -d '\r' > "$DELTA"
    fi
    { echo "===== delta overlay ====="; cat "$DELTA"; } >> "$OUT"
    python3 - "$DELTA" "$TABLE" <<'PY'
import csv, os, re, sys
rows = [r for r in csv.DictReader(open(sys.argv[2], encoding="utf-8"), delimiter="\t")
        if r["layer"] == "ACDB cal asset"]
want = {os.path.basename(r["item"]) + "delta" for r in rows}
if not want:
    sys.exit("gate: no ACDB cal asset rows -- cannot state the expected delta slots")
txt = open(sys.argv[1], encoding="utf-8", errors="replace").read()
absent = "No such file or directory" in txt
have = {}
for ln in txt.splitlines():
    p = ln.split()
    if not ln.startswith("-") or len(p) < 5:
        continue
    # this device's ls prints mode owner group SIZE date time name (no link column), stock ls prints
    # an extra column -- anchor on the date token instead of a fixed index
    di = [i for i, x in enumerate(p) if re.fullmatch(r"\d{4}-\d\d-\d\d", x)]
    if not di:
        continue
    have[p[-1]] = int(p[di[0] - 1])
if not have:
    if absent:
        sys.exit("FAIL: no delta directory on this machine -- either the ACDB driver never created "
                 "it or the cal files were never opened; that is a different state from §274's seven "
                 "empty slots, so the port must not assume the shipped bytes are what plays")
    sys.exit("NO-ANSWER: the delta capture has no parsable file lines (column shape changed?) -- "
             "this is a broken ruler, not an empty delta directory. First lines: "
             + " | ".join(txt.splitlines()[:3]))
print(f"delta slots: {len(have)} present, max size {max(have.values())} bytes")
bad = 0
for f in sorted(want):
    if f not in have:
        print(f"  ABSENT  {f}"); bad += 1
    elif have[f] != 0:
        print(f"  OVERLAY {f} = {have[f]} bytes -- the shipped .acdb is being patched"); bad += 1
    else:
        print(f"  clean   {f} = 0")
extra = sorted(set(have) - want)
if extra:
    print(f"  (unexpected slot names: {', '.join(extra)})")
if bad:
    sys.exit(f"FAIL: {bad} delta slot(s) off the clean state")
print(f"all {len(want)} slots exist and are empty -- the calibration in use IS the shipped bytes, "
      f"and the bare names narrow the loaded set to the vivo dirs (PD1610/PD1610LG4/PD1516A)")
PY
    rc2=$?
    # --- landing-scoped content check (ledger 275): the arm above only proves "some directory holds
    # the baseline bytes"; this one asks whether THE DIRECTORY THE LOADER LANDS ON does, which is the
    # claim the port actually needs (a corrupt file that a sibling dir masks reads as clean up there).
    if [ -n "${DIRCAP:-}" ]; then
        [ -f "$DIRCAP" ] || { echo "acdb: DIRCAP=$DIRCAP missing"; exit 2; }
        DIRCAP_OURS=""
    else
        DIRCAP=/tmp/portcheck-dircap.$$
        DIRCAP_OURS=1
        run_acdbdir > "$DIRCAP"
        grep -q ACDBDIR_DONE "$DIRCAP" || { echo "acdb: acdbdir.sh never reported done"; rc3=2; }
    fi
    if [ "${rc3:-0}" -eq 0 ]; then
        # tee keeps the section in the timestamped capture AND in one stable path the port table cites;
        # pipefail makes rc3 the python's status, not tee's. A fixture-driven run (DIRCAP= from env)
        # must NOT overwrite the stable artifact, or a fake would masquerade as a live capture.
        # Measured cost of not having this (ledger 587): running this section against the
        # 7.1.1 phone rewrote the 6.0.1 baseline artifact with "the copy IN USE differs from 6.0.1",
        # which is a true statement about the OTHER machine and destroyed the evidence step 5b cites.
        # The stable path therefore only moves with an explicit COMMIT_CAPTURE=1, same convention as
        # the reach section; otherwise the verdict lands in /tmp and says so.
        STABLE="$ROOT/art/audio-6.0.1/live/acdb-landing-verify.txt"
        if [ "${COMMIT_CAPTURE:-0}" != 1 ]; then
            STABLE=/tmp/acdb-landing-verify.$$.txt
            echo "acdb: landing verdict NOT committed to the baseline (COMMIT_CAPTURE=1 to replace it) -> $STABLE"
        fi
        if [ -n "$DIRCAP_OURS" ]; then
            python3 "$ROOT/tools/acdb_landing.py" --verify "$OUT" \
                "$ROOT/art/audio-6.0.1/acdb-meta.PD1610.tsv" "$DIRCAP" \
                | tee -a "$OUT" | tee "$STABLE" 
        else
            python3 "$ROOT/tools/acdb_landing.py" --verify "$OUT" \
                "$ROOT/art/audio-6.0.1/acdb-meta.PD1610.tsv" "$DIRCAP" | tee -a "$OUT"
        fi
        rc3=$?
    fi
    [ -z "$DELTA_OURS" ] || rm -f "$DELTA"
    [ -z "$DIRCAP_OURS" ] || rm -f "$DIRCAP"
    if [ "$rc1" -ne 0 ] || [ "$rc2" -ne 0 ] || [ "$rc3" -ne 0 ]; then
        echo "acdb: content rc=$rc1, delta rc=$rc2, landing rc=$rc3"
        exit 1
    fi
    exit 0
fi

# dir mode: replay the loader's own directory cascade on this machine and judge it against the
# 6.0.1 table (ledger 273).  Read-only -- tools/acdbdir.sh only runs getprop/cat/ls; ONE
# implementation is ferried rather than re-typed here, the way pa-samples ferries tfasnap.sh.
if [ "$MODE" = dir ]; then
    if [ -n "${CAPTURE:-}" ]; then
        # comparator-only: judge an existing capture instead of a live device (used by the
        # negative control below in the ledger; never fabricates a device answer)
        [ -f "$CAPTURE" ] || { echo "dir: CAPTURE=$CAPTURE missing"; exit 2; }
        OUT=$CAPTURE
    else
        RES=$(run_acdbdir)
        echo "$RES" | grep -q 'ACDBDIR_DONE' ||
            { echo "dir: acdbdir.sh never reported done: $RES"; exit 1; }
        echo "$RES" > "$OUT"
    fi
    python3 - "$OUT" "$TABLE" "$ROOT/tools" <<'PY'
import csv, os, re, sys
sys.path.insert(0, sys.argv[3])
import acdb_landing
live = open(sys.argv[1]).read()
rows = list(csv.DictReader(open(sys.argv[2], encoding="utf-8"), delimiter="\t"))
base_rows = [r for r in rows if r["layer"] == "ACDB cal asset"]
if not base_rows:
    sys.exit("gate: table has no ACDB cal asset rows -- nothing to compare a directory against")
bdir = os.path.dirname(base_rows[0]["item"])
want = {os.path.basename(r["item"]) for r in base_rows}
if len(want) != len(base_rows):
    sys.exit("gate: duplicate file names in the table rows")
m = re.search(r"ACDBDIR inputs model=(\S*) platform=(\S*) hw_platform=(\S*) node=(\S+)"
              r"(?: device=(\S*))?", live)
if not m:
    sys.exit("gate: capture has no 'ACDBDIR inputs' line")
model, platform, hw, node, device = m.group(1, 2, 3, 4, 5)
print(f"loader inputs: ro.vivo.product.model={model!r} ro.vivo.product.platform={platform!r} "
      f"hw_platform({node})={hw!r}   (ro.product.device={device!r} is not read by the loader)")
ncal = len(re.findall(r"ACDBDIR calfile\d+=", live))
now = {"ro.vivo.product.model": model, "ro.vivo.product.platform": platform, node: hw,
       "ro.product.device": device if device is not None else "not captured",
       "persist.audio.calfile0..19": f"{ncal} of 20 slots set"}
for r in rows:
    if r["layer"] != "ACDB dir selection":
        continue
    if r["item"] not in now:
        print(f"  SKIP    {r['item']:31s} this capture does not read it")
        continue
    a, val = now[r["item"]], r["value"]
    # the calfile row is count-shaped: the baseline may also list names, so compare the numbers
    same = (re.match(r"\d+", a).group() == re.match(r"\d+", val).group()
            if r["item"].startswith("persist.") else a.strip() == val.strip())
    print(f"  {'same    ' if same else 'differs '} {r['item']:31s} 6.0.1={val:22s} this machine={a}"
          + ("" if same else "   <- diagnostic only, see the landing line"))
r_land = acdb_landing.landing(live)
if not r_land["chosen"]:
    sys.exit("FAIL: the cascade finds no directory under " + " or ".join(acdb_landing.BASES) +
             " -- the loader would log 'No .acdb files found' and ADSP runs on its own defaults")
path, n, src = r_land["chosen"]          # ONE implementation of the ordering, shared with acdb mode
print(f"cascade lands on {path} (resolves to {r_land['chosen_real']}, matched via {src}), "
      f"{n} *.acdb inside")
for b, lst in sorted(r_land["cascade"].items()):
    if b != r_land["base"] and lst:
        print(f"  NOTE  {b} also holds {', '.join(x[0].rsplit('/', 1)[-1] for x in lst)} -- the loader "
              f"does not use that base, but a port that changes the base string would")
if os.path.basename(path.rstrip("/")) != os.path.basename(bdir):
    # this is the assertion the port actually needs: a DIFFER on an input property is only news
    # when it moves the landing directory (platform may differ forever and change nothing)
    sys.exit(f"FAIL: lands on {os.path.basename(path.rstrip('/'))} but the baseline set is "
             f"{os.path.basename(bdir)} -- the ADSP would be running a different calibration")
if int(n) != len(want):
    print(f"FAIL: file COUNT differs from the 6.0.1 set (table {len(want)}, device {n})")
    sys.exit(1)
print(f"count matches the 6.0.1 set ({len(want)} files); run 'tools/port_check.sh acdb' to compare "
      f"them by content")
PY
    exit $?
fi

# reach mode: is the ACDB WRITE channel actually resident on this machine? (ledger 278)
# libacdbloader opens /dev/msm_audio_cal and brings up acph+FTS (ledger 276/277), so the question is
# whether ONE process holds all three ends: the ACDB libraries, the calibration node, and the diag
# transport. Read-only -- tools/acdb_reach.sh only runs cat/ls/grep/readlink.
if [ "$MODE" = reach ]; then
    if [ -n "${REACHCAP:-}" ]; then
        [ -f "$REACHCAP" ] || { echo "reach: REACHCAP=$REACHCAP missing"; exit 2; }
    else
        $ADB push "$ROOT/tools/acdb_reach.sh" /data/local/tmp/acdb_reach.sh >/dev/null 2>&1 ||
            { echo "reach: cannot push tools/acdb_reach.sh"; exit 2; }
        RES=$($ADB exec-out "$SU -c 'sh /data/local/tmp/acdb_reach.sh'" 2>/dev/null | tr -d '\r')
        echo "$RES" | grep -q 'REACH_DONE' ||
            { echo "reach: acdb_reach.sh never reported done: $RES"; exit 1; }
        echo "$RES" > "$OUT"
        REACHCAP=$OUT
        # the baseline capture is NOT overwritten by a check run: the same command pointed at the
        # Android 7 side would silently replace the 6.0.1 reference with 7's answer.  Committing a new
        # capture is a deliberate, separate act.
        if [ "${COMMIT_CAPTURE:-0}" = 1 ]; then
            cp "$OUT" "$ROOT/art/audio-6.0.1/live/acdb-reach.txt"
            echo "reach: COMMIT_CAPTURE=1 -> baseline replaced by $OUT"
        else
            echo "reach: fresh capture kept at $OUT (baseline untouched; COMMIT_CAPTURE=1 to replace it)"
        fi
    fi
    python3 - "$REACHCAP" "$TABLE" <<'PY'
import csv, re, sys
txt = open(sys.argv[1], encoding="utf-8", errors="replace").read()
maps = re.findall(r"REACH maps pid=(\d+) comm=(\S+) hal_loaded=(\d+) diag_mapped=(\d+) ctx=(\S+) libs=(\S*)", txt)
readers = re.findall(r"REACH diagreader pid=(\d+) tid=(\d+) comm=(\S+) wchan=(\S+)", txt)
cal = re.findall(r"REACH fd pid=(\d+) comm=(\S+) link=/dev/(msm_audio_cal|msm_acdb|audio_acdb)\b", txt)
diag = re.findall(r"REACH fd pid=(\d+) comm=(\S+) link=/dev/diag\b", txt)
node = re.findall(r"REACH node (\S+) (\S+)", txt)
if "REACH_DONE" not in txt:
    print("NO-ANSWER: the capture has no REACH_DONE marker -- the probe was truncated, so absent "
          "lines below are the cut, not the machine")
    sys.exit(1)
if not maps:
    sys.exit("NO-ANSWER: no REACH maps line -- the probe did not run or root could not read /proc; "
             "this is not evidence that nothing maps the libraries")
holders = {int(p) for p, _c, _l, _g, _x, _libs in maps}
withdiag = {int(p) for p, _c, _l, g, _x, _libs in maps if int(g) > 0}
readerpids = {int(p) for p, _t, _c, _w in readers}
calpids = {int(p) for p, _c, _n in cal}
diagpids = {int(p) for p, _c in diag}
print(f"ACDB-library hosts: {[(p, c, x) for p, c, _l, _g, x, _libs in maps]}")
print(f"/dev nodes: {', '.join(n for n, _m in node) or 'none listed'}")
print(f"calibration-node holders: {sorted(calpids) or 'NONE'}   diag holders: {len(diagpids)} process(es)"
      f"   diagchar_read threads: {len(readerpids)}")
rows = [r for r in csv.DictReader(open(sys.argv[2], encoding="utf-8"), delimiter="\t")
        if r["layer"] == "ACDB write reachability"]
bad = []
if not calpids:
    bad.append("nothing holds /dev/msm_audio_cal -- the write path cannot reach the kernel, so the "
               "baseline statement 'the channel is resident' would be false")
if not (holders & calpids):
    bad.append("the process holding the calibration node does NOT map the ACDB libraries")
if not (holders & diagpids):
    bad.append("no ACDB-library host holds /dev/diag -- the external peer would have no transport "
               "inside the process that registers the FTS file handler")
if not (holders & withdiag & readerpids):
    bad.append("no ACDB-library host both maps libdiag and has a thread blocked in diagchar_read -- "
               "the ATP table would have no reader it could be reached from")
for b in bad:
    print("FAIL:", b)
if bad:
    sys.exit(1)
print("chain resident in ONE process: ACDB libs + libdiag + a diagchar_read thread + /dev/diag + "
      "/dev/msm_audio_cal. libaudcal registers its ATP table with libdiag (imports diagpkt_tbl_reg / "
      "diagpkt_subsys_alloc / Diag_LSM_Init, and libdiag.so defines them), so the middle hop is a "
      "REGISTERED CALLBACK -- which is why no static call site to atp_receive_atp_frame exists: that "
      "zero is now explained, not a blind spot")
print("NOT demonstrated: no DIAG packet was ever sent (an actuation needing consent); wired != triggered")
if rows:
    print(f"(table row for this state exists: {rows[0]['item']})")
PY
    exit $?
fi

# container mode: prove the .cnt on this firmware carries the same DSP blocks as the 6.0.1 baseline.
# read-only against the device; the only write is a copy of the .cnt into /data/local/tmp (scratch).
if [ "$MODE" = container ]; then
    DT=/sys/firmware/devicetree/base/soc/i2c@75b6000/spkamp@34/vivo,tfa98xx-config
    # su on this device appends an exit marker to stdout, so grab only the shapes we expect
    CNT=$($ADB exec-out "$SU -c 'cat $DT'" 2>/dev/null | grep -aoE '[A-Za-z0-9._-]+\.cnt' | head -1)
    [ -n "$CNT" ] || { echo "container: cannot read $DT (is the tfa98xx node still at i2c@75b6000/spkamp@34?)"; exit 2; }
    echo "container: DT names the config as $CNT"
    FOUND=""
    for p in /system/etc /system/etc/firmware /vendor/firmware /vendor/etc; do
        if [ "$($ADB exec-out "$SU -c 'test -f $p/$CNT && echo FOUND'" 2>/dev/null | grep -ao FOUND)" = FOUND ]; then FOUND="$p/$CNT"; break; fi
    done
    [ -n "$FOUND" ] || { echo "container: $CNT not found under /system/etc, /system/etc/firmware, /vendor/firmware, /vendor/etc"; exit 2; }
    $ADB exec-out "$SU -c 'cat $FOUND'" > "$OUT" 2>/dev/null
    [ -s "$OUT" ] || { echo "container: pulled 0 bytes from $FOUND"; exit 2; }
    # exec-out can still fold LF->CRLF through su, which silently grows the file. Size must match the
    # device's own byte count or the difference is transport, not firmware -- never report that as a
    # content mismatch.
    DEVSIZE=$(sh_on "wc -c < $FOUND" | grep -aoE '^[0-9]+' | head -1)
    GOTSIZE=$(wc -c < "$OUT")
    if [ "$DEVSIZE" != "$GOTSIZE" ]; then
        echo "container: TRANSPORT SUSPECT -- device says $DEVSIZE bytes, cat pipe delivered $GOTSIZE (CRLF folding?)"
        echo "           re-pulling via adb pull (binary-safe)"
        $ADB exec-out "$SU -c 'cp $FOUND /data/local/tmp/pull.bin; chmod 644 /data/local/tmp/pull.bin'" >/dev/null 2>&1
        $ADB pull /data/local/tmp/pull.bin "$OUT" >/dev/null 2>&1
        $ADB exec-out "$SU -c 'rm -f /data/local/tmp/pull.bin'" >/dev/null 2>&1
        GOTSIZE=$(wc -c < "$OUT")
        [ "$DEVSIZE" = "$GOTSIZE" ] || { echo "container: still $GOTSIZE != $DEVSIZE after pull; aborting rather than mis-attribute"; exit 3; }
        echo "container: pulled $FOUND ($GOTSIZE bytes) -> $OUT via adb pull"
    else
        echo "container: pulled $FOUND ($GOTSIZE bytes, matches device count) -> $OUT"
    fi
    python3 "$ROOT/tools/cnt_compare.py" "$OUT" --cnt-name "$CNT"
    exit $?
fi

# pa-samples mode: re-take the multi-sample PA capture that the STABLE/cross-session/volatile
# classification consumes (ledger 260).  That baseline came from an ad-hoc loop, so nothing in the
# toolkit could re-produce it on another firmware -- which is exactly what the 6 -> 7 comparison needs.
# pa-samples mode: re-take the multi-sample PA capture that the register classification consumes
# (ledger 260/269).  The capture itself is tools/tfasnap.sh -- ONE implementation; this mode only
# ferries it to the device, runs it, and copies the result back with line-count checks.  An earlier
# version of this mode re-implemented the loop here, which silently changed the witness format
# (tfasnap.sh asks tinymix per name; a grep over the full dump gives different lines) -- same
# two-implementations drift this ledger keeps recording for other tools.
if [ "$MODE" = pa-samples ]; then
    N=${SAMPLES:-3}
    DEV=/data/local/tmp/tfasnap-live.txt
    $ADB push "$ROOT/tools/tfasnap.sh" /data/local/tmp/tfasnap.sh >/dev/null 2>&1 ||
        { echo "pa-samples: cannot push tools/tfasnap.sh"; exit 2; }
    DONE=$($ADB exec-out "$SU -c 'rm -f $DEV; OUT=$DEV sh /data/local/tmp/tfasnap.sh $N ${GAP:-700}'" 2>/dev/null | tr -d '\r')
    echo "$DONE" | grep -q 'TFASNAP_DONE' || { echo "pa-samples: tfasnap.sh never reported done: $DONE"; exit 1; }
    DEVNL=$($ADB exec-out "$SU -c 'wc -l $DEV'" 2>/dev/null | tr -d '\r' | awk '{print $1}')
    $ADB exec-out "$SU -c 'cat $DEV'" > "$OUT" 2>/dev/null
    $ADB exec-out "$SU -c 'rm -f $DEV /data/local/tmp/tfasnap.sh'" >/dev/null 2>&1
    NS=$(grep -c '===== sample' "$OUT")
    NR=$(grep -c '^reg{' "$OUT")
    LOCALNL=$(wc -l < "$OUT")
    echo "pa-samples: $NS samples, $NR reg lines, $LOCALNL local lines vs $DEVNL on device -> $OUT"
    [ "$NS" = "$N" ] || { echo "pa-samples: wanted $N samples, got $NS"; exit 1; }
    [ "$NR" -ge $((N*26)) ] || { echo "pa-samples: expected >= $((N*26)) reg lines (26-register whitelist per sample), got $NR"; exit 1; }
    [ "$DEVNL" = "$LOCALNL" ] || { echo "pa-samples: line count changed in transit ($DEVNL -> $LOCALNL); do not classify from this file"; exit 1; }
    exit 0
fi


if [ -n "${CAPTURE:-}" ]; then
    # judge an existing capture instead of a live machine (that is how the PA precondition below is
    # red-tested). Refuses anything that is not a real port_check capture, so a fixture can never
    # masquerade as a machine answer.
    [ -f "$CAPTURE" ] || { echo "CAPTURE=$CAPTURE not a file"; exit 2; }
    for need in "## tfa98xx/codec_reg" "## es9038/reg" "## controls"; do
        grep -q "^$need" "$CAPTURE" || { echo "CAPTURE lacks the $need section -- not a port_check capture"; exit 2; }
    done
    cp "$CAPTURE" "$OUT"
else
PA_RAW=$(sh_on 'cat /sys/kernel/debug/tfa98xx/codec_reg')
DAC_RAW=$(sh_on 'cat /sys/kernel/debug/es9038/reg')
# control names travel as a file: they contain spaces and nested adb/su quoting shatters them
$ADB push "$ROOT/tools/ctlread.sh" /data/local/tmp/ctlread.sh >/dev/null 2>&1
CTL_RAW=$(sh_on 'sh /data/local/tmp/ctlread.sh')

{
	echo "# port_check mode=$MODE table=$TABLE"
	echo "## tfa98xx/codec_reg"
	echo "$PA_RAW"
	echo "## es9038/reg"
	echo "$DAC_RAW"
	echo "## controls"
	printf '%s' "$CTL_RAW"
} > "$OUT"
fi

if [ "$MODE" = snapshot ]; then
	echo "snapshot -> $OUT"
	exit 0
fi

python3 - "$TABLE" "$OUT" <<'PY'
import csv, re, sys
table, snap = sys.argv[1], sys.argv[2]
txt = open(snap, encoding="utf-8", errors="replace").read()


def regs_in(sec):
    """reg{%x}:%x lines from ONE section only.  Both chips print the same shape and the ES9038's
    addresses (0x00-0x2e) are a subset of the TFA9890's, so parsing the whole file lets 47 DAC bytes
    overwrite 12 PA registers -- that is what produced the bogus '8 PA rows differ' reading of
    ledger 282, later traced to a wrong precondition instead of to this line (ledger 285).
    The DAC file also prints one fixed chip-id line as reg{0x60}, hence the optional 0x."""
    return {int(a, 16): int(v, 16)
            for a, v in re.findall(r"reg\{(?:0x)?([0-9a-f]+)\}:([0-9a-f]+)", sec)}


for need in ("## tfa98xx/codec_reg", "## es9038/reg", "## controls"):
    if need not in txt:
        sys.exit(f"NO-ANSWER: the capture has no {need} section -- refusing to guess which chip a "
                 "register line came from")
pa_sec = txt.split("## tfa98xx/codec_reg")[1].split("## es9038/reg")[0]
dac_sec = txt.split("## es9038/reg")[1].split("## controls")[0]
ctl_src = txt.split("## controls")[1]
pa, dac = regs_in(pa_sec), regs_in(dac_sec)
dac_off = not dac and "is off" in dac_sec
rows = list(csv.DictReader(open(table, encoding="utf-8"), delimiter="\t"))
ctl = {}
names = [r["item"] for r in rows if r["layer"] == "ALSA control"]
for ln in ctl_src.splitlines():
    for nm in names:
        if nm in ln and nm not in ctl:
            ctl[nm] = ln.split(nm, 1)[1].strip()
# expected counts come from the table, which is itself gated at build time against the binaries
# (PA 26 from tfa98xx_regs, DAC from dac_parameters) -- a second hardcoded copy here is how a gate
# and its baseline end up judging different denominators
exp = {}
for r in rows:
    if r["layer"] in ("PA/TFA9890", "DAC/ES9038", "ALSA control"):
        exp[r["layer"]] = exp.get(r["layer"], 0) + 1
got = {k: 0 for k in exp}
bad = []
# ALSA rows flagged WITNESS record WHICH route the capture was taken on.  They are not compared
# against a live value -- but they no longer gate the PA layer either: measured across the amp-off
# and amp-on captures, all 18 STABLE PA registers are identical (ledger 285), so an excusal here
# would only ever hide a real difference.
wit = [r for r in rows if r["layer"] == "ALSA control" and r["use_case"].startswith("WITNESS")]
pa_rows = skipped = wit_seen = 0
for r in rows:
    layer, item = r["layer"], r["item"]
    if layer not in exp:
        continue
    want = r["value"]
    if layer == "PA/TFA9890":
        a = int(item.split()[-1], 16)
        cand = [int(x, 16) for x in re.findall(r"(?:idle|play)=([0-9a-f]+)", want)]
        got[layer] += a in pa
        if a in pa:
            pa_rows += 1
            if r["use_case"] != "STABLE":
                skipped += 1
        if a in pa and cand and r["use_case"] == "STABLE" and pa[a] not in cand:
            bad.append(f"PA {item}: live={pa[a]:#06x} table idle/play={[hex(c) for c in cand]}")
    elif layer == "DAC/ES9038":
        a = int(item.split()[-1], 16)
        got[layer] += a in dac
        if a in dac and dac[a] != int(re.search(r"([0-9a-f]+) ", want).group(1), 16):
            bad.append(f"DAC {item}: live={dac[a]:#04x} table={want.split()[0]}")
    else:
        got[layer] += item in ctl
        # three route columns, and the values can contain spaces (Playback Channel Map0 lists eight
        # channels), so each is read up to the next " key=" anchor instead of by a word split
        cands = [c.strip() for c in
                 re.findall(r"(?:idle|play|speaker)=(.*?)(?=\s+(?:idle|play|speaker)=|$)", want)]
        if r["use_case"].startswith("WITNESS"):
            wit_seen += 1        # records the route this capture was taken on; never compared
        elif item in ctl and cands and ctl[item].strip() not in cands:  # controls: any recorded route is fine
            bad.append(f"CTL {item}: live={ctl[item]!r} table idle/play/speaker={cands}")
print("layer          got  expected  state")
ok = True
for k, n in exp.items():
    if k == "DAC/ES9038" and dac_off:
        print(f"{k:14} {got[k]:3}  {n:3}       UNAVAILABLE (dac powered off - §235; play through headphones to read it)")
        continue
    s = "OK" if got[k] == n else "SHORT"
    ok = ok and got[k] == n
    print(f"{k:14} {got[k]:3}  {n:3}       {s}")
print("\nPA rows not equality-enforced (class != STABLE):", skipped,
      "of", pa_rows)
print("ALSA witness rows read (route record only; PA equality is enforced in every route -- the "
      "18 STABLE registers do not move with SmartPA Switch, §285):", wit_seen, "of", len(wit))
for w in wit:
    print("   ", w["item"], "=", (ctl.get(w["item"]) or "NOT CAPTURED").strip())
print("mismatches vs the 6.0.1 table:", len(bad))
for b in bad[:15]:
    print("  ", b)
print("\nVERDICT:", "table fully reproducible on this machine" if ok and not bad else "see above")
sys.exit(0 if (ok and not bad) else 1)   # a content mismatch must fail the gate, not just print
PY
RC_TABLE=$?

# the PA acceptance windows live in the board device tree; a property missing on the next firmware
# silently swaps in a compiled default (ledger 258), so it is checked as its own layer.
echo
if [ -n "${SKIP_DT:-}" ]; then
    # tools/port_check_neg.py asserts on the table half only, so it must not spend five device
    # round-trips per run -- but the skip is announced, never silent.
    echo "== device-tree acceptance windows: SKIPPED (SKIP_DT set; this run judges the table half only)"
    RC_DT=0
else
    echo "== device-tree acceptance windows =="
    python3 "$ROOT/tools/dt_check.py"
    RC_DT=$?
fi

[ "$MODE" = check ] && echo && echo "exit codes: table=$RC_TABLE device-tree=$RC_DT"
[ "$RC_TABLE" -eq 0 ] && [ "$RC_DT" -eq 0 ]
