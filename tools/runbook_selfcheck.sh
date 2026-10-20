#!/usr/bin/env bash
# SU names the privileged-exec client.  The official 7.1.1 firmware refuses execve of any path # whose last component is exactly "su" (ledger 579), so on that machine run these tools with SU=sux.
SU=${SU:-su}
# tools/runbook_selfcheck.sh -- run the A-section of art/PORT-RUNBOOK-7.md against THIS machine.
#
# Why (ledger 360): the runbook is the deliverable, and §280/§349 each caught a step that could not
# actually be run (a positional argument that was not one, a judgement that named an arm of a tool that
# did not exist). Every check so far was one step at a time, by hand, when I happened to think of it.
# This script runs every step that has a 6.0.1-side form, reports the exit code against the expected
# one, and lists the rest with the specific input it is waiting for -- so "the procedure is executable"
# is something a reader can re-check in one command instead of something I assert.
#
# Nothing here writes into art/: outputs go under $WORK (default /tmp/runbook-selfcheck). Device steps
# are read-only and need `--device` (without it they are DEFERRED with the reason). Exit code is the
# number of steps that misbehaved, so CI can read it.
set -uo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD
WORK=${WORK:-/tmp/runbook-selfcheck}
mkdir -p "$WORK"
DEVICE=0
HAVE_DEV=0
# newest capture that the judge can actually use: §285 split the sections, §346 counted only 69 of 140
# portcheck files carrying all 26 PA registers -- so "newest by mtime" is NOT "judgable" and picking it
# made step 4 report "CAPTURE lacks the ## tfa98xx/codec_reg section" (this self-check caught that about
# itself on its first run)
CAPTURE=""
for f in $(ls -t art/audio-6.0.1/live/portcheck-*.txt 2>/dev/null); do
  n=$(sed -n '/^## tfa98xx\/codec_reg/,/^## /p' "$f" 2>/dev/null | grep -c '^reg{')
  if [ "$n" -ge 26 ]; then CAPTURE=$f; break; fi
done
[ $# -gt 0 ] && [ "$1" = "--device" ] && DEVICE=1
[ -n "${SKIP_DT:-}" ] || SKIP_DT=1
export SKIP_DT

fails=0
ANN=""
# coverage denominator: the step labels the runbook's A-table actually contains.  The first full run of
# this script printed "0 step(s) misbehaved" while silently never announcing step 5 -- a green that was
# missing a row (ledger 361), so the set of runbook labels is now part of the exit code.
WANT=$(python3 - <<'PY'
import re
src = open("art/PORT-RUNBOOK-7.md", encoding="utf-8").read()
if "## A." not in src or "## B." not in src:
    print("__PARSE_FAIL__")
    raise SystemExit
seg = src.split("## A.", 1)[1].split("## B.", 1)[0]
seen = []
for ln in seg.splitlines():
    if not ln.startswith("|"):
        continue
    c = [x.strip() for x in ln.split("|")]
    if len(c) > 2 and re.fullmatch(r"[0-9]+[a-z]?", c[1]) and c[1] not in seen:
        seen.append(c[1])
print(" ".join(seen))
PY
)
if [ "$WANT" = "__PARSE_FAIL__" ]; then
  echo "coverage: cannot find the A-table between '## A.' and '## B.' -- refusing to claim completeness"
  fails=$((fails + 1))
  WANT=""
fi

run() {   # run <step> <expected-rc> <cmd...>
  local step=$1 want=$2; shift 2
  local out rc
  out=$("$@" 2>&1); rc=$?
  local line; line=$(printf '%s' "$out" | tail -1 | cut -c1-96)
  ANN="$ANN $step"
  if [ "$rc" = "$want" ]; then
    printf '  ok    %-4s rc=%s (want %s)  %s\n' "$step" "$rc" "$want" "$line"
  else
    printf '  FAIL  %-4s rc=%s (want %s)  %s\n' "$step" "$rc" "$want" "$line"
    fails=$((fails + 1))
  fi
}
defer() { ANN="$ANN $1"; printf '  defer %-4s waiting for: %s\n' "$1" "$2"; }

[ -n "$CAPTURE" ] || { echo "no portcheck capture to judge -- nothing can be verified offline"; exit 1; }

echo "runbook self-check against 6.0.1 (work dir $WORK, capture $(basename "$CAPTURE"))"

# --- judgement steps that read only the shipped artifacts -------------------------------
run 4b  0 python3 tools/port_check_neg.py
run 5b  0 python3 tools/port_manifest.py
run 5t  0 python3 tools/tfa_field_history.py --selftest --out "$WORK/fh.tsv"
run 5u  0 python3 tools/tfa_field_family_docs.py --selftest --out "$WORK/ff.tsv"
run 5v  0 python3 tools/dt_prop_reads.py --selftest --out "$WORK/hdr.tsv"
# 5v's second command (the flag-bit face) -- same step, so the coverage denominator stays 40
run 5v  0 python3 tools/dt_prop_reads.py --bits --selftest --out "$WORK/flags-bit.tsv"
run 5q  0 python3 tools/dac_slot_filler.py --disps 0x8,0x60,0x68,0x98,0xa0 \
        --at 0xffffffc001b242c0,0xffffffc001b242c8,0xffffffc001b242d4,0xffffffc001b24368 \
        --selftest --out "$WORK/slots.tsv"
run 5r  0 python3 tools/dac_hifi_mode_enum.py --selftest --out "$WORK/hme.tsv"
run 5m  0 python3 tools/dac_dt_params_consumer.py --selftest --out "$WORK/dtc.tsv"
run 5n  0 python3 tools/dac_register_writers.py --out "$WORK/w.tsv"
run 5k  0 python3 tools/dapm_event_flags.py --out "$WORK/ev.tsv" --selftest
run 5j  0 python3 tools/tfa_bf_table.py --tsv "$WORK/tfa-bf.tsv"
run 5h  0 python3 tools/dapm_route_selectors.py --out "$WORK/sel.tsv"
run 5s  0 python3 tools/dac_slot_filler.py --disps 0x0 \
        --at 0xffffffc001b1dd10,0xffffffc001b1dd18,0xffffffc00179b170 --allow-absent \
        --selftest --out "$WORK/slot0.tsv"
run 5w  0 python3 tools/pa_session_check.py --selftest
run 5w  0 python3 tools/pa_session_check.py "$ROOT/art/audio-6.0.1/live/pa-samples-20261017-0732-ampoff.txt"
# step 5x's offline half: the HP one-byte knob's decision table, its transports and the text it
# actually prints are all judged here.  The half that touches the phone needs a transport this
# self-check deliberately does not own (see the 7-side defer below).
run 5x  0 python3 tools/hp_gain7.py --selftest
# step 8's offline half: the pure logic (translation search, RAM gate, pairs decode) is judged by arms
# that must be able to reject -- the live half runs below only with a device
run 8   0 python3 tools/devmem_read.py --selftest
# step 9: the surface-coverage ruler (offline arms always; the device sweep only with a phone)
run 9   0 python3 tools/surface_coverage.py --selftest
# step 10 (ledger 388): the loader's compiled-in allocation plan.  Offline by nature -- it reads the
# two shipped .so, not the phone.  --selftest proves the decode gates fire; --check-tsv proves the
# committed artifact still regenerates byte-identical (generate and check are separate paths).
run 10  0 python3 tools/loader_memplan.py --selftest
run 10  0 python3 tools/loader_memplan.py --check-tsv art/audio-6.0.1/loader-memplan.PD1610.tsv
run 10  0 python3 tools/got_readers.py --selftest
run 10  0 python3 tools/arm32_readers.py --selftest
run 11  0 python3 tools/audio_cfg_files.py --selftest
run 11  0 python3 tools/audio_cfg_files.py
run 12  0 python3 tools/audio_hal_surface.py --selftest
run 12  0 python3 tools/audio_hal_surface.py --check-tsv art/audio-6.0.1/hal-surface.PD1610.tsv
run 13  0 python3 tools/shipped_disposition.py --selftest
run 13  0 python3 tools/shipped_disposition.py

# --- the register-layer acceptance judgement, run offline against the captured baseline --
run 4   0 env CAPTURE="$CAPTURE" bash tools/port_check.sh check
# step 5's offline half.  argv[1] IS the output path, so it goes to $WORK: run against the baseline
# path it would overwrite the 6.0.1 table that 7 is supposed to be compared WITH (ledger 361).
run 5   0 python3 tools/tfa_reg_decode.py "$WORK/tfa-regs.tsv"
if [ "$DEVICE" = 1 ] && adb get-state >/dev/null 2>&1; then HAVE_DEV=1; fi
if [ "$HAVE_DEV" = 1 ]; then
run 1   0 bash tools/port_check.sh dir
run 2   0 bash tools/port_check.sh acdb
run 3   0 bash tools/port_check.sh reach
run 6   0 bash tools/port_check.sh container
# the live-RAM census: on 6.0.1 it answers "no door" (ENXIO, CONFIG_DEVMEM off); on 7 the same line is
# what re-opens §E's payload-slot read, so it is part of the procedure, not a one-off note
run 8   0 python3 tools/devmem_read.py --probe
run 9   0 python3 tools/surface_coverage.py --device
run 13  0 bash tools/grab_config_literals.sh /tmp/config-literals-probe.tsv
run 13  0 python3 -c "import sys;sys.exit(0 if open('/tmp/config-literals-probe.tsv').read().count(chr(10))>10 else 'probe table too small')"
run 14  0 python3 tools/audiofx_surface.py --selftest
run 14  0 python3 tools/audiofx_surface.py
run 15  0 python3 tools/audio_log_surface.py --selftest
run 15  0 python3 tools/audio_log_surface.py
run 19  0 python3 tools/inplay_accept.py --selftest
run 19  0 python3 tools/inplay_accept.py --check "$ROOT/art/audio-6.0.1/live/inplay-spk-20261017-2012" --baseline "$ROOT/art/audio-6.0.1/live/inplay-hifion-20261017-1933" --baseline "$ROOT/art/audio-6.0.1/live/inplay-spk-20261017-2012"
run 19  0 python3 tools/inplay_accept.py --check "$ROOT/art/audio-6.0.1/live/inplay-hifion-20261017-1933" --baseline "$ROOT/art/audio-6.0.1/live/inplay-hifion-20261017-1933" --baseline "$ROOT/art/audio-6.0.1/live/inplay-spk-20261017-2012"
run 19  0 python3 tools/inplay_accept.py --check "$ROOT/art/audio-6.0.1/live/inplay-hifion2-20261017-2303" --baseline "$ROOT/art/audio-6.0.1/live/inplay-hifion2-20261017-2303" --baseline "$ROOT/art/audio-6.0.1/live/inplay-spk-20261017-2012"
run 20  0 python3 tools/inplay_accept.py --matrix-selftest
run 20  0 python3 tools/inplay_accept.py --matrix --check-matrix "$ROOT/art/audio-6.0.1/route-state-matrix.PD1610.tsv"
run 21  0 python3 tools/dsd_gate.py --selftest
run 21  0 python3 tools/dsd_gate.py
run 21  0 python3 tools/dsd_gate.py --elf art/audio-6.0.1/shipped/system/lib/libmediaplayerservice.so --mime
run 22  0 python3 tools/dsd_runtime_face.py --selftest
run 22  0 python3 tools/dsd_runtime_face.py --all
run 22  0 python3 tools/dsd_runtime_face.py --time
run 23  0 python3 tools/hifi_param_grammar.py --selftest
run 23  0 python3 tools/hifi_param_grammar.py
run 24  0 python3 tools/backend_bitwidth_chain.py --selftest
run 24  0 python3 tools/backend_bitwidth_chain.py
run 24  0 python3 tools/dsd_audible.py "$ROOT/art/audio-6.0.1/live/dsd-inplay-20261018-0646" --report
run 25  0 python3 tools/symbol_refs.py --selftest
run 25  0 python3 tools/symbol_refs.py
run 16  0 python3 tools/boot_narrative.py --selftest
run 16  0 python3 tools/boot_narrative.py
run 17  0 python3 tools/acdb_api_surface.py --selftest
run 17  0 python3 tools/acdb_api_surface.py
run 17  0 python3 tools/dsd_surface.py --selftest
run 17  0 python3 tools/dsd_surface.py
run 18  0 python3 tools/control_state_diff.py --selftest
run 26  0 python3 tools/dsd_mime_symbol.py --selftest
run 26  0 python3 tools/dsd_mime_symbol.py
run 27  0 python3 tools/dai_name_surface.py --selftest
run 27  0 python3 tools/dai_name_surface.py
run 28  0 python3 tools/arm32_str_refs.py --elf "$ROOT/art/audio-6.0.1/shipped/system/lib/libmediaplayerservice.so" --selftest
run 28  0 python3 tools/arm32_str_refs.py --elf "$ROOT/art/audio-6.0.1/shipped/system/lib/libmediaplayerservice.so" --find audio/dsd
run 29  0 python3 tools/pa_name_provenance.py --selftest
run 29  0 python3 tools/pa_name_provenance.py
run 30  0 python3 tools/arm32_str_refs.py --coverage "$ROOT/art/audio-6.0.1/shipped/system/lib"
run 30  0 python3 tools/arm32_exidx_survey.py --elf "$ROOT/art/audio-6.0.1/shipped/system/lib/libaudioflinger.so"
run 30  0 python3 tools/arm32_exidx_survey.py --selftest
run 30  0 python3 tools/arm32_exidx_survey.py --census "$ROOT/art/audio-6.0.1/shipped/system/lib"
run 30  0 python3 tools/arm32_exidx_survey.py --elf "$ROOT/art/audio-6.0.1/shipped/system/lib/libstagefright.so" --roads --needle audio/dsd
run 18  0 python3 tools/control_state_diff.py
else
  for s in 1 2 3 6; do defer $s "the phone (these subcommands read the device; step 4 runs offline via CAPTURE=)"; done
  defer 5 "the phone: SAMPLES=3 bash tools/port_check.sh pa-samples FILE, and FILE must become a new session under live/tfa98xx/ before the decode can see it"
fi

# --- steps whose 6.0.1 form needs a directory argument ---------------------------------
run 7b  0 python3 tools/acdb_cdot.py --selftest --dirs PD1610
run 7c  0 python3 tools/acdb_ofst.py --selftest --dirs PD1610
run 7d  0 python3 tools/acdb_cvd.py --selftest --dirs PD1610
run 7e  0 python3 tools/acdb_pool.py --selftest --dirs PD1610
run 7i  0 python3 tools/acdb_dprop.py --dirs PD1610 --out "$WORK/dprop.tsv" --selftest
run 7j  0 python3 tools/acdb_lut_sense.py --dirs PD1610 --out "$WORK/sense.tsv" --selftest

# --- steps that need the phone or the 7 side -------------------------------------------
if [ "$DEVICE" = 1 ] && adb exec-out "$SU -c 'test -f /data/local/tmp/hifidt.sh && echo yes'" 2>/dev/null |
   grep -q yes; then
  # step 0 rewrites live/hifi-dt-raw.txt.  It runs only when the ferry script is already on the device:
  # re-taking a published witness is a deliberate act (that is why the runbook lists it first), not a
  # side effect a self-check should cause -- and a self-check that failed because /data/local/tmp was
  # cleaned would print a red that says nothing about the procedure.
  run 0   0 adb exec-out "$SU -c 'sh /data/local/tmp/hifidt.sh'"
else
  defer 0 "--device AND /data/local/tmp/hifidt.sh on the device (step 0 re-takes live/hifi-dt-raw.txt; push tools/hifidt.sh first, then run step 0 by hand)"
fi
if [ "$DEVICE" = 1 ]; then
  run 5d  0 adb exec-out "$SU -c 'ls /sys/kernel/debug/asoc'"
  run 5o  0 python3 tools/dac_impedance_chain.py --selftest --out "$WORK/imp.tsv"
  run 5p  0 python3 tools/dac_impedance_chain.py --selftest --out "$WORK/imp2.tsv"
  if adb exec-out "$SU -c 'test -f /data/local/tmp/dacdtnode.sh && echo yes'" 2>/dev/null | grep -q yes; then
    run 5l  0 adb exec-out "$SU -c 'sh /data/local/tmp/dacdtnode.sh'"
  else
    defer 5l "--device AND /data/local/tmp/dacdtnode.sh on it (step 5l re-takes the DAC node dump; push tools/dacdtnode.sh first)"
  fi
else
  defer 5d  "--device: the DAPM widget file for codec:hifi-codec"
  defer 5l  "--device: dacdtnode.sh"
  defer 5o  "the impedance chain selftest is offline, but its stage 6/7 read DAC_LIVE captures"
  defer 5p  "stage 7 needs a live dmesg window (§287: the ring covers ~459 s)"
fi

# --- steps whose OTHER SIDE is Android 7: announced on every run, phone or not ------------------
# They used to live in the no-device branch, so a --device run announced nothing about them and the
# coverage gate printed its first real finding: MISSING 5c,5e,5f,5g,5i,7,7f,7g,7h.  A step waiting for
# the NEW firmware does not stop waiting because the phone came back.
defer 5e  "7 side: its debugfs_asoc dump; 6.0.1 form needs --expect against a live dump"
defer 5f  "7 side: kssym_dapm_counts selftest runs offline but the route table needs 7's Image"
defer 5g  "7 side: dapmsnap dump of its debugfs_asoc directory"
defer 5i  "7 side: needs 5g's --emit-all output first"
defer 5c  "7 side: its Image and the enable-path function names (§287: names differ per build)"
defer 5x  "7 side: --apply/--restore need the root channel (clobber, rounds=40).  --read needs only adb and was run by hand on this phone 2026-10-20 (rc=0, DT {4,3,1,1}); NO face reads the value back, so the effect face is A/B -- the runbook says so in step 5x"
defer 7   "7 side: libacdbloader.so pulled off the new image"
defer 7f  "the pool slot table is offline; --compare against 7 needs 7's directories"
defer 7g  "same: the module anchor table needs 7's directories"
defer 7h  "7 side: its calibration card, then the row-group comparison"
defer 7k  "7 side: its libacdbloader.so (BOTH vendor/lib and vendor/lib64); the three anchors must be re-taken from the strings first"

# --- steps 14..30: their selftests are offline, but the dispatcher had NO branch for them at all ----
# Added to the runbook by §414-§441 without touching this script, so the coverage gate fell to
# 47/64 and 17 labels went unannounced -- the same shape as §361's "0 misbehaved while never reading
# step 5", now caught by the gate that was built for it.  Every line below is the arm actually running.
run 14  0 python3 tools/audiofx_surface.py --selftest
run 15  0 python3 tools/audio_log_surface.py --selftest
run 16  0 python3 tools/boot_narrative.py --selftest
run 17  0 python3 tools/acdb_api_surface.py --selftest
run 18  0 python3 tools/control_state_diff.py --selftest
run 19  0 python3 tools/inplay_accept.py --selftest
# step 20's documented form (--matrix --selftest with no --out) refuses: the matrix is a deliverable.
run 20  0 python3 tools/inplay_accept.py --matrix --selftest --out "$WORK/matrix-self.tsv"
run 21  0 python3 tools/dsd_gate.py --selftest
run 22  0 python3 tools/dsd_runtime_face.py --selftest
run 23  0 python3 tools/hifi_param_grammar.py --selftest
run 24  0 python3 tools/backend_bitwidth_chain.py --selftest
run 25  0 python3 tools/symbol_refs.py --selftest
run 26  0 python3 tools/dsd_mime_symbol.py --selftest
run 27  0 python3 tools/dai_name_surface.py --selftest
run 28  0 python3 tools/arm32_str_refs.py --elf art/audio-6.0.1/shipped/system/lib/libmediaplayerservice.so --selftest
run 29  0 python3 tools/pa_name_provenance.py --selftest
run 30  0 python3 tools/arm32_exidx_survey.py --selftest

# --- the classification step 5 promises, judged off the tool's own output (an internal check, so it
# does not announce a step label: 5 is already announced above) -------------------------------
if [ -f "$WORK/tfa-regs.tsv" ]; then
  c5_rc=0
  c5=$(python3 - "$WORK/tfa-regs.tsv" "$ROOT/art/audio-6.0.1/tfa-regs.PD1610.tsv" <<'PY'
import csv, sys
new = list(csv.DictReader(open(sys.argv[1], encoding="utf-8"), delimiter="\t"))
base = list(csv.DictReader(open(sys.argv[2], encoding="utf-8"), delimiter="\t"))
if len(new) != len(base):
    sys.exit(f"gate: the self-check decoded {len(new)} registers, the baseline table holds {len(base)}")
bad = [(n["reg"], n["class"], b["class"]) for n, b in zip(new, base) if n["class"] != b["class"]]
prov = " ".join((r.get("provenance") or "") for r in new)
if "amp-on" not in prov:
    bad.append(("provenance", "no session labelled amp-on", "step 5 requires one"))
for reg, a, b in bad:
    print(f"   {reg}: self-check={a} baseline={b}")
sys.exit(1 if bad else 0)
PY
) || c5_rc=1
  if [ "$c5_rc" = 0 ]; then
    printf '  chk   5    the four-state classes and the amp-on provenance reproduce from the corpus\n'
  else
    printf '  FAIL  5    the classification step 5 quotes does not reproduce:\n%s\n' "$c5"
    fails=$((fails + 1))
  fi
fi

# --- the write tool's own arms, run here so §C's --apply promise is judged and not remembered ----
# (a `chk`, not a `run`: --apply is a §C actuation and has no A-step row, so it is not in the coverage
# denominator -- but its gates must still be re-proven every time this script runs)
# the manifest checker must prove its volatile mask hides the counter and NOT the content (ledger 390)
mchk=$(python3 tools/man_check.py --selftest 2>&1); mchk_rc=$?
if [ "$mchk_rc" = 0 ]; then
  printf '  chk   manifest %s\n' "$(printf '%s' "$mchk" | tail -1)"
else
  printf '  FAIL  manifest the mask arms did not pass:\n%s\n' "$mchk"
  fails=$((fails + 1))
fi

# document-integrity gate: every path the runbook tells you to open must exist, or be an
# explicitly allowed device/scratch path.  A rotted path is invisible here and fatal on 7.
cit=$(python3 tools/runbook_citations.py 2>&1); cit_rc=$?
if [ "$cit_rc" = 0 ]; then
  printf '  chk   citations %s\n' "$(printf '%s' "$cit" | head -1)"
else
  printf '  FAIL  citations a path named in the runbook does not exist:\n%s\n' "$cit"
  fails=$((fails + 1))
fi
citT=$(python3 tools/runbook_citations.py --table 2>&1); citT_rc=$?
if [ "$citT_rc" = 0 ]; then
  printf '  chk   citations %s
' "$(printf '%s' "$citT" | head -1)"
else
  printf '  FAIL  citations a source path in the carry list does not resolve:
%s
' "$citT"
  fails=$((fails + 1))
fi
cit2=$(python3 tools/runbook_citations.py --selftest 2>&1); cit2_rc=$?
if [ "$cit2_rc" = 0 ]; then
  printf '  chk   citations %s\n' "$(printf '%s' "$cit2" | tail -1)"
else
  printf '  FAIL  citations the arms of this gate did not fire:\n%s\n' "$cit2"
  fails=$((fails + 1))
fi

pa=$(python3 tools/pa_apply.py --selftest 2>&1); pa_rc=$?
if [ "$pa_rc" = 0 ]; then
  printf '  chk   apply  %s\n' "$(printf '%s' "$pa" | tail -1)"
else
  printf '  FAIL  apply  the write-back gates do not reproduce:\n%s\n' "$pa"
  fails=$((fails + 1))
fi

# --- coverage: every runbook A-step must be announced, run or deferred -------------------------
# (skipped when the A-table could not be parsed: that fault is already counted once above, and a
#  second 0/0 line would make one defect print two misbehaviours)
if [ -n "$WANT" ]; then
cov_rc=0
cov=$(python3 - "$WANT" "$ANN" <<'PY'
import sys
want = sys.argv[1].split()
got = sys.argv[2].split()
missing = [w for w in want if w not in got]
extra = sorted({g for g in got if g not in want})
print(f"coverage: {len(want) - len(missing)}/{len(want)} runbook A-steps announced"
      + (f"; MISSING {','.join(missing)}" if missing else "")
      + (f"; announced but not in the A-table: {','.join(extra)}" if extra else ""))
sys.exit(1 if (missing or extra or not want) else 0)
PY
) || cov_rc=1
echo "$cov"
if [ "$cov_rc" != 0 ]; then fails=$((fails + 1)); fi
fi

echo "self-check: $fails step(s) misbehaved; work dir kept at $WORK"
exit "$fails"
