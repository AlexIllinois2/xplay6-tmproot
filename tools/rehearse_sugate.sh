#!/usr/bin/env bash
# One-command regression for the su-gate driver, entirely offline: each scenario runs
# tools/run_sugate.sh against the stateful mock adb with its own state file, and every
# scenario declares BOTH the exit code it expects and a line that must appear.  A scenario
# that cannot fail is not a control, so rc and pattern are checked independently.
#
# usage: bash tools/rehearse_sugate.sh
set -u
T="$(cd "$(dirname "$0")" && pwd)"
R="$T/run_sugate.sh"
LOGD=$(mktemp -d /tmp/sugate-rehearse.XXXXXX)
fails=0

# run <name> <expect-rc> <expect-pattern> <env assignments written out literally>
run() {
	local name=$1 want_rc=$2 want_pat=$3 state log rc envs
	state="$LOGD/$name.json"; log="$LOGD/$name.log"
	rm -f "$state"
	shift 3
	# NB: envs are passed as a literal env command per scenario -- an earlier version built
	# them in a loop and mangled the string, which faked a passing negative control.
	env "$@" LOGF= MOCK_ADB_STATE="$state" PATH="$T/mock:$PATH" bash "$R" mockdev >"$log" 2>&1
	rc=$?
	if [ "$rc" != "$want_rc" ]; then
		printf 'FAIL %-9s rc=%s (wanted %s)\n' "$name" "$rc" "$want_rc"; fails=$((fails + 1)); return
	fi
	# -z so a pattern may span lines (the whole log is one record); rc and pattern are
	# checked separately -- either one alone can pass by accident.
	if ! grep -zqE "$want_pat" "$log"; then
		printf 'FAIL %-9s rc=%s but no line matched: %s\n' "$name" "$rc" "$want_pat"; fails=$((fails + 1)); return
	fi
	printf 'pass %-9s rc=%s  [%s]\n' "$name" "$rc" "$want_pat"
}

# A: the intended route -- empty pgd slot opens the alias, EL0 line flush converges, cpu0 wins
run A 0 'GATE DEFEATED on cpu0.*converged by: line flush' MOCK_DEFAULTS=1

# B: negative control -- the alias never materialises, so nothing may be claimed as patched
run B 1 'ABORT: no writable window' MOCK_NO_ALIAS=1

# C: §173 fallback with the computed flip value, only reachable when the alias route is out
run C 0 'flip worked.*converged by: line flush' MOCK_NO_ALIAS=1 FLIP=1

# E: the trap this tooling exists to catch -- EL0 ops are ALLOWED but ignored for kernel
# lines.  A driver that trusted "ALLOWED" would report victory on a stale I-cache.
run E 0 'converged by: eviction sweeps' MOCK_EL0_NOPRIV=1

# F: no convergence method at all -- must end honestly, and must actually roll the word back
run F 1 'NOT YET: su never showed RAN' MOCK_NO_ELFUSH=1 MOCK_NO_SWEEP=1

# G: hotplug as the only method -- cpu0 can never converge this way, so the win must be
# reported on cpu1, not on the first core the loop touches
run G 0 'GATE DEFEATED on cpu1.*converged by: cpu online.offline cycle' \
	MOCK_NO_ELFUSH=1 MOCK_NO_SWEEP=1 MOCK_ROOT=1 HOTPLUG=1

# H: hotplug asked for but not permitted as uid 2000 -- skip it and say so, do not pretend
run H 1 'skipped: cpuN/online is not writable' MOCK_NO_ELFUSH=1 MOCK_NO_SWEEP=1 HOTPLUG=1

# F2: the rollback has to be verified, not assumed -- the mock clears its gate word only when
# the original instruction is written back in memory order (pgdalias' payload guard)
rm -f "$LOGD/F2.json"
env MOCK_NO_ELFUSH=1 MOCK_NO_SWEEP=1 LOGF= MOCK_ADB_STATE="$LOGD/F2.json" PATH="$T/mock:$PATH" \
	bash "$R" mockdev >"$LOGD/F2.log" 2>&1
if grep -q 'rollback landed' "$LOGD/F2.log" &&
	python3 -c "import json,sys; sys.exit(0 if json.load(open('$LOGD/F2.json'))['patch'] is None else 1)"; then
	printf 'pass %-9s gate word is back as shipped after a failed run\n' F2
else
	printf 'FAIL %-9s rollback claimed or performed wrong\n' F2; fails=$((fails + 1))
fi

# I: the channel itself misses (§174 left the hit rate degraded).  The driver must find this
# on a no-op write and stop, instead of spending the alias attempt and reading a miss there.
run I 1 'ABORT: the write channel is not landing' MOCK_NO_HIT=1

# J: the no-op write lands, but as the wrong value -- caught because getenforce moves.
run J 1 'landed WRONG -- stop' MOCK_WRONG=1

# K: the failure actually seen on-device on 2026-10-14 -- the pinned probe prints nothing at
# all (that taskset takes a mask, not -c N).  The driver must call it NO READING, not
# "still denied", and must still roll the word back.
run K 1 'MEASUREMENT FAILED.*rollback landed' MOCK_NO_OUT=1

# L: today's real device failure -- the window opens and every readv says "landed", but the
# descriptor's physical base is wrong, so writes go to some other page.  The semantic witness
# must refuse it; a proof built on readv alone would have gone straight to the patch.
run L 1 'alias not proven.*wrote 00000000 through the alias, getenforce is Enforcing' \
	MOCK_FORCESLOT_PA=0x80000000

printf '\n%s  (logs in %s)\n' "$([ "$fails" = 0 ] && echo 'ALL SCENARIOS PASS' || echo "$fails SCENARIO(S) FAILED")" "$LOGD"
exit "$([ "$fails" = 0 ] && echo 0 || echo 1)"
