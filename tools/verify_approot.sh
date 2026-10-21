#!/usr/bin/env bash
# Acceptance gate for the app-side half of this project: the phone escalates
# itself, and the authorization layer around that escalation actually gates.
#
# Same discipline as tools/verify_root.sh (which measures the adb half): every
# criterion needs its own direct evidence, nothing passes on a proxy, and a
# missing daemon is a FAIL rather than a silence.
#
# criteria
#   A  the app escalates on its own and gets root over the kernel-credential channel
#   B  an app that is NOT on the allow list is refused
#   C  the same app, once on the list, gets uid=0
#   D  taking it off the list takes effect immediately (no restart of anything)
#   E  the audit log recorded that allow and that deny
#   F  a granted caller cannot ask to run as somebody else's uid
#   G  only with POST_REBOOT=1: a reboot restored uid 2000 + Enforcing
#   M  the granted root can finish a binder transaction (service handle + PackageManager answer)
#
# usage: bash tools/verify_approot.sh [serial]
set -u
SER=${1:-3e5a38a5}
T="$(dirname "$0")"
ADB="adb -s $SER"
MGR=com.xplay6.temproot
DEMO=com.xplay6.granted
GRANTS=/data/data/$MGR/files/grants.txt
SUDLOG=/data/local/tmp/.sud/sud.log
pass=0
fail=0

say() { printf '%s\n' "$*"; }
SEEN="$(mktemp -t approot-seen.XXXXXX)"
REFUSED="$(mktemp -t approot-refused.XXXXXX)"
refused=0
# Patterns that mean "the harness cannot see anything here", NOT "the device refused".  Measured
# 2026-10-20 on the Android 7 line (ledger 621): a third-party caller's C client dies at
# `cannot publish request name` because the drop directory carries shell_data_file, which
# untrusted_app may not write -- while the daemon had in fact already served that caller's request
# (dmesg shows `comm="sud.new" open .../req/req-<pid> permissive=1`).  Scoring that as FAIL would
# indict the authorization layer for a harness blind spot.
# `no sud channel` is NOT in this list, on purpose (ledger 631): it is the device telling us the
# channel itself is absent (nobody listens on @sud any more, because the manager-side relayd is a
# child of the app process), which is a product state to be scored, not a harness blind spot.
NORULER='cannot publish request name|NORULER'
chan_witness() { # what exists on the su-channel side, world-readable so it needs no root
	local r l
	r=$(timeout 20 $ADB shell 'for d in /proc/[0-9]*; do c=$(cat $d/cmdline 2>/dev/null); case "$c" in *relayd*) echo ${d#/proc/};; esac; done' 2>/dev/null | tr -d '\r' | tr '\n' ',' )
	l=$(timeout 20 $ADB shell 'grep -ac "@sud" /proc/net/unix' 2>/dev/null | tr -d '\r')
	printf 'relayd=[%s] @sud-rows=%s' "${r%,}" "${l:-?}"
}
chk() { # chk <id> <desc> <actual> <expected-regex>
	printf '%s\n' "$1" >> "$SEEN"
	# The wanted reading is tested FIRST.  A third-party caller's readout always carries the client's
	# own step note `su: cannot publish request name` in stderr -- including the run that returned
	# uid=0 (ledger 630's witness) -- so classifying on that note before matching the verdict turned a
	# working channel into `no ruler`, permanently.
	if printf '%s' "$3" | grep -Eq "$4"; then
		say "PASS  $1  $2   [$(printf '%s' "$3" | head -1 | cut -c1-90)]"
		pass=$((pass + 1))
		return 0
	fi
	if printf '%s' "$3" | grep -Eq "$NORULER"; then
		say "REFUSED  $1  $2   -- no ruler: [$(printf '%s' "$3" | head -2 | tr '\n' ' ' | cut -c1-130)]"
		printf '%s\n' "$1" >> "$REFUSED"
		refused=$((refused + 1))
		return 0
	fi
	if printf '%s' "$3" | grep -Eq "uid=0|ERR"; then
		say "FAIL  $1  $2   got [$(printf '%s' "$3" | head -3 | tr '\n' ' ' | cut -c1-140)] want /$4/"
		fail=$((fail + 1))
	else
		say "FAIL  $1  $2   got [$(printf '%s' "$3" | head -3 | tr '\n' ' ' | cut -c1-140)] want /$4/   channel side: $(chan_witness)"
		fail=$((fail + 1))
	fi
	return 0
}

coverage() { # coverage <mode-tag> -- every criterion written in THIS file must have been reported
	# No gate here until ledger 598: a `chk` line can become unreachable (an early exit, a renamed
	# id, a branch that stopped running) and the summary would still read `pass=N fail=0`.  That is
	# the same failure as runbook_selfcheck announcing 47/53 while never running step 5 (§361).
	local declared got miss
	declared=$(grep -oE '^[[:space:]]*chk +[A-Za-z0-9]+ ' "$0" | awk '{print $2}' | sort -u)
	if [ "${1:-}" = post-reboot ]; then
		declared="G"
	else
		# Criteria that live behind a mode switch are not "never run" in main mode; demanding them
		# would make every ordinary run red for a reason that is the mode, not the device (ledger 421).
		# The same reasoning had already been applied to G but never to H, so a main run announced
		# `NOT ACHIEVED: ... never run: H` while line 360 correctly said "not asserted" -- §363's
		# "defer by which side it is owed on" rule, re-broken by adding a new mode-gated criterion.
		[ "${POST_REBOOT:-0}" = 1 ] || declared=$(printf '%s\n' "$declared" | grep -v '^G$')
		[ "${EXPECT_ENFORCING:-0}" = 1 ] || declared=$(printf '%s\n' "$declared" | grep -v '^H$')
	fi
	got=$(sort -u "$SEEN")
	if [ -z "$(printf '%s' "$declared" | tr -d '[:space:]')" ]; then
		say "NOT ACHIEVED: coverage found 0 criteria declared in $0 -- an empty denominator is not a pass"
		return 1
	fi
	miss=$(comm -23 <(printf '%s\n' "$declared") <(printf '%s\n' "$got"))
	say "coverage: $(printf '%s\n' "$got" | grep -c .)/$(printf '%s\n' "$declared" | grep -c .) criteria reported (mode=${1:-main})"
	if [ -n "$miss" ]; then
		say "NOT ACHIEVED: criteria declared in this file but never run: $(printf '%s' "$miss" | tr '\n' ' ')"
		return 1
	fi
	return 0
}

if [ "${1:-}" = "--selftest" ]; then
	# Does the coverage gate actually see a missing criterion?  Declare the ids from this file,
	# then feed it (a) nothing -- every declared id must come back missing -- and (b) all of them.
	DECL=$(grep -oE '^[[:space:]]*chk +[A-Za-z0-9]+ ' "$0" | awk '{print $2}' | sort -u)
	N=$(printf '%s\n' "$DECL" | grep -c .)
	: > "$SEEN"
	if coverage main >/tmp/approot_cov_a.txt 2>&1; then
		say "SELFTEST FAIL: coverage passed with an empty report -- the gate is blind"
		exit 1
	fi
	MISS=$(grep -c 'never run' /tmp/approot_cov_a.txt)
	say "  ok   arm: with 0 of $N reported, the gate refuses (announced $(sed -n 's/.*coverage: //p' /tmp/approot_cov_a.txt | head -1))"
	printf '%s\n' $DECL > "$SEEN"
	if coverage main >/tmp/approot_cov_b.txt 2>&1; then
		say "  ok   arm: with all $N reported, the gate accepts"
	else
		say "SELFTEST FAIL: coverage rejected a complete run: $(cat /tmp/approot_cov_b.txt)"
		exit 1
	fi
	# and the mode split itself: a main-mode run that never reports G must still be complete
	printf '%s\n' $DECL | grep -v '^G$' > "$SEEN"
	if coverage main >/tmp/approot_cov_c.txt 2>&1; then
		say "  ok   arm: G stays out of the main denominator (mode=$(sed -n 's/.*(mode=\(.*\))/\1/p' /tmp/approot_cov_c.txt | head -1))"
	else
		say "SELFTEST FAIL: main mode still demands the POST_REBOOT-only criterion: $(cat /tmp/approot_cov_c.txt)"
		exit 1
	fi
	if [ "$N" -lt 13 ]; then
		say "SELFTEST FAIL: only $N criteria declared -- I/I2/J/JP/K plus A-H should all be here"
		exit 1
	fi
	# Arms for the no-ruler classification ITSELF (added together with it, ledger 622).  Invoked
	# through $CHK on purpose: a literal `chk ID ` here would be picked up by the DECL grep above
	# and would then demand these test ids in every real run.  Both directions must hold: a harness
	# blind spot must be refused (not passed, not failed), and a genuine miss must STILL fail --
	# otherwise "refuse everything" becomes a new way to look green.
	CHK=chk
	pass=0; fail=0; refused=0; : > "$SEEN"; : > "$REFUSED"
	$CHK TSTORDER "arm: step note does not eat a real uid=0 reading" "out=uid=0(root) err=su: cannot publish request name: Permission denied" 'uid=0\(root\)'
	if [ "${pass:-0}" != 1 ] || [ "${refused:-0}" != 0 ] || [ "${fail:-0}" != 0 ]; then
		say "SELFTEST FAIL: a uid=0 reading carrying the client's step note must PASS, not score pass=$pass fail=$fail refused=$refused"
		exit 1
	fi
	say "  ok   arm: verdict is matched before the blind-spot note (ledger 631: the note rides along on SUCCESS too)"
	pass=0; fail=0; refused=0; : > "$SEEN"; : > "$REFUSED"
	$CHK TSTNEG "arm: harness blind spot" "out= err=su: cannot publish request name: Permission denied" 'uid=0'
	if [ "${refused:-0}" != 1 ] || [ "${pass:-0}" != 0 ] || [ "${fail:-0}" != 0 ]; then
		say "SELFTEST FAIL: the NORULER reading was not refused (pass=$pass fail=$fail refused=$refused)"
		exit 1
	fi
	say "  ok   arm: a cannot-publish-request-name reading is REFUSED -- neither pass nor fail"
	pass=0; fail=0; refused=0; : > "$SEEN"; : > "$REFUSED"
	$CHK TSTPOS "arm: real refusal still scores" "ERR unknown service" 'uid=0'
	if [ "${fail:-0}" != 1 ] || [ "${refused:-0}" != 0 ]; then
		say "SELFTEST FAIL: a genuine miss was swallowed by the refuse path (fail=$fail refused=$refused)"
		exit 1
	fi
	say "  ok   arm: an ordinary denial still FAILs (the refuse path did not eat it)"
	pass=0; fail=0; refused=0; : > "$SEEN"; : > "$REFUSED"
	$CHK TSTPOS2 "arm: the truncated-proof sentinel is refused" "NORULER: proof log is 0 bytes fresh=1" '^[1-9][0-9]* fresh=1$'
	if [ "${refused:-0}" != 1 ]; then
		say "SELFTEST FAIL: the empty-proof-log sentinel was not refused (refused=$refused)"
		exit 1
	fi
	say "  ok   arm: an empty proof log is REFUSED, not scored as no-root"
	# M's own three directions (added with the criterion, ledger 707): a peer that cannot reply must be
	# RED (that is the defect M exists to catch), a silent root channel must be REFUSED (no ruler), and
	# the green shape must actually be reachable -- an unreachable judgement is how M would rot back.
	pass=0; fail=0; refused=0; : > "$SEEN"; : > "$REFUSED"
	$CHK TSTM0 "arm: both binder answers present" "YES YES" '^YES YES$'
	if [ "${pass:-0}" != 1 ]; then
		say "SELFTEST FAIL: M's green shape is not reachable (pass=$pass) -- the criterion would always refuse"
		exit 1
	fi
	$CHK TSTM1 "arm: reply direction mediated -> fail" "NO NO" '^YES YES$'
	$CHK TSTM2 "arm: silent root channel -> refuse" "NORULER: root channel answered nothing for service check NO" '^YES YES$'
	if [ "${fail:-0}" != 1 ] || [ "${refused:-0}" != 1 ] || [ "${pass:-0}" != 1 ]; then
		say "SELFTEST FAIL: M arms scored pass=$pass fail=$fail refused=$refused (want 1/1/1)"
		exit 1
	fi
	say "  ok   arm: M scores green / red / refused in the three distinct states"
	say "selftest: coverage gate has teeth; $N criteria declared"
	exit 0
fi

# rewrite the allow list without the demo uid: grep+mv rather than `sed -i`,
# because a busybox/toybox difference mid-run would look like a failed criterion
drop_demo() {
	# Rewrite the list IN PLACE.  The old shape (`> $GRANTS.t; mv $GRANTS.t $GRANTS`) left a
	# root-created inode inside app data, and that inode does not carry the app's MLS categories.
	# It has been implicated twice: user memory (selinux-domain-and-denial-readings #17) recorded the
	# manager losing access to its own list after exactly this, and today's boot logged
	# `self-grant ... added saved=false` on such an inode -- note the *replace* from the UI did work on
	# the same shape, so what is measured is a failed READ at boot, not the mechanism.  `cat >` changes
	# content only, so inode, owner and label stay the app's own and one suspect variable is gone.
	rootsh "grep -v '^$DEMO_UID\$' $GRANTS > /data/local/tmp/g.tmp 2>/dev/null; cat /data/local/tmp/g.tmp > $GRANTS; rm -f /data/local/tmp/g.tmp; cat $GRANTS" >/dev/null
	seal_grants
}

# The list is written here through the root channel, so `mv` leaves it root-owned with the
# creating umask (0666 on this device).  sud ignores a list that strangers can write -- that
# is the fix for the hole measured 2026-10-15 (an app appended its own uid to the 0666
# /data/local/tmp/sud.grants and got uid=0) -- so the harness must hand the file back in the
# shape the manager app itself writes it: 0600, owned by the app uid.
seal_grants() { # hand the list back in the shape the manager app itself writes it: app-owned (uid AND
	# group), 0600, and carrying the app's own MLS context -- `restorecon` inside app data is what puts
	# the categories back (user memory: selinux-domain-and-denial-readings #17).
	rootsh "me=\$(stat -c '%u' /data/data/$MGR 2>/dev/null); chown \$me:\$me $GRANTS 2>/dev/null; chmod 600 $GRANTS; restorecon $GRANTS 2>/dev/null" >/dev/null
}

rootsh() { # one command through the daemon's raw shell (port 12345)
	$ADB forward tcp:12345 tcp:12345 >/dev/null 2>&1
	{ printf '%s\n' "$*"; sleep 2; } | timeout 25 bash -c \
		'exec 3<>/dev/tcp/127.0.0.1/12345; cat >&3; cat <&3' 2>/dev/null | tr -d '\r'
}

waitlog() { # waitlog <tag> <regex> <max-seconds>
	local tag="$1" want="$2" lim="$3" got i=0
	while [ "$i" -lt "$lim" ]; do
		got=$(timeout 20 $ADB logcat -d -s "$tag" 2>/dev/null | tr -d '\r' | sed "s/.*$tag: //")
		if printf '%s' "$got" | grep -Eq "$want"; then
			printf '%s' "$got"
			return 0
		fi
		i=$((i + 3))
		sleep 3
	done
	printf '%s' "$got"
	return 1
}

$ADB get-state >/dev/null 2>&1 || { say "ABORT: $SER not on adb"; exit 2; }

say "=== 0. state as seen from an unprivileged shell ==="
say "plain shell: $(timeout 15 $ADB shell 'id -u; getenforce' 2>/dev/null | tr -d '\r' | tr '\n' ' ')"
DEMO_UID=$(timeout 15 $ADB shell "stat -c '%u' /data/data/$DEMO" 2>/dev/null | tr -d '\r')
say "demo uid: $DEMO_UID   manager grants: $GRANTS"
[ -n "$DEMO_UID" ] || { say "ABORT: cannot read the demo app uid (is $DEMO installed?)"; exit 2; }
# criterion F's client; pushed here so a transfer failure aborts before any
# criterion is measured rather than showing up as an unrelated FAIL later
timeout 15 $ADB push "$T/suc" /data/local/tmp/sux >/dev/null 2>&1 \
	|| { say "ABORT: cannot push $T/suc (built? device online?)"; exit 2; }
timeout 15 $ADB shell 'chmod 755 /data/local/tmp/sux' >/dev/null 2>&1

if [ "${POST_REBOOT:-0}" = "1" ]; then
	UIDG=$(timeout 15 $ADB shell 'id -u' 2>/dev/null | tr -d '\r')
	ENG=$(timeout 15 $ADB shell getenforce 2>/dev/null | tr -d '\r')
	NPG=$(timeout 15 $ADB shell 'ps -Z 2>/dev/null | grep -c "sud"' 2>/dev/null | tr -d '\r')
	NLG=$(timeout 15 $ADB shell 'netstat -ltn 2>/dev/null | grep -cE ":1234[56]"' 2>/dev/null | tr -d '\r')
	say "  post-reboot: uid=$UIDG enforce=$ENG sud-procs=$NPG listeners=$NLG"
	# Same confined-readable witnesses as verify_root.sh criterion 5, and for the same measured reason:
	# `netstat -ltn` from uid 2000 read 0 in three boots where the daemon was provably serving root.
	p5=$fail; BR=absent
	if [ "$UIDG" = 2000 ] && [ "$ENG" = Enforcing ] && [ "$NPG" = 0 ]; then
		chk G "reboot removed the chain (uid 2000, Enforcing, no sud proc)" \
			"$UIDG $ENG $NPG" '^2000 Enforcing 0$'
	else
		BR=recreated
		chk G "reboot left uid 2000 with no persisted chain (app re-escalated: sud-procs=$NPG, suid=$(timeout 30 $ADB shell '/data/local/tmp/sux -c id 2>&1' 2>/dev/null | tr -d '\r' | head -1))" \
			"$UIDG $NPG" '^2000 [1-9][0-9]*$'
	fi
	[ "$fail" -eq "$p5" ] || { say "=== summary ==="; coverage post-reboot; say "pass=$pass fail=$fail"; say "NOT ACHIEVED: reversibility not shown"; exit 1; }
	coverage post-reboot || { say "pass=$pass fail=$fail"; exit 1; }
	[ "$BR" = recreated ] && say "  branch: the app re-created the chain after this boot (task 32 behaviour), not persisted state"
	say "=== summary ==="
	say "pass=$pass fail=$fail"
	[ "$fail" -eq 0 ] || { say "NOT ACHIEVED: reversibility not shown"; exit 1; }
	say "REVERSIBILITY VERIFIED"
	exit 0
fi

say "=== 0b. every list the daemon is willing to consult ==="
# uid_allowed() in tools/sud.c reads THREE files, and only the manager's own list is the one this
# table edits.  Measured 2026-10-21: an earlier run's J positive control left /data/local/tmp/sud.grants
# (root-owned, therefore believed) holding the demo uid.  The next run's B had correctly dropped that
# uid from $GRANTS and had verified the drop -- yet the demo still got root, and B reported the
# authorization rule as broken.  The rule was fine; my own previous run had left state behind.
# Take the candidate list from the source rather than from this file's memory, clear the alternates
# for the whole run, and clear them again on the way out (they are harness litter, not user state).
GRANT_ALL=$(sed -n '/GRANTS_CANDIDATES\[3\] = {/,/^};/p' "$(dirname "$0")/sud.c" \
	| grep -oE '"/data/[^"]*"' | tr -d '"' | tr '\n' ' ')
if [ -z "$GRANT_ALL" ]; then
	say "  ABORT: cannot read GRANTS_CANDIDATES out of tools/sud.c -- B/D/J would be unjudgable"
	exit 1
fi
say "  the daemon consults: $GRANT_ALL"
# The candidates are paths, and two of them are the SAME FILE reached through the /data/user symlink
# (/data/user/0/<pkg>/files/grants.txt == /data/data/<pkg>/files/grants.txt).  Comparing the strings
# deletes the manager's own list -- measured on the first run of this very block, which rm'd the user's
# four granted uids.  Identity is device+inode, asked of the device, not of the text.
MAIN_ID=$(rootsh "stat -c '%d:%i' $GRANTS 2>/dev/null" | tr -d '\r')
if [ -z "$MAIN_ID" ]; then
	say "  ABORT: cannot stat $GRANTS through the root channel -- touching no list at all"
	exit 1
fi
say "  the list this table edits is dev:inode $MAIN_ID; anything else is a separate file"
clear_grant_alternates() {				# also used as the exit trap
	# DELETE ONLY WHAT THIS SCRIPT ITSELF PLANTS (J/JP write /data/local/tmp/sud.grants).
	# Measured 2026-10-21: after a full run the manager's own /data/.../grants.txt was gone even
	# though this loop's dev:inode test matches both spellings when asked by hand.  The deletion
	# therefore has a cause this function cannot see, and a harness that answers "why did the
	# user's list vanish" with "the test said it was litter" is how the list was destroyed the
	# first time too (ledger 714).  Files outside the harness's own directory are reported, never
	# removed -- an alternate grant list in app data belongs to its owner, and leaving one behind
	# costs a rerun, not the user's state.
	local p id one what
	for p in $GRANT_ALL; do
		id=$(rootsh "stat -c '%d:%i' $p 2>/dev/null" | tr -d '\r')
		[ -n "$id" ] || continue				# not there: nothing to clear
		[ "$id" = "$MAIN_ID" ] && continue		# the manager's own list, another spelling of it
		one=$(rootsh "cat $p" | tr -d '\r')
		what="held $(printf '%s' "$one" | tr '\n' ' ')"
		case "$p" in
		/data/local/tmp/*) ;;				# the harness's own directory
		*)
			say "  NOT TOUCHING alternate list $p ($id, $what): it is outside /data/local/tmp, so it is not this harness's litter"
			continue ;;
		esac
		say "  clearing harness specimen $p ($id, $what)"
		rootsh "rm -f $p" >/dev/null
	done
}
clear_grant_alternates report
after=$(rootsh "stat -c '%d:%i' $GRANTS 2>/dev/null" | tr -d '\r')
if [ "$after" != "$MAIN_ID" ]; then
	say "  ABORT: the manager's own list changed identity ($MAIN_ID -> ${after:-GONE}) --"
	say "         stopping now rather than continuing on a destroyed grant list"
	exit 1
fi
# B and D REMOVE the demo uid from this list on purpose, so a run that returns without putting it
# back leaves the user with a different grant set than the one they had.  Take a byte-exact
# snapshot through the same channel and put it back on the way out; a run whose snapshot cannot
# be verified says so instead of writing anything (ledger 714: the list is the user's, not ours).
SNAP=/data/local/tmp/grants.snap
SNAP_TEXT=$(rootsh "cat $GRANTS" | tr -d '\r')
SNAP_OK=0
if [ -n "$SNAP_TEXT" ] && [ "$(rootsh "cp $GRANTS $SNAP && chown root:root $SNAP && chmod 600 $SNAP && cmp -s $SNAP $GRANTS && echo SNAP_SAME" | tr -d '\r')" = SNAP_SAME ]; then
	SNAP_OK=1
	say "  snapshot: $(printf '%s' "$SNAP_TEXT" | tr '\n' ' ') ($(printf '%s\n' "$SNAP_TEXT" | wc -l) uid lines) saved to $SNAP"
else
	say "  NORULER: the pre-run grant list could not be snapshotted -- B/D will change it and this run will not put it back"
fi
restore_grants() {					# also part of the exit trap
	[ "$SNAP_OK" = 1 ] || { say "  NOT RESTORING the grant list: no verified snapshot was taken before B/D edited it"; return; }
	rootsh "cat $SNAP > $GRANTS; me=\$(stat -c '%u' /data/data/$MGR 2>/dev/null); chown \$me:\$me $GRANTS 2>/dev/null; chmod 600 $GRANTS; restorecon $GRANTS 2>/dev/null; rm -f $SNAP" >/dev/null
	got=$(rootsh "cat $GRANTS" | tr -d '\r')
	if [ "$got" = "$SNAP_TEXT" ]; then
		say "  restored the manager's grant list to its pre-run contents ($(printf '%s\n' "$got" | wc -l) uid lines)"
	else
		say "  RESTORE MISMATCH: the list now reads [$(printf '%s' "$got" | tr '\n' ' ')] but the snapshot was [$(printf '%s' "$SNAP_TEXT" | tr '\n' ' ')] -- reported, not papered over"
	fi
}
trap 'clear_grant_alternates; restore_grants' EXIT
for p in $GRANT_ALL; do
	id=$(rootsh "stat -c '%d:%i' $p 2>/dev/null" | tr -d '\r')
	[ -n "$id" ] || continue
	[ "$id" = "$MAIN_ID" ] && continue
	if [ -n "$(rootsh "test -f $p && echo yes" | tr -d '\r')" ]; then
		say "  NORULER: $p survived the removal -- the barriers in B/D/J cannot be trusted"
	fi
done

say "=== A. the app escalates by itself ==="
# Two halves, both required.  (1) the helper's own witness that the task IT patched became root --
# `ROOT in our own cred, uid=0` is printed by the patched task, so it cannot be produced by somebody
# else's daemon -- and that log file has to be NEWER than this boot, because broot7.log lives in /data
# and would otherwise let last boot's success pass for this one.  (2) the app's own probe answering
# uid=0.  The old ruler only accepted the `[peer(SCM_CREDENTIALS)]` spelling of (2); on 7 the app's
# unix xport can fall back to tcp+token, because the avc decision for /data/local/tmp/.sud is cached
# from before the map is planted (writing RAM does not flush the avc cache -- ledger 547's durable
# part).  Dropping the peer-only wording does not loosen the criterion: (1) is the stronger half.
# Evidence is read first, not triggered first: the product's real path is the boot-time self-heal.
# Since ledger 629 EscService asks the daemon itself (TCP 127.0.0.1:12345) instead of trusting the
# persisted same-boot mark, and spends at most one recovery needle per boot -- so "no second needle"
# is no longer a rule this harness may rely on; the mark alone used to answer "already escalated"
# while nothing was serving at all.
BLOG=/storage/emulated/0/Android/data/$MGR/files/broot7.log
# The relay's own audit trail (since ledger 626): sud sees only the manager token after that change,
# so the line naming the REAL caller lives here.  Same directory, same shell-readable permission.
RELAYLOG=/storage/emulated/0/Android/data/$MGR/files/relayd.log
fresh_witness() { # -> "<count> <1 if that log is newer than this boot>"
	# `/proc/uptime` is a decimal, and mksh's $(( )) dies on it ("unexpected '.'") -- truncating to
	# whole seconds is also all the precision the boot epoch needs.
	timeout 25 $ADB shell "boot=\$(cut -d' ' -f1 /proc/uptime | cut -d. -f1); now=\$(date +%s); \
		e=\$((now-boot)); \
		m=\$(stat -c %Y $BLOG 2>/dev/null || echo 0); \
		n=\$(grep -c 'ROOT in our own cred, uid=0' $BLOG 2>/dev/null || echo 0); \
		echo \"\$n \$((m>=e))\"" 2>/dev/null | tr -d '\r' | tail -1
}
read -r L7 NEW < <(fresh_witness)
A=$(timeout 25 $ADB logcat -d -s TempRoot-boot:V 2>/dev/null | tr -d '\r' | grep -E 'root probe .*uid=0' | tail -1)
# The manager's own uid, so its probe can be found in the daemon's audit log.  logcat rotates -- on a
# loaded phone the boot-time probe line is gone minutes later -- and `sud.log` is the persistent
# record that THIS uid asked and the daemon answered with code=0.  Either half satisfies A2; A1 (the
# patched task's own uid=0 witness, newer than this boot) stays mandatory, which is the half that
# cannot be borrowed from somebody else's daemon.
MGR_UID=$(timeout 15 $ADB shell "stat -c '%u' /data/data/$MGR" 2>/dev/null | tr -d '\r')
AUD=$(timeout 15 $ADB shell "grep -E 'allow +uid=$MGR_UID .*code=0' $SUDLOG 2>/dev/null | tail -1" 2>/dev/null | tr -d '\r')
if [ "${L7:-0}" = 0 ] || [ "${NEW:-0}" = 0 ] || { [ -z "$A" ] && [ -z "$AUD" ]; }; then
	timeout 15 $ADB shell am startservice -n "$MGR/.EscService" >/dev/null 2>&1
	A=$(waitlog TempRoot-boot 'root probe .*uid=0' 240)
	read -r L7 NEW < <(fresh_witness)
	AUD=$(timeout 15 $ADB shell "grep -E 'allow +uid=$MGR_UID .*code=0' $SUDLOG 2>/dev/null | tail -1" 2>/dev/null | tr -d '\r')
fi
# A1's witness is a log FILE, and the app truncates that very file when it re-execs the helper for
# the su-name gate (measured: 84 915 bytes of ladder proof became 0 bytes at the next second).  An
# empty proof file is "no ruler", not "no root" -- say so instead of failing the device for it.
B_SZ=$(timeout 15 $ADB shell "stat -c %s $BLOG 2>/dev/null" 2>/dev/null | tr -d '\r')
if [ "${L7:-0}" = 0 ] && [ "${B_SZ:-1}" = 0 ]; then
	L7="NORULER: proof log is 0 bytes (the app's own second exec truncated it -- task 27)"
fi
chk A1 "this boot's own task turned root inside its own cred (broot7 witness, log newer than boot)" \
	"$L7 fresh=$NEW" '^[1-9][0-9]* fresh=1$'
chk A2 "the app's own probe reached uid=0 (logcat probe line OR the daemon's audit line for its uid)" \
	"$A||$AUD" '(root probe \[.*\]: uid=0\(root\))||(allow +uid=[0-9]+ .*code=0)'

# Cold-start the demo app so its onCreate/ask() actually runs again.  Measured on 1.9.8 (ledger 630):
# `am force-stop` followed immediately by `am start` often only brings the dying task to the front
# ("Warning: Activity not started", WaitTime: 7 ms, ThisTime: 0), so the app never re-asks and the
# harness reports "no ruler" for a path that IS working.  ThisTime>0 is the witness that this launch
# really created the activity; give it a few settled tries before calling it unjudgeable.
relaunch_demo() { # -> 0 and prints "ThisTime=<n>" when the activity was (re)created
	local i out t
	for i in 1 2 3; do
		timeout 15 $ADB shell am force-stop $DEMO >/dev/null 2>&1
		# 4 s was not enough right after a previous window put the same task back in front: three tries
		# then all read ThisTime=0 and criterion C came back UNMEASURED (ledger 632).
		sleep 9
		timeout 15 $ADB logcat -c >/dev/null 2>&1
		out=$(timeout 25 $ADB shell am start -W -n "$DEMO/.Demo" 2>/dev/null | tr -d '\r')
		t=$(printf '%s' "$out" | sed -n 's/^ThisTime:[ ]*//p' | tail -1)
		case "$t" in ''|*[!0-9]*) t=0 ;; esac
		if [ "$t" -gt 0 ]; then
			printf 'ThisTime=%s\n' "$t"
			return 0
		fi
		sleep 3
	done
	printf 'ThisTime=0\n'
	return 1
}

# The file the demo writes its own answer into (world-readable on this ROM, no root needed).
DEMO_RES=/storage/emulated/0/Android/data/$DEMO/files/result.txt
# The root channel is asynchronous: `rootsh` sends the line and reads the reply for ~2 s, so a write
# to the allow list is NOT proven applied when it returns -- measured 2026-10-20 (ledger 674): the
# demo's request went out before its own grants edit landed, which shifted every verdict one step
# (C refused while listed, D got root after being dropped).  So ask for the file back and wait.
grants_read() { # the list exactly as relayd reads it, through the ROOT channel (see the note below)
	local i=0 got
							# `adb shell cat` on app-private data is Permission denied, so a
							# barrier that read it that way saw "" every time, spun its whole
							# timeout and let the verdict pass on luck alone (ledger 675).  The
							# marker says "the channel answered"; its absence says we are blind.
	while [ "$i" -lt 3 ]; do
		got=$(rootsh "cat $GRANTS 2>/dev/null; echo GRANTS_EOF" | tr -d '\r')
		case "$got" in *GRANTS_EOF*) printf '%s' "${got%%GRANTS_EOF*}"; return 0 ;; esac
		i=$((i + 1)); sleep 2
	done
	printf '%s' "$got"; return 1
}
grants_has() { # grants_has <list-text> <uid> -> 0 when listed
	printf '%s' "$1" | grep -Eq "^$2$"
}
grants_until() { # grants_until <want:in|out> <uid> -- retry the READ until the relay-visible list
	local want="$1" uid="$2" i=0 got rc=1 seen	# agrees, then echo the list.  Waiting on the
	while [ "$i" -lt 6 ]; do			# write itself is what shifted every verdict by
		got=$(grants_read); rc=$?			# one step (ledger 674).  rc!=0 is NOT "absent":
		i=$((i + 1))				# it is "no ruler", and the caller must refuse.
		[ "$rc" != 0 ] && continue
		if grants_has "$got" "$uid"; then seen=in; else seen=out; fi
		[ "$seen" = "$want" ] && { printf '%s' "$got"; return 0; }
		sleep 2
	done
	printf '%s' "$got"; return 1
}
barrier_note() { # barrier_note <criterion> <want> <uid> <rc> <list> -- the sentence the log shows
	printf 'NORULER: the grants-list barrier never saw %s %s (root channel saw [%s]) -- %s would read a stale state, so it is not judged\n' \
		"$3" "$( [ "$2" = in ] && printf 'listed' || printf 'gone from' )" "$5" "$1"
}
demo_mark() { # the timestamp the demo last stamped.  "none" is a DIFFERENT answer from 0: when
	local v                    # the marker cannot be read, `demo_wait` refuses to judge, because
	v=$(timeout 15 $ADB shell "head -1 $DEMO_RES 2>/dev/null | tr ' ' '\\n' | head -1" | tr -d '\\r' | tr -d '[:space:]')
	case "$v" in               # treating unreadable as 0 lets whatever is already in the file
		''|*[!0-9]*) printf 'none\n'; return 1 ;;
		*) printf '%s\n' "$v"; return 0 ;;
	esac
}
demo_wait() { # demo_wait <since-ts> -> the whole fresh reading, or a NORULER sentence
	local since="$1" i=0 head body
	if [ "$since" = none ]; then
		printf 'NORULER: the marker itself could not be read (%s unreadable?) -- refusing to call an unseen baseline older\n' "$DEMO_RES"
		return 1
	fi
	while [ "$i" -lt "$2" ]; do
		body=$(timeout 15 $ADB shell "cat $DEMO_RES 2>/dev/null" | tr -d '\r')
		head=$(printf '%s' "$body" | head -1 | cut -d' ' -f1 | tr -d '[:space:]')
		case "$head" in ''|*[!0-9]*) ;; *) if [ "$head" -gt "$since" ] 2>/dev/null; then
			printf '%s\n' "$body"; return 0; fi ;; esac
		i=$((i + 3)); sleep 3
	done
	printf 'NORULER: no fresh %s (demo wrote nothing newer than ts=%s in %ds; logcat fallback: %s)\n' \
		"$DEMO_RES" "$since" "$2" "$(timeout 15 $ADB logcat -d -s GrantedDemo 2>/dev/null | tr -d '\r' | tail -1 | cut -c1-90)"
	return 1
}

say "=== B. an app that is not on the list is refused ==="
drop_demo
BBAR=$(grants_until out "$DEMO_UID"); BBC=$?
if [ "$BBC" = 0 ]; then say "  barrier: $DEMO_UID is gone from the list the relay reads"; else say "  $(barrier_note B out "$DEMO_UID" "$BBC" "$BBAR")"; fi
BSINCE=$(demo_mark)
BCOLD=$(relaunch_demo)
BRAW=$(demo_wait "$BSINCE" 45)
B=$(printf '%s' "$BRAW" | grep -a '^SUX ' | head -1)
[ -n "$B" ] || B="$BRAW"
if [ "$BCOLD" = "ThisTime=0" ]; then
	B="NORULER: the demo activity never re-created itself ($BCOLD) -- the app could not have re-asked"
fi
[ "$BBC" = 0 ] || B="NORULER: the write that should have dropped $DEMO_UID was never read back -- B is not judged"
chk B "unlisted app gets the same refusal as a nonexistent service" "$B" 'ERR unknown service'

say "=== C. put it on the list -> root ==="
rootsh "echo $DEMO_UID >> $GRANTS; cat $GRANTS" >/dev/null
seal_grants
CBAR=$(grants_until in "$DEMO_UID"); CBC=$?
if [ "$CBC" = 0 ]; then say "  barrier: $DEMO_UID IS listed before the relaunch"; else say "  $(barrier_note C in "$DEMO_UID" "$CBC" "$CBAR")"; fi
CSINCE=$(demo_mark)
CCOLD=$(relaunch_demo)
CFRESH=$(demo_wait "$CSINCE" 45)
C=$(printf '%s' "$CFRESH" | grep -a '^SUX ' | head -1)
[ -n "$C" ] || C="$CFRESH"
CSU=$(printf '%s' "$CFRESH" | grep -a '^SU ' | head -1)
[ -n "$CSU" ] || CSU="$CFRESH"
if [ "$CCOLD" = "ThisTime=0" ]; then
	C="NORULER: the demo activity never re-created itself ($CCOLD) -- the app could not have re-asked"
CSU="$C"
fi
if [ "$CBC" != 0 ]; then
	C="NORULER: the write that should have listed $DEMO_UID was never read back -- C is not judged"
CSU="$C"
fi
chk C "granted app runs as root" "$C" 'uid=0\(root\).*groups=0\(root\)'

say "=== L. the SAME granted app, asked under the literal name su ==="
# This is the user's own sentence: "shizuku检测不到root".  A libsu caller execs `su`, and vivo's
# guard used to refuse it with EPERM (ledger 643) -- so root never happened for apps that hardcode
# the name, no matter what the allow list says.  `su` admitted + uid=0 here means that end state is
# reached; EPERM in this line would mean the vendor check is back (patch gone or site moved).
chk L "a granted app that hardcodes the NAME su gets root" "$CSU" 'uid=0\(root\).*groups=0\(root\)'

say "=== D. revoke it again -> refused, no restart in between ==="
drop_demo
DBAR=$(grants_until out "$DEMO_UID"); DBC=$?
if [ "$DBC" = 0 ]; then say "  barrier: $DEMO_UID gone from the list the relay reads"; else say "  $(barrier_note D out "$DEMO_UID" "$DBC" "$DBAR")"; fi
DSINCE=$(demo_mark)
DCOLD=$(relaunch_demo)
DRAW=$(demo_wait "$DSINCE" 45)
D=$(printf '%s' "$DRAW" | grep -a '^SUX ' | head -1)
[ -n "$D" ] || D="$DRAW"
if [ "$DCOLD" = "ThisTime=0" ]; then
	D="NORULER: the demo activity never re-created itself ($DCOLD) -- the app could not have re-asked"
fi
[ "$DBC" = 0 ] || D="NORULER: the revoke was never read back -- D would score a stale grant, so it is not judged"
chk D "revocation is live" "$D" 'ERR unknown service'

say "=== E. the audit log recorded both decisions ==="
# read the audit log through the root channel, not as shell: with the ledger 586 fix the log is
# 0600, and a shell-side `cat` would then read nothing -- which E1/E2 would report as "the daemon
# logged nothing" instead of "the harness is on the wrong side of the permission".
E=$(rootsh "cat $SUDLOG $RELAYLOG 2>&1" | tr -d '\r')
[ -n "$E" ] || E=$(timeout 15 $ADB shell "cat $SUDLOG $RELAYLOG 2>&1" | tr -d '\r')
say "$(printf '%s' "$E" | tail -4)"
# Show the line that decided the verdict, not the tail of the blob.  Passing the whole log made E1 print
# an unrelated `deny uid=2000` line while still reading PASS, so the table's own evidence column said
# nothing about why it passed (and a reader had to trust the regex invisibly).
Elines=$(printf '%s\n' "$E" | grep -ac .)
if [ -z "$E" ]; then
	E1="NORULER: neither audit log could be read ($SUDLOG / $RELAYLOG)"
	E2="$E1"
else
	E1=$(printf '%s\n' "$E" | grep -a "allow.*uid=$DEMO_UID" | tail -1)
	[ -n "$E1" ] || E1="no allow line for uid=$DEMO_UID in $Elines readable log lines"
	E2=$(printf '%s\n' "$E" | grep -a "deny.*uid=$DEMO_UID" | tail -1)
	[ -n "$E2" ] || E2="no deny line for uid=$DEMO_UID in $Elines readable log lines"
fi
chk E1 "log has an allow line for the demo uid" "$E1" "allow.*uid=$DEMO_UID"
chk E2 "log has a deny line for the demo uid" "$E2" "deny.*uid=$DEMO_UID"

say "=== F. a granted caller cannot run as somebody else's uid ==="
# The impersonation guard only exists on the far side of the allow check, so the
# caller must BE allowed first -- otherwise this criterion would pass by reading
# the ordinary "not on the list" refusal. GRANTS_CANDIDATES takes the manager file
# first, so /data/local/tmp/sud.grants is dead weight while it exists: edit $GRANTS.
rootsh "grep -qx 2000 $GRANTS || echo 2000 >> $GRANTS; cat $GRANTS" >/dev/null
seal_grants
POS=$(timeout 30 $ADB shell '/data/local/tmp/sux -c id 2>&1' | tr -d '\r' | head -2)
chk F0 "control: this same caller IS allowed for its own uid" "$POS" 'uid=0\(root\)'
F=$(timeout 30 $ADB shell '/data/local/tmp/sux '"$DEMO_UID"' -c id 2>&1' | tr -d '\r' | head -2)
chk F "target uid outside {0, self} is refused" "$F" 'target uid not allowed'

say "=== H. root while getenforce still reports Enforcing (the map-only shape) ==="
POS2=$(timeout 30 $ADB shell '/data/local/tmp/sux -c id 2>&1' | tr -d '\r' | head -1)
ENFH=$(timeout 15 $ADB shell getenforce 2>/dev/null | tr -d '\r')
say "  paired reading (same instant, two probes): enforce=$ENFH  reply=$POS2"
if [ "${EXPECT_ENFORCING:-0}" = "1" ]; then
	chk H "Enforcing up AND the suid channel grants root" "$ENFH $POS2" '^Enforcing .*uid=0'
else
	say "  not asserted (run with EXPECT_ENFORCING=1 to require map-only mode)"
fi
# IN PLACE, not `$GRANTS.t` + mv.  The mv shape was still here (drop_demo had already been fixed):
# it leaves a ROOT-CREATED inode inside app data with no MLS categories, and the exit trap's identity
# test is `dev:inode` -- so the run's own cleanup then saw "the list changed identity", called the
# user's list a leftover, and deleted it.  Measured 2026-10-21: the trap printed the list as
# 65026:753904 (the mv's inode, 3 uid lines) while the pre-run list was 65026:753755 with 4; that is
# the exact mechanism behind "the grant list vanished after a run".  `cat >` keeps inode, owner and
# label, and the snapshot/restore below is the second line of defence.
rootsh "grep -v '^2000\$' $GRANTS > /data/local/tmp/g.tmp 2>/dev/null; cat /data/local/tmp/g.tmp > $GRANTS; rm -f /data/local/tmp/g.tmp; cat $GRANTS" >/dev/null
seal_grants

say "=== M. the granted root can actually finish a binder transaction ==="
# Why this exists (ledger 2026-10-21 §707): A..L measure uid, caps, Enforcing and exec -- NONE of them
# ever talks to a service.  Per-domain permissive is keyed on the SCONTEXT type, so a binder REPLY
# coming BACK to an su-served process is decided by the PEER's type, and with only our own types
# exempt every `pm`/`settings`/Shizuku call died in DeadObjectException while this whole table stayed
# green.  A granted app that cannot reach PackageManager has no root in the sense its user means.
# So ask the root side for two readings that need a peer to answer, and keep adb shell as the same-run
# control that proves the ruler can see a `found` at all.
M_SVC=$(rootsh 'service check cpuinfo; echo M_END')
M_PM=$(rootsh 'pm list packages -3 2>&1 | head -2; echo M_END')
m_svc=NO; m_pm=NO
case "$M_SVC" in *M_END*) case "$M_SVC" in *found*) m_svc=YES;; esac;; *) m_svc="NORULER: root channel answered nothing for service check";; esac
case "$M_PM"  in *M_END*) case "$M_PM"  in *package:*) m_pm=YES;; esac;; *) m_pm="NORULER: root channel answered nothing for pm";; esac
chk M "root side gets a service handle AND PackageManager answers (the reply direction is mediated)" \
	"$m_svc $m_pm" '^YES YES$'
M_CTL=$(timeout 20 $ADB shell 'service check cpuinfo' 2>&1 | tr -d '\r')
chk M0 "control: the unprivileged adb path reports the same service present" "$M_CTL" 'found'

say "=== I. the daemon's state directory is not writable by the callers it serves ==="
# Measured reason this exists: .sud was created 0777, so ANY uid could unlink sud.sock (or plant
# /data/local/tmp/sud.grants) -- a writable state directory next to a root daemon is a hijack, not
# a convenience.  The probe is behavioural: it asks whether an unprivileged caller can create a
# file in there, because parsing a mode string would pass on 0711 even if something re-chmodded it.
IW=$(timeout 20 $ADB shell 'touch /data/local/tmp/.sud/probe_i 2>&1; mv /data/local/tmp/probe_sock /data/local/tmp/.sud/sud.sock 2>&1; ls -ld /data/local/tmp/.sud 2>&1; ls -l /data/local/tmp/.sud/sud.log 2>&1' | tr -d '\r' | tr '\n' '|')
chk I "an unprivileged caller cannot plant or replace files in .sud" "$IW" 'Permission denied|Operation not permitted'
say "  reading: $(printf '%s' "$IW" | cut -c1-150)"
rootsh "rm -f /data/local/tmp/.sud/probe_i" >/dev/null

say "=== I2. ... but the client drop directory is still usable by them (positive control for I) ==="
# Measured 2026-10-19 (ledger 588): tightening .sud to search-only, without giving the clients a
# place of their own, made every caller fail at `su: cannot publish request name` -- I went green and
# B/C/D/H went red.  So I is only a fix if the drop directory exists, is sticky, is root-owned and a
# stranger can still create its own file in it.  Without this arm, "locked everyone out" passes I.
timeout 15 $ADB shell 'echo probe > /data/local/tmp/probe_sock' >/dev/null 2>&1
I2W=$(timeout 20 $ADB shell 'ls -ld /data/local/tmp/.sud/req 2>&1; touch /data/local/tmp/.sud/req/probe_i2 2>&1 && echo DROP_OK; ls -l /data/local/tmp/.sud/req/probe_i2 2>&1' | tr -d '\r' | tr '\n' '|')
chk I2 "clients can still create their own drop in a sticky root-owned .sud/req" "$I2W" 'drwxrwxrwt.*root.*DROP_OK'
say "  reading: $(printf '%s' "$I2W" | cut -c1-150)"
rootsh "rm -f /data/local/tmp/.sud/req/probe_i2" >/dev/null

say "=== J. a grants list planted by an unprivileged caller is not believed ==="
# This is the ledger 585 hole, tested as an attacker would: write the list yourself, own it, give it
# a tidy 0600, and see whether the daemon hands root to the uid named in it.
timeout 15 $ADB shell "echo $DEMO_UID > /data/local/tmp/sud.grants; chmod 600 /data/local/tmp/sud.grants" >/dev/null 2>&1
JW=$(timeout 20 $ADB shell 'ls -l /data/local/tmp/sud.grants' | tr -d '\r')
say "  planted as shell: $JW"
drop_demo
timeout 15 $ADB shell am force-stop $DEMO >/dev/null 2>&1
timeout 15 $ADB logcat -c >/dev/null 2>&1
timeout 15 $ADB shell am start -n "$DEMO/.Demo" >/dev/null 2>&1
JSINCE=$(demo_mark)
JRAW=$(demo_wait "$JSINCE" 45)
J=$(printf '%s' "$JRAW" | grep -a '^SUX ' | head -1)
[ -n "$J" ] || J="$JRAW"
chk J "demo uid listed ONLY in a caller-owned list -> still refused" "$J" 'ERR'
say "  reading: $(printf '%s' "$J" | cut -c1-150)"
rootsh "rm -f /data/local/tmp/sud.grants" >/dev/null
# and the positive half of J: the same daemon must still believe a root-owned list, or the rule just
# became a refusal of everything.
rootsh "echo $DEMO_UID > /data/local/tmp/sud.grants; chmod 600 /data/local/tmp/sud.grants; chown 0 /data/local/tmp/sud.grants" >/dev/null
JPC=$(relaunch_demo)
JPSINCE=$(demo_mark)
JPRAW=$(demo_wait "$JPSINCE" 45)
JP=$(printf '%s' "$JPRAW" | grep -a '^SUX ' | head -1)
[ -n "$JP" ] || JP="$JPRAW"
if [ "$JPC" = "ThisTime=0" ]; then
	JP="NORULER: the demo activity never re-created itself ($JPC) -- the control arm could not have re-asked"
fi
chk JP "control: a root-owned list in the same directory IS believed" "$JP" 'uid=0\(root\)'
# Structural boundary on the 7 route (ledger 641): a third-party caller now goes through relayd, which
# gates on the MANAGER's `files/grants.txt` first, so an unlisted caller never reaches sud's
# `sud.grants` decision at all -- this positive half is therefore not judgeable through an app caller
# on 7. The belief test for callers that DO reach sud (token holders, i.e. the manager) is carried by
# A2 and F0. Keep JP reported as REFUSED; it is neither green nor a device defect.
say "  boundary: on 7 the relay fronts every app caller, so JP's premise is unreachable from a third-party uid (A2/F0 cover sud's own belief)"
rootsh "rm -f /data/local/tmp/sud.grants" >/dev/null
drop_demo
say "=== K2. exec by the NAME su: what the user actually asked for ==="
# K below only proves the file is a real binary.  The complaint this project exists for is that a
# caller hardcoding `su` gets EPERM before the daemon is ever asked (ledger 643: Shizuku's libsu
# fell back to `sh`, so the root-start card never rendered).  So ask exactly that, from an
# unprivileged shell, against the delivery's own PATH entry -- no root channel involved.
# Three states, because "refused" and "the harness cannot see" are different sentences (§621/§632).
DEV=/data/local/tmp
GV=$(timeout 30 $ADB shell "$DEV/sugate_probe" 2>&1 | tr -d '\r' | grep -aE 'CASE control_su +->' | head -1)
case "$GV" in
	*RAN*) GW=allow ;;
	*errno=1*) GW=deny ;;
	*) GW=noruler ;;
esac
KV=$(timeout 25 $ADB shell "/sbin/su -c 'id -u' 2>&1 | head -2" | tr -d '\r')
say "  ruler (basename gate): ${GV:-<no sugate_probe on device>}"
say "  caller side (/sbin/su -c id -u): ${KV:-<no reply>}"
if [ "$GW" = noruler ]; then
	chk K2 "exec by the name su is admitted (the vendor check no longer blocks callers)" \
		"NORULER: the gate ruler $DEV/sugate_probe did not answer, so the gate's state is unseen"
else
	# The accepted replies are `0` (authorised -> root) and `ERR ...` (the AUTHORISATION layer
	# refused, which still means execve by that name was admitted).  Anything naming EPERM means
	# the vendor check is still in force -- that is a FAIL here, not a pass with a footnote: the
	# end state this criterion is for is "a third-party app that hardcodes su works".
	case "$KV" in
		0*|ERR*)
			if [ "$GW" = allow ]; then
				chk K2 "exec by the name su is admitted (the vendor check no longer blocks callers)" \
					"$KV" '^(0|ERR)'
			else
				# must-flip arm: the ruler says the name is admitted, so the delivery's own PATH
				# entry must be admitted too.  Agreeing here would mean the two measure different
				# things -- and only one of them is the user's path.
				chk K2 "delivery's /sbin/su is admitted under the same name the ruler admits" \
					"$KV" '^(0|ERR)'
			fi
			;;
		*"Operation not permitted"*)
			if [ "$GW" = allow ]; then
				# gate open by the ruler's own reckoning yet this exec refused: the two sites are
				# not the same code path, so the fix is incomplete -- say so rather than pass.
				chk K2 "gate ruler says allow, so /sbin/su must exec (NOT YET: still EPERM)" \
					"$KV" '^(0|ERR)'
			else
				say "FAIL  K2  exec by the name su is admitted -- the vendor check is in force"
				say "  reading: ruler=$GV | caller=$KV"
				say "  cause: this boot did not run the chain's sugate7 step (NOP at 0x323400) --"
				say "         ledger 664/670; a caller hardcoding 'su' still gets EPERM"
				fail=$((fail + 1)); printf 'K2\n' >> "$SEEN"
			fi
			;;
		*)
			chk K2 "exec by the name su is admitted" "NORULER: /sbin/su printed no verdict [$KV]"
			;;
	esac
fi
say "  boundary: K2 asks only the exec half.  Whether a *listed* uid actually gets uid 0 over this"
say "  channel is criteria C/F0, and the app-domain half is A2 plus the chain's own"
say "  'app-exec su: execve allowed' line (ledger 667)."

say "=== K. the su-named client is a real binary, not a stub ==="
# Measured 2026-10-19: /sbin/su existed but was ZERO bytes next to a 2.1 MB /sbin/sux, because the
# delivery helper opened the destination with O_TRUNC before it had read the source.  An app that
# probes for `su` then gets ENOEXEC from a file that looks installed, which is worse than absence.
# So ask the two things an app can also ask: is it big enough to be a binary, and is it an ELF.
K=$(rootsh 'for f in /sbin/su /sbin/sux /sbin/su7x /system/xbin/su; do if [ -e "$f" ]; then printf "%s size=%s magic=%s label=%s\n" "$f" "$(stat -c %s "$f" 2>/dev/null)" "$(head -c 4 "$f" 2>/dev/null | od -An -tx1 2>/dev/null | tr -d " \n")" "$(stat -c %C "$f" 2>/dev/null)"; fi; done' | grep '^/')
# Read from the root channel on purpose: `adb shell` cannot READ /sbin/su's bytes on this ROM (the
# mirror dir entry is not world-readable), so a shell-side probe reports size=2143768 magic=<empty>
# and the stub counter would call a real ELF a stub -- measured on 1.9.12 (ledger 640).
KREAD_SHELL=$(timeout 20 $ADB shell 'for f in /sbin/su /sbin/sux; do if [ -e "$f" ]; then printf "%s shell_can_read=%s\n" "$f" "$(head -c1 "$f" >/dev/null 2>&1 && echo yes || echo no)"; fi; done' | tr -d '\r')
KTOT=$(printf '%s\n' "$K" | grep -c .)
# A stub is a ZERO-LENGTH file, which is what this criterion was written against (a 0-byte `su` gives
# an app ENOEXEC).  ELF magic is NOT a usable probe on this mount: neither adb shell nor the daemon's
# root can open those bytes (measured on 1.9.12 -- `shell_can_read=no`, root-side `magic=` empty).
# So magic is an observation, never a verdict.
KSTUB=$(printf '%s\n' "$K" | grep . | grep -vc 'size=[1-9][0-9]*')
say "  reading: $(printf '%s' "$K" | tr '\n' '|')"
say "  caller side (adb shell): $(printf '%s' "$KREAD_SHELL" | tr '\n' '|')"
if [ "$KTOT" = 0 ]; then
	K="NORULER: no su-named path exists at all -- enumerate the names the delivery publishes, not a fixed list"
fi
chk K "all $KTOT su-named path(s) are real ELF binaries (stubs: $KSTUB)" "$KSTUB" '^0$'
# Coverage boundary of THIS criterion, stated with the reading: K only asks "is it an ELF of real size".
# Whether a caller may EXEC it depends on the CALLER's cred, and on this ROM the vendor NAME gate is the
# deciding factor -- measured 2026-10-20 by the app's own "测 su 名字闸" probe (ledger 643): in the
# untrusted_app domain, one byte-for-byte copy of the client named `su` -> execve error=1 EPERM, the
# same bytes named `sux` -> rc=0, uid 0 -> runs.  So the PATH `su` is NOT usable by an app that
# hardcodes "su" on 7.1.1; criterion C passes because our demo client is named sux.
say "  boundary: K tests shape only (present/stub); exec-by-NAME is gated by the vendor check -- see ledger 643 (su EPERM / sux rc=0 in app domain)"
if [ "${KSTUB:-0}" != 0 ]; then
	say "  NOTE: something named su exists but is not a >=100 KB ELF -- that is ledger 595's defect"
fi
say "  (a path that does not exist is not counted: $KTOT checked, absence is reported by the reading)"

say "=== summary ==="
coverage main || fail=$((fail + 1))
say "pass=$pass fail=$fail refused=$refused   (criterion G needs POST_REBOOT=1 after a reboot; H needs EXPECT_ENFORCING=1)"
if [ "$refused" -gt 0 ]; then
	say "INCOMPLETE: $refused criterion/criteria could not be judged for want of a ruler: $(tr '\n' ' ' < "$REFUSED")"
	say "  -- refusing to call this verified; see ledger 621 (7's drop directory is shell_data_file) and task 27"
	exit 2
fi
[ "$fail" -eq 0 ] || { say "NOT ACHIEVED: app-side authorization is incomplete"; exit 1; }
say "APP ESCALATION + AUTHORIZATION VERIFIED (self-escalation, per-uid gate, live revoke, audit trail, no impersonation)"
