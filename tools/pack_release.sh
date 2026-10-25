#!/usr/bin/env bash
# Pack the v1.9.19 source+docs archive exactly the way 1.9.12..1.9.17 were packed.
# Two rules carried over from ledger 682 (both came from being burned):
#   * SHA256SUMS.txt / ARCHIVE-SHA256.txt must NOT be inside the tar (a tar cannot contain its own hash),
#     and the paths they carry are bare file names to be checked INSIDE release/1.9.19/.
#   * slim pack: no fw/Image, no fw/7/Image -- their sha256 goes into INTEGRITY.txt section B instead.
set -eu
cd /home/v/.local/project/xplay6
# derived, never remembered: the version this packer ships is whatever the manifest says the APK is.
# (A hardcoded V would happily re-pack an old release after a bump and the hashes would still "verify".)
V=$(sed -n 's/.*android:versionName="\([^"]*\)".*/\1/p' tools/apk/AndroidManifest.xml | command head -1)
CODE=$(sed -n 's/.*android:versionCode="\([^"]*\)".*/\1/p' tools/apk/AndroidManifest.xml | command head -1)
# artifact name follows the app's display name for the same reason as the version: a literal here would
# keep shipping files called 月虹提权助手 after a rename. Spaces become '-' so the name stays shell/tar safe.
LABEL=$(sed -n 's/.*android:label="\([^"]*\)".*/\1/p' tools/apk/AndroidManifest.xml | command head -1)
[ -n "$V" ] && [ -n "$CODE" ] || { echo "pack aborted: versionName/versionCode not readable from tools/apk/AndroidManifest.xml"; exit 1; }
[ -n "$LABEL" ] || { echo "pack aborted: application label not readable from tools/apk/AndroidManifest.xml"; exit 1; }
SLUG=$(printf '%s' "$LABEL" | tr ' ' '-')
OUT="release/$V"
APK="$OUT/$SLUG-v$V-release.apk"
TAR="$OUT/$SLUG-v$V-src-docs.tar.gz"
LIST=/tmp/pack-$V-members.txt
[ -f "$APK" ] || { echo "pack aborted: $APK is not there -- build and stage the APK before packing"; exit 1; }
echo "packing v$V (versionCode $CODE, label '$LABEL')"

: > "$LIST"
# tools: every source and every script, no build products
find tools -maxdepth 1 -type f \( -name '*.c' -o -name '*.h' -o -name '*.S' -o -name '*.sh' -o -name '*.py' \) >> "$LIST"
# the APK's own tree (java + jni + manifest + build.sh + the debug keystore) and the demo app
{
  echo tools/apk/AndroidManifest.xml
  echo tools/apk/build.sh
  echo tools/apk/debug.keystore
  echo tools/apk/jni/jni_esc.c
  find tools/apk/src -name '*.java'
  # 模块引擎随 APK 打进 assets（modmount/modcust/modlist/modboot），它们也是源码，
  # 归档里没有就等于只给了编译产物、没给可改的源。
  find tools/apk/assets -maxdepth 1 -type f -name '*.sh' >> "$LIST"
  echo tools/apk/demo/AndroidManifest.xml
  echo tools/apk/demo/build.sh
  find tools/apk/demo/src -name '*.java'
} >> "$LIST"
# route 8（8.1 / 3.18.71）的内核写原语源码与实测说明：APK 里是 esc8.c，这里补齐
# 同一路线的实验源码（w2215 等），否则换机重打时只剩结论、没有过程。
find exp8 -maxdepth 1 -type f \( -name '*.c' -o -name '*.s' -o -name '*.md' \) >> "$LIST"
# 8.1 内核的构建配置与符号表（地址推导的原始依据；Image 太大不入包）
echo ota8/config.txt >> "$LIST"
echo ota8/syms8.txt >> "$LIST"
# evidence the release claim rests on
{
  # ledgers and procedure docs are DERIVED from disk, not remembered: the hand-written list stopped at
  # ledger-20261016, so v1.9.21 packed without the very evidence its own release claim rests on
  # (art/ledger-20261021.md §691-§703 and art/UNLOCK-ADB-INPUT.md).  The version was already derived
  # from the manifest for the same reason -- a stale literal still "verifies".
  find art -maxdepth 1 -name 'ledger-*.md' | sort
  find art -maxdepth 1 -name 'UNLOCK-*.md' | sort
  # recovered symbol tables and live-policy authorities: derived, not enumerated -- the 1.17.12
  # trio (kallsyms + policy tsv + the dump it parses) is evidence for this release the same way
  # kallsyms-7-real.txt is for the 7.x routes, and a hardcoded pair here would ship without them.
  find art -maxdepth 1 -name 'kallsyms*-real.txt' | sort
  find art -maxdepth 1 \( -name 'policy-types-*-live.tsv' -o -name 'pol*-live.bin' \) | sort
  echo art/PORT-RUNBOOK-7.md
  # same rule as the ledgers above: derive the on-device evidence from disk.  The hardcoded pair here
  # would have shipped v1.9.21 without the acceptance run that its own STATUS cites.
  find art -maxdepth 1 \( -name 'chain-*.txt' -o -name 'approot-*.txt' \) | sort
} >> "$LIST"
find pocs -type f \( -name '*.c' -o -name '*.h' \) >> "$LIST"
# per-version delivery documents, old APKs excluded; THIS version's APK included
find release -maxdepth 2 -type f \( -name 'README-build.txt' -o -name 'README-ARCHIVE.txt' \
     -o -name 'STATUS' -o -name 'INTEGRITY.txt' \) >> "$LIST"
echo "$APK" >> "$LIST"
find release -maxdepth 2 -type f -name 'SHA256SUMS.txt' ! -path "release/$V/*" >> "$LIST"

sort -u "$LIST" -o "$LIST"
missing=0
while read -r f; do [ -f "$f" ] || { echo "MISSING MEMBER: $f"; missing=1; }; done < "$LIST"
[ "$missing" = 0 ] || { echo "pack aborted: the member list names files that do not exist"; exit 1; }
echo "members: $(wc -l < "$LIST")"

tar -czf "$TAR" -T "$LIST"
echo "archive: $(du -h "$TAR" | cut -f1)"

( cd "$OUT" && sha256sum "$SLUG-v$V-release.apk" "$SLUG-v$V-src-docs.tar.gz" > SHA256SUMS.txt )
( cd "$OUT" && sha256sum "$SLUG-v$V-src-docs.tar.gz" > ARCHIVE-SHA256.txt )
sed -i "1i # 在此目录内校验：sha256sum -c SHA256SUMS.txt（这两行是交付面文件，随包附在 tar 外面，不进 tar，否则自指）" "$OUT/SHA256SUMS.txt"

# INTEGRITY section A: the files the delivery claim actually turns on.
{
  echo "# 从解开的树根运行：sha256sum -c --ignore-missing release/$V/INTEGRITY.txt（B 段两枚镜像不在包里，故 --ignore-missing）"
  echo "# INTEGRITY -- v$V 归档包的逐字节对账"
  echo "# A) 包内关键件（下面这些无 # 前缀的行就是校验行，\`sha256sum -c\` 直接吃本文件）："
  sha256sum "$APK"
  sha256sum tools/clobber.c tools/esc8.c tools/esc.h tools/copy_atomic.h tools/borrow_verdict.h \
            tools/hp_gain7.py tools/pgdalias.py tools/gate_constants.py tools/exempt_bits_check.py \
            tools/gen_policy_tsv.py tools/run_temproot.sh \
            tools/verify_approot.sh tools/rehearse_sugate.sh tools/port_check.sh tools/build_all.sh \
            tools/apk/jni/jni_esc.c tools/apk/build.sh \
            tools/apk/src/com/xplay6/temproot/Chain.java \
            tools/apk/src/com/xplay6/temproot/Esc.java \
            tools/apk/src/com/xplay6/temproot/BootJob.java \
            tools/apk/src/com/xplay6/temproot/Main.java \
            tools/apk/src/com/xplay6/temproot/EscService.java \
            tools/apk/src/com/xplay6/temproot/Modules.java \
            tools/apk/assets/modmount.sh tools/apk/assets/modcust.sh \
            tools/apk/assets/modlist.sh tools/apk/assets/modboot.sh \
            tools/sud.c tools/relayd.c tools/broot7.c tools/suc.c tools/sumount.c tools/nsmbind.c \
            exp8/w2215.c exp8/kgsl-plan.md ota8/config.txt ota8/syms8.txt \
            art/kallsyms-7-real.txt art/kallsyms_real.txt art/kallsyms-1712-real.txt \
            art/policy-types-1712-live.tsv art/pol1712-live.bin art/chain-1.9.19-boot.txt
  echo
  echo "# B) 不在包里（机主选择瘦包）。这两枚是 tools/pgdalias.py 与构建入口那道闸的权威依据；自己从同 ROM 的"
  echo "#    boot.img 取出 kernel 后，必须与下面两行逐字节相同，否则站点推导就没有意义（镜像不同＝地址不同）。"
  sha256sum fw/7/Image fw/Image fw/1712/Image
  echo
  echo "# 1.17.12 路线（v1.9.39 起）的权威依据 fw/1712/Image 同上：不在包里，哈希在 B 段；"
  echo "#    gate_constants.py 的 6.0.1-1712 臂与 exempt_bits_check.py 的 1712 臂用它和 A 段的"
  echo "#    kallsyms-1712-real.txt / policy-types-1712-live.tsv 重新推导全部三个地址与豁免位。"
  echo "#    拿到镜像后先跑这三条，它们会自己说不说话："
  echo "#      python3 tools/pgdalias.py --profile 7        （站点 0xffffffc000323400 的四项现读断言）"
  echo "#      python3 tools/gate_constants.py --selftest   （18 对比较 + 9 枚臂，含耳机增益那一枚）"
  echo
  echo "# C) 归档包本身的 sha256 见同目录 ARCHIVE-SHA256.txt（在 tar 外面，随包一起发）。"
} > "$OUT/INTEGRITY.txt"

echo "--- INTEGRITY self-check from the repo root ---"
sha256sum -c --ignore-missing "$OUT/INTEGRITY.txt" | command tail -3
echo "members packed: $(tar -tzf "$TAR" | wc -l)"
