月虹提权助手 v1.9.32 (versionCode 52) — 源码＋全部有用信息归档包
================================================================

目标机（本包所实证的那台，出货语义只对这一形状成立）
  机型        vivo Xplay6 (PD1610)・serial 现读 3e5a38a5
  ROM         Android 7.1.1・PD1610_D_7.12.15・ro.vivo.op.entry=FULL_SC・ro.vivo.oem.name=PD1610_FULL_SC
  内核        3.18.31-perf-g9dce1fbc9・msm8996・aarch64
  边界        不解 BL・不写任何分区・只做内存态提权（`adb reboot` 即回出厂）

本版修的这句话（机主原话）
  「提权后显示 root 可用 snub 和 shizuku 里用不了高权限」＋「snub 实际点冻结的时候提示没有权限」。
  真因（§707）＝**binder 回包方向**的 MAC：per-domain permissive 按 scontext 的型判，回包由对端
  （servicemanager / system_server / init / untrusted_app …）决定；只豁免自己那几个域，root 侧自己的
  调用全绿，而任何需要服务回包的调用都死。修法＝把**对端集合**（7 枚）一起 pin 进本机 permissive_map。
  逐条读数见 `release/1.9.32/STATUS` 与 `art/ledger-20261021.md` §707–§715。

包里有什么（424 枚文件・压缩包约 9 MB）
  release/1.9.32/月虹提权助手-v1.9.32-release.apk   出货 APK（`versionCode=52`・sha256 0b61f57f952fd04c…）
  release/1.9.32/{STATUS,README-build.txt,INTEGRITY.txt,README-ARCHIVE.txt(本文件),SHA256SUMS.txt,ARCHIVE-SHA256.txt}
  release/*/  各版的交付文档（版次史，不含旧 APK）
  tools/      全部 C／头文件／汇编・构建与验收脚本・APK 的 Java 源＋manifest＋debug.keystore・demo 源・自测臂
              本版关键件：ebitmap_map.h（ebmp_maps_word）・broot7.c（7 位集／双读拒答／cgroup 全枚举）・
                          sud.c（escape_app_cgroup）・ebitmap_chain_test.c（check_units_view 四档）・
                          exempt_bits_check.py（三处对照＋--verify-apk）・verify_approot.sh（0b／快照还原／M/M0）・
                          binder_peers.sh（22 发电池）
  art/ledger-20261021.md 完整取证台账（§707–§715 是本版正文）
  art/kallsyms_real.txt・art/kallsyms-7-real.txt  两档内核符号表现留底
  art/PORT-RUNBOOK-7.md  换 7 之后的音频复现核对序
  art/approot-1.9.32-main.txt  ★本版主模式验收表现场留底（19 PASS・`coverage: 19/19 (mode=main)`・不含 G）
  art/chain-1.9.19-boot.txt・art/chain-1.9.17-bootB.txt・art/approot-1.9.17-{main,GH}.txt・art/approot-1.9.21-main.txt
              更早几版的开机链与验收留底（打包清单从盘上推导，不手写）
  pocs/       内核侧 PoC 的 C 源（不含编译产物）

验收状态（本版实测）
  · 整机主模式表已在本版重跑：`EXPECT_ENFORCING=1 bash tools/verify_approot.sh` →
    `coverage: 19/19 criteria reported (mode=main)`・`pass=19 fail=0 refused=0` → `APP ESCALATION + AUTHORIZATION VERIFIED`。
  · Shizuku：server 进程 `/proc/10015` 为 `Uid=0000`・`u:r:init:s0`・`ppid=1`；界面自读 `Shizuku 正在运行`・`版本 13.6，root`。
  · snub：uid 10135 点冻结成功、目标包 `enabled=2`；机主 2026-10-21 亲手确认「有权限了」。
  · ★**G（重启自愈）不在那 19 枚分母里**：它要 `POST_REBOOT=1` ＋一次真实重启才跑，本版**没跑那一发**（1.9.17/1.9.19
    各自跑过并记绿，**不迁移**）。⇒ 本包出货语义＝"主模式 19/19 全绿・重启自愈待补"。
  · adb 侧 `run_credread7.sh` 的 `EXEMPT_BITS` 本版未在设备实跑（出货侧由 broot7 自证覆盖）。

已知边界（不是欠项，是明说的边界）
  · 7 枚型成为 per-domain permissive 是本修复的代价：这些域整体对 MAC 宽松，不只 su 一条。
  · 内存态：`adb reboot` 即复原；`getenforce` 全程 Enforcing。
  · 授权名单是机主的文件（`10133 10135 10151 10134`）；本版工装只读它、跑完逐字节还原（§715 的真因与修法写进账本）。
  · 音频线仍欠 LATE 窗判据与 `.cnt`／mixer XML 两层（换 7 的不可得边界，见 `art/PORT-RUNBOOK-7.md`）。

校验
  在 `release/1.9.32/` 内 `sha256sum -c SHA256SUMS.txt`（路径是裸文件名，别在仓库根跑）；
  归档自身 sha256 见 `ARCHIVE-SHA256.txt`；`INTEGRITY.txt` 的 A/B 两节由 `pack_release.sh` 末步自核。
