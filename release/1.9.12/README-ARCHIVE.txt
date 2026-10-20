月虹提权助手 v1.9.12 (versionCode 33) — 源码＋全部有用信息归档包
================================================================

目标机（本包所实证的那台，出货语义只对这一形状成立）
  机型        vivo Xplay6 (PD1610)
  ROM         Android 7.1.1・PD1610_D_7.12.15・ro.build.version.incremental=eng.compil.20181107.005721
  内核        3.18.31-perf-g9dce1fbc9・msm8996・aarch64
  边界        不解 BL・不写任何分区・只做内存态提权（`adb reboot` 即回到出厂）

包里有什么
  release/1.9.12/月虹提权助手-v1.9.12-release.apk   出货 APK（versionCode 33）
  release/1.9.12/{STATUS,README-build.txt,SHA256SUMS.txt,NOTE.txt}
  release/*/  各版的 README-build.txt・STATUS・SHA256SUMS.txt（版次史与每版的交付语义，不含旧 APK）
  tools/      全部 C/头文件/汇编・构建与验收脚本（.sh/.py）・APK 的 Java 源与 manifest・demo 源・自测臂
  art/        台账（ledger-*.md，含 §629–§642 这轮 relay 与判据的完整取证）与 PORT-RUNBOOK-7.md
  pocs/       内核侧 PoC 的 C 源（不含编译产物）
  不含        编译好的 ELF（`tools/build_all.sh` 现编）・APK assets（由 build.sh 从现编件拷入）・
              设备留底数据（live 捕获／音频基线）・NDK/SDK・内核整包源码・
              art/*.txt（55 个 ~17.8 MB 的草稿留底；权威记录是 art/ledger-*.md，交付表是 art/*.tsv，两样都在包里）

重建（一台干净机器上）
  1) 需要 Android NDK 29.0.13846066（`$SDK/ndk/.../bin/aarch64-linux-android21-clang`）与 Android SDK（aapt/zipalign/apksigner）。
  2) bash tools/build_all.sh        # 产出 broot7 / sud / suc / sumount / nsmbind / relayd / rootsh …（-static 是刻意的）
  3) bash tools/apk/build.sh        # 组 assets + dex + libesc.so + 对齐 + 签名 → tools/temproot.apk
  4) 校验与包内 SHA256SUMS.txt 一致

装机（本 ROM 上实测可无人）
  adb -s <ser> push release/1.9.12/月虹提权助手-v1.9.12-release.apk /data/local/tmp/temproot-1.9.12.apk
  adb -s <ser> shell pm install -r -t /data/local/tmp/temproot-1.9.12.apk      # 已装包的 -r 重装不需要屏上确认
  （首装／未知来源那一发才需要 §620 记的两段点框：先『继续安装』再点文案恰好是『安装』的那枚）

验收（判据都在这台机上真跑过）
  bash tools/verify_approot.sh <ser>                        # main 模式：A1 A2 B C D E1 E2 F0 F I I2 J K
  POST_REBOOT=1 bash tools/verify_approot.sh <ser>          # 重启复原＋开机自愈那一格 G
  EXPECT_ENFORCING=1 bash tools/verify_approot.sh <ser>     # Enforcing 保持且通道给 root 那一格 H
  bash tools/verify_approot.sh --selftest                   # 覆盖闸有无牙齿＋分类臂（现 16 枚在册）
  判据枚数与分母由尺自己报（`coverage: N/M`），不达标就 exit 2 报 INCOMPLETE，不会假绿。

这轮实测出来的交付形状（一句话版）
  · 提权：binder UAF 起针 → 现写 `policydb.permissive_map` 豁免 → 就地改自己 cred → `uid=0` 且把 `selinux_enforcing` 翻回 1 → 起 `sud`（TCP 12345/12346）。
  · 第三方 su 通道：提权后那枚 cred 能 create/connect/accept AF_UNIX，但 `bind(SOCK_STREAM)` 一律 EPERM（§623–§626）⇒ 由 **manager app 自己** bind 抽象 `@sud`
    （`relayd`），用 `SO_PEERCRED` 取调用方 uid、查 `files/grants.txt`，再以 manager 的 token 走 12346 让 `sud` 执行；`sud` 与协议一行没改。
  · 耐久：`relayd` 是 app 的子进程 ⇒ app 进程被回收（含装新 APK）通道即断；`Chain.ensureRelay()` 挂在开机触发器与 `EscService` 的 alive 分支上，一发 `am startservice` 即回。
  · 自愈取舍（用户已定）：同一次开机内 daemon 死亡**最多再花一枚针**（针有实测崩率），用完就明写"只剩人手点『提权』"，恢复也可靠重启。

已知未判／小债（别当已闭）
  · `JP`（"daemon 同目录下 root 拥有的名单仍被相信"）在 7 上是**结构性判不了**：第三方调用先过 relayd 的名单，未列名根本到不了 `sud` 的判定；直达侧由 `A2/F0` 覆盖。尺里写明边界，不计绿不计红。
  · `tools/nsmbind.c:114` 有 unused-`dst` 警告（一次 overlay 全名字的改法落地后留下的）。
  · `E1/E2` 的显示括号打的是日志首行而非命中行（口径待改，望文本身是对的）。

敏感件说明
  · `tools/apk/debug.keystore` 是本实验自签的 lab key（出货包同一枚证书），不是任何外部服务凭据；包里没有任何 token／grants 的真实内容（token 装机时现生成，`grants.txt` 只放装机那台机的 uid）。
