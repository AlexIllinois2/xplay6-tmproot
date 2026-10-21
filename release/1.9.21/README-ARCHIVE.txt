月虹提权助手 v1.9.21 (versionCode 41) — 源码＋全部有用信息归档包
================================================================

目标机（本包所实证的那台，出货语义只对这一形状成立）
  机型        vivo Xplay6 (PD1610)・serial 现读 3e5a38a5
  ROM         Android 7.1.1・PD1610_D_7.12.15・ro.vivo.op.entry=FULL_SC・ro.vivo.oem.name=PD1610_FULL_SC
  内核        3.18.31-perf-g9dce1fbc9・msm8996・aarch64
  边界        不解 BL・不写任何分区・只做内存态提权（`adb reboot` 即回出厂）

本版相对 1.9.19 的**唯一功能变化**（其余逐字节同）
  Chain.unlockAdbInput() —— 经 `Chain.su(0, …)` 往 Settings 自己的
  `/data/user_de/0/com.android.settings/shared_prefs/development.xml` 播种 `account_verified_ok=true`
  （`chown 1000:1000`・dir 771/file 660・`restorecon`・幂等），并回显一行证人
  `UNLOCK_ADB_INPUT st=written|already|write_failed count=<n> label=<seinfo>`；
  `EscService` 两条路都挂（`Chain.run` 之后・以及"本开机已提权"那支与 `ensureRelay` 并列）。
  ★效果＝开发者选项里「USB模拟点击」**不再要求登录 vivo 账号**，于是 adb 注入可用、装包全程无人。
  ★仍要人做的那一步＝**拨那一次开关**：Secure 值本身 root 写不了（daemon 的 root 无任何 servicemanager 查询能力）。
  取证：`art/ledger-20261021.md` §691–§705（判决点・登录门禁只在 UI・`user_de` 存储・重启对照・终证三枚连串）。

包里有什么（415 枚文件・压缩包约 9.0 MB）
  release/1.9.21/月虹提权助手-v1.9.21-release.apk   出货 APK＝手机上在跑的那一枚（`versionCode=41`・md5 d57d63785f80b6a1c5f0c0ebc13ac318）
  release/1.9.21/{STATUS,README-build.txt,INTEGRITY.txt,README-ARCHIVE.txt(本文件),SHA256SUMS.txt,ARCHIVE-SHA256.txt}
  release/*/  各版的交付文档（版次史，不含旧 APK）
  tools/      全部 C／头文件／汇编・构建与验收脚本・APK 的 Java 源＋manifest＋debug.keystore・demo 源・自测臂
              本版关键件：apk/src/com/xplay6/temproot/{Chain,EscService}.java（新能力）・
                          install_tap.py（`TAPBACKEND=adb` 默认・判据抽成 `candidates()`・`--selftest` 五臂）・
                          unlock_adb_input.py（`--feed`/`--check`）・gate_verdict.sh（闸的纯函数判决・七臂自检）・
                          install_and_verify.sh（push 前的前置闸）・pack_release.sh（★清单改为从盘上推导）・
                          clobber.c / gate_constants.py / pgdalias.py / sud.c / relayd.c / suc.c / broot7.c
  art/ledger-2026101[3-6].md・art/ledger-20261021.md  完整取证台账（§1–§705）
  art/UNLOCK-ADB-INPUT.md  「解开 USB模拟点击」的一次性程序与四条边界
  art/kallsyms_real.txt・art/kallsyms-7-real.txt  两档内核符号表现留底（pgdalias 的第二来路）
  art/PORT-RUNBOOK-7.md  换 7 之后的音频复现核对序
  art/approot-1.9.21-main.txt  ★本版主模式验收表的现场留底（17 PASS・`coverage: 17/17 (mode=main)`・不含 G）
  art/chain-1.9.19-boot.txt・art/chain-1.9.17-bootB.txt・art/approot-1.9.17-{main,GH}.txt
              更早几版的开机链与验收表留底（★`pack_release.sh` 的证据清单已改为从盘上推导，不再手写名单）
  pocs/       内核侧 PoC 的 C 源（不含编译产物）

字节政策（§676/§682/§690 延续）
  与 1.9.19 出货包逐成员对照，**7 枚原生件全部 SAME**：`assets/broot7 4ba5e535…`・`lib/arm64-v8a/libesc.so 95d7a617…`・
  `assets/{su,sud,sumount,relayd,nsmbind}` 各自 md5 一致；只有 `AndroidManifest.xml`（版本）・`classes.dex`（新能力）・签名块不同。
  ⇒ 本版**没有**新的内核写通路、没有新地址；`gate_constants` 在构建入口真跑（18 对 vs pgdalias 两档 profile → AGREE），未用 `SKIP_GATE`。

验收状态（本版实测）
  · 新能力那条链：已按设备现读判成（`release/1.9.21/STATUS` 第 1–6 条）。
  · 整机主模式表**已在 1.9.21 上重跑**：`EXPECT_ENFORCING=1 bash tools/verify_approot.sh` →
    `coverage: 17/17 criteria reported (mode=main)`・`pass=17 fail=0 refused=0` → `APP ESCALATION + AUTHORIZATION VERIFIED`。
  · ★**G（重启自愈）不在那 17 枚分母里**：它要 `POST_REBOOT=1` ＋一次真实重启才跑，本版**没跑那一发**（1.9.17/1.9.19 各自跑过并记绿，**不迁移**到本版）。
    ⇒ 本包的出货语义＝"主模式 17/17 全绿・重启自愈待补"，不是"含 G 的全绿"。

已知边界（不是欠项，是明说的边界）
  · 解开后**任何接上这台机的 ADB 都能注入点击**（厂商留的安全边界，我们只是把它从"要登录"降到"要拨一次"）。
  · `adb root` 在这台机上结构性不可能（adbd 起来即自降到 uid 2000）；代它发 `ctl.restart adbd` 会把 USB 整个打掉、要人重启才回（§699/§700）。
  · 音频线仍欠 LATE 窗判据与 `.cnt`／mixer XML 两层（换 7 的不可得边界，见 `art/PORT-RUNBOOK-7.md`）。
  · §696 那格"设过 `svc power stayon true` 之后读到 0"成因未解，别当已解释。

校验
  在 `release/1.9.21/` 内 `sha256sum -c SHA256SUMS.txt`（路径是裸文件名，别在仓库根跑）；
  归档自身 sha256 见 `ARCHIVE-SHA256.txt`；`INTEGRITY.txt` 的 A/B 两节由 `pack_release.sh` 末步自核。
