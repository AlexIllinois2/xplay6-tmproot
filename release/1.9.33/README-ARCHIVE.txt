xplay6 tmproot v1.9.33 (versionCode 53) — 源码＋全部有用信息归档包
====================================================================

本版是「界面重构＋改名」的壳版本:
  应用显示名由「月虹提权助手」统一改为 xplay6 tmproot（中英同串），包名 com.xplay6.temproot 不变；
  UI 改为 KernelSU 风格的底部导航三页（首页 / 应用 / 设置）＋全屏日志；卡片、开关、图标全部 Canvas 自绘
  （纯 framework View，无 AndroidX/Compose）。提权链与包内 7 枚原生件未改，与 1.9.32 逐字节相同。

目标机（本包所实证的那台，出货语义只对这一形状成立）
  机型        vivo Xplay6 (PD1610)・serial 现读 3e5a38a5
  ROM         Android 7.1.1・PD1610_D_7.12.15・ro.vivo.op.entry=FULL_SC・ro.vivo.oem.name=PD1610_FULL_SC
  内核        3.18.31-perf-g9dce1fbc9・msm8996・aarch64
  边界        不解 BL・不写任何分区・只做内存态提权（`adb reboot` 即回出厂）

包里有什么（成员数由 pack_release.sh 现枚举）
  release/1.9.33/xplay6-tmproot-v1.9.33-release.apk   出货 APK（`versionCode=53`・sha256 ef03090c3585094c…）
  release/1.9.33/{STATUS,README-build.txt,INTEGRITY.txt,README-ARCHIVE.txt(本文件),SHA256SUMS.txt,ARCHIVE-SHA256.txt}
  release/*/  各版的交付文档（版次史，不含旧 APK；1.9.32 及以前的 APK 名仍是「月虹提权助手-vX-release.apk」）
  tools/      全部 C／头文件／汇编・构建与验收脚本・APK 的 Java 源＋manifest＋debug.keystore・demo 源・自测臂
              本版关键件：apk/src/com/xplay6/temproot/Ui.java（新增）・Main.java（重写）・
                          apk/AndroidManifest.xml（显示名与版本）・pack_release.sh（产物名跟随 label）
  art/ledger-20261021.md 完整取证台账（1.9.32 正文 §707–§715；本版补记 §717）
  art/kallsyms_real.txt・art/kallsyms-7-real.txt  两档内核符号表现留底
  art/PORT-RUNBOOK-7.md  换 7 之后的音频复现核对序
  art/approot-1.9.32-main.txt・art/chain-1.9.19-boot.txt …  更早版本的验收与开机链留底
  pocs/       内核侧 PoC 的 C 源（不含编译产物）

验收状态（本版实测）
  · 构建入口两道闸真跑；包内 7 枚型豁免数组恰出现一次（`[7/7]`）。
  · 设备 3e5a38a5 装机成功：`landed=2 refused=0`・`installed versionCode: 53`；应用启动正常。
  · 三页＋日志页人工查看正常；首页 Root 已就绪 / Enforcing / su 在 PATH / 4 个已授权应用。
  · ★本版**未重跑** 19/19 整机验收表、未跑 G（重启自愈）——机主 2026-10-21 明确「改完不用回归测试」。
    业务逻辑与原生件未改（与 1.9.32 逐字节同），但 1.9.32 的绿**不迁移**为本版读数。

已知边界（不是欠项，是明说的边界）
  · 内存态：`adb reboot` 即复原；`getenforce` 全程 Enforcing。
  · 7 枚型 per-domain permissive 是本修复线的代价（同 1.9.32）：这些域整体对 MAC 宽松，不只 su 一条。
  · 音频线仍欠 LATE 窗判据与 `.cnt`／mixer XML 两层（换 7 的不可得边界，见 `art/PORT-RUNBOOK-7.md`）。

校验
  在 `release/1.9.33/` 内 `sha256sum -c SHA256SUMS.txt`（路径是裸文件名，别在仓库根跑）；
  归档自身 sha256 见 `ARCHIVE-SHA256.txt`；`INTEGRITY.txt` 的 A/B 两节由 `pack_release.sh` 末步自核。
