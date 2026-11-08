# xplay6-tmproot

[English](README.md) | **简体中文**

面向 **vivo Xplay6（PD1610，msm8996）** 的内存态临时 root 工具链。它不解 BL、不写入任何分区：全部效果只存在于运行内存和当前 SELinux 策略表中，重启即回到出厂状态。

这是针对特定机型的取证/研究代码，不是通用 root 方案。应用曾用名 **月虹提权助手**，自 v1.9.33 起显示名统一为 `xplay6 tmproot`（包名不变：`com.xplay6.temproot`）。

## 仓库包含什么

| 部分 | 路径 | 用途 |
| --- | --- | --- |
| 管理器 APK | `tools/apk/` | Java 界面、manifest、JNI 桥，以及打进 APK 的 assets。构建产物为 `tools/temproot.apk`。 |
| 原生提权源码 | `tools/*.c`、`tools/*.h`、`tools/*.S` | 内核写入/凭证借用代码、随包守护进程、`su` 客户端和辅助程序。 |
| 构建脚本 | `tools/build_all.sh`、`tools/apk/build.sh`、`tools/build_magisk_module.sh` | 原生件构建、APK 构建、Magisk 运行时模块构建。 |
| Magisk 模块支持 | `tools/apk/assets/modmount.sh`、`modboot.sh`、`modcust.sh`、`modlist.sh`、`tools/build_magisk_module.sh` | Magisk 格式模块引擎，以及用户态 Magisk 30.7 运行时（不修改 boot 镜像）。 |
| 验收与安装 | `tools/verify_approot.sh`、`tools/install_and_verify.sh`、`tools/install_magisk_module.sh`、`tools/run_temproot.sh` | 整机验收、APK 安装、模块安装和 adb 侧提权路线。 |
| 发行版 | `release/*/` | 各版本 APK 及对应的构建/状态/完整性文档；最新产物在 `release/1.9.39/`。 |
| 研究资料 | `art/`、`exp8/`、`ota8/`、`pocs/` | 取证台账、内核符号留底、活策略导出、8.1 研究笔记和公开 CVE PoC 源码。 |

应用源码树当前在 [AndroidManifest.xml](file:///home/v/.local/project/xplay6/xplay6-tmproot/tools/apk/AndroidManifest.xml) 中声明 **v1.9.40**；本仓库内最新已打包发行版为 **v1.9.39**。

## 支持的机型与固件

只接受下列 vivo Xplay6（PD1610）固件/内核组合。其它内核一律拒绝：代码不会猜测地址或偏移。

| ROM | Android | 内核 | 路线 |
| --- | --- | --- | --- |
| `PD1610_D_1.15.1` | 6.0.1 | `3.18.20-perf-gb6998a3` | 路线 6：`modprobe_path` / 用户态 helper |
| `PD1610_D_1.17.12` | 6.0.1 | `3.18.20-perf-geb775ef-dirty` | 路线 6，按运行内核的 UTS release 自选档案 |
| `PD1610_D_7.12.15` | 7.1.1 | `3.18.31-perf-g9dce1fbc9` | 路线 7：内核内自提权，并用 per-domain `permissive_map` 豁免 |
| `PD1610_D_8.19.16` | 8.1 | `3.18.71-perf-g8a8c60dd` | 路线 8：CVE-2019-2215 binder UAF 作为内核写 |

路线选择由 `Chain.java` 根据运行内核 release 决定。`3.18.71` 内核若构建标签不是精确的 `3.18.71-perf-g8a8c60dd`，会被拒绝，而不会降级到其它路线。

各路线已记录的边界：

- 路线 8 全局放开 SELinux（`selinux_enforcing=0`），并保持到重启；它没有 per-domain 豁免。
- 路线 7 会让 7 个 SELinux 类型进入 per-domain permissive；这些类型整体对 MAC 宽松，不只 `su` 一条。
- 8.1 上厂商的 exec 名字闸仍拒绝字面名 `su`，被授权应用需改用 `sux`。
- 路线 6 的 su 名字闸只在 1.15.1 上验证过；1.17.12 未移植该点位，这条臂会明确 refuse。
- 1.17.12 上 `adb install -r` 可能静默返回 `INSTALL_FAILED_CANCELLED_BY_USER`；先卸载（`adb uninstall com.xplay6.temproot`）再安装。

## 构建

要求（见 [README-build.txt](file:///home/v/.local/project/xplay6/xplay6-tmproot/README-build.txt)）：

- Android SDK build-tools **35.0.0**
- Platform **android-34**（`android.jar`）
- NDK **29.0.13846066**
- 路径可用 `SDK`、`BT`、`PLAT`、`NDK_VER`、`ROOT`、`OUT` 环境变量覆盖。

先编原生件（原生部分的唯一入口）：

```bash
SDK=/path/to/Android/Sdk bash tools/build_all.sh
```

再编 APK：

```bash
SDK=/path/to/Android/Sdk bash tools/apk/build.sh
```

产物为 `tools/temproot.apk`。若 `tools/` 下的原生件缺失或比源码旧，`tools/apk/build.sh` 会自行调用 `tools/build_all.sh`。仓库根目录另有便捷封装：

```bash
bash build.sh   # 等价于：SKIP_GATE=1 SDK=$HOME/Android/Sdk bash tools/apk/build.sh
```

**构建门禁：** `tools/apk/build.sh` 正常会从 `fw/Image`、`fw/7/Image`、`fw/1712/Image`（不在本仓库内，哈希见 `release/1.9.39/INTEGRITY.txt`）以及 `art/` 的符号/策略留底重新推导内核地址和 SELinux 豁免编号。镜像缺失时门禁会 ABORT。`SKIP_GATE=1` 会跳过重推并打印警告；这样构建出的产物不能当作“常量已核对”的交付件。

Magisk 运行时模块（需要 Magisk APK 和已构建的原生件）：

```bash
MAGISK_APK=/path/to/Magisk-v30.7.apk bash tools/build_magisk_module.sh
# 可选：bash tools/build_magisk_module.sh --install
```

签名：本仓库包含 `tools/apk/debug.keystore`（口令 `android`）。若该文件缺失，`tools/apk/build.sh` 会用相同 DN（`CN=TempRoot`）重新生成密钥，因此重建件内容逐字节一致、但签名证书不同。

## 使用

1. 安装 `tools/temproot.apk`（或 `release/` 下的发行版 APK）。
2. 打开应用点 **「提权」**。成功时显示 `Root 已就绪`；部分路线要等守护进程起来后 SELinux 才回到 `Enforcing`。
3. 在 **「应用授权」** 页勾选要授权的应用，名单立即生效。
4. 被授权应用通过本项目的通道调用 `su`；8.1 上请用 `sux`。以 root 身份运行的进程会被有意拒绝。
5. 如需重启后自动重新提权，请在 **i管家 → 权限管理 → 自启动** 中放行本应用。卸载重装会让这个厂商开关恢复为关闭。
6. 重启后一切消失。不存在持久 root、boot 镜像补丁或分区写入。

adb 侧路线和验收脚本也可用：

```bash
bash tools/run_temproot.sh <serial>          # 纯 adb 内存态提权路线
bash tools/install_and_verify.sh <serial>    # 自动选最新发行版 APK、安装并验收
bash tools/verify_approot.sh <serial>        # 验收判据；加 EXPECT_ENFORCING=1 判 Enforcing 下拿 root
```

## 目录结构

```text
xplay6-tmproot/
├── build.sh                 # 便捷 APK 构建封装（SKIP_GATE=1）
├── README-build.txt         # 历史 v1.6 构建说明（中文）
├── MANIFEST.txt             # 归档源码/文档成员的 SHA-256 清单
├── tools/                   # 原生源码、脚本、APK 的 Java/JNI/manifest、模块引擎
│   └── apk/                 # 管理器 APK 源码与构建
├── release/                 # 各版本 APK 与构建/状态/完整性文档
├── art/                     # 取证台账、kallsyms 与活策略留底、runbook
├── exp8/                    # 8.1 利用研究（CVE-2019-2215、KGSL 笔记）
├── ota8/                    # 8.1 配置与符号表
└── pocs/                    # 公开 CVE PoC 源码
```

`art/*.md` 是项目的取证证据链，主要以中文书写。`release/*/README-build.txt` 与 `STATUS` 同样是中文，记录每个版本实际验证过的内容。

## 风险与边界

- 这些是内核内存写入原语。源码、内核或固件不匹配可能导致崩溃或重启。不要在支持表之外的固件上运行。
- 各路线会在本次开机期间有意放松 SELinux（全局或按域）。处于 root 状态时应把设备视为隔离性下降。
- 没有持久化。每次重启都会清掉 root 以及内存中创建的挂载、模块和授权名单；只有 `/data` 下的文件会留存，但 root 通道不会。
- Magisk 运行时模块是用户态变通方案，不是常规的 Magisk boot 镜像安装。它依赖临时 root 通道，并随之消失。
- 仅在你自己拥有且可恢复的设备上使用。项目假定你手里有完整的刷机包可用于救砖。

## 许可与来源

本仓库包含原创研究代码，以及 `pocs/` 下的公开 CVE PoC 材料。复用前请先阅读各文件头部说明。本源码树未附带许可证文件；除仓库所有者明确授予的权利外，不要假设可以再分发。
