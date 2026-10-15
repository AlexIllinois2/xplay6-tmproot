月虹提权助手 v1.6 —— 源码包构建说明
=====================================

边界：全程内存态提权。不解 BL、不写任何分区（boot/system/verity 都不动）。
一次 `adb reboot` 就回到出厂状态；未提权时任何 PATH 上都没有 su。

构建（一条命令，需要 Android SDK build-tools 35.0.0 / platform android-34 / NDK 29.0.13846066）：

    SDK=/path/to/Android/Sdk bash tools/apk/build.sh

build.sh 发现 tools/ 下没有 sud/suc/sumount 时会自动调用 tools/build_all.sh（原生件唯一构建入口），
所以从干净源码一条命令就能出 APK（产物：tools/temproot.apk）。
工具链路径都能用环境变量覆盖：SDK / BT / PLAT / NDK_VER / ROOT / OUT。

已验证的可复现性（2026-10-15，v1.5 与 v1.6 同一把尺）：
本包解开后直接构建，得到的 APK 与本目录的 release APK 逐条目对拍 —— 条目名集合相同，
classes.dex、lib/arm64-v8a/libesc.so、assets/sud、assets/su、assets/sumount 全部字节相同，
唯一不同的是 META-INF/ANDROIDD.RSA（签名块）。

原因：签名用的 debug.keystore 没打进源码包（私钥不随包发）。
build.sh 在没有 keystore 时自动生成一枚同 DN（CN=TempRoot）的新密钥，
所以重编出来的 APK 内容一致、签名者证书不同。
要覆盖安装到已装官方包的手机上，请用本目录那枚 release APK，
或者把官方构建机的 tools/apk/debug.keystore 放到同一路径再构建。

v1.6 相对 v1.5 的唯一变化（见 art/ledger-20261015.md §210–§211）：
开机链在"map-only 没跑通、退回全局 Permissive 才拿到 root"的那类开机里，
如果本轮 permissive_map 确实种下去了（step1 map rc=0），就把 selinux_enforcing 翻回 1，
并当场用 su 通道自证（`id -u; getenforce`）；翻不回去就明说"唯一撤销是 adb reboot"。
⇒ 交付口径从此是"默认 Enforcing 下 root；全局兜底只在 map 没种成的那类开机留下 Permissive"。
