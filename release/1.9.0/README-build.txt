月虹提权助手 v1.9.0 (versionCode 21) -- 官方 Android 7.1.1 支持版
目标机：vivo Xplay6 PD1610_D_7.12.15, msm8996, Linux 3.18.31-perf-g9dce1fbc9

本版取代 1.8.9（未上过机）与 1.8.8（未上过机）；**1.8.7 已知坏，勿装**（§588/§590）。装机那一枚仍是 1.8.6（versionCode 17）。

相对 1.8.9 修掉一处**协议在三份文件之间裂开**的缺陷（ledger §596）：

  · app 侧的 JNI 探针（`libesc.so`，即判据 A 走的那条路）此前仍往 `/data/local/tmp/.sud` 投递 `req-<pid>`，
    而守护进程自 §590 起只扫 `/data/local/tmp/.sud/req`。两半都不新鲜才更危险：
    `.sud` 现在是 0711 root 私有 ⇒ app **连写都写不进去**，投递失败；换句话说 1.8.9 会把
    "daemon 与 su 客户端之间"修好，却把"daemon 与 app 自己"那条路弄断。
    现在 `tools/apk/jni/jni_esc.c` 的 `REQ_DIR` 与 `tools/suc.c` 一致 = `/data/local/tmp/.sud/req`。

  · 为这类"同一协议写在多个文件里"的裂开加了一把闸：**`tools/sud_layout.py`**
    从源码现读守护进程的 `SOCKDIR2/REQDIR/SU_LOG/SESSDIR` 与每个客户端的 `REQ_DIR`，
    要求逐枚相等，并要求守护进程自己的状态文件不得落在"陌生 uid 可写"的投递目录里。
    它带两枚臂（`--selftest`，2/2 绿）：① 把任一枚客户端改回旧目录必须被点名（MISMATCH）；
    ② 守护进程里少了必需宏时**拒绝回答**而不是给一个空判语。
    ★这把闸现在挂在 `tools/build_all.sh` 的臂段里自动跑（连同 `grants_rule_test` 14 臂・`copy_atomic_test` 10 臂），
    臂红即中断构建——**不再依赖"人记得去跑"**，因为这一类和 §585（自投 grants）、§595（空壳 su）
    一样，属于"要到设备上才露出来"的代码形状。

包内实测（现读 unzip 校验，不是"应该是"）：
    lib/arm64-v8a/libesc.so 里的投递路径串 = `/data/local/tmp/.sud/req`（旧那条 `/data/local/tmp/.sud` 已不出现）
    assets/sud md5 9bf850439ee2fffaad94ceade7b10ad9 ＝ tools/sud（含 §595 的原子投递修复）
    assets/su  md5 f93aa6ec82f63620b4058028180dd382 ＝ tools/suc（含 §588 的 req 目录形状）
    aapt 读回：versionCode=21 / versionName=1.9.0

本版携带的全部授权层与通道形状（相对装机那枚 1.8.6）：
    1) 不再采信调用者自己种的 grants 名单（§585），规则在 `tools/grants_rule.h`＋14 臂共编测试；
    2) `.sud` 收成 0711 root 私有，客户端投递移到 sticky 的 `.sud/req`（§586 的洞 ＋ §588 的修法之错 ＋ §596 的三文件对齐）；
    3) `su` 客户端原子投递，永不再产出 0 字节的空壳（§595，`teeth:` 臂复现过旧缺陷）；
    4) 审计日志 0600、`sess` 0700、socket 文件保持 0777（`connect()` 要可写位）。

判据与**它们当前的真实状态**（`tools/verify_approot.sh`）：
    已在设备上实测通过（1.8.6，同一台机、没重启那一轮）：A1 A2 E1 E2 F0 F H
    **已接好、一次都没跑过**：I（.sud 不可种/不可替换）、**I2**（`.sud/req` sticky・root 持有・陌生 uid 仍能建自己的投递＝I 的正控）、
    　J（shell 自种 grants 仍须被拒）、JP（root 种的仍须被采信＝J 的正控）、K（`su` 命名路径必须是真 ELF，非空壳）
    G（重启即复原）**从未在出货 build 上读过**，1.8.4 之后只有历史证据。

装包与验收：
    adb push release/1.9.0/月虹提权助手-v1.9.0-release.apk /data/local/tmp/
    adb shell pm install -r /data/local/tmp/月虹提权助手-v1.9.0-release.apk
    　　（`-r` 就地更新，**不要 uninstall**；屏上会弹 vivo 的安装确认，**要有人点『继续安装』**；
    　　　锁屏/灭屏时 `pm install` 回 `Failure [-200]`——ledger 563 实测）
    EXPECT_ENFORCING=1 bash tools/verify_approot.sh         # A1 A2 B C D E1 E2 F0 F H I I2 J JP K
    adb reboot; POST_REBOOT=1 bash tools/verify_approot.sh  # 允许重启时才读 G

★现在这一开机的 root 通道是断的（§590）：上一发为加载新 daemon 我杀掉了装机版 daemon，
  而 app 的自愈闸是"这一开机已提过权"（SharedPreferences 记 boot epoch）不是"通道现在活着"，
  `BootJob` 跑起来只报状态不重启。恢复只有两条：人在 UI 上按「提权」（直接走 `Chain.run`），
  或者重启一次（开机自愈 1.8.4/1.8.6 验过零 adb 输入可跑通，顺带把 G 补读）。
  要不要把"标记在但通道没了"也改成该补针——那会改变炸机概率——**等人点头**（任务 #24），我没自作主张。

一条与第三方 app 相关的边界（诚实写出）：§579 量到 7 的厂商名字闸按 **execve 传进去那条路径的最后一段**判，
非 root 域 exec 任何以 `/su` 结尾的路径都被静默 EPERM（无 avc）。所以 K 只担保"不再有 0 字节空壳"，
**不担保 app 硬编码的 `su` 能在 7 上 exec 成功**；第三方 app 在 7 上的可用入口是 `sux`（§18 的 nsmbind 挂进 init 命名空间那一条）。
真正把 `su` 交出去需要找到 7 上那把闸的实现位置并内存态放宽——§579 记了四条反证，仍未定位。

怎么重建（不需要 gradle）：
    bash tools/build_all.sh          # 原生件 + 三把主机闸（sud_layout / grants_rule / copy_atomic），臂红即中断
    bash tools/apk/build.sh          # aapt + javac + d8 + zipalign + apksigner -> tools/temproot.apk
    本 tar 不含任何二进制；解开后按上面两条即可复现同形产物（签名证书不在包内，签名不同是预期）。
不含：keystore／签名私钥／任何凭据。`file` 扫过全树，ELF／Zip／Java KeyStore 命中 0。
