月虹提权助手 v1.8.8 (versionCode 19) -- 官方 Android 7.1.1 支持版
目标机：vivo Xplay6 PD1610_D_7.12.15, msm8996, Linux 3.18.31-perf-g9dce1fbc9

本版是**替代 1.8.7 的修订**：1.8.7（versionCode 18）从未装上机，而且现在已知它是坏的——见下。

相对 1.8.6（versionCode 17，当前装在机上那一枚）的改动，全在授权层与通道形状：

  · **不再采信调用者自己种的 grants 名单**（ledger 585 审出的洞：`/data/local/tmp/sud.grants`
    只要存在且看起来干净就被读，于是能写 `/data/local/tmp` 的调用者（adb shell＝uid 2000）
    可以把自己列进去拿到 root）。规则抽进共编头 `tools/grants_rule.h`，daemon 与测试同一份实现；
    `tools/grants_rule_test.c` 14 枚臂，`cc -Wall -Wextra -Werror` 全绿，臂 9 编码了实测的真实布局
    （`files/` 0771 u0_a151 ＋ `grants.txt` 0600 root:root）。
    候选 `GRANTS_CANDIDATES[2] == /data/local/tmp/sud.grants` 现在**必须 root 持有**才被采信。

  · **daemon 私有目录与客户端投递目录拆开**（ledger 586 的洞 ＋ ledger 588 实测出的修法之错）：
    `.sud` 之前 0777 ⇒ 任何 app 能 unlink/替换里面的 `sud.sock`（假 daemon 劫持）。
    1.8.7 只把 `.sud` 收成 0711，结果**把客户端通道一起关了**——客户端的反向通道要在 `.sud` 里
    **创建** `req-<pid>` 投递文件，实测装机 1.8.6 被临时 chmod 成 0711 之后：
    `su: cannot publish request name: Permission denied`，判据 I 转绿而 B/C/D/H 全红（`pass=7 fail=6`）。
    1.8.8 的形状＝`.sud` 0711 root（只放 `sud.sock`/`sud.log`/`sess`/`mirror`）
    ＋ **`.sud/req` 01777、root 持有**（`mkdir`＋每次启动 `chown(...,0,0)`＋`chmod`；
    目录持有者可绕过 sticky 删别人的投递，所以所有权必须归 root；存量每次启动重刷，
    因为 `mkdir` 遇 `EEXIST` 会原样留着旧模式）。sticky 给的能力正是要的那一条：
    **能创建自己的投递，不能删除或替换别人的**。

  · `sess` 0700、审计日志 `sud.log` 0600；socket **文件**仍 0777（`connect()` 要可写位）。
    因此验收工装读日志改走 root 通道（`tools/verify_approot.sh` 的 `rootsh`），
    否则 shell 侧 `cat` 读到空会被误记成"daemon 什么都没记"。

  · 判据新增/接硬（`tools/verify_approot.sh`）：
    **I** 无特权调用者不能在 `.sud` 里种文件或替换 `sud.sock`（问能力，不解析权限位）
    **I2** `.sud/req` 必须是 sticky、root 持有、**而且陌生 uid 仍能创建自己的投递**——
    　　　这是 I 的正控；没有它，"把所有人都锁在门外"也能让 I 绿（本轮就是被这件事坑的）
    **J** shell 自种的 `sud.grants` 必须仍被拒；**JP** root 种的必须仍被采信（J 的正控）

装包之后要在设备上跑的（**本版出包时一条都还没跑过**）：
    EXPECT_ENFORCING=1 bash tools/verify_approot.sh      # A1 A2 B C D E1 E2 F0 F H I I2 J JP
    装包＝`pm install -r`（不要 uninstall），并且**要有人在屏上点『继续安装』**；
    锁屏/灭屏时 `pm install` 会回 `Failure [-200]`（ledger 563 实测）。

装机 1.8.6 已经实测过的部分（同一台机、没重启那一轮，`release/1.8.6/README-build.txt` 记的 pass=10 fail=0）：
    A1/A2（本 boot 的针＋app 自己的探针到 uid=0）、E1/E2、F0/F、H。
    G（重启复原）**从未在出货 build 上重读**，因为本轮的硬约束是"不重启手机"；
    该条在 1.8.4 上验过 `PASS G / REVERSIBILITY VERIFIED`。

本轮另外量到、但还没写进代码的两条产品性质（ledger 588）：
  · **daemon 中途死掉，同一开机内补不回来**：`EscService` 的闸是 `BootJob.alive(this)`＝
    "这一开机提过权"（SharedPreferences 记 boot epoch），不是"通道现在活着"；
    `BootJob` 跑起来只打印 `job fired, state=rc=0 uid=10151 enforce=Enforcing` 然后重新排自己，
    **不重启 daemon**。⇒ 想在不重启的情况下恢复，只有人在 UI 上按「提权」（那条直接走 `Chain.run`）。
    要不要把"标记在但通道没了"也当作该补针的情形，是一条**会改变炸机概率**的决定，未做，等人点头。
  · `/sbin/su` 设备上实测 **0 字节**（同处 `/sbin/sux` 是 2 143 768 字节）⇒ 字面 `su` 那枚名字仍未交付。

怎么重建（不需要 gradle）：
    bash tools/build_all.sh          # 原生半：sud/suc/sumount/... -> tools/ 下的二进制
    bash tools/apk/build.sh          # aapt + javac + d8 + zipalign + apksigner -> tools/temproot.apk
    SDK=${SDK:-/home/v/Android/Sdk} BT=... PLAT=... NDK_VER=... 都可覆盖。
    本 tar 内不含任何二进制，解开后按上面两条命令即可复现出与 SHA256SUMS 里那枚 APK 同形的产物
    （签名证书不在包内，所以复现出的 APK 与发布 APK 签名不同是预期）。

不含：keystore／签名私钥／任何凭据。`file` 扫过全树，ELF／Zip／Java KeyStore 命中 0，文本文件 307 枚，清单见 MANIFEST.txt。
