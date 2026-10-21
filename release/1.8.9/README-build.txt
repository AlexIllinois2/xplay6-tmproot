月虹提权助手 v1.8.9 (versionCode 20) -- 官方 Android 7.1.1 支持版
目标机：vivo Xplay6 PD1610_D_7.12.15, msm8996, Linux 3.18.31-perf-g9dce1fbc9

本版取代 1.8.8（versionCode 19，未上过机）与 1.8.7（versionCode 18，**已知坏，勿装**）。
装机那一枚仍是 1.8.6（versionCode 17）。

相对 1.8.8 只多一处修复（ledger §595）：

  · **`su` 客户端的投递不再能留下空壳**。设备上实测到 `/sbin/su` 是 **0 字节**，而同一处 `/sbin/sux`
    是 2 143 768 字节的真客户端。成因是量出来的、不是猜的：旧写法把
    `open(src, O_RDONLY)` 与 `open(dst, O_WRONLY|O_CREAT|O_TRUNC, 0755)` 写在**同一条声明**里，
    于是**源文件读不出来时目标已经被截空**；`tools/copy_atomic_test.c` 的第 2 枚臂把旧写法照抄进去，
    实测它确实把目标截成 0 字节（臂名 `teeth:`），所以这条判据是抓得住这个缺陷的，不是摆设。
    空壳比缺席更坏：app 探测到 `su` 存在、exec 之后拿到 ENOEXEC，账面看起来像"su 坏了"而不是"没装"。

    新实现在 `tools/copy_atomic.h`（daemon 与测试**同一份**代码）：
      - 先写 `dst.new<pid>`，`fsync` 后 `rename`；任何失败路径都不碰原目标；
      - 拷贝前后各比一次字节数，**0 字节的源直接拒绝投递**（永不产出空壳）；
      - `rename` 撞 `EBUSY/EPERM/EXDEV`（目标可能是上一发留下的 bind 挂载点）时才退回就地写，
        且就地写**自带校验**，失败时明确回报"目标已可疑"；
      - `mirror_overlay()` 不再给"我们要交付的那枚名字"建占位并 bind——旧的空 `/sbin/su`
        正是这样盖在写入目标上的；交付后逐枚比字节数并 `stage` 出来说话。

  · 判据加 **K**（`tools/verify_approot.sh`）：凡存在的 `su` 命名路径（`/sbin/su`、`/system/xbin/su`）
    必须是 ≥100 KB 且魔数为 `7f454c46` 的 ELF；按**行**计数（`all N su-named path(s) ... stubs: M`），
    任一枚是空壳即整条 FAIL。逻辑已离线拿三种输入验过：混合(0 字节＋真 ELF)⇒FAIL、
    12 字节带 ELF 魔数⇒FAIL、两处都不存在⇒PASS 但明说"不存在不在 K 的担保范围内"
    （§579 量过厂商名字闸按 execve 路径最后一段拦，`su` 命名交付在 7 上本来就可能无路可走）。

  · `tools/build_all.sh` 现在**顺带编译并运行两枚主机侧臂表**（`grants_rule_test`＝授权规则 14 臂、
    `copy_atomic_test`＝投递规则 10 臂），任一臂红就中断构建。
    此前这两枚测试是孤儿——只有人想起来才会跑，而 §585/§595 这两个洞都属于"设备上晚点才露出来"的那类代码。

装机 1.8.6 已实测过的部分（同一台机、没重启那一轮）：A1/A2、E1/E2、F0/F、H ＝ `pass=10 fail=0`；
`pass=7 fail=6` 那一发是**我上轮的临时 chmod 把通道关了**（§588），设备已恢复装机形态 0777。

还没在设备上跑过的判据（**这些是"已接好"，不是"已通过"**）：**I**、**I2**（`.sud/req` sticky・root 持有・陌生 uid 仍能建自己的投递）、
**J**（shell 自种的 grants 名单必须仍被拒）、**JP**（root 种的必须仍被采信）、**K**（本文新加）。

装包与验收：
    adb push release/1.8.9/月虹提权助手-v1.8.9-release.apk /data/local/tmp/
    adb shell pm install -r /data/local/tmp/月虹提权助手-v1.8.9-release.apk
    　　（`-r` 就地更新，**不要 uninstall**；屏上会弹 vivo 的安装确认，**要有人点『继续安装』**；
    　　　锁屏/灭屏时 `pm install` 会回 `Failure [-200]`——ledger 563 实测）
    EXPECT_ENFORCING=1 bash tools/verify_approot.sh        # A1 A2 B C D E1 E2 F0 F H I I2 J JP K
    adb reboot; POST_REBOOT=1 bash tools/verify_approot.sh # 只有允许重启时才读 G

★现在这一开机的 root 通道是断的：上一发为了加载新 daemon 我杀掉了装机版 daemon，而 app 的自愈闸是
  "这一开机已提过权"（SharedPreferences 记 boot epoch）不是"通道现在活着"，`BootJob` 跑起来只报状态不重启
  （§590 实测）。恢复只有两条：人在 UI 上按「提权」（那条直接走 `Chain.run`），或者重启一次
  （开机自愈已验过零 adb 输入可跑通，顺带能把从没在出货 build 上读过的 **G** 补上）。

怎么重建（不需要 gradle）：
    bash tools/build_all.sh          # 原生件 + 两枚主机臂表（臂红即中断）
    bash tools/apk/build.sh          # aapt + javac + d8 + zipalign + apksigner -> tools/temproot.apk
    本 tar 不含任何二进制；解开后按上面两条可复现同形产物（签名证书不在包内，签名不同是预期）。
不含：keystore／签名私钥／任何凭据。`file` 扫过全树，ELF／Zip／Java KeyStore 命中 0。

包内实测（现读 unzip 校验，不是"应该是"）：
    assets/sud md5 9bf850439ee2fffaad94ceade7b10ad9  ＝ tools/sud（含 §595 修复）
    assets/su  md5 f93aa6ec82f63620b4058028180dd382  ＝ tools/suc（含 §588 的 .sud/req 投递形状）
