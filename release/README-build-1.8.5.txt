月虹提权助手 v1.8.5 (versionCode 16) -- 官方 Android 7.1.1 支持版
目标机：vivo Xplay6 PD1610_D_7.12.15, msm8996, Linux 3.18.31-perf-g9dce1fbc9

重建（不需要 gradle）：
  SDK=/path/to/Android/Sdk NDK_VER=29.0.13846066 bash tools/build_all.sh
  SDK=/path/to/Android/Sdk BT=$SDK/build-tools/35.0.0 PLAT=$SDK/platforms/android-34/android.jar \
      bash tools/apk/build.sh
  -> tools/temproot.apk（debug 自签；apk/build.sh 缺 keystore 时自己生成一份，不进源码包）

路由在 tools/apk/src/com/xplay6/temproot/Chain.java：os.version 以 "3.18.31" 开头 -> route 7
（staged 的 tools/broot7 单进程自提权：binder UAF 写通道 + getgroups 读通道 + permissive_map 豁免
  + 就地改自己的 cred + 起 daemon 后再把 selinux_enforcing 翻回 1）；否则 -> route 6
（6.0.1 的 modprobe_path / usermodehelper 那一套，实测形状不变）。

7 这一路的验收（2026-10-19，同一台机、同一版本包）：
  bash tools/verify_approot.sh                    # A/B/C/D/E/F/H -> pass=9 fail=0
  EXPECT_ENFORCING=1 bash tools/verify_approot.sh # H：Enforcing 与 root 同时成立
  adb reboot; POST_REBOOT=1 bash tools/verify_approot.sh   # G：重启后 uid 2000 + Enforcing + 无 sud
边界：不解 BL、不写任何分区、纯内存态；`adb reboot` 之后一切消失。

交付前提：装完包要在 **i管家 → 权限管理 → 自启动** 里给「月虹提权助手」打开开关，
而且**每次 `pm uninstall` + 重装之后都要再打开一次**——那一行开关存在厂商自己的库里
（com.vivo.permissionmanager 的 bg_start_up_apps：currentstate=0 才是允许，setbyuser=1 表示用户亲手改过），
随包一起被删（2026-10-19 实测：装 1.8.3 之后重启，BOOT_COMPLETED 又被打回
`BroadcastQueue: ==/==> com.xplay6.temproot/…  BOOT_COMPLETED: XXXX`）。
**升级请用 `pm install -r`（覆盖安装），不要 uninstall + install**：实测 `-r` 之后厂商那一行原样保留
（`bg_start_up_apps id=32 … uid=10151 setbyuser=1 state=0`，前后两次抄表逐字段相同，uid 也没变），
而 uninstall + install 会连同那一行一起删掉、新装回来默认拒绝（§566）。
开关打开后实测（1.8.4，2026-10-19）：重启零 adb 输入，app 确实自己起来跑梯子；那一发**针没中**
（`L7: the needle never published a task`），于是 app 报 `NOT ROOTED after both routes` 并把 job 排成 1 小时后再试
——即没根的状态下也有无人值守的第二次机会，且这条退出路径**不会把设备留在 Permissive**、`uname -r` 仍是
`3.18.31-perf-g9dce1fbc9`。同 boot 手动补一发之后：`root probe [peer(SCM_CREDENTIALS)]: uid=0(root) …
50151(all_a151) context=u:r:init:s0`、daemon 与 12345/12346 都在、`getenforce`=Enforcing。
app 自己也会报告这一格：如果某次开机从没收到 BOOT_COMPLETED，logcat 的 TempRoot-boot 会打
`★ 本次开机没有被 BOOT_COMPLETED 唤醒（vivo 自启动未放行）——重启后要手点一次「提权」…`。

7 上已知没做到的（都记在 art/ledger-20261016.md §555–567）：
  · 自愈依赖上面那个用户侧开关（vivo 的 VBMService 同时掐 BOOT_COMPLETED 与持久 JobService）。
  · 针仍有实测失效率，且**集中在开机风暴里**：1.8.4 的 boot 触发 3 发里 2 发 `the needle never published a task`。
    1.8.5 起 boot 触发（`trigger=boot`）先等 150 s 再花那一枚针（UI 的「提权」按钮不等），改完后
    连打两发重启：两发都零 adb 输入直接到 root（`root probe … 50151(all_a151) context=u:r:init:s0`、
    双监听、Enforcing、`uname -r` 完好）。样本只有 2，方向支持，不写成"已解决"。
    失败那一发会自动排 1 小时后再试，所以漏针的 boot 不是死路。
  · `/sbin/su` 的名字闸在 7 上没打通（sugate 报 "window unproven"）；第三方 app 走 12346 的 su 服务
    + su.token 拿 root，不依赖 PATH 上的 `su`。
  · `L7: LATE window 0 could not open`＝换成自己的 root 凭证之后 `win_open()` 那对
    (uid==0 && securebits==marker) 自检失去分辨力，rc=2 只是这条判据失效，不影响交付面。
  · 种上去的 ebitmap 节点宿主 `0xffffffc001a41c00` 大概就是 `modprobe_path` 的 256 字节存储
    （旁证：同一 boot 里 `modprobe=` 先被写空又回 `/sbin/modprobe`，多读出的 14 位全落在节点
    `maps[5]` 高半部）⇒ 豁免可能随内核重写 modprobe_path 而衰减，未定性。
