月虹提权助手 v1.8.0 (versionCode 11) -- 官方 Android 7.1.1 支持版
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

交付前提（一句话）：装完包要在 **i管家 → 权限管理 → 自启动** 里给「月虹提权助手」打开开关。
开关存在厂商自己的库里（com.vivo.permissionmanager 的 bg_start_up_apps：currentstate=0 才是允许，
setbyuser=1 表示用户亲手改过），`adb reboot` 撤不掉它，也不是本包写的；不打开则重启后必须手点一次。
打开之后实测（2026-10-19）：重启零 adb 输入 ≈+1.5 min app 自己跑完整条，daemon 与 12345/12346 监听都在，
外面看仍是 uid 2000 + Enforcing；同一 boot 再跑 verify_approot.sh 仍 pass=9 fail=0。

7 上已知没做到的（都记在 art/ledger-20261016.md §555–561）：
  · 自愈依赖上面那个用户侧开关（vivo 的 VBMService 同时掐 BOOT_COMPLETED 与持久 JobService）。
  · `/sbin/su` 的名字闸在 7 上没打通（sugate 报 "window unproven"）；第三方 app 走 12346 的 su 服务
    + su.token 拿 root，不依赖 PATH 上的 `su`。
  · `L7: LATE window 0 could not open`＝换成自己的 root 凭证之后 `win_open()` 那对
    (uid==0 && securebits==marker) 自检失去分辨力，rc=2 只是这条判据失效，不影响交付面。
  · 种上去的 ebitmap 节点宿主 `0xffffffc001a41c00` 大概就是 `modprobe_path` 的 256 字节存储
    （旁证：同一 boot 里 `modprobe=` 先被写空又回 `/sbin/modprobe`，多读出的 14 位全落在节点
    `maps[5]` 高半部）⇒ 豁免可能随内核重写 modprobe_path 而衰减，未定性。
