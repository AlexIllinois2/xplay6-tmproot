月虹提权助手 v1.8.6 (versionCode 17) -- 官方 Android 7.1.1 支持版
目标机：vivo Xplay6 PD1610_D_7.12.15, msm8996, Linux 3.18.31-perf-g9dce1fbc9

本版相对 1.8.5 只动 route 7 的落地面与验收尺（6.0.1 那一路 route 6 的字节没改）：

  · 新增 `tools/nsmbind.c`：fork 之后 `setns(open("/proc/1/ns/mnt"), CLONE_NEWNS)` 再 bind。
    Android 7 的 zygote 给每个 app 自己的 mount namespace，daemon 自己挂的东西 adbd／别的 app 看不见，
    只有进 init 那枚命名空间挂才全局可见。route 7 现在用它把第三方 root 客户端以 **`sux`** 的名字挂进
    `/sbin`（`umask 022`＋显式 `chmod`；daemon 的 umask 是 077，0755 的请求会静默变成 0700）。
  · `Chain.openSuName7()`：7 走上面这条；6.0.1 仍走 `openSuName()`（sugate 那一套）。
  · 路由收紧：`os.version` 以 `3.18.31` 开头才走 route 7，`3.18.` 其余走 route 6，
    **两者都不是就拒绝写**（打印 REFUSING to write, nothing was attempted）；
    `kernelReleaseFor()` 把第一枚可信 release 缓存进 prefs `krel`——注意 Java 侧读到的
    `os.version` 是 **zygote 快照**，改内核字符串之后 app 不一定立刻看见新值。
  · `BootJob`：`bootEpoch()` 取 `/proc/uptime`（mksh 的 `$(( ))` 会被小数点打死，要 `cut -d. -f1`），
    `markEscalated()` 记本 boot 已提权，`alive()`＝Permissive 或本 boot 的标记（±120 s）。
    `EscService` 见 alive 就不再花第二枚针；`trigger=boot` 那发先等 150 s（开机风暴里针的失效率明显高）。
  · 出梯子的路径独立于 uid：`int own_uid = (int)getuid()`，route 6/7 共用同一道闸。
  · 写通道监督者改为**每请求 exec 一枚新 dancer**（`writer_supervise` 里 fork+execl，`WRITER7` 在监督模式里也读）。
    旧写法让一枚长命 dancer 反复 mmap，实测约 20 次写之后永久 `arm failed`（72/72）——每次写**故意**留着
    那 1 MB binder mmap 不放，关闭它会走被污染队列⇒重启。
  · `permmap_plant()` 合并位图前先排序＋去重（`ebmp_windows()` 要求 sorted＋duplicate-free，
    未去重时同一 boot 第二次种植会报 `24 bits need 1 windows` 而拒绝）。
  · Enforcing 债务标志：`out:` 那一行若发现本轮清过 `selinux_enforcing` 就一定翻回 1，
    除非显式 `ENFORCE7=0`；窗口关不掉时先打印再翻（旧版本把设备留在 Permissive 过）。

7 这一路的验收（2026-10-19，同一台机、装了 versionCode 17 的那一枚，全程没重启）：
  EXPECT_ENFORCING=1 bash tools/verify_approot.sh    # -> pass=10 fail=0
  A1 本 boot 的 task 在自己的 cred 里变成 uid=0（broot7 留底 mtime ≥ boot epoch）
  A2 app 自己的探针到了 uid=0（logcat 探针行或 sud 审计行，两式任一）
  B 不在名单上的 app 被拒 / C 加上名单就 root / D 撤掉名单立即失效（不重启）
  E1+E2 审计日志同时有 allow 与 deny / F0+F 不能指定别人的 uid（ERR target uid not allowed）
  H Enforcing 与 root 同时成立
  G（`adb reboot; POST_REBOOT=1 bash tools/verify_approot.sh`）本版**没重读**——本轮的硬约束是"不重启手机"。
  重启复原那条在 1.8.4 上验过（`PASS G / REVERSIBILITY VERIFIED`），1.8.5/1.8.6 的开机自愈各跑通过：
  1.8.6 那一发的日志里有 `nsmbind: ns: joined PID 1's mount namespace` ＋ `OK bound .../sux over /sbin`，
  同发 `app-exec su: execve refused`＝厂商名字闸仍在（见下）。

★A 的判据本版改硬了：旧 A 只问"logcat 里有没有 uid=0 那一行"，于是**上一条 boot 的留底**也会让它绿。
现在 A1 要 broot7 自己那行 root witness（在我们自己的 cred 里）＋留底 mtime 不早于本 boot 的 epoch，
A2 才问 app 侧证据；两枚分开报，任何一枚红都能看出断在哪段。

装包前提照旧（v1.8.5 起写明）：i管家 → 权限管理 → 自启动 要给本 app 打开，
**升级用 `pm install -r`，别 uninstall + install**——厂商那行 `bg_start_up_apps` 会随 uninstall 一起删掉，
新装回来默认拒绝（`currentstate=0` 才是允许，`setbyuser=1` 表示用户亲手改过）。
`install -r` 之后那一行原样保留、uid 不变。装 APK 本身要先 Permissive（`chcon apk_data_file` + `pm install` +
屏上点确认，14 s 超时）。

7 上已知没做到的：
  · **`su` 这个名字仍拿不到**。厂商闸的量法：按 exec 路径的最后一段判（`su` 一律 EPERM，静默、无 avc 行），
    改名或符号链接命名（`sux`）可过，root/init 域可过。开关位置在 3.18.31 上还没找到——
    本机只加载了 `wlan` 一枚模块，所以它是 built-in，`.bss` 里那枚 PowerMo 特性开关的旧读数（6.0.1）不适用。
    ⇒ 交付面是"`sux` 在 PATH 上、所有调用者可用"，不是"`su` 在 PATH 上"。第三方 app 另有 12346 的 su 服务＋`su.token`。
  · 自愈依赖上面那个用户侧开关（vivo 的 VBMService 同时掐 BOOT_COMPLETED 与持久 JobService）。
  · 针仍有实测失效率，且集中在开机风暴里：boot 触发先等 150 s 之后连打两发都到 root；
    手动 5 发里 1 发没中。样本小，方向支持，不写成"已解决"；没根时 app 会排 1 小时后再试。
  · `L7: LATE window 0 could not open`＝换成自己的 root 凭证之后 `win_open()` 那对
    (uid==0 && securebits==marker) 自检失去分辨力，rc=2 只是这条判据失效，不影响交付面。
  · 1.8.5 README 末尾那条「ebitmap 节点宿主 ≈ `modprobe_path` 的 256 B 存储」**已作废**：
    宿主已搬到 `argv_init`（`0xffffffc001a419c0`），反向臂（`uname -r` 全程完好）在 shell 与 app 两条路上都验过；
    `modprobe_path` 那条假说是离线否掉的。

调音面（6.0.1 → 7 的迁移，本轮 §575–§577）：ACDB 这一层基本不需要搬。
`art/audio-7.1.1/acdb-pool-coords.PD1610-vs-PD1610_7.tsv`＝按"谁指着这块"的对拍：37 302 枚具名槽里
**只有 1 枚在同一地址上内容不同**（`Headset_cal ACGICDOT g12/w4`，80 B、20 词里 15 词不同），
19 枚槽指向的字节另一侧根本没有，其余 613 枚是**组内重排**；正控（PD1610 vs PD1610LG4，逐字节相同的两枚）
37 338 枚槽 joined・0 差。四枚池（Bluetooth/General/Global/Hdmi）逐字节相同。
账在 `art/ledger-20261016.md` §575–§577（含本轮撤掉的两条自己口径：首词不是唯一键、§307 的 id 带锚不成立）。

重建（不需要 gradle）：
  SDK=/path/to/Android/Sdk NDK_VER=29.0.13846066 bash tools/build_all.sh   # 含 nsmbind
  SDK=/path/to/Android/Sdk BT=$SDK/build-tools/35.0.0 PLAT=$SDK/platforms/android-34/android.jar \
      bash tools/apk/build.sh
  -> tools/temproot.apk（debug 自签；keystore 不进源码包）

边界：不解 BL、不写任何分区、纯内存态；`adb reboot` 之后一切消失。
