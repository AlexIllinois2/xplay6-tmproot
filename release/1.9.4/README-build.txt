月虹提权助手 v1.9.4 (versionCode 25) -- Android 7.1.1 / PD1610_D_7.12.15 / 3.18.31-perf-g9dce1fbc9

这版只改一件事：包内 assets/broot7 换成**修好两枚 §600 回归**的那一枚（md5 c642565505b9d9d551d5b81b7a6cbdb3，
与 tools/build_all.sh 现产物逐字节相同；assets/sud 未变＝9bf850439ee2fffaad94ceade7b10ad9）。
1.9.3 的 ladder 在借券第一格就 win_open↔kread 无限互递归（实测同一枚 aim 写连打 1010 次），
永远走不到 permissive_map、起 daemon 与翻回 enforcing——所以 1.9.2／1.9.3 装机的开机自愈必然留下
"Permissive・无 daemon・日志停在 task= 之后"的形状（art/ledger-20261016.md 613-616）。

修法两行（tools/broot7.c）：
1) win_open() 里不读任何东西：before = g_owncred（borrow_verdict.h 里 0 的定义就是"读不到"），
   并加 g_opening 三脚架，再入＝有名拒止而不是空转；
2) kread() 的瞄写移到开窗之后（win_open 读回凭证会重新瞄 blocks[0]，先瞄的那次会被它盖掉，
   于是每次读回来都是 init_cred 指针本身 -> permmap_plant 报 "node 0 never landed"）。

上机实证（2026-10-20・冷启 Enforcing・adb shell 那一发・日志 /data/local/tmp/l7h.log）：
  L7: ROOT in our own cred, uid=0 euid=0 gid=0 nice=7 groups=10
  P7: node 0/1/2 verified byte-for-byte -> every wanted type reads exempt AND nothing of the vendor's was dropped
  L7: ORACLE mkdir /dev/.l7probe rc=0 errno=0
  L7: daemon /data/local/tmp/sudd started as pid 5108 (detached, not waited)
  L7: daemon listener confirmed on 12345          <- 本版新加的 daemon_up() 闸
  sud: sh listener up 12345 / su listener up 12346 / setcon -> u:r:init:s0 (ok)
  L7: LATE: enforcing written back to 1 after the daemon set up
  /data/local/tmp/.sud/req 由 drwx------ root(旧 interim 版) 自动修成 drwxrwxrwt root 01777
  终态 getenforce = Enforcing

装这版（唯一还没通的一格）：vivo 的安装确认框要有人点『继续安装』（~14 s 窗口），
或者用 tools/uinput_tap——它要 root 才能建 /dev/uinput（shell 在 group 1004 input，不在 net_bt_stack，
现读 errno=13 被拒）。adb 的 evdev 注入在这台机上不生效（ledger 604-607・615），别浪费时间再试。

验收（装上之后）：bash tools/install_and_verify.sh --yes
  它现读 versionCode・双端 md5・chcon・装完自动跑 EXPECT_ENFORCING=1 bash tools/verify_approot.sh
  判据枚数由尺自己报（现读 16）。重启复原那一格＝POST_REBOOT=1 bash tools/verify_approot.sh。

== 补充（2026-10-20 实测之后，覆盖本文件上面那段"装这版"的旧话）==
★装这一版**不需要人**，次序是这样（全部实测通过，art/ledger-20261016.md §620）：
  1) 先读 `adb -s <ser> shell dumpsys power | grep mWakefulness`：**只有 Asleep 才**发电源键
     `adb -s <ser> shell /data/local/tmp/sux -c '/data/local/tmp/uinput_key 116'`
     （116 是 toggle，屏已经亮着还发＝把屏按灭，vivo 的安装活动会在 31 ms 内自杀：`mCancledInstall : true`）
  2) 锁屏在位时上滑揭锁：`sux -c '/data/local/tmp/uinput_tap --drag 540 1750 540 400 16'`
     （判锁屏：`dumpsys window | grep -E "isStatusBarKeyguard|mKeyguardDrawComplete"`）
  3) `adb -s <ser> shell pm install -r -t /data/local/tmp/temproot-1.9.4.apk`
  4) 框是**两段**：先点『继续安装』，页面翻页后再点文案恰好是『安装』的那枚；坐标现读
     `adb -s <ser> shell uiautomator dump /data/local/tmp/ui.xml; cat /data/local/tmp/ui.xml`
     以上 1-4 已由 `tools/install_tap.py` 收拢（tap 走 `sux -c /data/local/tmp/uinput_tap`；
     前置闸：屏没亮或焦点还是 StatusBar 就 REFUSE 退出 2，**不开 pm install**）。
★拿到 root 通道的前提：`/dev/uinput` 是 system:net_bt_stack 0660，adb 只有 1004(input) ⇒ 建设备必须走 daemon 通道；
  而通道认授权表 `files/grants.txt`，默认只放本 app 的 uid（这是出货形状，别为了自己方便长期留着 adb 的 uid）。
★**开机自愈：不需要人，实测已过**（art/ledger-20261016.md §621）。本包的 BOOT_COMPLETED 确实收不到
  （`pm install -r` 会把包打回 stopped 态；揭开 stopped 后重启守 7 min 仍无 TempRoot 行；而这台 ROM
  连 shell 都不许伪造：`am broadcast -a android.intent.action.BOOT_COMPLETED` → `Permission Denial ... from uid=2000`），
  但**已入档的 `BootJob`（JobScheduler 持久作业）自己就能在重启后把链拉起来**：零 adb 输入的时间线
  `+181s enforce=Permissive（链开窗）→ +211s enforce=Enforcing`、`sud.ok`/`sud.stage` 新写、
  `.sud/req` 被新 daemon 刷回 01777，判据现读
  `post-reboot: uid=2000 enforce=Enforcing sud-procs=1 listeners=2` → **`PASS G`・`pass=1 fail=0`・`REVERSIBILITY VERIFIED`**。
  ⇒ 早期那版"必须先去设置里打开自启动"的话**已撤销**：开关只让它更早更稳，不是前置。
  复测命令：`POST_REBOOT=1 bash tools/verify_approot.sh <ser>`（判据枚数由尺现报）。
  本版**尚未**绿的部分（不是话术问题，是真缺件）：第三方 app 用 `sux` 客户端取 root 时，反向投递目录
  `/data/local/tmp/.sud/req` 是 `shell_data_file`，`untrusted_app` 写不进去 ⇒ 主模式 B／C／D 目前红，
  且 app 自己第二次起 broot7 时复用同名 `broot7.log` 会把上一发留底截成 0 字节（判据 A1 因此瞎）。
  这两条连同"工装遇到 `cannot publish request name` 应当 REFUSE 而不是 FAIL"一起记在 task #27（1.9.5）。
