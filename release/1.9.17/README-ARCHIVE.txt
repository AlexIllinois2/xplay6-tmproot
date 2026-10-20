月虹提权助手 v1.9.17 (versionCode 38) — 源码＋全部有用信息归档包
================================================================

目标机（本包所实证的那台，出货语义只对这一形状成立）
  机型        vivo Xplay6 (PD1610)
  ROM         Android 7.1.1・PD1610_D_7.12.15・incremental eng.compil.20181107.005721
  内核        3.18.31-perf-g9dce1fbc9・msm8996・aarch64
  边界        不解 BL・不写任何分区・只做内存态提权（`adb reboot` 即回出厂）

包里有什么（393 枚文件・压缩包约 8.8 MB）
  release/1.9.17/月虹提权助手-v1.9.17-release.apk   出货 APK＝手机上在跑的那一枚（sha256 见 SHA256SUMS.txt）
  release/1.9.17/{STATUS,README-build.txt,INTEGRITY.txt,SHA256SUMS.txt,README-ARCHIVE.txt(本文件)}
  release/*/  各版的 README-build.txt・STATUS・SHA256SUMS.txt・README-ARCHIVE.txt（版次史与每版交付语义，不含旧 APK）
  tools/      全部 C／头文件／汇编・构建与验收脚本（.sh/.py）・APK 的 Java 源＋manifest＋debug.keystore・demo 源・自测臂
              关键四枚：clobber.c（内核写通路＋两档名字闸的四个入口）、apk/jni/jni_esc.c、apk/src/com/xplay6/temproot/{Chain,Esc,BootJob,Main,EscService}.java、
                        sud.c/relayd.c/suc.c/sumount.c/nsmbind.c/broot7.c
  tools/pgdalias.py        闸站点的**权威推导**（对 fw/*/Image＋kallsyms＋iomem 现读做四项断言才肯吐常量）
  tools/gate_constants.py  构建入口那道"包里编译进去的 #define vs 权威推导"的 14 对比较（6 枚臂）
  art/ledger-2026101[3-6].md  完整取证台账（§1–§681），本轮 §664・§670・§675–§681 是名字闸与授权层那一段
  art/kallsyms_real.txt・art/kallsyms-7-real.txt  两档内核的符号表现读留底（pgdalias 的第二来路）
  art/PORT-RUNBOOK-7.md    换 7 之后的音频复现核对序（同一台机的另一条线；它引用的*留底数据不在包里*，脚本在）
  pocs/                    内核侧 PoC 的 C 源（不含编译产物）

不含
  编译好的 ELF（`tools/build_all.sh` 现编）・APK assets（`apk/build.sh` 从现编件拷入）・
  **fw/Image 与 fw/7/Image（24.5 MB＋28.9 MB，机主明确选择瘦包；两枚的 sha256 见 INTEGRITY.txt，
  自己从 ROM 的 boot.img 里取出后可逐字节核对）**・设备留底数据（live 捕获／音频基线）・
  NDK/SDK・内核整包源码・tools 的 *.out/*.log/*.tsv 中间产物

重建（一台干净机器上）
  1) 需要 Android NDK 29.0.13846066（`$SDK/ndk/.../bin/aarch64-linux-android21-clang`）与 SDK（aapt/zipalign/apksigner）。
     路径可用 SDK/BT/PLAT/NDK_VER 环境变量覆盖。
  2) bash tools/build_all.sh        # broot7 / sud / suc / sumount / nsmbind / relayd / rootsh …（-static 是刻意的）
  3) bash tools/apk/build.sh        # [0/6] 先跑 gate_constants.py（需要 fw/Image＋fw/7/Image），
                                    # 再组 assets+dex+libesc.so+对齐+签名 → tools/temproot.apk
     ★没有那两枚镜像时这一道闸会 ABORT（这是设计：闸不许在看不见依据的情况下放行）。
       两条正当出路：a) 自备同 sha256 的 Image 放进 fw/；b) `SKIP_GATE=1 bash tools/apk/build.sh`
       —— 后者会在构建日志里明写"本次构建没有重新推导"，那这次的产物就**不要**当"已核对常量"交付。
  4) 与包内 SHA256SUMS.txt 比对。**签名密钥在包里**（tools/apk/debug.keystore，口令 android），
     所以重建件与包内 APK **同签名**，可直接 `-r` 覆盖安装；若你换了自己的 keystore，签名不同，
     必须先卸载再装——而卸载会清掉 /data/data/com.xplay6.temproot 里的授权名单（grants.txt）。

本包已实测过的"源码可用"证人（在解开后的树里跑，不是照抄仓库那份构建产物）
  · 无 fw/*Image 时：`bash tools/apk/build.sh` ⇒ rc=1，[0/6] 报 `pgdalias.py --profile 6.0.1 refused
    … No such file or directory: <树>/fw/Image`，且**没有产出任何 APK**（这正是瘦包该有的行为）。
  · `SKIP_GATE=1 bash tools/apk/build.sh` ⇒ rc=0，日志第一行明写
    `★ SKIP_GATE=1 -- the constants were NOT re-derived for this build`。
  · 那一发重建出的 APK 与包内出货件逐文件比：classes.dex / lib/arm64-v8a/libesc.so /
    assets/sud / assets/su / assets/relayd / assets/broot7 / assets/nsmbind / assets/sumount
    **八枚全部 byte-同**（cmp）。签名证书也同：两枚的 `apksigner verify --print-certs` 都是
    `12be07da5eb86746362ff8d31fe11e092205e7bad600fe055b9b66a1fce3ca0b` ⇒ 覆盖安装不用先卸载。
  · 解开后的树里 `sha256sum -c --ignore-missing release/1.9.17/INTEGRITY.txt` ⇒ 19 行全 OK。

装机（本 ROM 实测可全程无人）
  adb -s <ser> push release/1.9.17/月虹提权助手-v1.9.17-release.apk /data/local/tmp/t.apk
  adb -s <ser> shell chcon u:object_r:shell_data_file:s0 /data/local/tmp/t.apk
  adb -s <ser> shell pm install -r -t /data/local/tmp/t.apk      # 已装过同签名包的 -r 重装不需要屏上确认
  （首装那一发才需要两段点框：先『继续安装』再点文案恰好是『安装』的那枚；坐标见台账 §620/§612）

验收（判据都在这台机上真跑过，不达标就 exit 2 报 INCOMPLETE，不会假绿）
  bash tools/verify_approot.sh <ser>                        # main 模式，现 16 枚在册
  POST_REBOOT=1 bash tools/verify_approot.sh <ser>          # 判完 G 就退出（重启复原那一格）
  EXPECT_ENFORCING=1 bash tools/verify_approot.sh <ser>     # 加判 H（Enforcing 下同刻拿 root）
  bash tools/verify_approot.sh --selftest                   # 覆盖闸有无牙齿＋"尺盲要拒判"那三枚臂
  bash tools/rehearse_sugate.sh                             # 14 档 mock 臂，不需要手机
  python3 tools/gate_constants.py --selftest                # 需要 fw/*Image（见上）
  判据枚数与分母由尺自己报（`coverage: N/M`）。

这轮实测出来的交付形状（一句话版）
  开机链自己起针（binder UAF・每枚开机最多一枚）→ 现写 `policydb.permissive_map` 豁免 → 就地改自己
  cred → 起 `sud`（TCP 12345 原始 root shell／12346 su 服务）→ 名字闸：经空 pgd 槽 511 开 1 GB 别名，
  **先用 `/proc/sys/kernel/modprobe` 串把别名语义证明两次（挪成 /zz、再整枚 char[64] 复原），才把
  do_execveat_common+0x… 那条判决 tbnz（VA 0xffffffc000323400）NOP 掉** → `nsmbind` 进 PID 1 的
  mount namespace 把 /sbin/su・/sbin/sux 投出去 → relayd 以 SO_PEERCRED 认调用者、按 app 自己写的
  grants.txt 放行。全内存态。

本包实证过的读数（细节在 art/ledger-20261016.md §664・§670・§675–§681）
  · 1.9.17 在自己两枚冷开机上：**16 main ＋ G ＋ H ＝ 18 格全判**，`pass=18 fail=0 refused=0`。
  · 判据 L（第三方 uid・字面名 `su`）：`SU out=uid=0(root) gid=0(root) … context=u:r:init:s0`，两枚开机各一次。
  · Shizuku：root 卡自己渲染（`启动（针对已 root 设备）`）→ 当面点『启动』→ `root 6250 1 S shizuku_server`
    （两枚开机 pid 6640 / 6250）。
  · snub：审计行计数 4→6，新增 `allow uid=10135 pid=6328 target=0 code=0`（新 pid＝本开机归因），
    界面上"没有权限"不再出现。
  · 窗口证人原文：`window PROVEN through the alias: modprobe_path "/sbin/modprobe" -> "/zz"` ＋
    `restore witnessed` ⇒ 然后才 `sugate7-patch written (NOP at 0x323400)`。

已知边界（不是欠项，是明说的边界）
  · 每次重启后需在 Shizuku 里点一次『启动』；闸的打开是链在 boot+约 4 分钟自己做的，不需要电脑。
  · 提权后 `getenforce` 不是立刻回 Enforcing：route 7 的翻回在 daemon 起来之后一两分钟才落地（H 判的是翻回后的成对读数）。
  · 这台 ROM 的 JobScheduler 不收续跑作业（`job schedule rc=1`）⇒ relayd 死了不会由调度器自恢复，
    要等 app 再起或点一次『提权』。
  · 6.0.1 那条路（`esc_sugate`）仍保留旧形状：自身 enforce 读不到时照样补丁＋靠 execve 反证
    （clobber.c:898）。本机是 7，那一支在这里验不了，所以**不写成已证**。
  · 已经在 root 的进程走我们的 su 通道会被拒（名单里放的是 app uid）——这是设计。
  · 不要用 root 侧 `mv` 去改 /data/data/com.xplay6.temproot/files/grants.txt：那样造出的 inode 缺 app 的
    MLS 类别，enforcing 下 app 连自己的表都读不动（§677 两枚开机单因子 A/B 量出来的）。要改就就地
    `cat new > file`，或收尾 `chown <uid>:<uid>` ＋ `restorecon`。
