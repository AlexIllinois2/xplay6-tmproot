月虹提权助手 v1.9.19 (versionCode 40) — 源码＋全部有用信息归档包
================================================================

目标机（本包所实证的那台，出货语义只对这一形状成立）
  机型        vivo Xplay6 (PD1610)
  ROM         Android 7.1.1・PD1610_D_7.12.15・incremental eng.compil.20181107.005721
  内核        3.18.31-perf-g9dce1fbc9・msm8996・aarch64
  边界        不解 BL・不写任何分区・只做内存态提权（`adb reboot` 即回出厂）

包里有什么（400 枚文件・压缩包约 8.9 MB）
  release/1.9.19/月虹提权助手-v1.9.19-release.apk   出货 APK＝手机上在跑的那一枚（sha256 见 SHA256SUMS.txt）
  release/1.9.19/{STATUS,README-build.txt,INTEGRITY.txt,README-ARCHIVE.txt(本文件)}
  release/*/  各版的 README-build.txt・STATUS・INTEGRITY.txt・README-ARCHIVE.txt・SHA256SUMS.txt（版次史，不含旧 APK）
  tools/      全部 C／头文件／汇编・构建与验收脚本（.sh/.py）・APK 的 Java 源＋manifest＋debug.keystore・demo 源・自测臂
              关键件：clobber.c（内核写通路＋名字闸入口＋**本轮新增的 hpgain 两档臂**）、
                      gate_constants.py（构建入口那道闸）、hp_gain7.py（HP 那一字节的离线工装）、
                      port_check.sh（音频核对序的腿）、pgdalias.py（闸站点的权威推导）、
                      apk/src/com/xplay6/temproot/{Chain,Main,Boot,BootJob,Esc,EscService}.java、
                      sud.c / relayd.c / suc.c / sumount.c / nsmbind.c / broot7.c
  art/ledger-2026101[3-6].md  完整取证台账（§1–§690）：本轮音频线记作 §683a–§690
    （★编号说明：另一条线在同一时段占了 §683，那一枚讲的是 BL 可解与改分区必 bootloop；为避免同号歧义，本文这几节记作 §683a）
  art/kallsyms_real.txt・art/kallsyms-7-real.txt  两档内核的符号表现读留底（pgdalias 与 HP 地址的第二来路）
  art/PORT-RUNBOOK-7.md  换 7 之后的音频复现核对序（D1/D2/G 三段本轮已改到当前状态）
  art/chain-1.9.19-boot.txt・art/chain-1.9.17-bootB.txt・art/approot-1.9.17-{main,GH}.txt
              开机链与验收表的现场留底（"开机自动落回我选的档"那格＝这枚里的 `hpgain 601: FIRED`）
  pocs/       内核侧 PoC 的 C 源（不含编译产物）

不含
  编译好的 ELF（`tools/build_all.sh` 现编）・APK assets（`apk/build.sh` 从现编件拷入）・
  **fw/Image 与 fw/7/Image（24.5 MB＋28.9 MB，机主明确选择瘦包；两枚的 sha256 见 INTEGRITY.txt B 段，
  自己从 ROM 的 boot.img 取出后可逐字节核对）**・设备留底数据（live 捕获／音频基线／ACDB 原件）・
  NDK/SDK・内核整包源码・tools 的 *.out/*.log/*.tsv 中间产物

重建（一台干净机器上）
  1) 需要 Android NDK 29.0.13846066（`$SDK/ndk/.../bin/aarch64-linux-android21-clang`）与 SDK（aapt/zipalign/apksigner）。
     路径可用 SDK/BT/PLAT/NDK_VER 环境变量覆盖。
  2) bash tools/build_all.sh        # broot7 / sud / suc / sumount / nsmbind / relayd / clobber …（-static 是刻意的）
  3) bash tools/apk/build.sh        # [0/6] 先跑 gate_constants.py（需要 fw/Image＋fw/7/Image），
                                    # 再组 assets+dex+libesc.so+对齐+签名 → tools/temproot.apk
     ★没有那两枚镜像时这一道闸会 ABORT（这是设计：闸不许在看不见依据的情况下放行）。
       两条正当出路：a) 自备同 sha256 的 Image 放进 fw/；b) `SKIP_GATE=1 bash tools/apk/build.sh`
       —— 后者会在日志第一行明写"本次构建没有重新推导"，那这次的产物就**不要**当"已核对常量"交付。
  4) 与包内 SHA256SUMS.txt 比对（**裸文件名・在 release/1.9.19/ 目录内校验**）。
     签名密钥在包里（tools/apk/debug.keystore，口令 android），所以重建件与包内 APK **同签名**，
     可直接 `-r` 覆盖安装；若你换了自己的 keystore，签名不同，必须先卸载再装——
     而卸载会清掉 /data/data/com.xplay6.temproot 里的授权名单（grants.txt）。

本包已实测过的"源码可用"证人（在解开后的树里跑，不是照抄仓库那份构建产物）
  · 无 fw/*Image 时：`bash tools/apk/build.sh` ⇒ rc=1，[0/6] 报 `pgdalias.py --profile 6.0.1 refused
    … No such file or directory: <树>/fw/Image`，且**没有产出任何 APK**（这正是瘦包该有的行为）。
  · `SKIP_GATE=1 bash tools/apk/build.sh` ⇒ rc=0，日志第二行明写
    `★ SKIP_GATE=1 -- the constants were NOT re-derived for this build`。
  · 手机上在跑的确实就是包内这一枚：`adb shell pm path com.xplay6.temproot` → `/data/app/com.xplay6.temproot-2/base.apk`，
    设备侧 `md5sum` 与 `release/1.9.19/月虹提权助手-v1.9.19-release.apk` 同为 `04d5c2d77f96c826627389bbcf9da7e1`。
  · 那一发重建出的 APK 与包内出货件逐文件 cmp：classes.dex / lib/arm64-v8a/libesc.so /
    assets/{sud,su,relayd,broot7,nsmbind,sumount} **八枚全部 byte-同**；两枚的
    `apksigner verify --print-certs` 同为 `12be07da5eb86746362ff8d31fe11e092205e7bad600fe055b9b66a1fce3ca0b`
    ⇒ 覆盖安装不用先卸载。
  · 解开后的树根 `sha256sum -c --ignore-missing release/1.9.19/INTEGRITY.txt` ⇒ 30 行全 OK。
  · 打包本身已写成 `tools/pack_release.sh`：版本由 `tools/apk/AndroidManifest.xml` **现取**（不是抄在脚本里），
    成员清单里任何一枚文件不在 ⇒ 立刻 abort；`SHA256SUMS.txt`/`ARCHIVE-SHA256.txt` 在 tar 外面重写。

装机（本 ROM 实测）
  adb -s <ser> push release/1.9.19/月虹提权助手-v1.9.19-release.apk /data/local/tmp/t.apk
  adb -s <ser> shell chcon u:object_r:shell_data_file:s0 /data/local/tmp/t.apk
  adb -s <ser> shell pm install -r -t /data/local/tmp/t.apk      # 已装过同签名包的 -r 重装：本轮实测直接 Success
  （首装那一发才需要两段点框：先『继续安装』再点文案恰好是『安装』的那枚；坐标见台账 §620/§612）

这版交付的两个功能（一句话版）
  A) **迁出来的调音回到 7**：6.0.1 的 PD1610 七枚 `.acdb`＋`workspaceFile.qwsp`（逐枚 md5 与主机两份副本相同）
     落在 `/data/local/acdb6`，目录与文件都标 `system_file`，钉成 `persist.audio.calfile0..7`＝**替换进料列表**
     （§377/§378 的语义在 7 上由 `/system/vendor/lib/libacdbloader.so` 承载）。机主判决：「是原来那台的声音」。
  B) **耳机增益两档可切换＋开机自动落回**：app 里两枚 chip 经自己的 SU 通道跑
     `clobber 40 hpgain <601|stock> 4 0`；内核地址**只存在于 tools/clobber.c 的 HPGAIN7_* 常量**里，
     由构建入口那道闸现读 `art/kallsyms-7-real.txt`（含与邻符 `soc_codec_dev_tasha` 的间距）校对，
     二进制自己还校 `osrelease`、不符即 REFUSE。机主判 B＝留 7 自己的值。

音频这条线怎么验（不依赖 6.0.1 基线留底）
  SU=/data/local/tmp/su7x bash tools/port_check.sh check      # 本轮 rc=0：与 6.0.1 表 0 处不等・ALSA 7/7
  SU=/data/local/tmp/su7x bash tools/port_check.sh reach      # 本轮 rc=0：整链驻留 audioserver 一枚 pid
  SU=/data/local/tmp/su7x bash tools/port_check.sh acdb       # props 替换态 ⇒ **rc=2 REFUSED（不是红）**：
                                                              # 它的"在用哪份"按目录枚举，替换列表它看不见
  这一层真正的答案＝成对两行：loader 的 `ACDB -> Prop Load file:` 只证"尝试"、
  ADSP 的 `[ACDB Command]->SW Minor/Major/Revision version info for <路径>` 才证"打开并握手"（8/8）。
  跑机侧判据的前提＝§605 那套配方（`SU=/data/local/tmp/su7x`・调用者 uid 临时进 `files/grants.txt`・
  用完按**跑前快照**就地还回并 chown/restorecon，终证＝daemon 对 uid 2000 回 `ERR unknown service`）。
  ★捕获默认不落基线：只有 `COMMIT_CAPTURE=1` 才移动留底（§587 那次是自己把 6.0.1 的证据洗掉了）。

已知边界（不是欠项，是明说的边界）
  · 内存态写**没有回读面**：`CLOBBER OK` 只证"打到"，不证"值"（`/dev/mem` 编掉・无 `/proc/kcore`・
    `codec_reg` 那两枚候选在本机是 0 字节）。所以 HP 那一格的判定列**不许写"验读通过"**，效果面＝人耳。
  · 开关依赖机上 `/data/local/tmp/clobber`（2 164 616 B・dev-pushed，**刻意没进 APK 资产**——进资产就得为
    那枚新字节再要一次开机读数）。缺件时按钮回「没打到 -> …」＝响亮失败，不是静默。
  · 切换后要耳机路重新使能（暂停→播放／切歌／拔插）才吃到：列在 enable 事件上锁存（§367/§370）。
  · `.cnt`（只差一块 vstep）与 mixer XML／配置文件层**在内存态边界内搬不动**：路径是硬编码的 `/system/etc/...`
    绝对串、`/system`＝dm-0 `ro,seclabel`、往只读挂载里 mount 目的地 EPERM ⇒ 要动就得改边界（写分区）。
  · 这台 7 的 logcat 环固定 256 KB・约 2 分钟被刷穿，`logcat -G` 被拒、`persist.logd.size*` 被 logd 忽略、
    `logcat -d -L` 实测与 `-d` 同起点 ⇒ **开机段证人只能开机前挂流**（本轮的 `hpgain 601: FIRED` 就是这么拿到的）。
  · 每次重启后需在 Shizuku 里点一次『启动』；提权后 `getenforce` 不是立刻回 Enforcing（route 7 的翻回在
    daemon 起来之后一两分钟才落地）。
  · 已经在 root 的进程走我们的 su 通道会被拒（名单里放的是 app uid）——这是设计。
  · 不要用 root 侧 `mv` 去改 /data/data/com.xplay6.temproot/files/grants.txt：那样造出的 inode 缺 app 的 MLS
    类别，enforcing 下 app 连自己的表都读不动（§677 两枚开机单因子 A/B 量出来的）。就地 `cat >`，或收尾
    `chown <uid>:<uid>` ＋ `restorecon`。
  · 本轮新增的常量闸是 **18 对／9 臂**（1.9.17 是 14 对／6 臂）：`gate_constants.py --selftest` 的三枚新臂
    分别把"地址末位挪一格／release 换成别的 build／写长越过邻符"钉成必失配。
