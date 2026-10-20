月虹提权助手 v1.9.2 (versionCode 23) -- 官方 Android 7.1.1 支持版
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
    bash tools/install_and_verify.sh --yes     # 按 versionCode 现读选最新・push・md5 双端相等・chcon、
                                               # pm install -r -t、读回 versionCode 才跑验收
    # 手工等价三步（不要 uninstall：那会重置 vivo 自启动授权）：
    #   adb push release/1.9.2/月虹提权助手-v1.9.2-release.apk /data/local/tmp/temproot-1.9.2.apk
    #   adb shell chcon u:object_r:apk_data_file:s0 /data/local/tmp/temproot-1.9.2.apk
    #   adb shell pm install -r -t /data/local/tmp/temproot-1.9.2.apk
    　　（`-r` 就地更新，**不要 uninstall**；屏上会弹 vivo 的安装确认，**要有人点『继续安装』**；
    #   灭屏/未解锁时 pm install 直接 -200；亮屏已解锁也要有人点『继续安装』——
    #   原因见下面『门的代码层形状』（ledger 602/604/606/607 取代旧的单一灭屏说法）。
    EXPECT_ENFORCING=1 bash tools/verify_approot.sh         # A1 A2 B C D E1 E2 F0 F H I I2 J JP K
    adb reboot; POST_REBOOT=1 bash tools/verify_approot.sh  # 允许重启时才读 G

★现在这一开机的 root 通道是断的（§590）：上一发为加载新 daemon 我杀掉了装机版 daemon，
  而 app 的自愈闸是"这一开机已提过权"（SharedPreferences 记 boot epoch）不是"通道现在活着"，
  `BootJob` 跑起来只报状态不重启。恢复只有两条：人在 UI 上按「提权」（直接走 `Chain.run`），
  或者重启一次（开机自愈 1.8.4/1.8.6 验过零 adb 输入可跑通，顺带把 G 补读）。
  要不要把"标记在但通道没了"也改成该补针——那会改变炸机概率——**等人点头**（任务 #24），我没自作主张。

★★**7 上没有 adb 侧兜底**（§599 本轮实测，别再按 6.0.1 的直觉行事）：
  · `modprobe_path` 那半：针命中、路径改成 `/data/local/tmp/sudA`、ENOEXEC 触发放出去了，daemon **从未被执行**
    （`sud.stage` 尾部仍是旧 daemon 的行）⇒ 7 上 usermodehelper 仍是死的（task #5 在新 build 上重放成立）；
  · 从 shell 打产品自己的 LADDER7：`the needle never published a task -- nothing to patch`、`result=1 uid=2000`
    ⇒ **针必须活在 app 进程里**（同一条 ladder 在 app 侧本开机早先是 `result=2 uid=0`）。
  结论：daemon 死掉 = 只能靠人在 UI 上按一次，或重启。**恢复现场用的写内核要 `rounds=40`**（同一发里 `rounds=10`
  连试 3 次都 `no hit`，换 40 第一发就中），别照抄 `CLOBBER_ROUNDS` 的默认 10。

一条与第三方 app 相关的边界（诚实写出）：§579 量到 7 的厂商名字闸按 **execve 传进去那条路径的最后一段**判，
非 root 域 exec 任何以 `/su` 结尾的路径都被静默 EPERM（无 avc）。所以 K 只担保"不再有 0 字节空壳"，
**不担保 app 硬编码的 `su` 能在 7 上 exec 成功**；第三方 app 在 7 上的可用入口是 `sux`（§18 的 nsmbind 挂进 init 命名空间那一条）。
真正把 `su` 交出去需要找到 7 上那把闸的实现位置并内存态放宽——§579 记了四条反证，仍未定位。

怎么重建（不需要 gradle）：
    bash tools/build_all.sh          # 原生件 + 三把主机闸（sud_layout / grants_rule / copy_atomic），臂红即中断
    bash tools/apk/build.sh          # aapt + javac + d8 + zipalign + apksigner -> tools/temproot.apk
    本 tar 不含任何二进制；解开后按上面两条即可复现同形产物（签名证书不在包内，签名不同是预期）。
不含：keystore／签名私钥／任何凭据。`file` 扫过全树，ELF／Zip／Java KeyStore 命中 0。

相对 1.9.1 的唯一改动（ledger §600）：
  · `broot7` 的"凭证借到没有"判决改用**同一枚通道的 cred 回读**作决定性证据，uid／securebits 降级为附带读数。
    旧判据要求 `uid==0 && securebits==64`，而 BACKLATE 路径跑到存活窗时 init_cred 的 securebits 已被 teardown 归零
    ⇒ 实测把一次**成功**的借券报成 `borrow did not take (uid=0 sb=0)` 并 rc=2（=LATE 窗存活判据失去分辨力，task #16）。
    现在四种情形各自有名：真取／已借（readback 前后都是 init_cred）／没落地／无回读只能靠附带证据（明说这不是证明）。
    共编头 `tools/borrow_verdict.h` ＋主机臂表 `tools/borrow_verdict_test.c`（7 臂，含一枚把旧判据照抄进去的 `teeth:` 臂，证明它确实会把那次成功读成失败）。
    五把闸现全挂在 build_all.sh：sud_layout 6/6・approot_coverage 16 判据・grants_rule 14・copy_atomic 10・borrow_verdict 7。
  · 包内实测：`assets/broot7` md5 `4c587d4f…` ＝ tools/broot7・`assets/sud` md5 `9bf85043…` 未变。

★那一按的最小准备（§602 现读，adb 能做的都做了，唯独注入事件被 InputDispatcher 按窗口属主拒）：
    adb shell svc power stayon true        # 叫亮屏幕（input keyevent 26/224 在这台机上叫不醒）
    adb shell wm dismiss-keyguard          # 无密码锁屏可直接划开
    adb shell am start -n com.xplay6.temproot/.Main
    adb shell pm install -r -t /data/local/tmp/temproot-1.9.2.apk
    # ★按文案点，不要按坐标：屏是 UI 1080x1920，而触摸屏原始值域是 1440x2560（4/3）——任何记住的
    #   像素中心到了 evdev 那层都落在别处（ledger 604）。安装框文案『继续安装』、app 内按钮文案『提权』；
    #   若先弹「您的IMEI或MEID是无效的」，先按掉它的『知道了』再点安装。
    adb shell svc power stayon false       # 收尾，别把屏幕留在常亮
  证据：`input tap` 在窗口已聚焦、节点 clickable=true、坐标正确的情况下仍无效果，logcat 给的是
  `W InputDispatcher: Permission denied: injecting event from pid N uid 2000 to window … owned by uid 10151`
    ⇒ shell 不能向别人的窗口注入；root 侧 input tap 也被 SIGKILL（Killed、rc=137，补 ANDROID_DATA
    一样）；而 sendevent 在通道在、root 在手时实测也不生效：修掉两枚形状错（BTN_TOUCH 不在该节点
    keybit、TRACKING_ID 值域 0..10 故 -1 被丢、抬起要用 TOUCH_MAJOR=0）之后，触摸与音量键
    （event1 的 EV_KEY 127）两枚独立证人都不产生 Android 侧效果（604/607）。★§611 更正：换 `/dev/uinput` **新建**设备后，普通 app 的窗口**确实被点动了**（app 自己的『授权日志』面板），但 vivo 的安装确认框仍点不动（对话框在 1.5 s 就现形、点击 4 s 落地，远早于 ~14 s 超时）⇒ 假设是安装框属受信任窗口、丢弃非可信输入设备的事件；**这一格仍要人按**。
    ★门的代码层形状（ledger 606）：system_server 的 VivoAdbInstallManager 只认三支回调——
    …_FROM_BC（vivo 自己的组件）／…_FROM_PKMS（真实 installer 包名）／…_FROM_TIMEOUT，
    adb 发起必然走到 TIMEOUT ⇒ 必须由人按。
