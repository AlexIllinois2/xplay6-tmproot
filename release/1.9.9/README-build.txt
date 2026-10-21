月虹提权助手 v1.9.9 (versionCode 30) -- Android 7.1.1 / PD1610_D_7.12.15 / 3.18.31-perf-g9dce1fbc9

这一版把 1.9.5 那条**没跑起来的 relay** 真装上并跑通了，另外交出四处我自己造成的缺陷与一处会说谎的设计。
账在 art/ledger-20261016.md §629（含每一条的当场读数）。

★这一版的新状态（相对 1.9.5）
1) **relay 在出货路径上监听成功**：app 起 `relayd --serve-if-free --sock sud` 后，
   `/sdcard/Android/data/com.xplay6.temproot/files/relayd.log` 现读
   `relayd: listening on @sud (uid=10151)`（38 字节），`/proc/net/unix` 里 `@sud` 1 枚。
   同一枚 relayd 在**借来的 cred** 下实测 `REFUSE: bind @sud-probe errno=1` —— 这正是"为什么必须由 app 来 bind"的正控
   （§623–§626：提权后的 cred `connect`/`accept` 全好，只有 `SOCK_STREAM` 的 `bind` 被拒，与 uid／能力／域／命名空间／enforcing 无关）。
2) **开机自愈的判据换了来源**：`BootJob.alive()` 以前只看持久 mark（`esc_boot`），daemon 死了它仍回答
   `this boot already reads as escalated`，于是"整台机既没 root 也没通道，只能等人手点『提权』"。
   现在顺序＝`enforce=Permissive`（窗正开着，别抢）→ **现读 TCP 127.0.0.1:12345 连不连得上**（不需要 root 的证人）
   → 只有 daemon 真没了才允许再花一枚针，且**每枚开机只给一次**（`retry_boot` 记下花掉的那枚 boot epoch；
   用完就在日志里明写"只剩人手点『提权』"）。
   实测：1.9.8 装机后我把 dev daemon kill 掉，`adb shell am startservice -n com.xplay6.temproot/.EscService`
   一发自动重跑整条链，恢复 `uid=0`＋relay 监听＋`Enforcing`，屏上零操作。
   **代价说清楚**：针的实测崩率 ~1/13 从"人手那一发"搬到"自动那一发"，总预算不变；不同意这个取舍就装回 1.9.5/1.9.6，即回退。
3) 修了三处会让人误判的工装缺陷：`stage()` 唯一临时名（1.9.6 起，不再 ETXTBSY）、`openSuName7` 不再把自己的
   `broot7.log` 截成 0 字节（1.9.6 起）、`apk/build.sh` 的前置闸曾被上一次补丁写成 `]; t|| [ …`（`then` 被吃掉一枚字符，
   且 `[ ]||[ ]` 让前半段变死码）——现已修并把 `broot7`/`nsmbind` 一起纳入闸，`bash -n` 过。
4) `tools/install_tap.py`：tap 之前发到设备上会散架（adb 用空格拼 argv、设备 shell 再切一次词 ⇒ 坐标成了额外参数，
   `sud` 答 `ERR target uid not allowed`）。现改成一条引号完整的字符串参数，并加"landed/refused"计数：
   **有 tap 被拒就 rc=3**，因为 `Success` 本身不能证明 tap 通（本次就是三枚全拒而安装仍 Success）。

★装机（这一版**不需要人**）
`adb -s <ser> push release/1.9.8/月虹提权助手-v1.9.8-release.apk /data/local/tmp/temproot-1.9.8.apk`
`adb -s <ser> shell pm install -r -t /data/local/tmp/temproot-1.9.8.apk` → `Success`
（对**已装包**的 `-r` 重装，本 ROM 不需要屏上确认框；§620 那套"两段框：先点『继续安装』再点文案恰好是『安装』的那枚"
 只适用于**首装／未知来源**那条流程。首装要先 `chcon u:object_r:apk_data_file:s0 <apk>`，
 且要先有一条 root 通道（开发期用 `tools/install_and_verify.sh`／daemon 的 TCP 12345 都行；没有通道时就得按 §620 那套点框）。）
校验：`cd release/1.9.8 && sha256sum -c SHA256SUMS.txt`

★装上之后自己检查（判据，不是话术）
1) `bash tools/verify_approot.sh <ser>` —— 判据枚数由尺自己报；E1/E2 现在同时读 `sud.log` 与 `relayd.log` 两本账
   （relay 之后 `sud` 只看得见 manager 的 token，真实调用方的 allow/deny 行只在 relay 那本里）。
2) `cat /sdcard/Android/data/com.xplay6.temproot/files/relayd.log` 应出现 `relayd: listening on @sud`；
   若 6.0.1 那条路径已由 daemon 自己 bind，则应出现 `... standing down`（`--serve-if-free` 是专门防劫持的）。二者都算对。
3) 自愈那一格：`POST_REBOOT=1 bash tools/verify_approot.sh <ser>`（重启后零 adb 输入应自己出现 `sud` 监听＋`getenforce=Enforcing`）。
   注意 **卸载重装会重置 vivo 自启动开关**，`pm install -r` 不会。

★边界（本包做到的形状）
不解 BL・不写任何分区・只做内存态（`adb reboot` 即回到出厂）；授权表默认只放本 app 的 uid；
`su` 名字闸按 exec 路径最后一段判；未列名的一律 `ERR unknown service`。
