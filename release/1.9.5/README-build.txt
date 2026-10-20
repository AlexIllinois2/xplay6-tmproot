月虹提权助手 v1.9.5 (versionCode 26) -- Android 7.1.1 / PD1610_D_7.12.15 / 3.18.31-perf-g9dce1fbc9

唯一的新能力：**manager app 自己 bind `@sud`**，让第三方 app 也能在这台 7 上拿到有内核身份的 su 通道。
为什么必须这样（art/ledger-20261016.md 623-626，全部实测）：
  · 提权后的那枚 cred 可以 create/connect/accept AF_UNIX，但 **bind SOCK_STREAM 一律 EPERM**（SOCK_DGRAM 可用）；
    uid 0→2000、capset 拉满、setgroups 削组、`enforcing=0` 窗口内、`u:r:init` 域下——全都一样；
    而未提权的 adb shell 与 manager app 自己（`@trq10151.*`）bind stream 是通的。
  · 第三方 app 要一条有内核身份（SO_PEERCRED）的通道，就必须有人能 bind stream ⇒ 让**能 bind 的人**来 bind：
    app 里 exec `relayd --serve-if-free`，它 accept 调用方 → `getsockopt(SO_PEERCRED)` 取 uid → 查自己的
    `grants.txt` → 才用 app 自己的 `su.token` 走 TCP 12346 发 `SU 0 <cmd> TOK=...`（与 Chain.java 逐字同形），
    stdout 沿同一条 unix 连接转回。**`sud` 一行没改、协议没扩**；授权仍由 manager 的名单决定，身份仍是内核给的。
  · `--serve-if-free`＝先探测 `@sud` 是否已有人监听，有就**主动让位**：这条保证 6.0.1 那条已出货路径
    （daemon 自己 bind `@sud`）不会被 app 端劫走；同一开机重复调用也自然幂等。

包内 asset 与主机现编逐字节相同（出包时现算）：assets/relayd 2 155 848 B・assets/broot7 2 240 192 B・assets/sud 2 204 376 B。
`tools/build_all.sh` 现在直接产出 relayd（不是手编），`tools/apk/build.sh` 缺它会拒绝出包。

装机后自己检查这三条（不是话术，是判据）：
  1) `relayd --selftest`（dev 件，未提权即可跑）：bind 通・uid 来自内核・撤销即时生效；
  2) `/sdcard/Android/data/com.xplay6.temproot/files/relayd.log` 里应出现
     `relayd: listening on @sud`（接管）或 `... already listened to ... standing down`（让位），二者都算对；
  3) `bash tools/verify_approot.sh <ser>`：判据 E 已改成**同时读 sud 与 relay 两本账**（sud 只看得见 manager 的
     token，真实调用方的 allow/deny 行从 626 起只在 relay 那本里）；B/C/D 在 7 上此前是 REFUSED（工装没尺），
     这一版之后应当变成可判。
装机路径与 1.9.4 相同（本目录 SHA256SUMS 校验后用 tools/install_tap.py，全程无人：亮屏需先看 mWakefulness）。
