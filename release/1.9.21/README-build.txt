构建配方（原生件字节未变，只多了 app 侧"喂 pref"那一手）:
  1) bash tools/build_all.sh          # 本次未跑（六枚原生件已存在且逐字节同，见下方"字节政策"）
  2) bash tools/apk/build.sh          # [0/6] gate_constants 真跑：18 对常量 vs pgdalias 从 fw/*/Image 的推导 → GATE CONSTANTS AGREE
                                      # 产物 tools/temproot.apk（5445906 B，md5 d57d63785f80b6a1c5f0c0ebc13ac318）
  3) cp tools/temproot.apk release/1.9.21/月虹提权助手-v1.9.21-release.apk && bash tools/pack_release.sh
                                      # 版本由 manifest 现取（v1.9.21 / versionCode 41）、406 枚成员、8.9M

本版新增（唯一功能变化）:
  Chain.unlockAdbInput() —— 经 `Chain.su(0, …)` 往 **`/data/user_de/0/com.android.settings/shared_prefs/development.xml`**
  写 Settings 自己的 `account_verified_ok=true`（`chown 1000:1000`・dir 771/file 660・`restorecon`・**幂等**），
  并回显一行证人：`UNLOCK_ADB_INPUT st=written|already|write_failed count=<n> label=<seinfo>`。
  `EscService` 两条路都挂：`Chain.run` 之后、以及"本开机已提权"那支与 `ensureRelay` 并列。
  ★目的＝让开发者选项里「USB模拟点击」**不再要求登录 vivo 账号**（那枚开关的正按钮先读这条记录，真则直接写 Secure 值）。

装机与读数（设备 3e5a38a5・PD1610・7.1.1・Enforcing，2026-10-21）:
  · 无人装机：`python3 tools/install_tap.py /data/local/tmp/n.apk` → `继续安装`→`安装` 两发 `landed=2 refused=0` → `Success`・`installed versionCode: 41`
  · 针：`am startservice …/.EscService` → `ladder attempt 1` 中（`uid=0(root) … context=u:r:init:s0`）
  · 幂等支：`adb-input witness: UNLOCK_ADB_INPUT st=already count=1 label=u:object_r:system_app_data_file:s0`
  · ★新鲜支：以 root 删掉那枚文件后重发 EscService（走 alive 支，不再花针）→
    `UNLOCK_ADB_INPUT st=written count=1 label=u:object_r:system_app_data_file:s0`，`cat` 回读 126 B、形状与验过的那份逐字节同

字节政策（§676/§682 延续）:
  - 与 1.9.19 出货包逐成员对照，**7 枚原生件全部 SAME**：`assets/broot7 4ba5e535…`・`assets/su f93aa6ec`・`assets/sud 9bf85043`・
    `assets/sumount 5bd9f8d7`・`assets/relayd 33b15721`・`assets/nsmbind 3bc654f8`・`lib/arm64-v8a/libesc.so 95d7a617…`（前两枚与 1.9.19 README 记的 md5 前缀一致）。
  - 只有 `AndroidManifest.xml`（版本）、`classes.dex`（新功能）与签名块不同。

校验:  在此目录内 `sha256sum -c SHA256SUMS.txt`；`INTEGRITY.txt` 的 A/B 两节自核已在打包末步跑过（rc=0）。

边界（别当成已除去）:
  - ★**Secure 值本身仍要人拨**：daemon 的 root 没有任何 servicemanager 能力（`dumpsys window`→`Can't find service: window`），
    所以 app 只能让那一拨**不要账号**，不能替你拨。
  - 解开后任何接上这台机的 ADB 都能注入点击（厂商留的边界）。
  - 取证正文：`art/ledger-20261021.md` §691–§702（含我三次自我撤销的原文与 292 枚 `.odex` 的分母）。
