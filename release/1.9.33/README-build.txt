构建配方（本版原生源未改；包内原生件与 1.9.32 逐字节同）:
  1) bash tools/build_all.sh          # 需要重编原生件时跑；本版沿用 1.9.32 的产物字节
  2) bash tools/apk/build.sh          # [0/6] gate_constants 真跑（18 对常量 vs pgdalias 推导 → AGREE）
                                      # [0/6b] exempt_bits_check 真跑：c7_want / EXEMPT_BITS / 活策略表三处一致
                                      # 产物 tools/temproot.apk（5460057 B，
                                      #   sha256 ef03090c3585094c18fb770d09055263af01200157f028020bc390c73e2eaf26）
                                      # 末步 --verify-apk：包内豁免数组 ≠ 活策略答案时 ABORT
  3) cp tools/temproot.apk "release/1.9.33/xplay6-tmproot-v1.9.33-release.apk" && bash tools/pack_release.sh
                                      # 版本与产物名都由 manifest 现取（1.9.33 / versionCode 53 /
                                      #   label "xplay6 tmproot" → 文件名 xplay6-tmproot-v1.9.33-*）

本版改了什么（按文件）:
  tools/apk/src/com/xplay6/temproot/Ui.java     新增（约 400 行）：M3 暗色配色表、dp/text/heading/section、
                                                shape/groupBg/press（Ripple）、glyph/icon（24 网格 Canvas 自绘
                                                13 种图标）、Toggle（52x32 自绘开关，thumb 20→24dp）。
  tools/apk/src/com/xplay6/temproot/Main.java   重写（约 1200 行）：底部导航三页（首页/应用/设置）＋全屏
                                                日志覆盖层；首页 hero 状态卡（Root/SELinux/su 三格＋提权/刷新）
                                                ＋已授权应用概览卡（最多 4 行＋「管理 ›」）；应用页搜索过滤＋
                                                显示系统应用开关＋单卡片 ListView（行内 Toggle 不抢点击）；
                                                设置页四组；日志可选中、可清空；返回键先关日志再回首页。
  tools/apk/AndroidManifest.xml                 label 月虹提权助手 → xplay6 tmproot；versionCode 53 /
                                                versionName 1.9.33；Main 加 windowSoftInputMode=adjustResize。
  tools/pack_release.sh                         发布产物名改由 manifest 的 label 现取（空格→'-'），
                                                不再硬编码旧名；版本仍由 manifest 现取。

未改（与 1.9.32 相同）:
  Chain.java / Esc.java / EscService.java / BootJob.java / jni_esc.c / clobber.c / broot7.c / sud.c /
  suc.c / sumount.c / nsmbind.c / relayd.c。包内 7 枚原生件（assets/broot7・nsmbind・relayd・su・sud・
  sumount・lib/arm64-v8a/libesc.so）与 1.9.32 包内同名成员逐字节相同。

装机与读数（设备 3e5a38a5・PD1610・7.1.1・Enforcing，2026-10-21）:
  · 装机：`TAPBACKEND=adb python3 tools/install_tap.py /data/local/tmp/temproot-1.9.33-n.apk 3e5a38a5`
          → `landed=2 refused=0`・`installed versionCode: 53`；`am start -n com.xplay6.temproot/.Main` 正常。
  · 人工查看三页与日志页：见 `STATUS` 第 4 条；本版未跑自动验收表（机主明确豁免）。

字节政策:
  - 包内 `assets/broot7` 与 `tools/broot7` 逐字节同（sha256 301a0faa…）；
    出口闸 `exempt_bits_check.py --verify-apk` 在构建末步读包内数组，旧包会被当场拒。
  - 包内 `lib/arm64-v8a/libesc.so` 与 1.9.32 同（add897eb…）。

校验:  在此目录内 `sha256sum -c SHA256SUMS.txt`；`INTEGRITY.txt` 的 A/B 两节自核在打包末步跑过。

边界（别当成已验）:
  - 本版**未跑** 19/19 验收表与 G（重启自愈）；1.9.32 的绿不迁移为本版结论。
  - 7 枚型 per-domain permissive 的代价同 1.9.32：这些域整体对 MAC 宽松，不只 su 一条。
