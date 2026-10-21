月虹提权助手 v1.9.3 (versionCode 24) —— 诊断件，不是功能版

相对 1.9.2 有**三处**改动（art/ledger-20261016.md 614/615/616）：
  1) broot7 的输出**直接**落在 getExternalFilesDir()/broot7.log —— adb（shell）可以**实时**读，
     不再依赖 app 活到"复制日志"那一步（1.9.2 那两发重启就是死在复制之前，什么也没留下）；
  2) pb.start() 之前加一行 `ladder attempt N: exec … rounds=… log=…`，
     用来分辨"停在 exec 之前还是之后"。
提权链、授权层、SELinux 处理、assets 里的 sud/broot7/libesc 全部与 1.9.2 逐字节相同（未改）。

为什么需要它：1.9.2 装在机上后，开机链打完 `staged …/broot7` 就再无一行，而 `.sud/req` 仍是
interim 版留下的 0700 —— sud 从未执行。这一发把那一步的日志变成 adb 可见，G 与 I／I2／J／JP／K
才谈得上重测。

装它（**versionCode 从 23 升到 24，覆盖安装即可，不要 uninstall**——uninstall 会重置 vivo 自启动授权）：
    bash tools/install_and_verify.sh --yes
它自己会选到本目录（现读 versionCode）。装的时候弹 vivo 的『继续安装』：
    · 如果**有** root 通道（daemon 活着），我可以自己点：`adb shell … /data/local/tmp/uinput_tap <x> <y>`；
    · 如果**没有**通道（当前这台机就是这个状态），这一下必须由人在屏上按——按文案，不按坐标
      （触摸屏原始值域 1440x2560 ≠ UI 1080x1920，见 ledger 604）。
装完我这边接：adb reboot → 读 /sdcard/Android/data/com.xplay6.temproot/files/broot7.log
→ 拿一次 root 后把 .sud/req 修成 01777 root → EXPECT_ENFORCING=1 bash tools/verify_approot.sh
→ 再重启一次 POST_REBOOT=1 bash tools/verify_approot.sh（= 判据 G）。
