构建配方（与 1.9.17 同一套，只是原生件字节未变）:
  1) bash tools/build_all.sh          # 原生件：clobber / broot7 / sud / su / sumount / relayd / nsmbind + 五把主机臂表
  2) bash tools/apk/build.sh          # [0/6] 先跑 tools/gate_constants.py（18 对／9 臂），不一致就 ABORT 且不出包
                                      # SKIP_GATE=1 是唯一退出口，会在日志里明写"本次没有重新推导"
  3) 装包：adb push 本目录的 APK 到 /data/local/tmp → adb shell pm install -r -t <apk> → am start -n com.xplay6.temproot/.Main
     （本次实测没有弹 vivo 确认框；这与 §606/§620 不同，未取证，别当规律）

字节政策（§676/§682 延续）:
  - HP 那枚内核地址只存在于 tools/clobber.c 的 HPGAIN7_* 常量里，由常量闸现读 art/kallsyms-7-real.txt 校对
    （wcd_hph_gain 与邻符 soc_codec_dev_tasha 的间距 + HPGAIN7_LEN ≤ span），Java 侧不带任何地址。
  - CLI 的 hpgain 臂用 #ifndef ESC_LIB 圈住 ⇒ broot7 与 libesc.so 重新编译后逐字节不变
    （现读 cmp：4ba5e5355632aab37d3ed158214627df / 95d7a617ac533bbf5345e943e969162f）。
  - clobber 仍是 dev-pushed（不进气包）：进资产就要为那枚新字节再要一次开机读数。

SHA256SUMS.txt 的校验位置 = 本目录内（路径是裸文件名，别在仓库根跑 sha256sum -c）。
