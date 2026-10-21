构建配方（本版原生件全部重编过，不是"缺件才编"）:
  1) bash tools/build_all.sh          # 六枚原生件
  2) bash tools/apk/build.sh          # [0/6] gate_constants 真跑（18 对常量 vs pgdalias 推导 → AGREE）
                                      # [0/6b] exempt_bits_check 真跑：c7_want / EXEMPT_BITS / 活策略表三处一致
                                      # 产物 tools/temproot.apk（5448108 B，sha256 0b61f57f952fd04c55f14bec3c980dbcaad7130a48d960891cf2399d11cafe64）
                                      # 末步 --verify-apk：包内豁免数组 ≠ 活策略答案时 ABORT（防"源码对了、包是旧的"）
  3) cp tools/temproot.apk release/1.9.32/月虹提权助手-v1.9.32-release.apk && bash tools/pack_release.sh
                                      # 版本由 manifest 现取（1.9.32 / versionCode 52）

本版改了什么（按文件）:
  tools/ebitmap_map.h      ★新增 ebmp_maps_word()：maps 字的正确取法（高半＝nd[3+2j]，低半＝nd[2+2j]）。
                           旧式 `nd[3+j*2+1]` 取到下一字，j=5 时取到 startbit ⇒ 任何住在字高半的位（含 192）永远读不出。
  tools/broot7.c           ① 出货位集 c7_want 七枚（kernel 192 / qti_init_shell 279 / init 593 / untrusted_app 743 /
                           shell 1083 / servicemanager 1156 / system_server 9）；② walk 解码改共用函数；
                           ③ 每枚节点连读两次，任一 u32 不一致即 refuse（不再把"瞄漏"当判决）；
                           ④ daemon fork 前从 /proc/mounts 现枚举全部 cgroup 挂载写 tasks，回读 /proc/self/cgroup 要求不含 uid_。
  tools/sud.c              escape_app_cgroup()：同式（枚举全部控制器，3/3）。
  tools/ebitmap_chain_test.c  新增 check_units_view()：字节视图＝逐 u32 单元视图＝输入，四档臂。
  tools/exempt_bits_check.py  三处对照 + --verify-apk。
  tools/verify_approot.sh  ① 新增 0b 段（从 sud.c 现读候选名单、dev:inode 判同、只清 /data/local/tmp 的工装残留）；
                           ② 跑前快照 + EXIT 还原（机主的名单跑完=跑前）；③ B/D/E/M/M0 判据；
                           ④ H 段删 2000 改 in-place（旧 `mv` 换 inode 会让收尾把自己的名单当垃圾删掉）。
  tools/binder_peers.sh    22 发电池（service/pm/settings/dumpsys/wm/appops/pm disable|enable），数 permissive=0 的真拒绝。

装机与读数（设备 3e5a38a5・PD1610・7.1.1・Enforcing，2026-10-21）:
  · 装机：`TAPBACKEND=adb python3 tools/install_tap.py`（两段确认框）→ `installed versionCode: 52`
  · 主模式验收表：`EXPECT_ENFORCING=1 bash tools/verify_approot.sh` → `coverage: 19/19 (mode=main)`・`pass=19 fail=0 refused=0`
  · Shizuku：`/proc/10015` `Uid=0000 u:r:init:s0 ppid=1`；界面 `Shizuku 正在运行`／`版本 13.6，root`
  · snub：uid 10135 点冻结成功、目标包 `enabled=2`；机主确认「有权限了」

字节政策:
  - 本版原生件与 1.9.21 **不同**（broot7/sud 都改了），包内 `assets/broot7` 与 `tools/broot7` 逐字节同（sha256 301a0faa…）。
  - 出口闸：`exempt_bits_check.py --verify-apk` 在构建末步读**包内**数组，旧包会被当场拒。

校验:  在此目录内 `sha256sum -c SHA256SUMS.txt`；`INTEGRITY.txt` 的 A/B 两节自核在打包末步跑过。

边界（别当成已除去）:
  - ★G（重启自愈）本版**没跑**：需 POST_REBOOT=1 ＋真实重启 ＋机主打开 vivo 自启动。
  - 7 枚型成为 per-domain permissive 是本修复的代价：这些域整体对 MAC 宽松，不只 su 一条。
  - 取证正文：`art/ledger-20261021.md` §707（真因）・§710（解码式）・§711（cgroup）・§712（对端集合）・§715（工装自伤）。
