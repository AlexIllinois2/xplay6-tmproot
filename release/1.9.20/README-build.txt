1.9.20 —— 只装「解开 USB模拟点击 / 装包不再需要人按」这一条能力

★这一格**没有新的 APK／原生件**：daemon、Java、C 全未改动（root 也写不了那枚旗，见 STATUS 的边界）。
  出货包仍是 `release/1.9.19/月虹提权助手-v1.9.19-release.apk`（`versionCode=40`，md5 `04d5c2d77f96c826627389bbcf9da7e1`）。
  1.9.20 的语义＝**工装＋程序**的版次，不是提权链的版次；别拿它当"装了就有 root"的那一类。

包内（`usb-simulate-click-tools.tar.gz`，按仓库相对路径解）:
  tools/unlock_adb_input.py   --feed 写 pref（含 owner/label/restorecon＋读回）・--check 只读判闸
  tools/install_tap.py        默认后端＝`input tap`（uinput 留作闸为 0 时的兜底）・`--selftest` 五臂
  art/UNLOCK-ADB-INPUT.md     一次性步骤＋四条实测边界
  art/ledger-20261021.md      §691–§701 全部取证（含我三次自我撤销的原文）

用法（一次性，之后每次开机自带）:
  1) bash tools/build_all.sh 不需要（原生件未动）。
  2) python3 tools/unlock_adb_input.py --feed      # 要 root 通道活着（daemon 在跑）
  3) 人做一次：设置 → 更多设置 → 开发者选项 → 「USB模拟点击」拨开 → 弹框按正按钮（喂过 pref 后**不应再要 vivo 账号**）
  4) python3 tools/unlock_adb_input.py --check     # 期望 `vivo_adb_simulate_input = '1'` → UNLOCKED
  5) 装包：bash tools/install_and_verify.sh 或 python3 tools/install_tap.py <设备上的APK路径>

校验:
  在此目录内 `sha256sum -c SHA256SUMS.txt`（路径是裸文件名，别在仓库根跑）。

字节政策延续（§676/§682/§690）:
  - 本格不含任何二进制，故不重签、不动 `INTEGRITY.txt` 那套；`broot7`/`libesc.so` 的逐字节不变仍由 1.9.19 那格负责。
  - `install_tap.py` 的判据形状（`clickable="true"` 结构过滤・`(text,point)` 去重）由 `--selftest` 五臂守着，
    其中一臂专门确认**夹具本身仍带那个陷阱**——臂在"本来就不会失败"的对象上永远绿，那不算尺。
