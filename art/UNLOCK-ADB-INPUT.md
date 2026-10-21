# 解开「USB模拟点击」＝让装包不再需要人按（一次性）

取证全文在 `art/ledger-20261021.md` §691–§701。这一页只写**怎么做**和**边界**。

## 一句话原理

system_server 的 `VivoPackageManagerSerivceUtils.preCheckUidPermission` 对 **uid 2000** 扣住 `INJECT_EVENTS`，
放行条件只有 `Settings.Secure vivo_adb_simulate_input == 1`（＋`vivo_monkey_test`／一枚属性）。
**判决里没有 vivo 账号**——"必须登录"整条只活在 Settings 的 UI：弹框正按钮先读
`SharedPreferences("development").getBoolean("account_verified_ok")`，真就直接写 1、不问账号。
PKMS 对该 Secure URI 挂了 ContentObserver ⇒ 拨完立刻生效，不用重启；且**实测跨开机存活**（1 → `adb reboot` → 1，本次开机 0 条写入日志）。

## 步骤（一次性）

```bash
python3 tools/unlock_adb_input.py --feed      # 需要 root 通道（daemon 活着）
# 然后：手机 设置 → 更多设置 → 开发者选项 → 「USB模拟点击」拨开 → 弹框按正按钮（不应再要账号）
python3 tools/unlock_adb_input.py --check     # 读数：vivo_adb_simulate_input = '1' → UNLOCKED
```

之后装包全程无人：`bash tools/install_and_verify.sh` 或 `python3 tools/install_tap.py <设备上APK路径>`
（`TAPBACKEND=adb` 已是默认，`--selftest` 五臂守着判据形状）。

## 边界（都是实测，不是推测）

- ★**最后那一下必须人拨**：root 侧写不了这枚值——daemon 的 root shell **没有任何 servicemanager 查询能力**
  （`dumpsys window` → `Can't find service: window`；`settings put` → `IActivityManager` NPE）。
- ★**pref 只能写 `/data/user_de/0/com.android.settings/shared_prefs/`**：Settings 的 manifest 带
  `defaultToDeviceProtectedStorage=true`，写 CE 那处（`/data/data/…`）会**静默读到 false**。
- ★`input tap` 要打在**行的开关侧**（实测 `(950,558)` 令 `screen_brightness_mode` 1→0→1）；打在标题中心不吃点击。
  两段安装框的按钮**同一坐标** `(540,1662)`，文案依次是『继续安装』→『安装』。
- ★解开后**任何接上这台机的 ADB 都能注入点击**（厂商留的安全边界，不是我们的缺陷）。
- 未做／未判：`ADB_SHELL_SIMULATE_PROP` 的属性名（`<clinit>` jadx 丢段）；`INTERCEPT_SHELL_PERMISSION_LIST` 的成员；
  `adb root` 已判为**这台机上结构性不可能**（adbd 起来自降到 uid 2000），代它发 `ctl.restart adbd` 会把 USB 整个打掉、要人重启才回——不推进。
