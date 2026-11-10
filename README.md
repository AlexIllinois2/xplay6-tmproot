# xplay6-tmproot

**English** | [简体中文](README.zh-CN.md)

Memory-only temporary root toolchain for the **vivo Xplay6 (PD1610, msm8996)**. It explores and delivers root access without unlocking the bootloader and without writing any partition: the whole effect lives in RAM and in the running SELinux policy table, and a reboot returns the device to its factory state.

This is device-specific research code, not a general-purpose root solution. The app was previously published as **月虹提权助手**, and its display name has been `xplay6 tmproot` since v1.9.33 (package name unchanged: `com.xplay6.temproot`).

## What is in this repository

| Part | Path | Purpose |
| --- | --- | --- |
| Manager APK | `tools/apk/` | Java UI, manifest, JNI bridge, and the assets bundled into the APK. Built to `tools/temproot.apk`. |
| Native escalation sources | `tools/*.c`, `tools/*.h`, `tools/*.S` | Kernel-write / credential-borrowing code, the bundled daemons, the `su` client, and helper binaries. |
| Build scripts | `tools/build_all.sh`, `tools/apk/build.sh`, `tools/build_magisk_module.sh` | Native build, APK build, and Magisk runtime module build. |
| Magisk module support | `tools/apk/assets/modmount.sh`, `modboot.sh`, `modcust.sh`, `modlist.sh`, `tools/build_magisk_module.sh` | A Magisk-format module engine and a userspace Magisk 30.7 runtime (no patched boot image). |
| Verification and install | `tools/verify_approot.sh`, `tools/install_and_verify.sh`, `tools/install_magisk_module.sh`, `tools/run_temproot.sh` | Device acceptance, APK install, module install, and the adb-side escalation route. |
| Releases | `release/*/` | Versioned release APKs and per-version build/status/integrity documents. The newest artifact is `release/1.9.39/`. |
| Research material | `art/`, `exp8/`, `ota8/`, `pocs/` | Forensic ledgers, kernel symbol dumps, live policy dumps, 8.1 exploitation notes, and public CVE PoC sources. |

The app source tree currently declares **v1.9.40** in [AndroidManifest.xml](file:///home/v/.local/project/xplay6/xplay6-tmproot/tools/apk/AndroidManifest.xml); the newest packaged release in this repository is **v1.9.39**.

## Supported devices and firmware

Only the following vivo Xplay6 (PD1610) firmware/kernel combinations are accepted. Any other kernel is refused: the code does not guess addresses or offsets.

| ROM | Android | Kernel | Route |
| --- | --- | --- | --- |
| `PD1610_D_1.15.1` | 6.0.1 | `3.18.20-perf-gb6998a3` | Route 6: `modprobe_path` / usermode helper |
| `PD1610_D_1.17.12` | 6.0.1 | `3.18.20-perf-geb775ef-dirty` | Route 6, profile selected from the running UTS release |
| `PD1610_D_7.12.15` | 7.1.1 | `3.18.31-perf-g9dce1fbc9` | Route 7: self-contained in-kernel privilege changes plus a per-domain `permissive_map` exemption |
| `PD1610_D_8.19.16` | 8.1 | `3.18.71-perf-g8a8c60dd` | Route 8: CVE-2019-2215 binder UAF used as a kernel write |

Route selection is based on the running kernel release in `Chain.java`. A `3.18.71` kernel whose build tag is not exactly `3.18.71-perf-g8a8c60dd` is refused rather than downgraded to another route.

Known route-specific limits, as documented by the project:

- Route 8 relaxes SELinux globally (`selinux_enforcing=0`) and leaves it off until reboot. It has no per-domain exemption.
- Route 7 makes seven SELinux types per-domain permissive; this weakens the whole security context of those types, not only the `su` path.
- On 8.1 the vendor's exec-time gate still rejects the literal name `su`; granted apps must invoke `sux` instead.
- Route 6's name-gate support is verified for 1.15.1; the equivalent site is not ported to 1.17.12, which refuses that arm.
- On 1.17.12, `adb install -r` may silently return `INSTALL_FAILED_CANCELLED_BY_USER`; uninstall the package first (`adb uninstall com.xplay6.temproot`), then install.
- Route 7 defeats its name gate with a RAM-only patch on every boot (see [su delivery and the route-7 name gate](#su-delivery-and-the-route-7-name-gate)). On a boot where that patch does not land, only `sux` works there.
- No route can deliver `su` into `/system/bin`: it is the read-only `dm-0`, and this kernel refuses both bind and tmpfs mounts there.

## su delivery and the route-7 name gate

On `3.18.31-perf-g9dce1fbc9`, any domain but init/root is refused when it execs a file whose last path component is `su`. The verdict is `tbnz w0,#0x1f` at `0xffffffc000323400` in `do_execveat_common`, branching to the `mov w19,#-1` reported as `EPERM`. It matches the name only: inode, label and contents do not matter, and the same bytes named `sux` run.

Route 7 removes that check instead of renaming around it. `Chain.openSuName7` drives `libesc.so` through four steps, in this order:

1. plant the top pgd slot (`0xffffffc001f4cff8`, descriptor `0x0040000040000711`) so the kernel image is writable through the `0xffffffffc0000000` alias;
2. write `/zz` over `modprobe_path` (`0xffffffc001a499b8`) through the alias and read it back through the root channel;
3. restore the original path through the alias and read it back again;
4. only then write `NOP` (`0xD503201F`) over `0xffffffc000323400`, and prove it by exec'ing the delivered `su` from the app's own `untrusted_app` process.

The two data witnesses exist because the alias is the same mechanism the `.text` write uses: if either read-back does not move, the chain aborts and no text byte is written. Nothing persists, so the whole sequence is re-run on every boot (up to four attempts), and the delivered `sux` remains the fallback for a boot where it does not land.

`su`/`sux` are published by `nsmbind` at the end of the chain. Two details are load bearing: the bind must be `MS_BIND | MS_REC`, because the mirror reproduces every pre-existing entry as a file placeholder and a plain `MS_BIND` would expose those as 0-byte files (the `/sbin` 0-byte entries that used to restart critical services); and the mirror path is unique per run (`<base>.<pid>.<timestamp>.`), so a second run cannot publish over the first. `sysoverlay` skips `su`/`sux` under `/sbin`, `/system/bin` and `/system/xbin`, so a module's copy cannot replace the client that talks to this daemon.

The su service frames its replies when the client opens with `XSU2 ...` / `XSU2B ...`: `[1 byte type][4 byte big-endian length][payload]`, where 1 = stdout, 2 = stderr, 3 = exit code, 4 = ready, 5 = retry. stdout and stderr stay separate, which is what libsu's `ShellImpl` expects: it waits for its UUID marker on both streams and reports "no root" when they are merged. Plain `SU ...` clients keep the old merged stream byte for byte.

## Build

Requirements, as stated by [README-build.txt](file:///home/v/.local/project/xplay6/xplay6-tmproot/README-build.txt):

- Android SDK build-tools **35.0.0**
- Platform **android-34** (`android.jar`)
- NDK **29.0.13846066**
- Paths are overridable with `SDK`, `BT`, `PLAT`, `NDK_VER`, `ROOT`, and `OUT`.

Native pieces first (this is the single entry point for the native half):

```bash
SDK=/path/to/Android/Sdk bash tools/build_all.sh
```

Then the APK:

```bash
SDK=/path/to/Android/Sdk bash tools/apk/build.sh
```

The result is `tools/temproot.apk`. If the native binaries under `tools/` are missing or older than their sources, `tools/apk/build.sh` calls `tools/build_all.sh` itself. The repository root also has a convenience wrapper:

```bash
bash build.sh   # equivalent to: SKIP_GATE=1 SDK=$HOME/Android/Sdk bash tools/apk/build.sh
```

**Build gates:** `tools/apk/build.sh` normally re-derives the kernel addresses and SELinux exemption numbers from `fw/Image`, `fw/7/Image`, and `fw/1712/Image` (not shipped in this repository, see `release/1.9.39/INTEGRITY.txt`) plus the `art/` symbol and policy dumps. If those images are absent the gate aborts. `SKIP_GATE=1` bypasses the re-derivation and prints a warning; artifacts built that way must not be presented as constants-verified. With `SKIP_GATE=1`, the route-7 constants in the shipped binary are the ones measured and verified on this build, not re-derived: pgd entry `0xffffffc001f4cff8`, gate `0xffffffc000323400` (`0x37F823A0` to `0xD503201F`), `modprobe_path` `0xffffffc001a499b8`, alias base `0xffffffffc0000000`, block descriptor `0x0040000040000711`.

Magisk runtime module (needs a Magisk APK and a built native tree):

```bash
MAGISK_APK=/path/to/Magisk-v30.7.apk bash tools/build_magisk_module.sh
# optional: bash tools/build_magisk_module.sh --install
```

Signing: `tools/apk/debug.keystore` is included in this repository (password `android`). If it is absent, `tools/apk/build.sh` generates a new key with the same DN (`CN=TempRoot`), so rebuilds are byte-identical in content but not in signing certificate.

## Usage

1. Install `tools/temproot.apk` (or the release APK from `release/`).
2. Open the app and tap **「提权」**. Success is reported as `Root 已就绪`; on some routes the SELinux state returns to `Enforcing` only after the daemon is up.
3. Authorize apps on the **「应用授权」** page. The allow list takes effect immediately.
4. Granted apps call `su` through the project's channel; on 8.1, and on 7.1.1 in a boot where the gate patch did not land, call `sux`. Root-owned processes are intentionally rejected.
5. For automatic re-root after reboot, allow the app to auto-start in **i管家 → 权限管理 → 自启动**. Uninstalling and reinstalling resets this vendor switch.
6. A reboot removes everything. There is no persistent root, no boot image patch, and no partition write.

The adb-side route and acceptance scripts are also available:

```bash
bash tools/run_temproot.sh <serial>          # adb-only memory root route
bash tools/install_and_verify.sh <serial>    # pick the newest release APK, install, verify
bash tools/verify_approot.sh <serial>        # acceptance criteria; EXPECT_ENFORCING=1 for the Enforcing check
```

## Directory layout

```text
xplay6-tmproot/
├── build.sh                 # convenience APK build wrapper (SKIP_GATE=1)
├── README-build.txt         # historical v1.6 build notes (Chinese)
├── MANIFEST.txt             # SHA-256 manifest of archived source/doc members
├── tools/                   # native sources, scripts, APK Java/JNI/manifest, module engine
│   └── apk/                 # manager APK source and build
├── release/                 # versioned APKs and build/status/integrity documents
├── art/                     # forensic ledgers, kallsyms and live-policy dumps, runbooks
├── exp8/                    # 8.1 exploitation research (CVE-2019-2215, KGSL notes)
├── ota8/                    # 8.1 config and symbol tables
└── pocs/                    # public CVE PoC sources
```

`art/*.md` ledgers are the project's evidence trail and are written mainly in Chinese. The `release/*/README-build.txt` and `STATUS` files are likewise Chinese; they record what was actually verified for each version.

## Risks and scope

- These are kernel-memory write primitives. A mismatch between source, kernel, or firmware can crash or reboot the device. Do not run this on firmware outside the supported table.
- The routes deliberately weaken SELinux, globally or per domain, for the duration of the boot. Treat the device as less isolated while rooted.
- There is no persistence. Every reboot removes root and any mounts, modules, and allow list created in RAM; only files under `/data` survive, but the root channel does not.
- The Magisk runtime module is a userspace workaround, not a normal Magisk boot-image installation. It depends on the temporary root channel and disappears with it.
- Use this only on a device you own and can restore. The project assumes a full flash package is available for recovery.

## License and provenance

This repository contains original research code plus public CVE PoC material under `pocs/`. Check each file's header before reuse. No license file is included in this source tree; do not assume redistribution rights beyond what the repository owner grants.
