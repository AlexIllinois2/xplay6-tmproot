月虹提权助手 1.9.17 (versionCode 38) -- current shipping build
===============================================================

WHAT IT IS
  Memory-only temp root for the Xplay6 (PD1610).  Boot-time self-escalation (one binder needle), a
  daemon that gates root per app uid, and on Android 7.1.1 the defeat of vivo's exec-time guard on the
  literal name `su` so unmodified third-party apps (Shizuku, libsu callers) work.  No partition is
  written and the bootloader stays locked: `adb reboot` returns the phone to factory behaviour.

REBUILD
  bash tools/build_all.sh
  bash tools/apk/build.sh
  Produces tools/temproot.apk; this release is that file, sha256 in SHA256SUMS.txt, versionCode 38.
  Byte policy, verified with cmp after building: assets/sud, assets/su (=tools/suc), assets/sumount,
  assets/relayd, assets/nsmbind, assets/broot7 and lib/arm64-v8a/libesc.so are byte-equal to the tools/
  binaries built from this tree, and it is exactly this package that ran the boot reported in STATUS --
  so unlike 1.9.16 (which deliberately carried 1.9.15's broot7), no shipped byte here is unbooted.
  Note if you rebuild: a fresh `tools/apk/build.sh` run produces a ZIP whose md5 differs from this
  file's (zip timestamps), while classes.dex, libesc.so and the six assets cmp identical.  The
  installed-on-device copy and this release copy are the same file (md5 b5b14563...), taken before
  the gate step was added to build.sh.

JUDGE IT
  bash tools/verify_approot.sh <serial>                      # 16 criteria, main mode
  POST_REBOOT=1 bash tools/verify_approot.sh <serial>        # criterion G, exits right after G
  EXPECT_ENFORCING=1 bash tools/verify_approot.sh <serial>   # adds criterion H (root with Enforcing)
  python3 tools/pgdalias.py --profile 7                      # re-derives and asserts the gate site
  python3 tools/gate_constants.py --selftest                 # the APK's compiled-in numbers vs that
                                                             # derivation; apk/build.sh runs it as [0/6]
  bash tools/rehearse_sugate.sh                              # 14 mock arms, no phone

FOR ANYONE EDITING THE ALLOW LIST FROM A SHELL
  The list is the manager app's own file: /data/data/com.xplay6.temproot/files/grants.txt, one uid per
  line, mode 0600, owned by the app uid AND labelled with the app's MLS categories.  Do not create it
  with `mv` from a root shell: a root-made inode inside app data arrives without those categories, and
  an enforcing appdomain can then neither read nor replace its own list -- measured as a two-boot
  single-factor A/B in art/ledger-20261016.md 677.  Rewrite in place instead:

      grep -v '^10134$' $G > /tmp/x; cat /tmp/x > $G; rm /tmp/x

  and if you must replace the file, finish with `chown <uid>:<uid> $G; chmod 600 $G; restorecon $G`.
  The in-app UI path (勾上某个应用 -> 保存) is unaffected and is what the owner actually uses.

KNOWN LIMITS OF THIS BUILD
  * One kernel needle per boot; the boot trigger does not re-fire on a boot already served.
  * JobScheduler on this ROM refuses the re-check job (`job schedule rc=1`), so if the relay dies it is
    re-armed when the app starts again or when 提权 is tapped -- not by the scheduler.
  * A caller that is already root is refused by the relay by design (the list holds app uids).
  * The 6.0.1 route keeps the older gate-patch shape (window unproven -> patch anyway, clobber.c:898);
    it cannot be witnessed while this phone runs 7, so it is stated as a limit, not as verified.

TRAIL: art/ledger-20261016.md 664, 670, 675, 676, 677, 678.
