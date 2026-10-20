月虹提权助手 1.9.16 (versionCode 37) -- build recipe, byte policy, how to judge it
======================================================================================

WHAT IT DELIVERS
  A memory-only temp root for the Xplay6 (PD1610).  The app escalates itself at boot with one binder
  use-after-free needle, starts a daemon (sud), and hands root to the app uids listed in its own
  per-uid allow list.  On Android 7.1.1 (kernel 3.18.31-perf-g9dce1fbc9) it additionally defeats
  vivo's exec-time guard on the literal name `su` so that third-party apps which hardcode `su`
  (Shizuku, libsu callers) work unmodified.  Nothing is written to any partition: `adb reboot`
  restores the factory state, including the name gate.

REBUILD (needs Android SDK build-tools 35.0.0, platform android-34, NDK 29.0.13846066)
  bash tools/build_all.sh          # native half: sud suc sumount relayd broot7 nsmbind libesc.so ...
  bash tools/apk/build.sh          # signs tools/temproot.apk with tools/apk/debug.keystore
  The APK's native half is the SAME tools/clobber.c compiled a second way (-DESC_LIB) plus
  tools/apk/jni/jni_esc.c -- there is no second implementation to drift.
  This package was built from versionName 1.9.16 / versionCode 37 in AndroidManifest.xml.

BYTE POLICY OF THIS PACKAGE (why assets/broot7 is 1.9.15's bytes, verified with cmp)
  Every byte shipped here has a reading from a device that ran it:
    classes.dex, lib/arm64-v8a/libesc.so   == the artifact that produced the boot log quoted in STATUS
    assets/sud, su, sumount, relayd, nsmbind == byte-equal to tools/ built from the current sources
    assets/broot7                          == byte-equal to the 1.9.15 package (three successful boots)
  A freshly relinked broot7 exists in this tree too (+520 bytes, five extra `sugate7*` symbols that
  broot7 never calls, because build_all.sh links clobber.c's ESC_LIB object into it).  It was
  deliberately NOT shipped in 1.9.16: shipping it would have put an unbooted binary in a package that
  claims a green table.  It became the shipped one in 1.9.17, whose own boot ran it.

HOW TO JUDGE IT (device attached, daemon already up from a boot-time chain run)
  bash tools/verify_approot.sh <serial>                     # the 16-line main table
  POST_REBOOT=1 bash tools/verify_approot.sh <serial>       # criterion G: reboot restores factory
  EXPECT_ENFORCING=1 bash tools/verify_approot.sh <serial>  # criterion H: root with Enforcing up
  bash tools/rehearse_sugate.sh                             # 14 mock arms, no phone needed
  python3 tools/pgdalias.py --profile 7                     # re-derives and asserts the gate site
                                                            # (0xffffffc000323400) against fw/7/Image

KNOWN DEFECT IN THIS BUILD  -- see STATUS for the full text; fixed in 1.9.17
  The boot path's self-grant reads its own allow list as empty when the list's inode was last created
  by root (missing the app's MLS categories), and 1.9.16 treats an empty read as an empty list and
  tries to write it back.  The owner's third-party entries survive only because that write also fails.
  Do not hand-edit /data/data/com.xplay6.temproot/files/grants.txt with `mv`; rewrite it in place
  (`cat new > file`), or run `chown <uid>:<uid>` plus `restorecon` on it afterwards.

TRAIL
  art/ledger-20261016.md sections 664 (site), 670 (boot chain opens the gate), 673 (reboot durability),
  675 (first green 16/16), 676 (window witness moved before the .text write), 677 (the self-grant
  mechanism, measured as a two-boot A/B), 678 (1.9.17's own green boot).
