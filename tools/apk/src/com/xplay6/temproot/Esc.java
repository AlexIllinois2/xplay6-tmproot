package com.xplay6.temproot;

/* libesc.so is the ESC_LIB build of tools/clobber.c plus the JNI bridge.
 * loadLibrary is the app's only way in: /data is mounted nosuid, so there is no
 * setuid helper to exec -- and none is needed, the chain needs no privileges. */
public final class Esc {

    static {
        System.loadLibrary("esc");
    }

    public static native String nativeProbe();

    public static native String nativeState();

    /** mapOnly=1: exempt only our own SELinux types through policydb.permissive_map and leave
     *  selinux_enforcing at 1, so `getenforce` keeps answering Enforcing.  mapOnly=0: the older,
     *  measured shape that writes selinux_enforcing=0 (everything permissive). */
    public static native String nativeEscalate(String daemonPath, int rounds, int mapOnly);

    /** Android 8.1 (3.18.71-perf-g8a8c60dd, PD1610_D_8.19.16): CVE-2019-2215 binder UAF as an
     *  arbitrary kernel write.  Two writes -- selinux_enforcing=0 (4 bytes; 8 panics) and
     *  modprobe_path=&lt;payload&gt; -- then one trigger that makes the kernel exec the payload as
     *  uid 0.  The payload must be a SHELL SCRIPT: the kernel-helper domain on this ROM runs
     *  #! scripts and dynamic /system binaries but silently loses everything a static libc ELF
     *  does.  The function refuses unless uname(2)'s release carries the exact build tag
     *  3.18.71-perf-g8a8c60dd (another 3.18.71 patch would move both globals; the proc file
     *  is unreadable from the app domain on this ROM, hence uname).
     *  rc 0 ok; -10/-11 enforcing write missed / readback still enforcing; -20/-21 modprobe write
     *  missed / not on readback; -30 the helper never opened 12346. */
    public static native String nativeEscalate8(String payloadPath, int rounds);

    /** Defeats vivo's exec-time guard on the *name* `su` with two RAM writes: a 1 GB alias
     *  into an empty pgd slot, then one instruction word through that window.  The window is
     *  proven semantically (flip selinux_enforcing and back) before any text is touched;
     *  rc -2 means "unproven, nothing patched".  Not persistent: a reboot restores the gate.
     *  0 ok, -1 entry write missed, -2 alias unproven, -3 patch missed (word rolled back). */
    public static native String nativeSugate();

    /** Write the gate's original instruction back, leaving the shipped behaviour. */
    public static native String nativeSugateRevert();

    /** 3.18.31 (Android 7.1.1) version of the same two writes, split so the window witness can be
     *  read by the caller.  The site there is the one instruction that *consumes* the gate's verdict
     *  (`tbnz` in do_execveat_common), so the word written is a NOP; the window is proven by moving
     *  the /proc/sys/kernel/modprobe string through the alias, because this kernel exposes no
     *  selinux_enforcing symbol -- and this uid only reads that file thanks to the exemption planted
     *  earlier in the same run, so the witness goes through the root channel instead.
     *
     *  Call order, with nothing written to .text unless every step is witnessed:
     *    nativeSugate7Open()    plant the alias, move the string to "/zz"
     *    -> read /proc/sys/kernel/modprobe as root: must be "/zz", else nativeSugate7Abort(orig)
     *    nativeSugate7Restore(orig)  put the read path back through the alias
     *    -> read it again: must equal orig, else nativeSugate7Abort(orig)
     *    nativeSugate7Patch()   the NOP, then witness by execve'ing a file literally named su.
     *  Open: 0 alias planted and witness written, -1 entry write missed, -2 witness write missed.
     *  Restore/Abort: 0 written, <0 refused or missed.  Patch: 0 ok, -3 missed (word rolled back),
     *  -4 missed and the rollback missed too. */
    public static native String nativeSugate7Open();

    public static native String nativeSugate7Restore(String origModprobePath);

    public static native String nativeSugate7Patch();

    public static native String nativeSugate7Abort(String origModprobePath);

    /** Put 7's verdict branch back exactly as shipped. */
    public static native String nativeSugate7Revert();

    /** Reverse-direction su request: native code listens, the daemon connects back,
     *  and the uid it reads comes from SCM_CREDENTIALS.  Java cannot receive
     *  ancillary credentials, so this has to live in the .so. */
    public static native String nativePeerSu(int toUid, String cmd);

    /** Exit status of the last nativePeerSu command (the daemon sends it as an
     *  "@SUD_EXIT=<n>" trailer because a socket has no wait status). */
    public static native int nativeLastExit();
}
