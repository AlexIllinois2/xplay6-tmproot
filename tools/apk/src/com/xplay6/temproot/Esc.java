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

    /** Defeats vivo's exec-time guard on the *name* `su` with two RAM writes: a 1 GB alias
     *  into an empty pgd slot, then one instruction word through that window.  The window is
     *  proven semantically (flip selinux_enforcing and back) before any text is touched;
     *  rc -2 means "unproven, nothing patched".  Not persistent: a reboot restores the gate.
     *  0 ok, -1 entry write missed, -2 alias unproven, -3 patch missed (word rolled back). */
    public static native String nativeSugate();

    /** Write the gate's original instruction back, leaving the shipped behaviour. */
    public static native String nativeSugateRevert();

    /** Reverse-direction su request: native code listens, the daemon connects back,
     *  and the uid it reads comes from SCM_CREDENTIALS.  Java cannot receive
     *  ancillary credentials, so this has to live in the .so. */
    public static native String nativePeerSu(int toUid, String cmd);

    /** Exit status of the last nativePeerSu command (the daemon sends it as an
     *  "@SUD_EXIT=<n>" trailer because a socket has no wait status). */
    public static native int nativeLastExit();
}
