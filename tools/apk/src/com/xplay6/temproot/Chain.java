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

            String probe = Esc.nativeProbe();
            log.line("selftest (diagnostic only): " + probe);

            File sud = stage(ctx, log, "sud");
            if (sud == null) {
                log.line("ABORT: daemon not staged");
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
            boolean rooted = tryEscalate(sud.getAbsolutePath(), rounds, 1, log, 6);
            if (!rooted) {
                log.line("map-only left us unrooted; falling back to the globally-permissive shape");
                rooted = tryEscalate(sud.getAbsolutePath(), rounds, 0, log, 6);
            }
            log.line("state after: " + Esc.nativeState());
            if (!rooted)
                log.line("NOT ROOTED after both routes -- see the escalate lines above");
            if (rooted)
                openSuName(ctx, log, rounds);
            if (rooted && mapPlanted)
                restoreEnforcing(log);
            else if (rooted)
                log.line("permissive map never planted this boot -> staying globally permissive "
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

    private static String trim1(String s) {
        if (s == null)
            return "";
        s = s.replace('\n', '|').replace('\r', ' ').trim();
        return s.length() > 160 ? s.substring(0, 160) : s;
    }

    private static File stage(Context ctx, Log log, String name) {
        File dst = new File(ctx.getFilesDir(), name);
        /* Write to a temporary name and rename: the previous daemon is often
         * still running from that exact path, and writing it in place fails with
         * ETXTBSY ("Text file busy").  rename() swaps the directory entry and the
         * running process keeps its own inode, which is what we want. */
        File tmp = new File(ctx.getFilesDir(), name + ".new");
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
        List<Integer> out = new ArrayList<Integer>();
        try {
            InputStream in = new java.io.FileInputStream(grantsFile(ctx));
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
        } catch (Throwable t) {
            /* no file yet */
        }
        return out;
    }

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
            if (g.exists() && !g.delete())
                return false;
            OutputStream o = new FileOutputStream(g);
            o.write(sb.toString().getBytes("UTF-8"));
            o.close();
            g.setReadable(true, true);
            g.setWritable(true, true);
            return g.length() > 0;
        } catch (Throwable t) {
            return false;
        }
    }

    /** Our own uid has to be in the list or the manager cannot use its own service. */
    public static void selfGrant(Context ctx, Log log) {
        int me = android.os.Process.myUid();
        List<Integer> g = readGrants(ctx);
        boolean missing = !g.contains(Integer.valueOf(me));
        if (missing)
            g.add(Integer.valueOf(me));
        /* Rewrite even when our uid is already there: a list left root-owned and 0666 by some
         * earlier root-side edit is both a security hole and, now that the daemon refuses such
         * files, a lock-out of this app's own service. */
        log.line("self-grant uid=" + me + (missing ? " added" : " resealed")
                + " saved=" + writeGrants(ctx, g));
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

    /** Which channel the last request went over -- shown in the log so a
     *  kernel-credential decision is never confused with the TCP+token fallback. */
    public static String lastChannel = "-";

    /** Ask for a command to run as `toUid` (0 = root, like KernelSU's uid choice).
     *  Peer first: that is the one whose uid the kernel filled in. */
    public static String su(int toUid, String cmd) {
        String r = null;

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

    public static void useToken(Context ctx) {
        currentToken = token(ctx);
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

    /** The daemon's own decision record.  It sits in the 0777 request directory
     *  and is append-only, so this app can read it without root and a granted app
     *  cannot rewrite the history of its own grants. */
    public static String suLog() {
        try {
            File f = new File("/data/local/tmp/.sud/sud.log");
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
            return new String(b, 0, Math.max(n, 0), "UTF-8").trim();
        } catch (Throwable t) {
            return "log unreadable: " + t;
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
