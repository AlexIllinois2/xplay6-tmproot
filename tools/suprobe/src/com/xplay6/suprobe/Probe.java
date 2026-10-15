package com.xplay6.suprobe;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.IOException;

/* One question, measured from the untrusted_app domain: can a file whose basename is
 * exactly "su" be execve'd now that the kernel name gate is patched out?  The four cases
 * are chosen so each refusal names its own cause:
 *   files/su   vs files/sux   -- same bytes, same directory, only the name differs
 *   marker/su  in /data/local/tmp -- whether MAC lets an app execute shell_data_file at all
 *   /data/local/tmp/su -c id  -- the real client, i.e. whether the delivery path is reachable
 * Nothing here writes kernel state; it only observes execve.
 */
public class Probe extends Activity {
    static final String TAG = "suprobe";
    final StringBuilder report = new StringBuilder();

    @Override
    protected void onCreate(Bundle saved) {
        super.onCreate(saved);
        try {
            run();
        } catch (Exception e) {
            say("FATAL", String.valueOf(e));
        }
        finish();
    }

    void say(String label, String what) {
        String line = "T " + pad(label) + " -> " + what;
        Log.i(TAG, line);
        report.append(line).append('\n');
    }

    static String pad(String s) {
        StringBuilder b = new StringBuilder(s);
        while (b.length() < 18)
            b.append(' ');
        return b.toString();
    }

    static String slurp(InputStream in) {
        try {
            ByteArrayOutputStream o = new ByteArrayOutputStream();
            byte[] buf = new byte[512];
            int n;
            while ((n = in.read(buf)) > 0)
                o.write(buf, 0, n);
            return new String(o.toByteArray(), "UTF-8").trim();
        } catch (IOException e) {
            return "READ-ERR " + e;
        }
    }

    String readPath(String p) {
        try {
            ProcessBuilder pb = new ProcessBuilder("/system/bin/cat", p);
            pb.redirectErrorStream(true);
            return slurp(pb.start().getInputStream());
        } catch (IOException e) {
            return "OPEN-ERR " + e;
        }
    }

    String exec(String... argv) {
        try {
            ProcessBuilder pb = new ProcessBuilder(argv);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String out = slurp(p.getInputStream());
            int rc = p.waitFor();
            return "RAN rc=" + rc + " out=[" + out.replace('\n', '|') + "]";
        } catch (IOException e) {
            return "EXEC-FAIL " + e;
        } catch (InterruptedException e) {
            return "INTR " + e;
        }
    }

    void copyAsset(String asset, File dst) throws IOException {
        InputStream in = getAssets().open(asset);
        OutputStream out = new FileOutputStream(dst);
        byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) > 0)
            out.write(buf, 0, n);
        out.close();
        in.close();
        if (!dst.setExecutable(true, false))
            say("chmod", "setExecutable returned false for " + dst);
    }

    void run() throws Exception {
        say("self-uid", "" + android.os.Process.myUid());
        say("self-domain", readPath("/proc/self/attr/current"));
        say("self-context-attr", readPath("/proc/self/attr/prev"));

        File dir = getFilesDir();
        File suName = new File(dir, "su");
        File suxName = new File(dir, "sux");
        copyAsset("marker", suName);
        copyAsset("marker", suxName);
        say("appdata-su", exec(suName.getAbsolutePath()));
        say("appdata-sux-control", exec(suxName.getAbsolutePath()));

        say("shelltmp-su", exec("/data/local/tmp/marker/su"));
        say("shelltmp-real-su-c-id", exec("/data/local/tmp/su", "-c", "id"));
        say("shelltmp-sux-c-id", exec("/data/local/tmp/sux", "-c", "id"));

        /* The part a third-party root manager actually depends on: a bare `su` found
         * through PATH, not an absolute path we chose.  /system/bin/sh is used the way
         * Runtime.exec("su") uses it. */
        say("path-env", exec("/system/bin/sh", "-c", "echo $PATH").trim());
        say("which-su", exec("/system/bin/sh", "-c", "command -v su 2>&1"));
        say("stat-xbin-su", exec("/system/bin/ls", "-lZ", "/system/xbin/su"));
        say("abs-xbin-su-c-id", exec("/system/xbin/su", "-c", "id"));
        say("abs-sbin-su-c-id", exec("/sbin/su", "-c", "id"));
        say("sh-c-su-c-id", exec("/system/bin/sh", "-c", "su -c id"));

        /* Audit question for the authorization layer: the daemon also reads a grants list that
         * lives in /data/local/tmp with mode 0666.  Identity is kernel-supplied, but the allow
         * list is a file -- and a world-writable list is not a list.  These three rows decide
         * whether any app can simply add itself. */
        say("list-before", exec("/system/bin/cat", "/data/local/tmp/sud.grants"));
        say("app-appends-own-uid", exec("/system/bin/sh", "-c",
                "id -u >> /data/local/tmp/sud.grants 2>&1; cat /data/local/tmp/sud.grants"));
        say("after-selfgrant-su-c-id", exec("/system/bin/sh", "-c", "su -c id"));

        File r = new File(dir, "result.txt");
        try (OutputStream o = new FileOutputStream(r)) {
            o.write(report.toString().getBytes("UTF-8"));
        }
        Log.i(TAG, "DONE");
    }
}
