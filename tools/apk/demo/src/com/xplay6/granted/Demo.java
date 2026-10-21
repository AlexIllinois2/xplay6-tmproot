package com.xplay6.granted;

import android.app.Activity;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * The proof the grant list is real: this app contains no escalation code at all.
 * It copies the bundled client out of its own assets, execs it (an app may exec
 * from its own data dir -- measured), and whatever comes back is exactly what
 * TempRoot's daemon decided for this uid.
 *
 * Not granted   -> "ERR unknown service"
 * Granted       -> "uid=0(root) ... CapEff: 0000003fffffffff"
 */
public final class Demo extends Activity {

    private static final String CMD =
            "id; getenforce; grep -m1 CapEff /proc/self/status";

    private TextView view;
    private final Handler ui = new Handler(Looper.getMainLooper());

    @Override
    protected void onCreate(Bundle saved) {
        super.onCreate(saved);

        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        view = new TextView(this);
        view.setTextSize(13f);
        ScrollView sc = new ScrollView(this);
        sc.addView(view);
        box.addView(sc, new LinearLayout.LayoutParams(-1, 0, 1f));

        Button b = new Button(this);
        b.setText("请求 root / ask for root");
        b.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                ask();
            }
        });
        box.addView(b);
        setContentView(box);

        view.append("uid=" + android.os.Process.myUid() + "\n");
        ask();
    }

    private void ask() {
        new Thread(new Runnable() {
            @Override
            public void run() {
                /* The same bytes under two names, in one run: `sux` is our own client's shipped
                 * name, `su` is the name vivo's exec-time guard used to refuse (ledger 643/664).
                 * A criterion that only ever asks for `sux` cannot see the vendor check come back. */
                final String a = requestRoot("sux", CMD);
                final String b = requestRoot("su", CMD);
                Log.i("GrantedDemo", a + " || " + b);
                record("SUX " + a + "\nSU " + b);
                ui.post(new Runnable() {
                    @Override
                    public void run() {
                        view.append("---\nsux: " + a + "\nsu: " + b + "\n");
                    }
                });
            }
        }, "demo-ask").start();
    }

    /* Why a file and not just logcat: the logcat ring on this ROM is flooded by vivo services,
     * so the harness' B/C/D lines came back empty while `relayd.log` proved the caller HAD run
     * (ledger 673).  The result therefore gets written where the harness can read it without
     * root, with a timestamp the harness compares against its own earlier reading -- "newer than
     * the trigger" is then a witness, not an assumption. */
    private void record(String body) {
        try {
            File dir = getExternalFilesDir(null);
            File f = new File(dir != null ? dir : getFilesDir(), "result.txt");
            OutputStream o = new FileOutputStream(f);
            o.write((System.currentTimeMillis() + " uid=" + android.os.Process.myUid() + "\n"
                    + body + "\n").getBytes("UTF-8"));
            o.close();
        } catch (Throwable t) {
            Log.i("GrantedDemo", "record failed: " + t);
        }
    }

    private String requestRoot(String name, String cmd) {
        try {
            File dst = new File(getFilesDir(), name);
            InputStream in = getAssets().open("sux");
            OutputStream out = new FileOutputStream(dst);
            byte[] buf = new byte[64 * 1024];
            int n;
            while ((n = in.read(buf)) > 0)
                out.write(buf, 0, n);
            out.close();
            in.close();
            dst.setExecutable(true, false);
            dst.setReadable(true, false);

            Process pr = Runtime.getRuntime().exec(
                    new String[] { dst.getAbsolutePath(), "-c", cmd });
            String so = slurp(pr.getInputStream());
            String se = slurp(pr.getErrorStream());
            pr.waitFor();
            return ("out=" + so.trim() + (se.length() > 0 ? " err=" + se.trim() : "")).trim();
        } catch (Throwable t) {
            return "FAILED " + t.getClass().getSimpleName() + ": " + t.getMessage();
        }
    }

    private String slurp(InputStream in) throws java.io.IOException {
        byte[] b = new byte[4096];
        StringBuilder sb = new StringBuilder();
        int n;
        while ((n = in.read(b)) > 0)
            sb.append(new String(b, 0, n, "UTF-8"));
        return sb.toString();
    }
}
