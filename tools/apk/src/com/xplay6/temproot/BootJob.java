package com.xplay6.temproot;

import android.app.job.JobInfo;
import android.app.job.JobParameters;
import android.app.job.JobScheduler;
import android.app.job.JobService;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.util.Log;

/* A second boot trigger, because vivo's auto-start manager cancels BOOT_COMPLETED
 * for every third-party package on this device (measured 2026-10-14, twice:
 * "BroadcastQueue: Cancel launching app com.xplay6.temproot/10022 ... process is
 * forbid to start up"). Persisted jobs are restored by JobScheduler after boot,
 * which is a different code path, so this may still start us.
 *
 * The job re-arms itself with a latency that depends on the result: if the kernel
 * is already permissive it only re-checks (cheap), if not it runs the chain -- and
 * the chain is a kernel write, so we deliberately do NOT retry that every minute. */
public final class BootJob extends JobService {

    static final int ID = 6210;
    static final long CHECK_MS = 10 * 60 * 1000L;
    static final long ESC_MS = 60 * 60 * 1000L;

    static void schedule(Context c, long latency) {
        JobScheduler js = (JobScheduler) c.getSystemService(Context.JOB_SCHEDULER_SERVICE);
        if (js == null) {
            Log.i("TempRoot-boot", "no JobScheduler service");
            return;
        }
        JobInfo job = new JobInfo.Builder(ID, new ComponentName(c, BootJob.class))
                .setPersisted(true)
                .setMinimumLatency(latency)
                .setOverrideDeadline(latency + 5 * 60 * 1000L)
                .build();
        Log.i("TempRoot-boot", "job schedule rc=" + js.schedule(job) + " latency=" + latency);
    }

    /* "Is this boot already covered?"
     *
     * The 6.0.1 answer was "the kernel is permissive", because that shape really does make the flag
     * stay off.  The 7 route does the opposite on purpose -- it plants permissive_map, escalates,
     * starts the daemon and then writes selinux_enforcing back to 1 -- so on 7 a successful boot reads
     * Enforcing and the old witness reports "not covered", which would fire the binder needle once
     * more every hour (and the needle has a measured crash rate).  So a successful run stamps the boot
     * it escalated, identified by the boot epoch derived from /proc/uptime, and either witness
     * counts. */
    static long bootEpoch() {
        try {
            java.io.BufferedReader r = new java.io.BufferedReader(
                    new java.io.FileReader("/proc/uptime"));
            String line = r.readLine();
            r.close();
            long up = (long) Double.parseDouble(line.split(" ")[0]);
            return System.currentTimeMillis() / 1000L - up;
        } catch (Throwable t) {
            return -1L;
        }
    }

    static void markEscalated(Context c) {
        long e = bootEpoch();
        if (e < 0)
            return;
        c.getSharedPreferences("temproot", 0).edit()
                .putLong("esc_boot", e).apply();
        Log.i("TempRoot-boot", "marked this boot as escalated, epoch=" + e);
    }

    static boolean alive(Context c) {
        try {
            if (Esc.nativeState().indexOf("enforce=Permissive") >= 0)
                return true;
        } catch (Throwable t) {
            /* fall through to the live probe */
        }
        if (daemonReachable())
            return true;
        /* The mark alone used to be enough here, and that lied: with the daemon dead the boot trigger
         * answered "this boot already reads as escalated" and stood by, so nothing short of a hand on
         * the 提权 button could bring root back (measured on 1.9.7, art/ledger-20261016.md 629).
         * The mark now only caps how often we recover: the needle a recovery fires has a measured
         * crash rate, so this boot gets one. */
        SharedPreferences p = c.getSharedPreferences("temproot", 0);
        long mark = p.getLong("esc_boot", -1L);
        long now = bootEpoch();
        /* +-120 s: the mark is taken a few seconds after this reading, and the two are only meant to
         * identify the same boot, not to be exact. */
        if (!(mark > 0 && now > 0 && Math.abs(mark - now) <= 120))
            return false;
        if (p.getLong("retry_boot", -1L) == mark) {
            Log.i("TempRoot-boot", "daemon unreachable and this boot's one recovery needle is already spent"
                    + " -- standing by, the 提权 button is the only thing left");
            return true;
        }
        p.edit().putLong("retry_boot", mark).apply();
        Log.i("TempRoot-boot", "daemon unreachable on a boot already marked escalated -- spending this boot's"
                + " one recovery needle");
        return false;
    }

    /* Something serving the su channel, read without needing root: the daemon's own TCP listeners.
     * Both ports are probed and EITHER answering is enough to call the boot "already served".
     * A single false negative here costs a kernel needle -- and the needle has a measured crash
     * rate (this happened on 2026-10-20: 12345 and 12346 were both in `netstat` LISTEN owned by
     * the same pid 5450/sud, yet the probe said unreachable and EscService spent a second needle;
     * the probe's own failure mode is still NOT established, so this is defence in depth, not a
     * root-cause fix).  12346 is the su port the relay itself reaches successfully per request,
     * so it is the stronger of the two witnesses. */
    static boolean daemonReachable() {
        final boolean[] up = { false };
        Runnable probe = new Runnable() {
            @Override public void run() {
                int[] ports = { 12346, 12345 };
                for (int p : ports) {
                    try {
                        java.net.Socket s = new java.net.Socket();

                        s.connect(new java.net.InetSocketAddress("127.0.0.1", p), 1500);
                        s.close();
                        Log.i("TempRoot-boot", "daemon probe :" + p + " answered -- daemon is up");
                        up[0] = true;
                        return;
                    } catch (Throwable t) {
                        Log.i("TempRoot-boot", "daemon probe :" + p + " failed: " + t);
                    }
                }
            }
        };
        /* The probe HAS to leave the main thread.  Both callers (EscService.onStartCommand and
         * onStartJob) run on it, and Android forbids a socket from there -- so every single probe
         * threw NetworkOnMainThreadException, `alive()` answered "unreachable" on a boot that was
         * plainly being served, and the recovery branch went and spent a kernel needle that did not
         * need spending.  Measured 2026-10-20 with the per-port logging in place:
         *   daemon probe :12346 failed: android.os.NetworkOnMainThreadException
         *   daemon probe :12345 failed: android.os.NetworkOnMainThreadException
         *   daemon unreachable on a boot already marked escalated -- spending this boot's one needle
         * -- which is the mechanism behind the reboot of 06:29 that this whole line of work kept
         * blaming on the page-table alias.  join() gives the happens-before for `up[0]`. */
        Thread t = new Thread(probe, "temproot-probe");
        t.start();
        try {
            t.join(7000);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        if (t.isAlive())
            Log.i("TempRoot-boot", "daemon probe still running after 7 s -- treating as unreachable");
        return up[0];
    }

    @Override
    public boolean onStartJob(JobParameters p) {
        boolean done = alive(this);

        Log.i("TempRoot-boot", "job fired, state=" + Esc.nativeState());
        if (!done)
            try {
                Intent i = new Intent(this, EscService.class);
                i.putExtra("trigger", "boot");
                startService(i);
            } catch (Throwable t) {
                Log.i("TempRoot-boot", "startService from job refused: " + t);
            }
        jobFinished(p, false);
        /* EscService re-arms on its own once it has run; only arm here when it did not,
         * so the two paths do not stack two schedules per wake. */
        if (done)
            schedule(this, CHECK_MS);
        return false;
    }

    @Override
    public boolean onStopJob(JobParameters p) {
        return false;
    }
}
