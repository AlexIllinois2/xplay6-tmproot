package com.xplay6.temproot;

import android.app.job.JobInfo;
import android.app.job.JobParameters;
import android.app.job.JobScheduler;
import android.app.job.JobService;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
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

    /* "Is this boot already covered?" -- the escalation's visible effect is that
     * selinux_enforcing went to 0, and the app can read /sys/fs/selinux/enforce. */
    static boolean alive(Context c) {
        try {
            return Esc.nativeState().indexOf("enforce=Permissive") >= 0;
        } catch (Throwable t) {
            return false;
        }
    }

    @Override
    public boolean onStartJob(JobParameters p) {
        boolean done = alive(this);

        Log.i("TempRoot-boot", "job fired, state=" + Esc.nativeState());
        if (!done)
            try {
                startService(new Intent(this, EscService.class));
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
