package com.xplay6.temproot;

import android.app.Service;
import android.content.Intent;
import android.os.IBinder;
import android.util.Log;

/* BOOT_COMPLETED is delivered to the receiver, whose onReceive() must return in a
 * few seconds -- the chain takes longer than that and can hang on readv, so the
 * work is handed to a service and the receiver returns immediately. */
public final class EscService extends Service {

    /* The chain is NOT safe to run twice at once: two rounds race for the same
     * freed kmalloc-512 slot, and the loser misses (measured on-device: one run
     * hit step1 on round 0 while the concurrent one reported rc=0/no-hit).
     * vivo delivers BOOT_COMPLETED and QUICKBOOT_POWERON to the same receiver, so
     * serialize here rather than trusting the broadcast count. */
    private static volatile boolean busy = false;

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        final int id = startId;

        if (busy) {
            Log.i("TempRoot-boot", "already running, ignoring startId=" + startId);
            stopSelf(id);
            return START_NOT_STICKY;
        }
        busy = true;
        new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    Chain.run(EscService.this, new Chain.Log() {
                        @Override
                        public void line(String s) {
                            Log.i("TempRoot-boot", s);
                        }
                    }, 24);
                } finally {
                    busy = false;
                    /* Arm the persisted job from here rather than only from the UI: this
                     * is the one code path every trigger (boot job, broadcast, adb, the
                     * 提权 button) passes through, so the next boot is always covered. */
                    BootJob.schedule(EscService.this,
                            BootJob.alive(EscService.this) ? BootJob.CHECK_MS : BootJob.ESC_MS);
                    stopSelf(id);
                }
            }
        }, "temproot-boot").start();
        return START_NOT_STICKY;
    }
}
