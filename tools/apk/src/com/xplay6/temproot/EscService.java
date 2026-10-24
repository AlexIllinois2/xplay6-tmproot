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

    /* How long the boot trigger waits before spending the needle (see onStartCommand). */
    static final long SETTLE_MS = 150 * 1000L;

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        final int id = startId;

        if (busy) {
            Log.i("TempRoot-boot", "already running, ignoring startId=" + id);
            stopSelf(id);
            return START_NOT_STICKY;
        }
        /* Route 8's responder (a shell script) cannot attribute a caller by uid, so every request it
         * accepts must carry the token.  The boot path can run in a process where Main.onCreate never
         * did, so load the token and recover the route here before anything calls Chain.su() --
         * otherwise the "already escalated" branch's unlockAdbInput() would send a token-less request
         * and be refused on 8.1 (routes 6/7 still fall back to their peer attribution). */
        Chain.useToken(this);
        /* The boot/job trigger must not fire the binder needle a second time on a boot that is already
         * served: every attempt carries the leak loop's measured crash rate, and a second daemon would
         * find 12345/12346 taken anyway.  The UI's 提权 button goes through Chain.run directly, so an
         * explicit user retry is still possible. */
        if (BootJob.alive(this)) {
            Log.i("TempRoot-boot", "this boot already reads as escalated -- not firing the needle again");
            /* "Already escalated" is about the daemon, not about the caller's door: relayd lives in this
             * process, so a recycled process means a granted app can no longer reach su at all.
             * Re-arm it here -- this is the branch every non-needle trigger lands in (ledger 631). */
            Chain.ensureRelay(this, new Chain.Log() {
                @Override
                public void line(String s) {
                    Log.i("TempRoot-boot", s);
                }
            });
            unlockAdbInput();
            /* Rebuild the module mounts for THIS boot and run the modules'
             * service phase.  Chain.su is a TCP socket, so this stays off the
             * main thread; best-effort inside Modules.bootRun. */
            new Thread(new Runnable() {
                @Override
                public void run() {
                    Modules.bootRun(EscService.this);
                }
            }, "temproot-mods").start();
            BootJob.schedule(this, BootJob.CHECK_MS);
            stopSelf(id);
            return START_NOT_STICKY;
        }
        busy = true;
        new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    /* The boot trigger fires while the whole phone is still booting (dex2oat, every
                     * vendor service starting), which is exactly when kmalloc-512 churns fastest and the
                     * freed slot the needle is hunting gets snatched -- measured on 1.8.4: the two
                     * boot-triggered attempts both logged `L7: the needle never published a task`, while
                     * every manual attempt at rest hit.  The chain itself is unchanged; it just waits
                     * for the machine to quiet down before spending its one needle. */
                    boolean bootTrigger = intent != null && "boot".equals(intent.getStringExtra("trigger"));
                    if (bootTrigger) {
                        Log.i("TempRoot-boot", "boot trigger: waiting for the boot storm to settle before the needle");
                        try {
                            Thread.sleep(SETTLE_MS);
                        } catch (InterruptedException ie) {
                            Log.i("TempRoot-boot", "settle wait interrupted");
                        }
                    }
                    Chain.run(EscService.this, new Chain.Log() {
                        @Override
                        public void line(String s) {
                            Log.i("TempRoot-boot", s);
                        }
                    }, 24);
                    unlockAdbInput();
                    /* Fresh escalation: apply module mounts + run the modules'
                     * boot scripts while we are already on a worker thread. */
                    Modules.bootRun(EscService.this);
                } finally {
                    busy = false;
                    /* Tell it plainly when the vendor's autostart switch is not on for this package: the
                     * escalation works (something woke us -- the broadcast, the job, adb or the user),
                     * but the next reboot will need a hand unless 自启动 is allowed.  An uninstall +
                     * reinstall resets that row, so this is a real state of the shipped app, not a
                     * hypothetical. */
                    try {
                        long epoch = BootJob.bootEpoch();
                        long saw = getSharedPreferences("temproot", 0).getLong("saw_boot", -1L);
                        if (epoch > 0 && (saw < 0 || Math.abs(saw - epoch) > 120))
                            Log.i("TempRoot-boot", "★ 本次开机没有被 BOOT_COMPLETED 唤醒（vivo 自启动未放行）"
                                    + "——重启后要手点一次「提权」；i管家→权限管理→自启动 打开本应用即可，"
                                    + "卸载重装后这个开关会回到关闭");
                    } catch (Throwable t) {
                        Log.i("TempRoot-boot", "autostart witness unavailable: " + t);
                    }
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

    /** Plant Settings' own `account_verified_ok` so the 「USB模拟点击」 row stops demanding a vivo account.
     *  Chain.unlockAdbInput's comment carries why this is only a file write -- the switch itself still
     *  needs a finger, because the daemon's root cannot reach the settings provider. */
    private static void unlockAdbInput() {
        try {
            Log.i("TempRoot-boot", "adb-input witness: " + Chain.unlockAdbInput());
        } catch (Throwable t) {
            Log.i("TempRoot-boot", "adb-input unlock could not run: " + t);
        }
    }
}
