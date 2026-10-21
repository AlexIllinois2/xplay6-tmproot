package com.xplay6.temproot;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Log;

public final class Boot extends BroadcastReceiver {

    @Override
    public void onReceive(Context ctx, Intent intent) {
        String action = intent == null ? "?" : intent.getAction();
        Log.i("TempRoot-boot", "received " + action + " -> starting EscService");
        /* The one honest witness that vivo let us start at all this boot.  The product is judged on
         * "root after a reboot without a PC", and the vendor's 自启动 switch is reset by an
         * uninstall+reinstall (measured 2026-10-19: after installing 1.8.3 the row went back to
         * currentstate=1 and BOOT_COMPLETED was cancelled again), so the app has to be able to say
         * "this boot I was never woken by the broadcast" instead of leaving the user to notice. */
        try {
            long e = BootJob.bootEpoch();
            if (e > 0)
                ctx.getSharedPreferences("temproot", 0).edit().putLong("saw_boot", e).apply();
        } catch (Throwable t) {
            Log.i("TempRoot-boot", "could not record the boot mark: " + t);
        }
        try {
            Intent i = new Intent(ctx, EscService.class);
            i.putExtra("trigger", "boot");
            ctx.startService(i);
        } catch (Throwable t) {
            Log.e("TempRoot-boot", "startService refused (vivo autostart block?): " + t);
        }
    }
}
