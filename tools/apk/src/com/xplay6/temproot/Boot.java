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
        try {
            ctx.startService(new Intent(ctx, EscService.class));
        } catch (Throwable t) {
            Log.e("TempRoot-boot", "startService refused (vivo autostart block?): " + t);
        }
    }
}
