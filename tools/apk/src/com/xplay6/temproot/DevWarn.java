package com.xplay6.temproot;

import android.net.LocalServerSocket;
import android.os.IBinder;

import java.io.File;
import java.lang.reflect.Method;

/**
 * Root-side watcher for the vendor's 开发模式 ongoing notification.
 *
 * com.vivo.daemonService re-posts notification id 10100 every time
 * development_settings_enabled is written, so a one-shot cancel is undone by the
 * next toggle.  This process stays resident and cancels it again every 3 s.
 *
 * Runs as uid 0 through app_process (CLASSPATH points at the installed APK), which
 * is what makes the cancel legal: NotificationManagerService.cancelNotificationWithTag
 * requires the caller to be system or the same app, and isUidSystem() accepts uid 0.
 * The tag MUST be a real null String -- "null" as text does not match the record.
 *
 * Single instance: the abstract socket is bound by the first watcher and the
 * kernel refuses a second bind, so a repeated chain run cannot stack watchers.
 * The sentinel file is the switch: deleting it makes this loop exit within one
 * poll interval.
 */
public final class DevWarn {

    static final String PKG = "com.vivo.daemonService";
    static final int ID = 10100;

    public static void main(String[] args) {
        String sentinel = (args == null || args.length == 0) ? null : args[0];
        if (sentinel == null || sentinel.length() == 0)
            return;

        LocalServerSocket lock;
        try {
            lock = new LocalServerSocket("devwarn-watch");
        } catch (Throwable t) {
            /* Another watcher already holds the name; nothing to do. */
            return;
        }
        try {
            Object nm = null;
            Method get = null;
            Method cancel = null;
            while (new File(sentinel).exists()) {
                if (nm == null) {
                    try {
                        nm = notificationManager();
                        get = nm.getClass().getMethod("getAppActiveNotifications",
                                String.class, int.class);
                        cancel = nm.getClass().getMethod("cancelNotificationWithTag",
                                String.class, String.class, int.class, int.class);
                    } catch (Throwable t) {
                        nm = null;
                    }
                }
                if (nm != null) {
                    try {
                        /* Query first: a blind cancel would log a notification_cancel event
                         * every 3 s forever, which is pure event-log churn when the warning is
                         * already gone.  Only the present case is worth the transaction. */
                        if (hasWarning(nm, get))
                            cancel.invoke(nm, PKG, null, ID, 0);
                    } catch (Throwable t) {
                        /* The service may have restarted between rounds; resolve again. */
                        nm = null;
                    }
                }
                try {
                    Thread.sleep(3000);
                } catch (InterruptedException ie) {
                    return;
                }
            }
        } finally {
            try {
                lock.close();
            } catch (Throwable t) {
            }
        }
    }

    private static boolean hasWarning(Object nm, Method get) throws Exception {
        Object page = get.invoke(nm, PKG, 0);
        Object list = page.getClass().getMethod("getList").invoke(page);
        if (!(list instanceof java.util.List))
            return true; /* Unknown shape -- fall back to cancelling. */
        for (Object sbn : (java.util.List<?>) list) {
            Object id = sbn.getClass().getMethod("getId").invoke(sbn);
            if (id instanceof Integer && ((Integer) id).intValue() == ID)
                return true;
        }
        return false;
    }

    private static Object notificationManager() throws Exception {
        Class<?> sm = Class.forName("android.os.ServiceManager");
        IBinder b = (IBinder) sm.getMethod("getService", String.class).invoke(null, "notification");
        if (b == null)
            throw new IllegalStateException("notification service absent");
        Class<?> stub = Class.forName("android.app.INotificationManager$Stub");
        return stub.getMethod("asInterface", IBinder.class).invoke(null, b);
    }
}
