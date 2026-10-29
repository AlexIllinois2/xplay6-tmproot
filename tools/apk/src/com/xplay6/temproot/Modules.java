package com.xplay6.temproot;

import android.content.Context;
import android.net.Uri;
import android.util.Log;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/** Magisk-format module front end.  Storage mirrors Magisk's layout so a module
 *  can never tell the difference:
 *
 *      /data/adb/modules/<id>/module.prop   id/name/version/versionCode/author/description
 *      /data/adb/modules/<id>/system/...    files overlaid onto /system
 *      /data/adb/modules/<id>/disable       marker file: module skipped
 *      /data/adb/modules/<id>/post-fs-data.sh | service.sh   boot scripts
 *
 *  The mounts themselves are built by assets/modmount.sh (the vivo mount-string
 *  hook forces "//path" bind targets -- see its header); this class only stages
 *  the engine, drives it through Chain.su, and moves zips into place.  Every
 *  artifact lives under /data/adb: like the rest of tmproot, a reboot wipes it. */
public final class Modules {

    public static final String TAG = "TempRoot-mods";
    private static final String ENGINE_DIR = "/data/adb/tmproot";
    private static final String MODS = "/data/adb/modules";
    private static final String[] ENGINE = {"modmount.sh", "modcust.sh", "modlist.sh", "modboot.sh"};
    private static final Pattern ID_OK = Pattern.compile("[a-zA-Z0-9._-]{1,64}");

    /** One installed module as the module page shows it. */
    public static final class ModEntry {
        public final String dir, name, version, author, description, versionCode;
        public final boolean enabled;

        ModEntry(String dir, String name, String version, String author,
                 String description, String versionCode, boolean enabled) {
            this.dir = dir;
            this.name = name;
            this.version = version;
            this.author = author;
            this.description = description;
            this.versionCode = versionCode;
            this.enabled = enabled;
        }
    }

    /** Populated by list() when the su channel or the engine failed; the page
     *  shows it instead of a bare "no modules". */
    public static String lastError = null;

    private static final Chain.Log QLOG = new Chain.Log() {
        @Override
        public void line(String s) {
            Log.i(TAG, s);
        }
    };

    private Modules() {
    }

    /* ------------------------------------------------------- engine staging */

    /** Copy the four shell scripts from the APK into /data/adb/tmproot.  Cheap and
     *  idempotent, so every caller just does it before use instead of tracking
     *  whether the on-device copies are current. */
    public static void ensureEngine(Context ctx, Chain.Log log) throws Exception {
        StringBuilder paths = new StringBuilder();
        for (String name : ENGINE) {
            File dst = new File(ctx.getFilesDir(), name);
            InputStream in = ctx.getAssets().open(name);
            OutputStream out = new FileOutputStream(dst);
            byte[] buf = new byte[64 * 1024];
            int n;
            while ((n = in.read(buf)) > 0)
                out.write(buf, 0, n);
            out.close();
            in.close();
            dst.setReadable(true, false);
            paths.append(' ').append(dst.getAbsolutePath());
        }
        String out = Chain.root("mkdir -p " + ENGINE_DIR + "/logs && cp" + paths
                + " " + ENGINE_DIR + "/ && chmod 755 " + ENGINE_DIR + "/*.sh");
        log.line("mod engine staged:" + out);
    }

    /** Rebuild the whole mount set from whatever is in /data/adb/modules. */
    public static String applyAll(Context ctx, Chain.Log log) throws Exception {
        ensureEngine(ctx, log);
        String out = Chain.root("sh " + ENGINE_DIR + "/modmount.sh mount");
        log.line("modmount: " + out);
        return out;
    }

    /* --------------------------------------------------------------- listing */

    public static List<ModEntry> list(Context ctx) {
        lastError = null;
        List<ModEntry> out = new ArrayList<ModEntry>();
        String raw;
        try {
            ensureEngine(ctx, QLOG);
            raw = Chain.root("sh " + ENGINE_DIR + "/modlist.sh");
        } catch (Throwable t) {
            lastError = String.valueOf(t);
            Log.i(TAG, "list: " + t);
            return out;
        }
        String dir = null, name = "", ver = "", auth = "", desc = "", vc = "";
        boolean enabled = true;
        for (String ln : raw.replace("\r", "").split("\n")) {
            if (ln.startsWith("==MOD ")) {
                if (dir != null)
                    out.add(new ModEntry(dir, name, ver, auth, desc, vc, enabled));
                dir = ln.substring(6).trim();
                name = ver = auth = desc = vc = "";
                enabled = true;
            } else if (dir != null) {
                if (ln.startsWith("==NAME "))
                    name = ln.substring(7);
                else if (ln.startsWith("==VER "))
                    ver = ln.substring(6);
                else if (ln.startsWith("==AUTH "))
                    auth = ln.substring(7);
                else if (ln.startsWith("==DESC "))
                    desc = ln.substring(7);
                else if (ln.startsWith("==VC "))
                    vc = ln.substring(5).trim();
                else if (ln.startsWith("==DISABLED"))
                    enabled = false;
            }
        }
        if (dir != null)
            out.add(new ModEntry(dir, name, ver, auth, desc, vc, enabled));
        return out;
    }

    /* --------------------------------------------------------- state changes */

    private static String checkId(String dir) {
        if (dir == null || !ID_OK.matcher(dir).matches())
            throw new IllegalArgumentException("bad module id: " + dir);
        return dir;
    }

    /** enable=true clears the disable marker, enable=false sets it, then rebuilds
     *  the mounts (a rebuild unmounts the previous set first, so a disable takes
     *  the module's files out of /system immediately). */
    public static void setEnabled(Context ctx, String dir, boolean on, Chain.Log log) throws Exception {
        checkId(dir);
        String out = Chain.root((on ? "rm -f " : "touch ") + MODS + "/" + dir + "/disable");
        log.line((on ? "启用 " : "停用 ") + dir + ": " + out);
        applyAll(ctx, log);
    }

    public static void uninstall(Context ctx, String dir, Chain.Log log) throws Exception {
        checkId(dir);
        String out = Chain.root("rm -rf " + MODS + "/" + dir);
        log.line("卸载模块 " + dir + ": " + out);
        applyAll(ctx, log);
    }

    /* --------------------------------------------------------------- install */

    /** Install a Magisk-format module zip picked through SAF: unzip into a private
     *  staging dir, validate module.prop, copy into /data/adb/modules/<id> as
     *  root:root, run customize.sh the Magisk way (MODDIR=dest, UNZIPED=1; abort
     *  rolls the module dir back), then rebuild the mounts.  Returns the module
     *  display name for the toast. */
    /** Install the Magisk runtime module that ships inside the APK.
     *
     * The module is a normal Magisk-format zip (assets/magisk_runtime.zip),
     * built by tools/build_magisk_module.sh.  It carries Magisk 30.7 plus the
     * LD_PRELOAD shim that moves the daemon's socket into the abstract
     * namespace -- this kernel refuses bind(2) on a filesystem AF_UNIX path.
     *
     * Installing it is the same operation as picking a zip through SAF, so
     * the module ends up in /data/adb/modules/<id> with the same layout, the
     * same module.prop and the same service.sh.  Afterwards the boot-time
     * chain starts the daemon: modboot.sh service runs the module's
     * service.sh, which creates the runtime directory and launches magiskd.
     */
    public static String installBundled(Context ctx, Chain.Log log) throws Exception {
        File zip = new File(ctx.getCacheDir(), "magisk_runtime.zip");
        if (!zip.exists()) {
            try {
                copy(ctx.getAssets().open("magisk_runtime.zip"), new FileOutputStream(zip));
            } catch (java.io.IOException e) {
                throw new Exception("读不出内置的 Magisk 模块: " + e.getMessage());
            }
        }
        return installZip(ctx, zip, log);
    }

    /** Install a Magisk-format module zip from a local file. */
    public static String installZip(Context ctx, File zip, Chain.Log log) throws Exception {
        long ts = System.currentTimeMillis();
        File stage = new File(ctx.getCacheDir(), "stage-" + ts);
        try {
            stage.mkdirs();
            unzip(zip, stage, log);

            Prop p = Prop.parse(new File(stage, "module.prop"));
            if (p.id == null || !ID_OK.matcher(p.id).matches())
                throw new Exception("module.prop 的 id 缺失或不合法（" + p.id + "），拒绝安装");
            String blob = (p.name + " " + p.description).toLowerCase(Locale.US);
            if (blob.contains("zygisk") || blob.contains("riru"))
                log.line("警告：该模块声明依赖 Zygisk/Riru 注入，本机没有注入器，"
                        + "其核心功能多半不会生效（纯文件替换部分仍可用）");

            String dest = MODS + "/" + p.id;
            String sp = stage.getAbsolutePath();
            File customize = new File(stage, "customize.sh");
            // Magisk semantics: SKIPUNZIP=1 means the installer must NOT unpack the
            // archive into MODPATH; customize.sh extracts the files it wants itself.
            boolean skipUnzip = customize.isFile() && wantsSkipUnzip(customize);
            if (skipUnzip) {
                String mk = Chain.root("rm -rf " + dest + " && mkdir -p " + dest);
                log.line("SKIPUNZIP=1，交由 customize.sh 自己解包: " + mk);
            } else {
                String cp = Chain.root("rm -rf " + dest + " && mkdir -p " + dest
                        + " && cp -a '" + sp + "/.' '" + dest + "/'"
                        + " && chown -R 0:0 " + dest
                        + " && find " + dest + " -type d -exec chmod 755 {} +"
                        + " && find " + dest + " -type f -exec chmod 644 {} +"
                        + " && find " + dest + " -name '*.sh' -exec chmod 755 {} +");
                log.line("复制到 " + dest + ": " + cp);
            }

            if (customize.isFile()) {
                log.line("执行 customize.sh …");
                ensureEngine(ctx, log);
                String rcOut = Chain.root("MODDIR=" + dest + " ZIPFILE=" + zip.getAbsolutePath()
                        + (skipUnzip ? "" : " UNZIPED=1")
                        + " sh " + ENGINE_DIR + "/modcust.sh " + sp
                        + "; echo RC=$?");
                log.line(rcOut);
                int rc = rcOf(rcOut);
                if (rc != 0) {
                    Chain.root("rm -rf " + dest);
                    throw new Exception("customize.sh 中止（rc=" + rc + "），已回滚");
                }
                if (!Chain.root("test -f " + dest + "/module.prop && echo MODOK").contains("MODOK")) {
                    Chain.root("rm -rf " + dest);
                    throw new Exception("安装后 " + dest + " 缺少 module.prop，已回滚");
                }
            }

            applyAll(ctx, log);
            return p.name.isEmpty() ? p.id : p.name;
        } finally {
            delTree(stage);
        }
    }

    /** Install a Magisk-format module zip picked through SAF. */
    public static String install(Context ctx, Uri uri, Chain.Log log) throws Exception {
        File zip = new File(ctx.getCacheDir(), "module-" + System.currentTimeMillis() + ".zip");
        try {
            InputStream in = ctx.getContentResolver().openInputStream(uri);
            if (in == null)
                throw new Exception("读不了所选文件（内容提供方返回 null）");
            copy(in, new FileOutputStream(zip));
            in.close();
            return installZip(ctx, zip, log);
        } finally {
            zip.delete();
        }
    }

    /** Pull the "RC=<n>" line the install command appends; anything missing is
     *  reported as failure so a dead channel can never pass for success. */
    private static int rcOf(String out) {
        if (out == null)
            return -1;
        int rc = -1;
        for (String ln : out.replace("\r", "").split("\n")) {
            if (ln.startsWith("RC=")) {
                try {
                    rc = Integer.parseInt(ln.substring(3).trim());
                } catch (Throwable ignore) {
                }
            }
        }
        return rc;
    }

    /** SKIPUNZIP=<bool> declared at the top of customize.sh (Magisk's own switch). */
    private static boolean wantsSkipUnzip(File customize) {
        try {
            java.io.BufferedReader r = new java.io.BufferedReader(new java.io.FileReader(customize));
            for (String ln; (ln = r.readLine()) != null; ) {
                String s = ln.trim();
                if (s.startsWith("#"))
                    continue;
                int eq = s.indexOf('=');
                if (eq <= 0 || !"SKIPUNZIP".equals(s.substring(0, eq).trim()))
                    continue;
                String v = s.substring(eq + 1).trim().replace("\"", "").replace("'", "").toLowerCase(Locale.US);
                r.close();
                return v.equals("1") || v.equals("true");
            }
            r.close();
        } catch (Throwable ignore) {
        }
        return false;
    }

    private static void unzip(File zip, File dst, Chain.Log log) throws Exception {
        String root = dst.getCanonicalPath() + File.separator;
        ZipInputStream zin = new ZipInputStream(new BufferedInputStream(new FileInputStream(zip)));
        byte[] buf = new byte[64 * 1024];
        int files = 0;
        for (ZipEntry e; (e = zin.getNextEntry()) != null; ) {
            if (e.isDirectory())
                continue;
            File f = new File(dst, e.getName());
            if (!f.getCanonicalPath().startsWith(root))
                throw new SecurityException("zip-slip 拒绝: " + e.getName());
            File parent = f.getParentFile();
            if (parent != null && !parent.isDirectory() && !parent.mkdirs() && !parent.isDirectory())
                throw new Exception("建目录失败: " + parent);
            copy(zin, new FileOutputStream(f));
            files++;
        }
        zin.close();
        log.line("解包 " + files + " 个文件");
    }

    private static void copy(InputStream in, OutputStream out) throws Exception {
        byte[] buf = new byte[64 * 1024];
        int n;
        while ((n = in.read(buf)) > 0)
            out.write(buf, 0, n);
        out.close();
    }

    private static void delTree(File f) {
        File[] kids = f.listFiles();
        if (kids != null)
            for (File k : kids)
                delTree(k);
        f.delete();
    }

    private static final class Prop {
        String id, name = "", version = "", author = "", description = "";

        static Prop parse(File f) throws Exception {
            if (!f.isFile())
                throw new Exception("压缩包根目录没有 module.prop，不是 Magisk 格式的模块包");
            Prop p = new Prop();
            java.io.BufferedReader r = new java.io.BufferedReader(new java.io.FileReader(f));
            for (String ln; (ln = r.readLine()) != null; ) {
                int eq = ln.indexOf('=');
                if (eq <= 0)
                    continue;
                String k = ln.substring(0, eq).trim();
                String v = ln.substring(eq + 1).trim();
                if ("id".equals(k))
                    p.id = v;
                else if ("name".equals(k))
                    p.name = v;
                else if ("version".equals(k))
                    p.version = v;
                else if ("author".equals(k))
                    p.author = v;
                else if ("description".equals(k))
                    p.description = v;
            }
            r.close();
            return p;
        }
    }

    /* ------------------------------------------------------------------ boot */

    /** One boot-time pass, called by EscService once the root channel is up.
     *  Magisk order: module post-fs-data.sh + global post-fs-data.d synchronously,
     *  then the mount rebuild, then service.sh + service.d detached.  Everything
     *  is best-effort: a broken module must never take the boot chain down.
     *
     *  On 7.1.1 the mount rebuild goes through sysoverlay, not modmount.sh:
     *  modmount.sh mounts in the manager app's own mount namespace, where
     *  nothing else can see it (measured: the manager app's mountinfo listed
     *  the tmpfs while init's and every other app's did not).  sysoverlay
     *  publishes in BOTH namespaces and applies the //system bypass, the
     *  system_file labels and the shipped modes.  modmount.sh still runs,
     *  because it is what the module scripts and the /data overlays use. */
    public static void bootRun(Context ctx) {
        try {
            ensureEngine(ctx, QLOG);
            String p = Chain.root("sh " + ENGINE_DIR + "/modboot.sh postfs");
            Log.i(TAG, "boot postfs: " + p);
            String m = Chain.root("sh " + ENGINE_DIR + "/modmount.sh mount");
            Log.i(TAG, "boot mounts: " + m);
            /* The /system overlay: one call per enabled module that has a
             * system/ tree.  sysoverlay is a native binary, so it has to be
             * staged from the assets first. */
            File so = stageNative(ctx, QLOG, "sysoverlay");
            if (so != null) {
                /* The module directory is root-only (0700), so the app process
                 * cannot list it -- the list has to come through the root
                 * channel.  sysoverlay itself skips a module without a system/
                 * tree, so no check is needed here. */
                for (String id : moduleIdsOverRoot()) {
                    String r = Chain.root(so.getAbsolutePath() + " '" + MODS + "/" + id
                                          + "' " + SYSTEM_ROOT + " --init-ns");
                    Log.i(TAG, "sysoverlay " + id + ": " + r);
                }
            }
            String s = Chain.root("sh " + ENGINE_DIR + "/modboot.sh service");
            Log.i(TAG, "boot service: " + s);
        } catch (Throwable t) {
            Log.i(TAG, "bootRun: " + t);
        }
    }

    /** The directory the overlay publishes into. */
    private static final String SYSTEM_ROOT = "/system";

    /** Copy a native binary out of the assets into our files dir and make it
     *  executable.  The APK's own files dir is the only place we can exec
     *  from on this ROM (SELinux will not let us run an ELF out of /data). */
    static File stageNative(Context ctx, Chain.Log log, String name) {
        File dst = new File(ctx.getFilesDir(), name);
        try {
            /* Freshness, not existence: a cached binary from an older APK must
             * be replaced when the asset changed.  Measured 2026-10-29: the
             * sysoverlay fix for /system/lib sat in assets while files/ kept
             * running the pre-fix binary -- every boot re-published /system/lib
             * and crashed every app, because this check only looked at
             * existence.  Compare content hashes, not timestamps. */
            String cached = dst.canExecute() ? fileMd5(dst) : null;
            InputStream in = ctx.getAssets().open(name);
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("MD5");
            OutputStream out = new FileOutputStream(dst);
            byte[] buf = new byte[64 * 1024];
            int n, total = 0;
            while ((n = in.read(buf)) > 0) {
                out.write(buf, 0, n);
                md.update(buf, 0, n);
                total += n;
            }
            out.close();
            in.close();
            dst.setExecutable(true, false);
            dst.setReadable(true, false);
            String fresh = hex(md.digest());
            log.line("staged native " + dst.getAbsolutePath() + " bytes=" + total
                      + " canExec=" + dst.canExecute()
                      + (cached == null ? " (first stage)"
                         : cached.equals(fresh) ? " (unchanged)" : " (REPLACED, was " + cached + ")"));
            return dst;
        } catch (Throwable t) {
            log.line("stage native " + name + " failed: " + t);
            return null;
        }
    }

    /** MD5 of a file's contents, hex-encoded; null when unreadable. */
    private static String fileMd5(File f) {
        try {
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("MD5");
            InputStream in = new FileInputStream(f);
            byte[] buf = new byte[64 * 1024];
            int n;
            while ((n = in.read(buf)) > 0)
                md.update(buf, 0, n);
            in.close();
            return hex(md.digest());
        } catch (Throwable t) {
            return null;
        }
    }

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b)
            sb.append(String.format("%02x", x));
        return sb.toString();
    }

    /** The ids of the enabled modules, listed THROUGH the root channel.
     *
     *  /data/adb/modules is 0700 root, so the app process cannot read it --
     *  the listing has to go through su.  Modules with a `disable` or
     *  `remove` marker are skipped, as modmount.sh does. */
    private static java.util.List<String> moduleIdsOverRoot() {
        java.util.List<String> out = new java.util.ArrayList<String>();
        String raw;

        try {
            raw = Chain.root("ls -1 " + MODS + " 2>/dev/null; "
                             + "for d in " + MODS + "/*; do "
                             + "  [ -d \"$d\" ] || continue; "
                             + "  [ -f \"$d/disable\" ] && continue; "
                             + "  [ -f \"$d/remove\" ] && continue; "
                             + "  basename \"$d\"; "
                             + "done");
        } catch (Throwable t) {
            Log.i(TAG, "module list failed: " + t);
            return out;
        }
        if (raw == null)
            return out;
        for (String ln : raw.replace("\r", "").split("\n")) {
            String id = ln.trim();
            if (id.isEmpty() || id.startsWith(".") || id.contains("/"))
                continue;
            out.add(id);
        }
        return out;
    }
}
