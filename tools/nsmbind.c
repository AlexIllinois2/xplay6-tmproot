/* tools/nsmbind.c -- put a `su` client on PATH where EVERY process can see it.

Why this exists (measured 2026-10-19 on the official 7.1.1):  the 6.0.1 delivery could mount from a
process in the initial mount namespace, because that route reached root through the kernel's
usermodehelper.  On 7 the ladder runs inside the app, and Android 7's zygote gives each app its own
mount namespace -- so a mount done by our daemon binds in the APP's namespace and nobody else can see
it.  The witness pair: the daemon's root channel listed `/sbin` as `drwxr-xr-x ... 4096` (our tmpfs
mirror), while `adb shell` -- init's namespace -- still listed the same path as `drwxr-x--- 2 root
root 180 1970-01-01` and answered `/sbin/su: not found`.  No avc line was involved: the difference is
namespace, not policy.

So: fork (setns(CLONE_NEWNS) refuses a multithreaded caller, and the daemon serves one thread per
connection), move the child into PID 1's mount namespace, mirror the target directory entry by entry
so nothing that lived there disappears, drop our client in as `<name>`, then bind the mirror over the
target.  Still memory-only: `umount -l <target>` or a reboot restores the shipped view, and no byte
is written to any block device.

usage: nsmbind <su-client> <target-dir> [name=su] [ns=1|0]
       nsmbind --umount <target>        detach our mirror from <target> in PID 1's namespace
       nsmbind --sh '<command>'         run one shell command in PID 1's namespace
*/
/* bionic hides setns() behind _GNU_SOURCE, and the define has to precede every include. */
#define _GNU_SOURCE 1
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <sched.h>

/* NOT /dev: files created on devtmpfs come back labelled u:object_r:device:s0, and a `su` with that
 * label is unreadable/unexecutables for the very callers this is meant to serve (measured: after
 * binding a /dev mirror over /sbin, `ls -lZ /sbin/su` from uid 2000 was Permission denied).  /data's
 * shell_data_file is what the 6.0.1 mirror used and what shell and apps can actually exec.
 *
 * The mirror path is per target AND per run.  It used to be one fixed directory, which broke in two
 * ways the moment a second target existed: a later run for /system/bin inherited /sbin's entries,
 * and on a repeated run the O_TRUNC that creates a placeholder wrote THROUGH the still-mounted
 * entry and truncated the original binary.  A fresh directory has neither problem. */
#define MIRROR_BASE "/data/local/tmp/.sud/nsmbind"

static char g_mirror[256];

static void pick_mirror(const char *target)
{
    const char *p;
    size_t n;

    /* Per target, per process AND per run.  A pid alone is not enough: pids are reused,
     * and a stale mirror from an earlier run then gets reused as the source -- measured
     * 2026-11-10, `cp .../su: Text file busy` because the leftover file was still a
     * mountpoint, and every pre-existing entry showed its 0-byte placeholder again. */
    snprintf(g_mirror, sizeof g_mirror, "%s.%d.%ld.", MIRROR_BASE, (int) getpid(),
             (long) time(NULL));
    n = strlen(g_mirror);
    for (p = target; *p && n + 1 < sizeof g_mirror; p++)
        g_mirror[n++] = (*p == '/') ? '_' : *p;
    g_mirror[n] = 0;
}

static int path_in_mirror(const char *name, char *to, size_t tolen)
{
    return snprintf(to, tolen, "%s/%s", g_mirror, name);
}

static int copy_in(const char *src, const char *dst, int exe)
{
    char buf[65536];
    int si, di, n;

    si = open(src, O_RDONLY);
    if (si < 0) {
        printf("open %s: errno=%d\n", src, errno);
        return -1;
    }
    di = open(dst, O_WRONLY | O_CREAT | O_TRUNC, exe ? 0755 : 0644);
    if (di < 0) {
        printf("open %s: errno=%d\n", dst, errno);
        close(si);
        return -1;
    }
    while ((n = read(si, buf, sizeof buf)) > 0) {
        if (write(di, buf, (size_t)n) != n) {
            printf("write %s: errno=%d\n", dst, errno);
            close(si);
            close(di);
            return -1;
        }
    }
    close(si);
    close(di);
    return 0;
}

/* Reproduce `target`'s current entries inside the mirror, bind-mounting each one so the content
 * stays the original on-disk bytes.  A mirror we simply filled with new files would hide whatever
 * the shipped directory held.
 *
 * STRICT on purpose: the caller overlays this mirror over a whole directory, so a single entry we
 * failed to reproduce would silently remove a working binary (one failed bind in /system/bin hides
 * `sh`).  Any failure therefore aborts before the overlay -- the shipped directory stays exactly as
 * it was and only the extra `su`/`sux` names are missing.
 *
 * Symlinks are copied as symlinks instead of bound: binding one makes the kernel resolve it at
 * mount time and turns it into a regular file, and a dangling link cannot be stat()ed at all. */
static int mirror_dir(const char *target)
{
    DIR *d = opendir(target);
    struct dirent *e;
    struct stat st;
    char from[512], to[512];

    if (!d) {
        printf("opendir %s: errno=%d\n", target, errno);
        return -1;
    }
    while ((e = readdir(d)) != NULL) {
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, ".."))
            continue;
        snprintf(from, sizeof from, "%s/%s", target, e->d_name);
        path_in_mirror(e->d_name, to, sizeof to);
        if (lstat(from, &st) != 0) {
            printf("lstat %s: errno=%d -- ABORT (no overlay)\n", from, errno);
            closedir(d);
            return -1;
        }
        if (S_ISLNK(st.st_mode)) {
            char lnk[512];
            ssize_t k = readlink(from, lnk, sizeof lnk - 1);

            if (k <= 0) {
                printf("readlink %s: errno=%d -- ABORT (no overlay)\n", from, errno);
                closedir(d);
                return -1;
            }
            lnk[k] = 0;
            unlink(to);
            if (symlink(lnk, to)) {
                printf("symlink %s -> %s: errno=%d -- ABORT (no overlay)\n", to, lnk, errno);
                closedir(d);
                return -1;
            }
            continue;
        }
        if (S_ISDIR(st.st_mode)) {
            if (mkdir(to, 0755) && errno != EEXIST) {
                printf("mkdir %s: errno=%d -- ABORT (no overlay)\n", to, errno);
                closedir(d);
                return -1;
            }
        } else {
            int fd = open(to, O_WRONLY | O_CREAT | O_TRUNC, 0644);

            if (fd < 0) {
                printf("touch %s: errno=%d -- ABORT (no overlay)\n", to, errno);
                closedir(d);
                return -1;
            }
            close(fd);
        }
        if (mount(from, to, NULL, MS_BIND, NULL)) {
            printf("mirror bind %s -> %s: errno=%d -- ABORT (no overlay)\n", from, to, errno);
            closedir(d);
            return -1;
        }
    }
    closedir(d);
    return 0;
}

static int child(const char *su, const char *target, const char *names)
{
    char list[256], *p, *save, to[512];
    int n = 0;

    /* One bind PER NAME, not one mirror directory over the whole target: mounting the mirror over
     * `target` replaces whatever the previous bind published, so the second name turned the first
     * into a 0-byte placeholder (measured on 1.9.10 -- /sbin/su a real ELF while /sbin/sux became
     * 0 bytes; art/ledger-20261016.md 634).  `names` may be a comma-separated list.
     * The daemon runs with a 077 umask, so every mode asked for below came back as 0700/0750 --
     * measured: with the mirror at `drwx------` and the client at `-rwx------`, uid 2000 could
     * neither traverse /sbin nor exec the file, which looks exactly like "the mount did not land". */
    umask(022);
    if (chdir("/"))
        printf("chdir /: errno=%d (continuing)\n", errno);
    pick_mirror(target);
    if (mkdir(g_mirror, 0755) && errno != EEXIST) {
        printf("mkdir %s: errno=%d\n", g_mirror, errno);
        return 1;
    }
    if (chmod(g_mirror, 0755))
        printf("chmod %s: errno=%d\n", g_mirror, errno);
    /* Publish EVERY name into the mirror first, then overlay the target ONCE.  Binding name by name
     * onto <target>/<name> was tried and does not work here: creating the mount point inside /sbin
     * fails (read-only at that moment), so the bind has nothing to land on and a clean boot ends up
     * with NO su-named entry at all -- measured on 1.9.11 (art/ledger-20261016.md 637-638).  The old
     * one-mount-per-invocation form did overlay successfully but each new mirror replaced the previous
     * one, leaving the earlier name a 0-byte placeholder; filling the mirror with all names in a
     * single pass gets both shapes right.
     * /system/bin is read-only as well, which is why the same mirror trick -- and not a copy -- is
     * the only way to put a name there. */
    if (mirror_dir(target))
        return 1;
    snprintf(list, sizeof list, "%s", names);
    for (p = list, save = NULL; p; p = NULL) {
        char *name = strtok_r(p, ",", &save);

        for (; name; name = strtok_r(NULL, ",", &save)) {
            if (!*name)
                continue;
            path_in_mirror(name, to, sizeof to);
            if (copy_in(su, to, 1))
                return 1;
            if (chmod(to, 0755))
                printf("chmod %s: errno=%d\n", to, errno);
            n++;
            printf("published %s\n", to);
        }
    }
    if (!n) {
        printf("REFUSE: no name given ('%s') -- nothing mounted\n", names);
        return 1;
    }
    /* MS_REC is not optional here.  mirror_dir() reproduces every pre-existing entry as a FILE
     * bind inside the mirror, and a plain MS_BIND of the mirror over `target` does NOT carry those
     * child mounts across (that is --rbind, not --bind).  Measured on 2026-11-10: the bind reported
     * success, yet /sbin/healthd and /sbin/adbd resolved to the 0-byte placeholders underneath --
     * healthd is `critical` in init.rc and adbd is exec'd from /sbin, so a restart of either would
     * exec an empty file.  MS_REC clones the whole mirror subtree, placeholders stay hidden. */
    if (mount(g_mirror, target, NULL, MS_BIND | MS_REC, NULL)) {
        printf("bind %s -> %s: errno=%d\n", g_mirror, target, errno);
        return 1;
    }
    printf("OK bound %d name(s) from %s over %s (recursive)\n", n, g_mirror, target);
    return 0;
}

int main(int argc, char **argv)
{
    const char *su = argc > 1 ? argv[1] : "/data/local/tmp/su";
    const char *target = argc > 2 ? argv[2] : "/sbin";
    const char *name = argc > 3 ? argv[3] : "su";
    int use_ns = argc > 4 ? atoi(argv[4]) : 1;
    int fd, st, rc;

    setvbuf(stdout, NULL, _IONBF, 0);
    /* Recovery mode: `nsmbind --umount <target>` detaches the mirror from <target> in
     * PID 1's namespace.  A publish that landed there cannot be undone from an app or
     * stage shell -- that shell has its own copy of the mount -- and a stale mirror keeps
     * hiding the shipped /sbin entries (measured 2026-11-10: /sbin/healthd stayed a
     * 0-byte placeholder while the app-side view showed the real file). */
    if (!strcmp(su, "--umount")) {
        fd = open("/proc/1/ns/mnt", O_RDONLY | O_CLOEXEC);
        if (fd < 0) {
            printf("open /proc/1/ns/mnt: errno=%d -- need root; nothing done\n", errno);
            return 2;
        }
        rc = fork();
        if (rc == 0) {
            if (setns(fd, CLONE_NEWNS)) {
                printf("setns(/proc/1/ns/mnt): errno=%d -- not unmounted\n", errno);
                _exit(3);
            }
            if (umount2(target, MNT_DETACH))
                printf("umount %s: errno=%d\n", target, errno);
            else
                printf("umount %s: OK\n", target);
            _exit(0);
        }
        close(fd);
        if (rc < 0) {
            printf("fork: errno=%d\n", errno);
            return 1;
        }
        if (waitpid(rc, &st, 0) < 0)
            printf("waitpid: errno=%d\n", errno);
        return WIFEXITED(st) ? WEXITSTATUS(st) : 1;
    }
    /* `nsmbind --sh '<command>'` runs ONE shell command in PID 1's mount namespace.
     *
     * A copy aimed at /system/xbin has to happen THERE and nowhere else.  The root channel (sud)
     * does not live in PID 1's namespace on this ROM -- measured 2026-11-10: the same
     * /system/xbin was a tmpfs with mount id 1727 (0:25, no shared tag) in the channel's view and
     * a DIFFERENT tmpfs, id 895 (0:24, shared:306), in PID 1's.  A plain `cp` therefore reported
     * success while writing into a private copy no other process could see, which is exactly the
     * shape the boot pass kept producing: copied file present for the channel, "No such file" for
     * `adb shell`.  setns() first, then write. */
    if (!strcmp(su, "--sh")) {
        const char *cmd = argc > 2 ? argv[2] : "true";

        fd = open("/proc/1/ns/mnt", O_RDONLY | O_CLOEXEC);
        if (fd < 0) {
            printf("open /proc/1/ns/mnt: errno=%d -- need root; nothing run\n", errno);
            return 2;
        }
        rc = fork();
        if (rc == 0) {
            if (setns(fd, CLONE_NEWNS)) {
                printf("setns(/proc/1/ns/mnt): errno=%d -- command NOT run\n", errno);
                _exit(3);
            }
            execl("/system/bin/sh", "sh", "-c", cmd, (char *)NULL);
            printf("exec /system/bin/sh: errno=%d\n", errno);
            _exit(4);
        }
        close(fd);
        if (rc < 0) {
            printf("fork: errno=%d\n", errno);
            return 1;
        }
        if (waitpid(rc, &st, 0) < 0)
            printf("waitpid: errno=%d\n", errno);
        return WIFEXITED(st) ? WEXITSTATUS(st) : 1;
    }
    if (!use_ns)
        return child(su, target, name);
    fd = open("/proc/1/ns/mnt", O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        printf("open /proc/1/ns/mnt: errno=%d -- need root; nothing done\n", errno);
        return 2;
    }
    rc = fork();                        /* setns(CLONE_NEWNS) is refused for a threaded process */
    if (rc == 0) {
        if (setns(fd, CLONE_NEWNS)) {
            printf("setns(/proc/1/ns/mnt): errno=%d -- NOT mounted\n", errno);
            _exit(3);
        }
        printf("ns: joined PID 1's mount namespace\n");
        _exit(child(su, target, name));
    }
    close(fd);
    if (rc < 0) {
        printf("fork: errno=%d\n", errno);
        return 1;
    }
    if (waitpid(rc, &st, 0) < 0)
        printf("waitpid: errno=%d\n", errno);
    if (WIFEXITED(st))
        return WEXITSTATUS(st);
    printf("child terminated abnormally status=%d\n", st);
    return 1;
}
