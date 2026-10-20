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
#include <unistd.h>
#include <sched.h>

/* NOT /dev: files created on devtmpfs come back labelled u:object_r:device:s0, and a `su` with that
 * label is unreadable/unexecutables for the very callers this is meant to serve (measured: after
 * binding a /dev mirror over /sbin, `ls -lZ /sbin/su` from uid 2000 was Permission denied).  /data's
 * shell_data_file is what the 6.0.1 mirror used and what shell and apps can actually exec. */
#define MIRROR "/data/local/tmp/.sud/nsmbind"

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
 * the shipped directory held. */
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
        snprintf(to, sizeof to, "%s/%s", MIRROR, e->d_name);
        if (stat(from, &st) != 0)
            continue;
        if (S_ISDIR(st.st_mode)) {
            if (mkdir(to, 0755) && errno != EEXIST) {
                printf("mkdir %s: errno=%d\n", to, errno);
                continue;
            }
        } else {
            int fd = open(to, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (fd >= 0)
                close(fd);
            else {
                printf("touch %s: errno=%d\n", to, errno);
                continue;
            }
        }
        if (mount(from, to, NULL, MS_BIND, NULL))
            printf("mirror bind %s -> %s: errno=%d\n", from, to, errno);
    }
    closedir(d);
    return 0;
}

static int child(const char *su, const char *target, const char *names)
{
    char list[256], *p, *save, to[512], dst[512];
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
    if (mkdir(MIRROR, 0755) && errno != EEXIST) {
        printf("mkdir %s: errno=%d\n", MIRROR, errno);
        return 1;
    }
    if (chmod(MIRROR, 0755))
        printf("chmod %s: errno=%d\n", MIRROR, errno);
    /* Publish EVERY name into the mirror first, then overlay the target ONCE.  Binding name by name
     * onto <target>/<name> was tried and does not work here: creating the mount point inside /sbin
     * fails (read-only at that moment), so the bind has nothing to land on and a clean boot ends up
     * with NO su-named entry at all -- measured on 1.9.11 (art/ledger-20261016.md 637-638).  The old
     * one-mount-per-invocation form did overlay successfully but each new mirror replaced the previous
     * one, leaving the earlier name a 0-byte placeholder; filling the mirror with all names in a
     * single pass gets both shapes right. */
    if (mirror_dir(target))
        return 1;
    snprintf(list, sizeof list, "%s", names);
    for (p = list, save = NULL; p; p = NULL) {
        char *name = strtok_r(p, ",", &save);

        for (; name; name = strtok_r(NULL, ",", &save)) {
            if (!*name)
                continue;
            snprintf(to, sizeof to, "%s/%s", MIRROR, name);
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
    if (mount(MIRROR, target, NULL, MS_BIND, NULL)) {
        printf("bind %s -> %s: errno=%d\n", MIRROR, target, errno);
        return 1;
    }
    printf("OK bound %d name(s) from %s over %s\n", n, MIRROR, target);
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
