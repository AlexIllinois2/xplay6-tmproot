/* Arms for tools/copy_atomic.h -- compiled natively, no device needed.
 *
 * The defect being closed is a measured one: /sbin/su on the phone was a ZERO-BYTE executable
 * while /sbin/sux beside it was the real client (2026-10-19).  The old helper evaluated
 * `open(src)` and `open(dst, O_TRUNC)` in one statement, so a failure to read the source still
 * destroyed the destination.  Arm 2 reproduces that exact shape against a reference copy of the
 * old code, so the arm cannot be satisfied by a test that is too weak to see the bug.
 *
 * build & run:  cc -Wall -Wextra -Werror -O1 -o /tmp/copy_atomic_test tools/copy_atomic_test.c \
 *               && /tmp/copy_atomic_test
 */
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "copy_atomic.h"

static int fails;

static void mkpath(char *out, size_t n, const char *tag)
{
    snprintf(out, n, "/tmp/copytest-%s-%d", tag, (int)getpid());
}

static void write_file(const char *p, const char *what, size_t len)
{
    int fd = open(p, O_WRONLY | O_CREAT | O_TRUNC, 0755);

    if (fd < 0 || write(fd, what, len) != (ssize_t)len) {
        fprintf(stderr, "fixture: cannot write %s\n", p);
        exit(2);
    }
    close(fd);
}

/* verbatim shape of the pre-fix helper, kept only so the negative arms have teeth */
static int legacy_copy_file(const char *src, const char *dst)
{
    char b[COPY_CHUNK];
    int fi = open(src, O_RDONLY), fo = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    int r;

    if (fi < 0 || fo < 0) {
        if (fi >= 0)
            close(fi);
        if (fo >= 0)
            close(fo);
        return -1;
    }
    while ((r = read(fi, b, sizeof b)) > 0) {
        int n = 0;
        while (n < r) {
            int w = write(fo, b + n, r - n);
            if (w <= 0) {
                close(fi);
                close(fo);
                return -1;
            }
            n += w;
        }
    }
    close(fi);
    close(fo);
    return r < 0 ? -1 : 0;
}

static long size_of(const char *p)
{
    struct stat st;

    return stat(p, &st) == 0 ? (long)st.st_size : -1;
}

static void arm(const char *name, int cond)
{
    printf("  %s %s\n", cond ? "ok  " : "FAIL", name);
    if (!cond)
        fails++;
}

int main(void)
{
    char src[128], dst[128], missing[128], tmp[160], bad[128];
    char payload[9000];
    int rc, damaged_flag;

    mkpath(src, sizeof src, "src");
    mkpath(dst, sizeof dst, "dst");
    mkpath(missing, sizeof missing, "absent");
    mkpath(bad, sizeof bad, "empty");
    snprintf(tmp, sizeof tmp, "%s.parent-missing/deep", src);
    memset(payload, 'A', sizeof payload);
    unlink(src);
    unlink(dst);
    unlink(missing);
    unlink(bad);

    /* 1 -- the delivered file must be the whole client, executable, and sized like it */
    write_file(src, payload, 8192);
    rc = deliver_client(src, dst, &damaged_flag);
    arm("deliver: full client lands, right size", rc == 0 && size_of(dst) == 8192);
    {
        struct stat st;
        arm("deliver: mode is 0755 (not the daemon's 077 umask)",
            stat(dst, &st) == 0 && (st.st_mode & 07777) == 0755);
    }

    /* 2 -- THE regression: source missing, destination already holds a previous client.
     * The new code must leave it intact; the legacy shape must destroy it (proving the arm
     * can actually see this failure mode). */
    write_file(dst, payload, 4096);
    rc = deliver_client(missing, dst, &damaged_flag);
    arm("guard: unreadable source leaves the previous client intact",
        rc == -1 && size_of(dst) == 4096);
    write_file(dst, payload, 4096);
    rc = legacy_copy_file(missing, dst);
    arm("teeth: the pre-fix helper really does truncate it (arm would catch the bug)",
        rc == -1 && size_of(dst) == 0);

    /* 3 -- an empty source must never be delivered at all: an empty `su` is the exact observed
     * defect, and it reads to an app as a broken binary rather than as absence. */
    write_file(bad, "", 0);
    write_file(dst, payload, 4096);
    rc = deliver_client(bad, dst, &damaged_flag);
    arm("guard: a zero-length client is refused, not published",
        rc == -1 && size_of(dst) == 4096 && size_of(bad) == 0);

    /* 4 -- no temporary file left behind on any failure path */
    {
        char left[200];
        snprintf(left, sizeof left, "%s.new%d", dst, (int)getpid());
        unlink(left);
        write_file(dst, payload, 4096);
        rc = deliver_client(bad, dst, &damaged_flag);
        arm("cleanup: a refused delivery leaves no .new<pid> litter",
            rc == -1 && access(left, F_OK) != 0);
    }

    /* 5 -- destination parent missing: failure without touching anything */
    rc = deliver_client(src, tmp, &damaged_flag);
    arm("refuse: missing parent directory fails cleanly, damaged flag not asserted",
        rc == -1 && damaged_flag == 0);

    /* 6 -- the in-place variant (used when rename hits a mount point) must VERIFY, because
     * there the destination really is opened with O_TRUNC. */
    write_file(dst, payload, 4096);
    rc = copy_inplace_checked(src, dst, &damaged_flag);
    arm("in-place: verified rewrite lands the full 8192 bytes", rc == 0 && size_of(dst) == 8192);
    rc = copy_inplace_checked(bad, dst, &damaged_flag);
    arm("in-place: a bad source is refused BEFORE the destination is truncated",
        rc == -1 && damaged_flag == 0 && size_of(dst) == 8192);

    /* 7 -- a directory as source is not a client */
    {
        char dir[128];
        mkpath(dir, sizeof dir, "adir");
        mkdir(dir, 0755);
        write_file(dst, payload, 4096);
        rc = deliver_client(dir, dst, &damaged_flag);
        arm("refuse: a directory is never delivered as the client",
            rc == -1 && size_of(dst) == 4096);
        rmdir(dir);
    }

    unlink(src);
    unlink(dst);
    unlink(bad);
    printf("copy_atomic: %d arm(s) failed\n", fails);
    return fails ? 1 : 0;
}
