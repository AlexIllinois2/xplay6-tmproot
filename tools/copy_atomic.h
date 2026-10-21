/* Atomic delivery of the `su` client binary, shared by the daemon and its test.
 *
 * Why this exists (measured on-device 2026-10-19): /sbin/su was found as a ZERO-BYTE executable
 * while /sbin/sux beside it was the real 2.1 MB client.  The old helper opened the DESTINATION
 * with O_TRUNC before it had even opened the source, so any failure -- unreadable client, a short
 * write, an interrupted copy -- left an empty file where the client should be.  That is worse than
 * not delivering `su` at all: an app that probes for `su` then execs a stub and gets ENOEXEC, and
 * the log says "su is broken" instead of "su was never installed".
 *
 * Rules both functions follow:
 *   - the destination is only replaced once the full payload is on disk and its size matches;
 *   - a failure leaves the previous destination exactly as it was (or absent), never truncated;
 *   - size is verified after the write, because that is the only cheap check that catches a stub.
 * `copy_inplace_checked()` exists because the destination may be the target of a per-file bind
 * mount from an earlier run, and rename over a mount point is EBUSY -- there the in-place write is
 * the only option, so it must carry its own verification instead of relying on rename.
 */
#ifndef SUD_COPY_ATOMIC_H
#define SUD_COPY_ATOMIC_H

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef COPY_CHUNK
#define COPY_CHUNK 8192
#endif

/* returns 0 on success; -1 with *err set, destination untouched in every failure path */
static int copy_bytes(int fi, int fo, size_t want, int *err)
{
    char b[COPY_CHUNK];
    size_t got = 0;
    ssize_t r;

    while ((r = read(fi, b, sizeof b)) > 0) {
        ssize_t n = 0;
        while (n < r) {
            ssize_t w = write(fo, b + n, (size_t)(r - n));
            if (w <= 0) {
                *err = errno ? errno : EIO;
                return -1;
            }
            n += w;
        }
        got += (size_t)r;
    }
    if (r < 0) {
        *err = errno;
        return -1;
    }
    if (want && got != want) {
        *err = EIO;                     /* short read: never deliver a partial binary */
        return -1;
    }
    *err = 0;
    return 0;
}

static int copy_atomic(const char *src, const char *dst)
{
    char tmp[512];
    struct stat sa;
    int fi, fo, err = 0;

    if (stat(src, &sa) != 0 || !S_ISREG(sa.st_mode) || sa.st_size == 0) {
        fprintf(stderr, "copy: %s is not a regular non-empty file\n", src);
        return -1;
    }
    snprintf(tmp, sizeof tmp, "%s.new%d", dst, (int)getpid());
    fi = open(src, O_RDONLY);
    if (fi < 0) {
        fprintf(stderr, "copy: open %s: errno=%d\n", src, errno);
        return -1;
    }
    fo = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (fo < 0) {
        fprintf(stderr, "copy: open %s: errno=%d\n", tmp, errno);
        close(fi);
        unlink(tmp);
        return -1;
    }
    if (copy_bytes(fi, fo, (size_t)sa.st_size, &err) < 0) {
        close(fi);
        close(fo);
        unlink(tmp);                    /* the destination was never touched */
        fprintf(stderr, "copy: %s -> %s failed, errno=%d (destination left as it was)\n",
                src, dst, err);
        return -1;
    }
    close(fi);
    if (fsync(fo) != 0) {
        err = errno;
        close(fo);
        unlink(tmp);
        fprintf(stderr, "copy: fsync %s: errno=%d\n", tmp, err);
        return -1;
    }
    if (close(fo) != 0) {
        fprintf(stderr, "copy: close %s: errno=%d\n", tmp, errno);
        unlink(tmp);
        return -1;
    }
    if (chmod(tmp, 0755) != 0) {
        fprintf(stderr, "copy: chmod %s: errno=%d\n", tmp, errno);
        unlink(tmp);
        return -1;
    }
    if (rename(tmp, dst) != 0) {
        int e = errno;
        unlink(tmp);
        fprintf(stderr, "copy: rename %s -> %s: errno=%d\n", tmp, dst, e);
        if (e == EBUSY || e == EPERM || e == EXDEV)
            return 1;                   /* caller falls back to the in-place variant */
        return -1;
    }
    return 0;
}

/* Same guarantees, but writing through whatever `dst` currently is (it may be a mount target).
 * Here a failure CAN damage the destination, so the size is checked and reported; a caller that
 * gets -1 must treat `dst` as suspect and say so instead of trusting its existence. */
static int copy_inplace_checked(const char *src, const char *dst, int *damaged)
{
    struct stat sa, sb;
    int fi, fo, err = 0;

    *damaged = 0;
    if (stat(src, &sa) != 0 || !S_ISREG(sa.st_mode) || sa.st_size == 0) {
        fprintf(stderr, "copy: %s is not a regular non-empty file\n", src);
        return -1;
    }
    fi = open(src, O_RDONLY);
    if (fi < 0) {
        fprintf(stderr, "copy: open %s: errno=%d\n", src, errno);
        return -1;
    }
    fo = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (fo < 0) {
        int e = errno;
        close(fi);
        fprintf(stderr, "copy: open %s: errno=%d\n", dst, e);
        if (e == ENOENT)                 /* parent vanished; nothing was written */
            return -1;
        *damaged = 1;                    /* the truncate itself may have landed */
        return -1;
    }
    if (copy_bytes(fi, fo, (size_t)sa.st_size, &err) < 0 || fsync(fo) != 0) {
        close(fi);
        close(fo);
        *damaged = 1;
        fprintf(stderr, "copy: %s -> %s failed (errno=%d) and %s is now suspect\n",
                src, dst, err, dst);
        return -1;
    }
    close(fi);
    close(fo);
    if (stat(dst, &sb) != 0 || sb.st_size != sa.st_size) {
        *damaged = 1;
        fprintf(stderr, "copy: %s holds %lld bytes, client is %lld -- deliver FAILED\n",
                dst, (long long)sb.st_size, (long long)sa.st_size);
        return -1;
    }
    return 0;
}

/* The one entry point the daemon should call. */
static int deliver_client(const char *src, const char *dst, int *damaged)
{
    int rc = copy_atomic(src, dst);

    if (rc == 0)
        return 0;
    if (rc == 1)
        return copy_inplace_checked(src, dst, damaged);
    *damaged = 0;
    return -1;
}

#endif /* SUD_COPY_ATOMIC_H */
