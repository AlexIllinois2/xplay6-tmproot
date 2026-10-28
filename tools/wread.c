/* wread.c — task #7, step 1: prove plan-A premise ② with zero kernel content.
 *
 * Ledger §484 plan A needs a writev whose iovec iterator is BLOCKED with
 * entry[6] NOT yet consumed, so that an in-flight iov_base rewrite of
 * entry[6] (done later through the broot7 write channel) lands on a
 * descriptor the iterator still honours.
 *
 * Measurement rules learned the hard way (first run):
 *   - a read-to-EOF drain swallows whatever the writer pushes AFTER the
 *     unblock, so "what the first drain contains" must be a LIMITED read
 *     (exactly the pipe capacity), taken while the writer is provably still
 *     inside writev;
 *   - "provably still inside" needs witness FILES, not stdio timing: the
 *     writer touches armed right before writev and done right after it
 *     returns -- done absent at check time == still blocked.
 *
 * Sequence:
 *   1. pipe capacity pinned with F_SETPIPE_SZ;
 *   2. writer: 18-entry writev, entries 0..5 totalling 72 KiB > 64 KiB pipe
 *      -> blocks with the iterator inside entry[5], entry[6] untouched;
 *   3. reader: witness check (armed yes, done no), then read EXACTLY the
 *      pipeful and check it holds only entry[0..5] bytes  -- premise ②;
 *   4. positive control: keep reading to EOF -- entry[6] bytes MUST appear
 *      (the iterator does honour entry[6] later, which is what the rewrite
 *      depends on).
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <sys/stat.h>

#define NENT   18
#define BIGLEN (12 * 1024)          /* per-entry payload for entries 0..5 */
#define PIPESZ (64 * 1024)          /* pinned pipe capacity */
/* 6 * 12 KiB = 72 KiB > 64 KiB: the iterator MUST stop inside entry[5]. */

#define ARMED "/data/local/tmp/wread.armed"
#define DONE  "/data/local/tmp/wread.done"

static unsigned char mark(int entry) { return (unsigned char)(0x40 + entry); }

/* read exactly `want` bytes (blocking), count per-entry markers */
static int read_limited(int rfd, long want, long *seen)
{
    static unsigned char buf[4096];
    int i;
    long got = 0;

    for (i = 0; i < NENT; i++)
        seen[i] = 0;
    while (got < want) {
        long n = (long)read(rfd, buf, sizeof buf);
        long k;
        if (n < 0) { printf("  read error errno=%d\n", errno); return -1; }
        if (n == 0) { printf("  EOF after %ld of %ld bytes\n", got, want); return -1; }
        got += n;
        for (k = 0; k < n; k++)
            for (i = 0; i < NENT; i++)
                if (buf[k] == mark(i)) { seen[i]++; break; }
    }
    return 0;
}

/* read to EOF (the writer's close), counting markers */
static int read_rest(int rfd, long *seen)
{
    static unsigned char buf[4096];
    int i, n;
    long k;

    while ((n = (int)read(rfd, buf, sizeof buf)) > 0) {
        for (k = 0; k < n; k++)
            for (i = 0; i < NENT; i++)
                if (buf[k] == mark(i)) { seen[i]++; break; }
    }
    if (n < 0) { printf("  read error errno=%d\n", errno); return -1; }
    return 0;
}

int main(void)
{
    int pfd[2], i, rc = 0;
    long total = 0, seen[NENT];
    struct iovec iov[NENT];
    unsigned char *blk[NENT];
    pid_t w;
    int wstatus;

    setvbuf(stdout, NULL, _IONBF, 0);
    unlink(ARMED); unlink(DONE);
    if (pipe(pfd) < 0) { perror("pipe"); return 1; }
    if (fcntl(pfd[1], F_SETPIPE_SZ, PIPESZ) != PIPESZ) {
        printf("F_SETPIPE_SZ(%d) failed errno=%d -- refusing\n", PIPESZ, errno);
        return 1;
    }
    printf("pipe capacity pinned: %d\n", PIPESZ);

    for (i = 0; i < NENT; i++) {
        size_t len = (i < 6) ? BIGLEN : BIGLEN / 4;
        blk[i] = malloc(len);
        if (!blk[i]) { perror("malloc"); return 1; }
        memset(blk[i], mark(i), len);
        iov[i].iov_base = blk[i];
        iov[i].iov_len = len;
        total += (long)len;
    }
    printf("writev: %d entries, total %ld KiB, pipe %d KiB -> the iterator must "
           "block inside entry[5] (%d KiB short of finishing entry[5])\n",
           NENT, total / 1024, PIPESZ / 1024,
           (6 * BIGLEN - PIPESZ) / 1024);

    w = fork();
    if (w == 0) {
        int af, df;
        ssize_t wv;
        close(pfd[0]);
        af = open(ARMED, O_WRONLY | O_CREAT | O_TRUNC, 0666);
        if (af >= 0) close(af);
        printf("writer: armed, issuing writev\n");
        fflush(stdout);
        wv = writev(pfd[1], iov, NENT);
        printf("writer: writev returned %zd errno=%d\n", wv, wv < 0 ? errno : 0);
        fflush(stdout);
        df = open(DONE, O_WRONLY | O_CREAT | O_TRUNC, 0666);
        if (df >= 0) close(df);
        close(pfd[1]);
        _exit(wv < 0 ? 1 : 0);
    }
    close(pfd[1]);

    sleep(2);   /* the writer is either blocked mid-entry[5] or long gone */
    {
        struct stat sa, sd;
        int have_a = (stat(ARMED, &sa) == 0);
        int have_d = (stat(DONE, &sd) == 0);
        printf("witness: armed=%s done=%s\n",
               have_a ? "yes" : "no", have_d ? "yes" : "no");
        if (!have_a || have_d) {
            printf("FAIL: the writer did not stay blocked -- setup wrong\n");
            return 1;
        }
    }
    printf("reader: writer blocked -- limited read of exactly the pipeful\n");
    if (read_limited(pfd[0], PIPESZ, seen) != 0) {
        printf("== PREMISE 2 INCONCLUSIVE ==\n");
        return 1;
    }
    printf("  first pipeful marker counts:\n");
    for (i = 0; i < NENT; i++)
        printf("    entry[%2d] mark 0x%02x : %ld\n", i, mark(i), seen[i]);
    {
        int ok05 = seen[0] > 0 && seen[1] > 0 && seen[2] > 0 &&
                   seen[3] > 0 && seen[4] > 0 && seen[5] > 0;
        if (!ok05) {
            printf("FAIL: entries 0..5 not all present in the first pipeful\n");
            rc = 1;
        } else if (seen[6] > 0) {
            printf("FAIL: entry[6] bytes in the first pipeful -- the iterator "
                   "crossed it (premise 2 dead in this shape)\n");
            rc = 1;
        } else {
            printf("PASS: iterator still inside entry[5], entry[6] untouched\n");
        }
    }

    printf("reader: positive control -- drain to EOF, entry[6] must appear\n");
    if (read_rest(pfd[0], seen) != 0)
        rc = 1;
    if (seen[6] > 0)
        printf("PASS: entry[6] consumed later (%ld bytes) -- the in-flight "
               "rewrite would be honoured\n", seen[6]);
    else {
        printf("FAIL: entry[6] never consumed -- rewrite could not work\n");
        rc = 1;
    }

    close(pfd[0]);
    waitpid(w, &wstatus, 0);
    printf("writer exit status: %d\n", WEXITSTATUS(wstatus));
    unlink(ARMED); unlink(DONE);
    printf(rc == 0 ? "== PREMISE 2 HOLDS ==\n" : "== PREMISE 2 FAILED ==\n");
    return rc;
}
