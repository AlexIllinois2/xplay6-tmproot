/* tools/icache_sync.c -- make a patched kernel-text line actually take effect, using
 * nothing but operations a user process is allowed to do, on ONE chosen CPU.
 *
 * Why this exists: we can write .text through the pgd-slot alias (§175) but we cannot
 * execute anything at EL1, so we cannot issue `ic iallu`.  Both caches have to be
 * dealt with, and both are capacity-missible from user space:
 *   D side -- the store that patched the text left the line DIRTY in the writing CPU's
 *             L1D.  Instruction fetches are satisfied from L2/DRAM, so until that line
 *             is written back, every core keeps fetching the OLD bytes.  Sweeping more
 *             user memory than L1D (with a 64-byte stride, so every set way is used)
 *             evicts it, and eviction of a dirty line is a write-back to L2.
 *   I side -- a core that already fetched the gate's line holds a STALE copy in L1I.
 *             Sweeping an *executed* footprint larger than L1I (one `ret` per cache
 *             line) evicts it; the next fetch of the patched address refills from L2
 *             and gets the new bytes.  This is the userspace equivalent of ic iallu.
 * Neither sweep is global, so run it once per CPU: `icache_sync N` pins to CPU N.
 * The kernel's own online path does the same invalidation for CPU1..7 (§178), so this
 * tool is what makes CPU0 -- which cannot be offlined -- converge too.
 *
 * The executable footprint is a FILE mapping, not anonymous execmem: SELinux for the
 * shell/app domains permits executing files under /data/local/tmp but execmem on
 * anonymous mappings has been refused on this device family.
 *
 * usage: icache_sync <cpu> [textfile]   (textfile default /data/local/tmp/ict.bin)
 *        ICT_MB=8 ICX_MB=6 icache_sync 0     -- tune the footprints
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sched.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

#define LINE 64
#define RET_AARCH64 0xd65f03c0u    /* `ret` -- a 4-byte body that returns immediately */

static long mb_to_long(const char *s, long dflt)
{
    char *end = NULL;
    long v;
    if (!s || !*s)
        return dflt;
    v = strtol(s, &end, 10);
    if (s == end || v <= 0)
        return dflt;
    return v;
}

static int ensure_text_file(const char *path, size_t bytes)
{
    struct stat sb;
    const uint32_t probe[2] = { 0x52800b40u, RET_AARCH64 };
    if (stat(path, &sb) == 0 && (size_t)sb.st_size >= bytes) {
        /* reuse it, but page 0 must carry the probe or the control means nothing */
        int fd = open(path, O_RDWR);
        if (fd < 0) {
            fprintf(stderr, "open %s: %s\n", path, strerror(errno));
            return -1;
        }
        if (pwrite(fd, probe, sizeof probe, 0) != (ssize_t)sizeof probe) {
            fprintf(stderr, "pwrite probe into %s: %s\n", path, strerror(errno));
            close(fd);
            return -1;
        }
        close(fd);
        return 0;
    }
    int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0755);
    if (fd < 0) {
        fprintf(stderr, "open %s: %s\n", path, strerror(errno));
        return -1;
    }
    uint32_t word = RET_AARCH64;
    unsigned char blk[4096];
    for (size_t i = 0; i < sizeof blk; i += 4)
        memcpy(blk + i, &word, 4);
    /* page 0 slot 0 becomes a probe function: `mov w0,#0x5a; ret` -- the sweep only
     * means something if we can actually execute mapped code, so prove it. */
    memcpy(blk, probe, sizeof probe);
    for (size_t off = 0; off < bytes; off += sizeof blk)
        if (write(fd, blk, sizeof blk) != (ssize_t)sizeof blk) {
            fprintf(stderr, "short write at %zu: %s\n", off, strerror(errno));
            close(fd);
            return -1;
        }
    if (fchmod(fd, 0755) != 0)
        fprintf(stderr, "fchmod %s: %s\n", path, strerror(errno));
    close(fd);
    return 0;
}

/* D side: dirty every line of a big anonymous buffer, twice, so the whole L1D is
 * recycled and any dirty line belonging to someone else (our patched text) gets
 * written back. */
static size_t sweep_dcache(size_t bytes)
{
    volatile unsigned char *p = mmap(NULL, bytes, PROT_READ | PROT_WRITE,
                                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        fprintf(stderr, "d-sweep mmap %zu: %s\n", bytes, strerror(errno));
        return 0;
    }
    for (int pass = 0; pass < 2; pass++)
        for (size_t off = 0; off < bytes; off += LINE)
            p[off] = (unsigned char)(pass + 1);
    munmap((void *)p, bytes);
    return bytes;
}

/* I side: execute one `ret` per cache line across a footprint bigger than L1I. */
static size_t sweep_icache(const char *path, size_t bytes)
{
    if (ensure_text_file(path, bytes) != 0)
        return 0;
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "open %s: %s\n", path, strerror(errno));
        return 0;
    }
    unsigned char *base = mmap(NULL, bytes, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, 0);
    close(fd);
    if (base == MAP_FAILED) {
        fprintf(stderr, "exec mmap %s (%zu): %s\n", path, bytes, strerror(errno));
        return 0;
    }
    size_t n = 0;
    int probe = ((int (*)(void))base)();
    if (probe != 0x5a) {
        fprintf(stderr, "EXEC CONTROL FAIL: mapped page0 returned %d (want 90) -- "
                        "executing this file is not allowed here, the I-sweep proves nothing\n", probe);
        munmap(base, bytes);
        return 0;
    }
    for (size_t off = 0; off + 4 <= bytes; off += LINE, n++)
        ((void (*)(void))(base + off))();
    munmap(base, bytes);
    printf("  exec control: ok (page0 probe returned %d), swept %zu lines\n", probe, n);
    return n;
}

int main(int argc, char **argv)
{
    size_t d_mb = mb_to_long(getenv("ICT_MB"), 8);
    size_t i_mb = mb_to_long(getenv("ICX_MB"), 6);
    const char *path = argc > 2 ? argv[2] : "/data/local/tmp/ict.bin";
    int cpu = argc > 1 ? atoi(argv[1]) : -1;

    if (cpu >= 0) {
        cpu_set_t set;
        CPU_ZERO(&set);
        CPU_SET(cpu, &set);
        if (sched_setaffinity(0, sizeof set, &set) != 0)
            fprintf(stderr, "pin to cpu%d: %s\n", cpu, strerror(errno));
    }

    struct timeval t0, t1;
    gettimeofday(&t0, NULL);
    size_t dbytes = sweep_dcache(d_mb << 20);
    size_t ilines = sweep_icache(path, i_mb << 20);
    gettimeofday(&t1, NULL);
    long us = (t1.tv_sec - t0.tv_sec) * 1000000L + (t1.tv_usec - t0.tv_usec);

    pid_t me = getpid();
    char lane[128], where[64] = "?";
    snprintf(lane, sizeof lane, "/proc/%d/stat", (int)me);
    FILE *f = fopen(lane, "r");
    if (f) {
        /* field 39 of /proc/<pid>/stat is the CPU the task was last seen on */
        char tok[64];
        int nf = 0;
        while (fscanf(f, "%63s", tok) == 1)
            if (++nf == 39) {
                snprintf(where, sizeof where, "%s", tok);
                break;
            }
        fclose(f);
    }
    printf("ICACHE_SYNC cpu=%s ran_on=%s d_bytes=%zu i_lines=%zu us=%ld\n",
           argc > 1 ? argv[1] : "any", where, dbytes, ilines, us);
    fflush(stdout);
    if (dbytes == 0 || ilines == 0)
        return 1;
    return 0;
}
