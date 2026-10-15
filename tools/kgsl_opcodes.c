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

/* Which a5xx CP packets does the PFP firmware allow from a *user* IB1?
 *
 * Everything I tried so far faults with `a5xx_cp_hw_err_callback ringbuffer
 * opcode error` -- including a bare CP_NOP -- while the kernel driver itself
 * contains no packet scanning at all (no IsIB1Authorized / adreno_config /
 * CP_SUCRE_CAT anywhere), so the filter lives in CP firmware.  The vendor's GL
 * stack clearly does submit IB1s, so some opcodes must pass.
 *
 * Each opcode gets its OWN context, because the fault is reported per
 * (ctx, timestamp): dmesg prints "gpu fault ctx N ts M" / "gpu failed ctx N ts M",
 * so after the sweep I can attribute every fault precisely and get an
 * allow-list as a table.  A faulting IB only kills nothing here -- GPU recovery
 * is device-wide but the box keeps running (verified: ts1 faulted, ts2 still got
 * submitted and retired as a failure).
 *
 * usage: kgsl_opcodes            sweep the default list, print ctx/ts map
 *        kgsl_opcodes dump        only print the ctx map (dmesg read separately)
 */

#define OFF(id)   ((off_t)(id) << 12)

/* EXACT copy of this tree's pm4_calc_odd_parity_bit() (adreno_pm4types.h:236-242).
 * It is the 0x9669 EVEN-parity nibble fold: it returns 1 when popcount(val) is
 * EVEN.  My first implementation returned popcount%2 (the inverse), which set both
 * parity bits backwards in every header -- that is why all 23 packets faulted with
 * "ringbuffer opcode error" including a bare CP_NOP.  Copy the source, don't recall it. */
static unsigned int pm4_parity(unsigned int val)
{
    return (0x9669 >> (0xF & (val ^ (val >> 4) ^ (val >> 8) ^ (val >> 12) ^
                              (val >> 16) ^ (val >> 20) ^ (val >> 24) ^ (val >> 28)))) & 1;
}

/* adreno_pm4types.h:268 cp_type7_packet(): cnt = payload dwords, excluding header */
static uint32_t cp7(uint32_t opcode, uint32_t cnt)
{
    return (7u << 28) | (cnt & 0x7FFFu) | (pm4_parity(cnt) << 15) |
           (((opcode) & 0x7Fu) << 16) | (pm4_parity(opcode) << 23);
}

struct cand { uint32_t op; const char *name; int payload; };

static struct cand list[] = {
    { 0x10, "CP_NOP", 0 },
    { 0x12, "CP_WAIT_MEM_WRITES", 0 },
    { 0x13, "CP_WAIT_FOR_ME", 0 },
    { 0x26, "CP_WAIT_FOR_IDLE", 0 },
    { 0x30, "CP_LOAD_STATE", 0 },
    { 0x32, "CP_COND_INDIRECT_BUFFER_PFD", 0 },
    { 0x34, "CP_DRAW_INDX_BIN", 0 },
    { 0x37, "CP_INDIRECT_BUFFER_PFD", 0 },
    { 0x38, "CP_DRAW_INDX_OFFSET", 0 },
    { 0x3a, "CP_COND_INDIRECT_BUFFER_PFE", 0 },
    { 0x3c, "CP_WAIT_REG_MEM", 0 },
    { 0x3d, "CP_MEM_WRITE", 0 },
    { 0x3e, "CP_REG_TO_MEM", 0 },
    { 0x3f, "CP_INDIRECT_BUFFER_PFE", 0 },
    { 0x42, "CP_MEM_TO_REG", 0 },
    { 0x43, "CP_SET_DRAW_STATE", 0 },
    { 0x45, "CP_COND_WRITE", 0 },
    { 0x46, "CP_EVENT_WRITE", 0 },
    { 0x48, "CP_ME_INIT", 0 },
    { 0x52, "CP_WAIT_REG_EQ", 0 },
    { 0x53, "CP_SMMU_TABLE_UPDATE", 0 },
    { 0x5c, "CP_WAIT_UNTIL_READ", 0 },
    { 0x5d, "CP_WAIT_IB_PFD_COMPLETE", 0 },
};

/* One opcode per PROCESS.  Needed because the only per-submission oracle that is
 * unambiguous is the delta of /sys/class/kgsl/kgsl-3d0/reset_count around a run:
 * a batch that submits 23 IBs tells me "the GPU reset 23 times", not which ones. */
int main(int argc, char **argv)
{
    int fd = open("/dev/kgsl-3d0", O_RDWR);
    struct kgsl_gpumem_alloc_id aid;
    struct kgsl_drawctxt_create dctx;
    struct kgsl_command_object objs[1];
    struct kgsl_gpu_command cmd;
    uint32_t *ib;
    unsigned int n = sizeof list / sizeof list[0];
    int i, only = -1;

    if (argc > 1) only = (int)strtol(argv[1], NULL, 0);

    setvbuf(stdout, NULL, _IONBF, 0);
    if (fd < 0) { printf("open kgsl: %s\n", strerror(errno)); return 1; }

    memset(&aid, 0, sizeof aid);
    aid.flags = 0;
    aid.size = 0x1000;
    if (ioctl(fd, IOCTL_KGSL_GPUMEM_ALLOC_ID, &aid)) {
        printf("alloc FAILED errno=%d\n", errno); return 1;
    }
    ib = mmap(NULL, aid.mmapsize, PROT_READ | PROT_WRITE, MAP_SHARED, fd, OFF(aid.id));
    if (ib == MAP_FAILED) { printf("mmap FAILED errno=%d\n", errno); return 1; }
    printf("IB id=%u gpuaddr=%#lx\n", aid.id, (unsigned long)aid.gpuaddr);

    printf("op   ctx  ts   header      name\n");
    for (i = 0; i < (int)n; i++) {
        if (only >= 0 && list[i].op != (uint32_t)only) continue;
        uint32_t hdr = cp7(list[i].op, list[i].payload);
        int rc;

        memset(&dctx, 0, sizeof dctx);
        dctx.flags = KGSL_CONTEXT_PREAMBLE | KGSL_CONTEXT_NO_GMEM_ALLOC;
        if (ioctl(fd, IOCTL_KGSL_DRAWCTXT_CREATE, &dctx)) {
            printf("%#04x drawctxt FAILED errno=%d -- aborting sweep\n", list[i].op, errno);
            break;
        }

        memset(ib, 0, 0x40);
        ib[0] = hdr;                      /* payload 0: a bare, well-formed packet */

        memset(objs, 0, sizeof objs);
        objs[0].gpuaddr = aid.gpuaddr;
        objs[0].size = 4;
        objs[0].flags = KGSL_CMDLIST_IB;

        memset(&cmd, 0, sizeof cmd);
        cmd.cmdlist = (uint64_t)(unsigned long)objs;
        cmd.cmdsize = sizeof objs[0];
        cmd.numcmds = 1;
        cmd.context_id = dctx.drawctxt_id;
        cmd.timestamp = 0;
        errno = 0;
        rc = ioctl(fd, IOCTL_KGSL_GPU_COMMAND, &cmd);
        printf("%#04x %5u %4u  %08x  %-30s submit rc=%d errno=%d\n",
               list[i].op, dctx.drawctxt_id, cmd.timestamp, hdr, list[i].name, rc, errno);
        if (only >= 0) { usleep(1200000); break; }
        usleep(400000);                   /* let the CP reach it and the recovery run */
    }
    printf("SWEEP_DONE  (now read dmesg: gpu fault ctx <id> ts <n> = filtered)\n");
    return 0;
}
