/*
 * KGSL smoke test - shell domain, no GPU dependency
 * 1. open + GETPROPERTY
 * 2. create ctx (PREAMBLE|NO_GMEM_ALLOC|USER_GENERATED_TS)
 * 3. submit SYNC batch, numcmds=0, syncpoint (other ctx, big ts) -> must stay pending
 * 4. preload 32 syncs on one batch
 * 5. destroy ctx -> clean teardown
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <stdint.h>

#define KGSL_IOC_TYPE 0x09
#define _IOWR_T(nr, size) ((3UL << 30) | ((size & 0x3fff) << 16) | (KGSL_IOC_TYPE << 8) | nr)
#define _IOW_T(nr, size)  ((1UL << 30) | ((size & 0x3fff) << 16) | (KGSL_IOC_TYPE << 8) | nr)

#define IOCTL_KGSL_DEVICE_GETPROPERTY _IOWR_T(0x2, 24)
#define IOCTL_KGSL_DRAWCTXT_CREATE    _IOWR_T(0x13, 8)
#define IOCTL_KGSL_DRAWCTXT_DESTROY   _IOW_T(0x14, 4)
#define IOCTL_KGSL_SUBMIT_COMMANDS    _IOWR_T(0x3d, 56)

#define KGSL_CONTEXT_PREAMBLE         0x00000010
#define KGSL_CONTEXT_NO_GMEM_ALLOC    0x00000002
#define KGSL_CONTEXT_USER_GENERATED_TS 0x00000080

#define KGSL_CMDBATCH_SYNC 0x00000008

#define KGSL_CMD_SYNCPOINT_TYPE_TIMESTAMP 1

struct kgsl_device_getproperty { uint32_t type; void *value; size_t sizebytes; };
struct kgsl_drawctxt_create { uint32_t flags; uint32_t drawctxt_id; };
struct kgsl_drawctxt_destroy { uint32_t drawctxt_id; };
struct kgsl_submit_commands {
    uint32_t context_id; uint32_t flags;
    void *cmdlist; uint32_t numcmds;
    void *synclist; uint32_t numsyncs;
    uint32_t timestamp; uint32_t __pad[4];
};
struct kgsl_cmd_syncpoint { int type; void *priv; size_t size; };
struct kgsl_cmd_syncpoint_timestamp { uint32_t context_id; uint32_t timestamp; };

static int kfd;
#define CK(x, msg) do { if ((x) < 0) { printf("FAIL %s: %s\n", msg, strerror(errno)); return 1; } } while (0)

static uint32_t mkctx(uint32_t flags)
{
    struct kgsl_drawctxt_create p = { .flags = flags };
    CK(ioctl(kfd, IOCTL_KGSL_DRAWCTXT_CREATE, &p), "DRAWCTXT_CREATE");
    return p.drawctxt_id;
}

static void rmctx(uint32_t id)
{
    struct kgsl_drawctxt_destroy d = { .drawctxt_id = id };
    int r = ioctl(kfd, IOCTL_KGSL_DRAWCTXT_DESTROY, &d);
    printf("destroy ctx %u -> %d (%s)\n", id, r, r ? strerror(errno) : "ok");
}

/* submit SYNC batch on ctx, with ns syncpoints all on (tgt, ts...) */
static int submit_sync(uint32_t ctx, struct kgsl_cmd_syncpoint_timestamp *ts, int ns, uint32_t *out_ts)
{
    struct kgsl_cmd_syncpoint sp[64];
    for (int i = 0; i < ns; i++) {
        sp[i].type = KGSL_CMD_SYNCPOINT_TYPE_TIMESTAMP;
        sp[i].priv = &ts[i];
        sp[i].size = 8;
    }
    struct kgsl_submit_commands sc = {
        .context_id = ctx, .flags = KGSL_CMDBATCH_SYNC,
        .numcmds = 0, .synclist = sp, .numsyncs = ns, .timestamp = 1,
    };
    int r = ioctl(kfd, IOCTL_KGSL_SUBMIT_COMMANDS, &sc);
    if (r == 0 && out_ts) *out_ts = sc.timestamp;
    return r;
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    kfd = open("/dev/kgsl-3d0", O_RDWR);
    CK(kfd, "open kgsl-3d0");
    printf("open ok fd=%d\n", kfd);

    struct kgsl_device_getproperty gp = { .type = 0x1 /*KGSL_PROP_DEVICE_INFO*/ };
    unsigned int info[8];
    gp.value = info; gp.sizebytes = sizeof(info);
    int r = ioctl(kfd, IOCTL_KGSL_DEVICE_GETPROPERTY, &gp);
    printf("getproperty -> %d, chip_id=0x%08x gpu_id=0x%08x\n", r, r ? 0 : info[1], r ? 0 : info[3]);

    uint32_t CTX_A = mkctx(KGSL_CONTEXT_PREAMBLE | KGSL_CONTEXT_NO_GMEM_ALLOC | KGSL_CONTEXT_USER_GENERATED_TS);
    uint32_t CTX_B = mkctx(KGSL_CONTEXT_PREAMBLE | KGSL_CONTEXT_NO_GMEM_ALLOC | KGSL_CONTEXT_USER_GENERATED_TS);
    printf("ctxA=%u ctxB=%u\n", CTX_A, CTX_B);

    /* pending cross-ctx sync: B waits for A's far-future ts */
    uint32_t ts_out = 0;
    struct kgsl_cmd_syncpoint_timestamp t1 = { .context_id = CTX_A, .timestamp = 0x1000 };
    r = submit_sync(CTX_B, &t1, 1, &ts_out);
    printf("submit B(1 sync, pending) -> %d ts=%u\n", r, ts_out);

    /* 32 syncpoints in one batch */
    struct kgsl_cmd_syncpoint_timestamp t32[32];
    for (int i = 0; i < 32; i++) { t32[i].context_id = CTX_A; t32[i].timestamp = 0x2000 + i; }
    r = submit_sync(CTX_B, t32, 32, &ts_out);
    printf("submit B(32 syncs, pending) -> %d ts=%u\n", r, ts_out);

    /* 20 pending batches on B */
    for (int i = 0; i < 20; i++) {
        struct kgsl_cmd_syncpoint_timestamp t = { .context_id = CTX_A, .timestamp = 0x10000 + i };
        r = submit_sync(CTX_B, &t, 1, &ts_out);
        if (r) { printf("batch %d FAIL %d\n", i, r); break; }
    }
    printf("20 pending batches done\n");

    /* self sync with USER_GENERATED_TS: ts 0 <= queued 0 -> ok */
    struct kgsl_cmd_syncpoint_timestamp tself = { .context_id = CTX_B, .timestamp = 0 };
    r = submit_sync(CTX_B, &tself, 1, &ts_out);
    printf("submit self-sync ts0 -> %d ts=%u\n", r, ts_out);

    rmctx(CTX_A);   /* A destroyed first: B's batches cancelled via A's group */
    rmctx(CTX_B);
    close(kfd);
    printf("SMOKE OK\n");
    return 0;
}
