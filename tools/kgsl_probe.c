#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include "msm_kgsl.h"

/* Reachability oracle (ledger S2 / memory): call each ioctl with a NULL argument.
 * EFAULT = the command was dispatched into the handler (the struct copy is what
 * faulted) -> live surface.  ENOTTY = not implemented.  EACCES/EPERM = denied by
 * DAC/MAC.  EINVAL = handler refused before touching the pointer (patched shape).
 * Nothing is ever written to the kernel with this probe. */
static struct { unsigned long c; const char *n; } cmds[] = {
 {IOCTL_KGSL_CFF_SYNC_GPUOBJ,"CFF_SYNC_GPUOBJ"},
 {IOCTL_KGSL_CFF_SYNCMEM,"CFF_SYNCMEM"},
 {IOCTL_KGSL_CFF_USER_EVENT,"CFF_USER_EVENT"},
 {IOCTL_KGSL_CMDSTREAM_FREEMEMONTIMESTAMP,"CMDSTREAM_FREEMEMONTIMESTAMP"},
 {IOCTL_KGSL_CMDSTREAM_FREEMEMONTIMESTAMP_CTXTID,"CMDSTREAM_FREEMEMONTIMESTAMP_CTXTID"},
 {IOCTL_KGSL_CMDSTREAM_FREEMEMONTIMESTAMP_OLD,"CMDSTREAM_FREEMEMONTIMESTAMP_OLD"},
 {IOCTL_KGSL_CMDSTREAM_READTIMESTAMP,"CMDSTREAM_READTIMESTAMP"},
 {IOCTL_KGSL_CMDSTREAM_READTIMESTAMP_CTXTID,"CMDSTREAM_READTIMESTAMP_CTXTID"},
 {IOCTL_KGSL_CMDSTREAM_READTIMESTAMP_OLD,"CMDSTREAM_READTIMESTAMP_OLD"},
 {IOCTL_KGSL_CMDWINDOW_WRITE,"CMDWINDOW_WRITE"},
 {IOCTL_KGSL_DEVICE_GETPROPERTY,"DEVICE_GETPROPERTY"},
 {IOCTL_KGSL_DEVICE_WAITTIMESTAMP,"DEVICE_WAITTIMESTAMP"},
 {IOCTL_KGSL_DEVICE_WAITTIMESTAMP_CTXTID,"DEVICE_WAITTIMESTAMP_CTXTID"},
 {IOCTL_KGSL_DRAWCTXT_BIND_GMEM_SHADOW,"DRAWCTXT_BIND_GMEM_SHADOW"},
 {IOCTL_KGSL_DRAWCTXT_CREATE,"DRAWCTXT_CREATE"},
 {IOCTL_KGSL_DRAWCTXT_DESTROY,"DRAWCTXT_DESTROY"},
 {IOCTL_KGSL_DRAWCTXT_SET_BIN_BASE_OFFSET,"DRAWCTXT_SET_BIN_BASE_OFFSET"},
 {IOCTL_KGSL_GPU_COMMAND,"GPU_COMMAND"},
 {IOCTL_KGSL_GPUMEM_ALLOC,"GPUMEM_ALLOC"},
 {IOCTL_KGSL_GPUMEM_ALLOC_ID,"GPUMEM_ALLOC_ID"},
 {IOCTL_KGSL_GPUMEM_FREE_ID,"GPUMEM_FREE_ID"},
 {IOCTL_KGSL_GPUMEM_GET_INFO,"GPUMEM_GET_INFO"},
 {IOCTL_KGSL_GPUMEM_SYNC_CACHE,"GPUMEM_SYNC_CACHE"},
 {IOCTL_KGSL_GPUMEM_SYNC_CACHE_BULK,"GPUMEM_SYNC_CACHE_BULK"},
 {IOCTL_KGSL_GPUOBJ_ALLOC,"GPUOBJ_ALLOC"},
 {IOCTL_KGSL_GPUOBJ_FREE,"GPUOBJ_FREE"},
 {IOCTL_KGSL_GPUOBJ_IMPORT,"GPUOBJ_IMPORT"},
 {IOCTL_KGSL_GPUOBJ_INFO,"GPUOBJ_INFO"},
 {IOCTL_KGSL_GPUOBJ_SET_INFO,"GPUOBJ_SET_INFO"},
 {IOCTL_KGSL_GPUOBJ_SYNC,"GPUOBJ_SYNC"},
 {IOCTL_KGSL_MAP_USER_MEM,"MAP_USER_MEM"},
 {IOCTL_KGSL_PERFCOUNTER_GET,"PERFCOUNTER_GET"},
 {IOCTL_KGSL_PERFCOUNTER_PUT,"PERFCOUNTER_PUT"},
 {IOCTL_KGSL_PERFCOUNTER_QUERY,"PERFCOUNTER_QUERY"},
 {IOCTL_KGSL_PERFCOUNTER_READ,"PERFCOUNTER_READ"},
 {IOCTL_KGSL_PREEMPTIONCOUNTER_QUERY,"PREEMPTIONCOUNTER_QUERY"},
 {IOCTL_KGSL_RINGBUFFER_ISSUEIBCMDS,"RINGBUFFER_ISSUEIBCMDS"},
 {IOCTL_KGSL_SETPROPERTY,"SETPROPERTY"},
 {IOCTL_KGSL_SHAREDMEM_FLUSH_CACHE,"SHAREDMEM_FLUSH_CACHE"},
 {IOCTL_KGSL_SHAREDMEM_FREE,"SHAREDMEM_FREE"},
 {IOCTL_KGSL_SHAREDMEM_FROM_PMEM,"SHAREDMEM_FROM_PMEM"},
 {IOCTL_KGSL_SHAREDMEM_FROM_VMALLOC,"SHAREDMEM_FROM_VMALLOC"},
 {IOCTL_KGSL_SUBMIT_COMMANDS,"SUBMIT_COMMANDS"},
 {IOCTL_KGSL_SYNCSOURCE_CREATE,"SYNCSOURCE_CREATE"},
 {IOCTL_KGSL_SYNCSOURCE_CREATE_FENCE,"SYNCSOURCE_CREATE_FENCE"},
 {IOCTL_KGSL_SYNCSOURCE_DESTROY,"SYNCSOURCE_DESTROY"},
 {IOCTL_KGSL_SYNCSOURCE_SIGNAL_FENCE,"SYNCSOURCE_SIGNAL_FENCE"},
 {IOCTL_KGSL_TIMESTAMP_EVENT,"TIMESTAMP_EVENT"},
 {IOCTL_KGSL_TIMESTAMP_EVENT_OLD,"TIMESTAMP_EVENT_OLD"},
};

int main(int argc, char **argv)
{
    const char *dev = argc > 1 ? argv[1] : "/dev/kgsl-3d0";
    int fd, i;
    fd = open(dev, O_RDWR);
    if (fd < 0) { printf("open %s: errno=%d %s\n", dev, errno, strerror(errno));
                  fd = open(dev, O_RDONLY);
                  if (fd < 0) { printf("O_RDONLY also failed: %s\n", strerror(errno)); return 1; }
                  printf("(opened O_RDONLY only)\n"); }
    printf("%s fd=%d  probing %d ioctls with NULL arg\n", dev, fd, (int)(sizeof cmds/sizeof *cmds));
    for (i = 0; i < (int)(sizeof cmds/sizeof *cmds); i++) {
        errno = 0;
        (void)ioctl(fd, (unsigned long)cmds[i].c, NULL);
        int e = errno;
        printf("  %-34s cmd=%08lx -> errno=%-3d %-12s %s\n", cmds[i].n,
               (unsigned long)cmds[i].c, e, strerror(e),
               e == EFAULT ? "<<< DISPATCHED (handler reached the arg copy)"
                         : e == ENOTTY ? "not implemented"
                         : (e == EACCES || e == EPERM) ? "DENIED by DAC/MAC"
                         : e == EINVAL ? "handler refused first" : "");
    }
    close(fd);
    return 0;
}
