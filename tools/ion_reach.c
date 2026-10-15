#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/ioctl.h>

/* Discriminator for the ion route (CVE-2016-9120 candidate), layout-independent
   and cannot trigger the race: issue the ioctl with a NULL argument on an
   O_RDONLY fd. The kernel faults while copying in, so it never touches a
   buffer -- but the errno tells us which gate stopped us.
     EFAULT  -> ioctl dispatched: no SELinux block AND no f_mode gate
     EACCES  -> SELinux (or DAC) denies chr_file:ioctl
     EINVAL  -> ion_ioctl gates on f_mode (patched shape)
     ENOTTY  -> this build does not implement that ioctl */

#define ION_IOC_MAGIC 'O'
#define ION_IOC_ALLOC      _IOWR(ION_IOC_MAGIC, 0, int)
#define ION_IOC_FREE       _IOW(ION_IOC_MAGIC, 1, int)
#define ION_IOC_SYNC       _IOW(ION_IOC_MAGIC, 2, int)
#define ION_IOC_CUSTOM     _IOWR(ION_IOC_MAGIC, 4, int)
#define ION_IOC_QUERY_HEAP _IOWR(ION_IOC_MAGIC, 5, int)

static const char *why(int e)
{
    switch (e) {
    case 0: return "OK";
    case EACCES: return "EACCES -> MAC/DAC blocked";
    case EPERM: return "EPERM";
    case EINVAL: return "EINVAL -> gated on f_mode";
    case ENOTTY: return "ENOTTY -> ioctl absent";
    case EFAULT: return "EFAULT -> dispatched, arg only";
    case ENODEV: return "ENODEV";
    default: return strerror(e);
    }
}

static void try(int fd, unsigned long req, const char *nm)
{
    errno = 0;
    int rc = ioctl(fd, req, NULL);
    printf("  %-14s NULL-arg: rc=%d  %s\n", nm, rc, why(errno));
}

int main(void)
{
    int ro, rw;

    errno = 0; ro = open("/dev/ion", O_RDONLY);
    printf("open O_RDONLY  : fd=%d %s\n", ro, ro >= 0 ? "OK" : why(errno));
    if (ro < 0) return 1;
    printf("ioctl dispatch from a READ-ONLY fd:\n");
    try(ro, ION_IOC_ALLOC, "ALLOC");
    try(ro, ION_IOC_FREE, "FREE");
    try(ro, ION_IOC_QUERY_HEAP, "QUERY_HEAP");
    try(ro, ION_IOC_CUSTOM, "CUSTOM");

    errno = 0; rw = open("/dev/ion", O_RDWR);
    printf("open O_RDWR    : fd=%d %s\n", rw, rw >= 0 ? "OK" : why(errno));
    if (rw >= 0) {
        printf("ioctl dispatch from a READ-WRITE fd:\n");
        try(rw, ION_IOC_FREE, "FREE");
        close(rw);
    }
    close(ro);
    return 0;
}
