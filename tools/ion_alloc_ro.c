#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/ioctl.h>

/* Correct encodings from the CAF uapi: ION_IOC_MAGIC == 'I'
 *   ALLOC 0 ion_allocation_data | FREE 1 ion_handle_data | MAP 2 ion_fd_data
 *   CUSTOM 6 | SHARE 4 | IMPORT 5 | SYNC 7
 * Phase 1 is safe-by-construction: single-threaded, no racing FREE, so it
 * cannot reach the CVE-2016-9120 window. It answers: from an O_RDONLY ion fd,
 * does ALLOC succeed (=> ion_ioctl has no f_mode gate) and what are the heaps.
 */
struct ion_allocation_data { unsigned long long len, align; unsigned heap_id_mask, flags; unsigned long long handle; };
struct ion_handle_data { unsigned long long handle; };
struct ion_fd_data { unsigned long long handle; int fd; };
struct ion_custom_data { unsigned int cmd; unsigned long long arg; };

#define MAGIC 'I'
#define ION_IOC_ALLOC   _IOWR(MAGIC, 0, struct ion_allocation_data)
#define ION_IOC_FREE    _IOWR(MAGIC, 1, struct ion_handle_data)
#define ION_IOC_MAP     _IOWR(MAGIC, 2, struct ion_fd_data)
#define ION_IOC_SHARE   _IOWR(MAGIC, 4, struct ion_fd_data)
#define ION_IOC_IMPORT  _IOWR(MAGIC, 5, struct ion_fd_data)
#define ION_IOC_CUSTOM  _IOWR(MAGIC, 6, struct ion_custom_data)
#define ION_IOC_SYNC    _IOWR(MAGIC, 7, struct ion_fd_data)

static const char *why(int e)
{
    switch (e) {
    case 0: return "OK";
    case EACCES: return "EACCES -> MAC/DAC";
    case EINVAL: return "EINVAL -> unknown cmd OR f_mode gate";
    case ENODEV: return "ENODEV -> bad handle/heap";
    case EFAULT: return "EFAULT -> arg only";
    case ENOMEM: return "ENOMEM";
    default: return strerror(e);
    }
}

int main(void)
{
    int fd, i, rc;
    struct ion_allocation_data ad;
    struct ion_handle_data hd;

    errno = 0;
    fd = open("/dev/ion", O_RDONLY);
    printf("open O_RDONLY: fd=%d %s\n\n", fd, fd >= 0 ? "OK" : why(errno));
    if (fd < 0) return 1;

    printf("cmd encoding sanity: ALLOC=%08x FREE=%08x (nr must be 'I'=0x49)\n",
           ION_IOC_ALLOC, ION_IOC_FREE);

    /* which heap ids exist? probe each single-bit mask with a tiny alloc */
    printf("\nprobe ALLOC per heap_id bit (O_RDONLY fd!):\n");
    int first_ok = -1;
    for (i = 0; i < 12 && first_ok < 0; i++) {
        memset(&ad, 0, sizeof ad);
        ad.len = 4096; ad.align = 4096; ad.heap_id_mask = 1u << i;
        errno = 0; rc = ioctl(fd, ION_IOC_ALLOC, &ad);
        printf("  mask=1<<%-2d %-9s rc=%d len=%llu handle=%p\n", i, why(errno), rc, ad.len,
               (void *)ad.handle);
        if (rc == 0) {
            first_ok = i;
            /* sequential double free: the 2nd must fail cleanly (safe path) */
            memset(&hd, 0, sizeof hd); hd.handle = ad.handle;
            errno = 0; rc = ioctl(fd, ION_IOC_FREE, &hd);
            printf("     FREE #1: rc=%d %s\n", rc, why(errno));
            errno = 0; rc = ioctl(fd, ION_IOC_FREE, &hd);
            printf("     FREE #2 (sequential, same handle): rc=%d %s\n", rc, why(errno));
        }
    }
    if (first_ok < 0)
        printf("\n=> no heap accepted an ALLOC from a read-only fd\n");
    else
        printf("\n=> heap id %d allocated AND freed through an O_RDONLY fd"
               "  => ion_ioctl has NO f_mode gate\n", first_ok);
    close(fd);
    return 0;
}
