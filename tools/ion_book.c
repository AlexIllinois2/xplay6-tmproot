#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/ioctl.h>

/* Deterministic refcount bookkeeping test for ion, observed through debugfs
 * (which shell can read on this device):
 *   /sys/kernel/debug/ion/clients/<pid>-<n> prints
 *      heap_name : size_in_bytes : handle refcount : buffer
 *   /sys/kernel/debug/ion/heaps/system prints one row per buffer.
 * No race, no crafted object: we only ask whether a reference is taken/put the
 * number of times the code implies. */
#define ION_ALLOC 0xc0204900u   /* _IOWR('I', 0, ion_allocation_data) */
#define ION_FREE  0xc0044901u   /* _IOW ('I', 1, ion_handle_data)     */
#define ION_MAP   0xc0084903u   /* _IOWR('I', 3, ion_fd_data)         */
#define ION_SHARE 0xc0084904u   /* _IOWR('I', 4, ion_fd_data)         */

struct alloc_data { unsigned long long len, align; unsigned mask, flags;
                    unsigned handle, pad; };
struct fd_data { unsigned handle; int fd; };

static void dump(const char *tag)
{
    char path[128], line[256];
    DIR *d;
    struct dirent *e;
    int fd;
    ssize_t n;

    printf("  [%s]\n", tag);
    snprintf(path, sizeof path, "/sys/kernel/debug/ion/clients");
    d = opendir(path);
    if (!d) { printf("    clients dir: %s\n", strerror(errno)); return; }
    while ((e = readdir(d))) {
        if (strncmp(e->d_name, "ion", 3) == 0) continue;
        if (atoi(e->d_name) != getpid()) continue;
        snprintf(path, sizeof path, "/sys/kernel/debug/ion/clients/%s", e->d_name);
        fd = open(path, O_RDONLY);
        if (fd < 0) continue;
        while ((n = read(fd, line, sizeof line - 1)) > 0) {
            line[n] = 0;
            if (strstr(line, "system") || line[0] == '-')
                printf("    %s", line);
        }
        close(fd);
    }
    closedir(d);
}

int main(void)
{
    struct alloc_data ad;
    struct fd_data fd2u;
    int fd, rc;

    setvbuf(stdout, NULL, _IONBF, 0);
    printf("pid=%d\n", getpid());
    fd = open("/dev/ion", O_RDONLY);
    if (fd < 0) { printf("open /dev/ion: %s\n", strerror(errno)); return 1; }

    memset(&ad, 0, sizeof ad);
    ad.len = 0x1000; ad.align = 4096; ad.mask = 1u << 9;
    errno = 0;
    rc = ioctl(fd, ION_ALLOC, &ad);
    printf("ALLOC rc=%d errno=%d handle=%u\n", rc, errno, ad.handle);
    if (rc) return 1;
    dump("after ALLOC");

    memset(&fd2u, 0, sizeof fd2u);
    fd2u.handle = ad.handle;
    errno = 0;
    rc = ioctl(fd, ION_MAP, &fd2u);
    printf("ION_IOC_MAP rc=%d errno=%d fd=%d   (ENOTTY = opcode not implemented)\n",
           rc, errno, fd2u.fd);
    if (rc == 0) {
        dump("after MAP");
        close(fd2u.fd);
        dump("after close(map fd)  <-- watch whether our handle's buffer survives");
        /* touch the handle again: if the buffer was freed early this is the trigger */
        errno = 0;
        rc = ioctl(fd, ION_FREE, &(struct { unsigned h; }){ ad.handle });
        printf("FREE rc=%d errno=%d\n", rc, errno);
        dump("after FREE");
    }

    /* same experiment with SHARE, whose get/put we measured as balanced */
    memset(&fd2u, 0, sizeof fd2u);
    fd2u.handle = ad.handle;
    errno = 0;
    rc = ioctl(fd, ION_SHARE, &fd2u);
    printf("ION_IOC_SHARE rc=%d errno=%d fd=%d\n", rc, errno, fd2u.fd);
    if (rc == 0) {
        close(fd2u.fd);
        dump("after close(share fd)");
        errno = 0;
        rc = ioctl(fd, ION_FREE, &(struct { unsigned h; }){ ad.handle });
        printf("FREE rc=%d errno=%d\n", rc, errno);
        dump("after FREE (2)");
    }
    close(fd);
    return 0;
}
