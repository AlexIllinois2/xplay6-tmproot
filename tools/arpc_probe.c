#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>

/* Zero-write reachability probe for the Qualcomm fastRPC driver (/dev/adsprpc-smd).
 *
 * Why: adsprpc.c has NO permission gate at all (grep for capable/CHECK_PERM/f_mode/
 * MAY_WRITE/prev_level/isadsp over the whole file = 0 hits), its file_operations only
 * expose open/release/ioctl, and get_args() contains a deterministic arbitrary-address
 * kernel write (contained-overlap buffers keep a stale ->offset while mlen becomes 0, so
 * the rlen >= mlen check is vacuous and copy_from_user writes to args - offset).
 * The only thing standing between that and a root path is whether an unprivileged shell
 * process can get an ioctl *dispatched* at all -- DAC is 0664 root:system (shell may
 * read), and SELinux labels the node qdsp_device.
 *
 * Method (no risk, no layout dependence): pass NULL as the argument and read the errno.
 *   EFAULT  = the handler ran and copied from our pointer  => dispatched  (the answer we want)
 *   ENOTTY  = command not implemented / not this driver
 *   EINVAL  = rejected before copy (e.g. patched to require f_mode write)
 *   EACCES  = MAC/DAC refused
 * Positive control: _IO('R', 127), a command number the driver cannot know, must give
 * ENOTTY on the same fd -- so an EFAULT below is proof of dispatch, not of a permissive fd.
 */
#define IOCS(n, sz) (unsigned long)((3u << 30) | ((sz) << 16) | ((unsigned long)'R' << 8) | (n))

int main(void)
{
    static const struct { const char *nm; unsigned long cmd; } probes[] = {
        { "INVOKE     (1, 16)", IOCS(1, 16) },
        { "MMAP       (2, 24)", IOCS(2, 24) },
        { "MUNMAP     (3, 16)", IOCS(3, 16) },
        { "INVOKE_FD  (4, 20)", IOCS(4, 20) },
        { "SETMODE    (5,  4)", IOCS(5, 4)  },
        { "INIT       (6, 40)", IOCS(6, 40) },
        { "INIT_CREATE(7, 40)", IOCS(7, 40) },
        { "CONTROL unknown(127)", IOCS(127, 4) },
    };
    int fd, i;

    setvbuf(stdout, NULL, _IONBF, 0);
    for (i = 0; i < 3; i++) {
        int oflag = i == 0 ? O_RDONLY : (i == 1 ? O_RDWR : O_WRONLY);
        fd = open("/dev/adsprpc-smd", oflag);
        printf("open O_%s -> fd=%d errno=%d (%s)\n",
               i == 0 ? "RDONLY" : (i == 1 ? "RDWR" : "WRONLY"),
               fd, fd < 0 ? errno : 0, fd < 0 ? strerror(errno) : "ok");
        if (fd >= 0) {
            int j;
            for (j = 0; j < (int)(sizeof probes / sizeof probes[0]); j++) {
                errno = 0;
                int r = ioctl(fd, probes[j].cmd, NULL);
                printf("   %-22s cmd=%08lx rc=%d errno=%-3d %-16s %s%s\n",
                       probes[j].nm, probes[j].cmd, r, errno, strerror(errno),
                       errno == EFAULT ? "  <== DISPATCHED" : "",
                       errno == ENOTTY && j == (int)(sizeof probes / sizeof probes[0]) - 1
                       ? "  (control behaves)" : "");
            }
            close(fd);
            break;
        }
    }
    return 0;
}
