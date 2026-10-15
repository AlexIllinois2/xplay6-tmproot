#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>

/* Phase 1b -- all safe, single-threaded, no race:
 *   ion: ALLOC / FREE(0xc0044901, int handle) / FREE again / MAP->fd / mmap+peek
 *   unix sockets: pure connect() probe of the 0666 root-service sockets
 */
#define ION_ALLOC 0xc0204900u
#define ION_FREE  0xc0044901u
#define ION_MAP   0xc0084902u
#define ION_SHARE 0xc0084904u

struct alloc_data { unsigned long long len, align; unsigned mask, flags; unsigned handle; unsigned pad; };
struct fd_data { unsigned handle; int fd; };

static const char *W(int e)
{
    if (e == 0) return "OK";
    if (e == EACCES) return "EACCES";
    if (e == EPERM) return "EPERM";
    if (e == ENOENT) return "ENOENT";
    if (e == ENOTTY) return "ENOTTY(not recognized)";
    if (e == ENODEV) return "ENODEV";
    if (e == ECONNREFUSED) return "ECONNREFUSED";
    return strerror(e);
}

int main(void)
{
    int fd, rc;
    struct alloc_data ad;
    struct fd_data fd_;

    errno = 0;
    fd = open("/dev/ion", O_RDONLY);
    printf("open /dev/ion (O_RDONLY): %s\n", fd >= 0 ? "OK" : W(errno));
    if (fd < 0) return 1;

    memset(&ad, 0, sizeof ad);
    ad.len = 8192; ad.align = 4096; ad.mask = 1u << 9;
    errno = 0; rc = ioctl(fd, ION_ALLOC, &ad);
    printf("ALLOC   0xc0204900 mask=1<<9 : rc=%d handle=%u %s\n", rc, ad.handle, W(errno));
    if (rc) goto socks;

    memset(&fd_, 0, sizeof fd_); fd_.handle = ad.handle;
    errno = 0; rc = ioctl(fd, ION_MAP, &fd_);
    printf("MAP     0xc0084902            : rc=%d fd=%d %s\n", rc, fd_.fd, W(errno));
    if (rc == 0 && fd_.fd > 0) {
        void *p = mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_SHARED, fd_.fd, 0);
        printf("mmap ion fd                 : %s\n", p == MAP_FAILED ? W(errno) : "OK");
        if (p != MAP_FAILED) {
            printf("   read-back first 8 bytes    : %02x %02x %02x %02x\n",
                   ((unsigned char *)p)[0], ((unsigned char *)p)[1],
                   ((unsigned char *)p)[2], ((unsigned char *)p)[3]);
            munmap(p, 8192);
        }
        close(fd_.fd);
    }

    {
        unsigned h = ad.handle;
        errno = 0; rc = ioctl(fd, ION_FREE, &h);
        printf("FREE #1 0xc0044901          : rc=%d %s\n", rc, W(errno));
        errno = 0; rc = ioctl(fd, ION_FREE, &h);
        printf("FREE #2 sequential (safe)   : rc=%d %s   <- must fail cleanly\n", rc, W(errno));
    }

socks:
    printf("\nconnect() probe of root-service sockets (DAC 0666 per init rc):\n");
    {
        static const char *sk[] = { "perfd", "iop", "thermal-send-client",
                                    "thermal-recv-passive-client", "logd", "dumpstate",
                                    "backuprestore", "qseecomd", "rmt_storage", NULL };
        int i;
        for (i = 0; sk[i]; i++) {
            char path[128];
            struct sockaddr_un a;
            int s = socket(AF_UNIX, SOCK_STREAM, 0);
            struct stat st;
            snprintf(path, sizeof path, "/dev/socket/%s", sk[i]);
            int exist = (stat(path, &st) == 0);
            if (s < 0) { printf("  %-28s socket(): %s\n", sk[i], W(errno)); continue; }
            memset(&a, 0, sizeof a);
            a.sun_family = AF_UNIX;
            strncpy(a.sun_path, path, sizeof a.sun_path - 1);
            errno = 0;
            rc = connect(s, (struct sockaddr *)&a, sizeof a);
            printf("  %-28s stat=%-8s connect: %s\n", sk[i],
                   exist ? "exists" : "ENOENT", rc == 0 ? "OK(root service accepted us)" : W(errno));
            close(s);
        }
    }
    close(fd);
    return 0;
}
