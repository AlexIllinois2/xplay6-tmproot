#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>

/* Which (device, prot, flags) combinations does this shell domain actually get?
 * Distinguishes an LSM denial (EACCES on binder only) from a driver/vm refusal. */
static const char *names[] = {
    "/dev/binder", "/dev/ashmem", "/dev/kgsl-3d0", "/dev/adsprpc-smd", "/dev/ion",
    "/dev/pmsg0", "/dev/hwbinder", "/dev/vndbinder", "/dev/uinput", "/dev/ptmx",
};

static const char *protname(int p)
{
    if (p == (PROT_READ | PROT_WRITE)) return "RW";
    if (p == PROT_READ) return "R";
    if (p == PROT_WRITE) return "W";
    if (p == (PROT_READ | PROT_WRITE | PROT_EXEC)) return "RWX";
    return "?";
}

int main(void)
{
    size_t i;
    int pr[] = { PROT_READ | PROT_WRITE, PROT_READ, PROT_WRITE };
    int fl[] = { MAP_SHARED, MAP_PRIVATE };

    for (i = 0; i < sizeof names / sizeof *names; i++) {
        int fd = open(names[i], O_RDWR | O_NONBLOCK);
        int rdonly = 0;
        if (fd < 0) {
            fd = open(names[i], O_RDONLY | O_NONBLOCK);
            if (fd < 0) { printf("%-20s open: %s\n", names[i], strerror(errno)); continue; }
            rdonly = 1;
        }
        printf("%-20s fd=%d (%s)\n", names[i], fd, rdonly ? "O_RDONLY" : "O_RDWR");
        for (unsigned p = 0; p < sizeof pr / sizeof *pr; p++)
            for (unsigned f = 0; f < sizeof fl / sizeof *fl; f++) {
                void *m = mmap(NULL, 0x1000, pr[p], fl[f], fd, 0);
                if (m == MAP_FAILED)
                    printf("    mmap %-3s %-7s -> FAIL errno=%d %s\n", protname(pr[p]),
                           fl[f] == MAP_SHARED ? "SHARED" : "PRIVATE", errno, strerror(errno));
                else {
                    printf("    mmap %-3s %-7s -> OK %p\n", protname(pr[p]),
                           fl[f] == MAP_SHARED ? "SHARED" : "PRIVATE", m);
                    munmap(m, 0x1000);
                }
            }
        close(fd);
    }
    return 0;
}
