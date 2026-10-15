/* sel_write_load() does vmalloc(count) + copy_from_user(count) + security_load_policy(count)
 * for EACH write() -- so `cat file > /sys/fs/selinux/load` hands the kernel a 64 KB fragment
 * and fails. This reads the whole policy into memory and writes it in ONE call.
 *
 * usage: loadpol <policy-file>        (run as root; the policy is the kernel's own
 * format, which is also what /sys/fs/selinux/policy dumps back out -- POLICYDB_MAGIC is
 * SELINUX_MAGIC in this tree, ss/policydb.h:324)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

int main(int argc, char **argv)
{
    unsigned char *buf;
    struct stat st;
    ssize_t n, rd;
    int fd, off;

    if (argc < 2) {
        printf("usage: loadpol <policy-file>\n");
        return 2;
    }
    fd = open(argv[1], O_RDONLY);
    if (fd < 0) {
        printf("open policy: errno=%d\n", errno);
        return 3;
    }
    if (fstat(fd, &st) != 0 || st.st_size <= 0) {
        printf("fstat: errno=%d size=%lld\n", errno, (long long)st.st_size);
        return 4;
    }
    buf = malloc(st.st_size);
    if (buf == NULL) {
        printf("malloc %lld: errno=%d\n", (long long)st.st_size, errno);
        return 5;
    }
    for (off = 0; off < st.st_size;) {
        rd = read(fd, buf + off, st.st_size - off);
        if (rd <= 0) {
            printf("read at %d: rd=%zd errno=%d\n", off, rd, errno);
            return 6;
        }
        off += rd;
    }
    close(fd);
    printf("loaded %lld bytes, magic=0x%02x%02x%02x%02x\n", (long long)st.st_size,
           buf[3], buf[2], buf[1], buf[0]);

    fd = open("/sys/fs/selinux/load", O_WRONLY);
    if (fd < 0) {
        printf("open load: errno=%d\n", errno);
        return 7;
    }
    n = write(fd, buf, st.st_size);
    printf("one-shot write: rc=%zd errno=%d (%s)\n", n, errno,
           n == st.st_size ? "ACCEPTED" : "REJECTED");
    close(fd);
    return n == st.st_size ? 0 : 8;
}
