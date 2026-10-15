#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

/* Does an execve() of a file with no known binary magic make THIS kernel call
 * modprobe_path?  We cannot read /proc/sys/kernel/modprobe as shell (EACCES),
 * so we test the behaviour instead: the child either comes back ENOENT
 * (modprobe_path resolved but its file is missing -> the request WAS issued),
 * or EACCES (SELinux stopped it), or nothing observable (module autoloading is
 * disabled -> the request never left the kernel). */

static const char *BAD[] = { "/data/local/tmp/badmagic_a", "/data/local/tmp/badmagic_b" };

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);

    /* 1. does the configured helper path exist at all? */
    {
        struct stat st;
        static const char *cand[] = { "/sbin/modprobe", "/system/bin/modprobe",
                                      "/sbin/insmod", "/system/bin/toybox" };
        for (unsigned i = 0; i < sizeof cand / sizeof cand[0]; i++)
            printf("stat %-22s = %s\n", cand[i],
                   stat(cand[i], &st) == 0 ? "EXISTS" : "missing");
    }

    /* 2. write a file whose first bytes are not any registered magic */
    for (unsigned i = 0; i < sizeof BAD / sizeof BAD[0]; i++) {
        int fd = open(BAD[i], O_RDWR | O_CREAT | O_TRUNC, 0755);
        if (fd < 0) { printf("open %s: %s\n", BAD[i], strerror(errno)); continue; }
        const char *body = i == 0 ? "AAAAAAAA\n" : "\xff\xff\xff\xff\xff\xff\xff\xff";
        size_t n = strlen(body) + 1;
        if (write(fd, body, n) != (ssize_t)n) printf("write %s short\n", BAD[i]);
        close(fd);
    }

    /* 3. execve each directly (bypassing any shell ENOEXEC fallback) */
    for (unsigned i = 0; i < sizeof BAD / sizeof BAD[0]; i++) {
        char *av[] = { (char *)BAD[i], NULL };
        char *ep[] = { NULL };
        errno = 0;
        execve(BAD[i], av, ep);
        printf("execve(%s) returned: errno=%d %s\n", BAD[i], errno, strerror(errno));
    }

    /* 4. also try the classic "ELF magic but garbage rest" shape */
    {
        const char *p = "/data/local/tmp/badelf";
        int fd = open(p, O_RDWR | O_CREAT | O_TRUNC, 0755);
        if (fd >= 0) {
            char b[64];
            memset(b, 0, sizeof b);
            memcpy(b, "\x7f" "ELF", 4);
            b[4] = 2; b[5] = 1; b[6] = 1;
            if (write(fd, b, sizeof b) != sizeof b) printf("write badelf short\n");
            close(fd);
            char *av[] = { (char *)p, NULL };
            char *ep[] = { NULL };
            errno = 0;
            execve(p, av, ep);
            printf("execve(badelf) returned: errno=%d %s\n", errno, strerror(errno));
        }
    }
    (void)argc; (void)argv;
    return 0;
}
