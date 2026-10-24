#define _GNU_SOURCE
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

static void msg(const char *s)
{
    write(2, s, strlen(s));
}

int main(void)
{
    int fd, e;
    struct stat st;
    char b[256];

    msg("topen2 start\n");
    snprintf(b, sizeof b, "uid=%d euid=%d\n", getuid(), geteuid());
    msg(b);
    fd = open("/data/local/tmp/t.out", O_WRONLY | O_CREAT | O_APPEND, 0644);
    e = errno;
    snprintf(b, sizeof b, "open fd=%d errno=%d\n", fd, e);
    msg(b);
    if (fd >= 0) {
        snprintf(b, sizeof b, "write=%zd\n", write(fd, "X\n", 2));
        msg(b);
        close(fd);
    }
    if (stat("/data/local/tmp/t.out", &st) == 0)
        snprintf(b, sizeof b, "stat ok ino=%lu mode=%o\n", (unsigned long)st.st_ino, st.st_mode);
    else
        snprintf(b, sizeof b, "stat fail errno=%d\n", errno);
    msg(b);
    int lf = open("/data/local/tmp", O_RDONLY | O_DIRECTORY);
    snprintf(b, sizeof b, "dirfd=%d errno=%d\n", lf, errno);
    msg(b);
    return 0;
}
