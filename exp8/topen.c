#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
int main(void)
{
    int fd = open("/data/local/tmp/t.out", O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) return 100 + errno;
    dprintf(fd, "uid=%d euid=%d ctx_ok\n", getuid(), geteuid());
    close(fd);
    return 0;
}
