/* Executed as modprobe_path (so stdout is /dev/null): report the domain the kernel
 * actually put us in, then exercise exactly the operations the su stack needs and
 * record rc/errno for each. Run under permissive, where SELinux logs but does not
 * block: the lines this prints are the list of what enforcing would deny us in this
 * domain. Result goes to /data/local/tmp/ctxprobe.out, one block per invocation. */
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <netinet/in.h>

/* No libselinux in the NDK sysroot: /proc/self/attr/current is the same reading. */
static void my_context(char *out, int cap)
{
    int f = open("/proc/self/attr/current", O_RDONLY);
    ssize_t n = f < 0 ? -1 : read(f, out, cap - 1);
    int e = errno;

    if (n > 0) {
        out[n] = 0;
        while (n > 0 && (out[n - 1] == '\n' || out[n - 1] == 0))
            out[--n] = 0;
    } else {
        snprintf(out, cap, "(read failed errno=%d)", e);
    }
    if (f >= 0)
        close(f);
}

static int fd;

static void say(const char *fmt, ...)
{
    char buf[512];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    strcat(buf, "\n");
    if (write(fd, buf, strlen(buf)) < 0)
        _exit(3);
}

static void try_exec(void)
{
    pid_t p = fork();

    if (p < 0) {
        say("exec: fork errno=%d", errno);
        return;
    }
    if (p == 0) {
        char *av[] = { "sh", "-c", "true", NULL };
        execv("/system/bin/sh", av);
        _exit(errno);
    }
    {
        int st = 0;
        pid_t w = waitpid(p, &st, 0);

        if (w < 0)
            say("exec: waitpid errno=%d", errno);
        else if (WIFEXITED(st))
            say("exec /system/bin/sh: exit=%d (0=ok, else errno of the failed execv)", WEXITSTATUS(st));
        else
            say("exec /system/bin/sh: status=0x%x (signalled => denied mid-run)", st);
    }
}

static void try_unix_bind(void)
{
    int s = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un a;

    if (s < 0) {
        say("unix socket(): errno=%d", errno);
        return;
    }
    memset(&a, 0, sizeof a);
    a.sun_family = AF_UNIX;
    a.sun_path[0] = 0;
    strcpy(a.sun_path + 1, "ctxprobe-abs");
    say("unix abstract bind: rc=%d errno=%d", bind(s, (struct sockaddr *)&a, sizeof(sa_family_t) + 13), errno);
    close(s);
}

static void try_tcp(void)
{
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a;

    if (s < 0) {
        say("tcp socket(): errno=%d", errno);
        return;
    }
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons(12377);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    say("tcp bind: rc=%d errno=%d", bind(s, (struct sockaddr *)&a, sizeof a), errno);
    say("tcp listen: rc=%d errno=%d", listen(s, 4), errno);
    close(s);
}

static void try_file(const char *path, int how)
{
    int f = open(path, how);
    int e = errno;

    say("open %s (%s): rc=%d errno=%d", path, how == O_WRONLY ? "O_WRONLY" : "O_RDONLY", f, e);
    if (f >= 0)
        close(f);
}

int main(void)
{
    char con[128];

    fd = open("/data/local/tmp/ctxprobe.out", O_WRONLY | O_CREAT | O_APPEND, 0666);
    if (fd < 0)
        return 1;
    say("---- probe pid=%d uid=%d gid=%d", getpid(), getuid(), getgid());
    my_context(con, sizeof con);
    say("context=%s", con);
    try_exec();
    try_unix_bind();
    try_tcp();
    try_file("/sys/fs/selinux/enforce", O_WRONLY);
    try_file("/sys/fs/selinux/load", O_WRONLY);
    try_file("/proc/sys/kernel/modprobe", O_RDONLY);
    try_file("/data/data/com.xplay6.temproot/files/grants.txt", O_RDONLY);
    try_file("/data/local/tmp/.sud/sud.log", O_WRONLY);
    say("---- end");
    close(fd);
    return 0;
}
