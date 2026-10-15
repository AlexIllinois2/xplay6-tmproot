#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>

/* Localize the "bind(): EPERM for every unix socket, even as root" observation.
 * appprobe measured abstract bind+listen succeeding from untrusted_app, and sud
 * measures EPERM from the kernel domain -- so the question is whether it is the
 * binary, the domain, the uid, or the socket type.  One binary, five attempts,
 * each with its own errno, plus the identity facts that could explain a match:
 * uid/euid/CapEff/ns-net/ns-mnt.
 *
 * Run it twice: from adb shell (uid 2000, shell) and through the root daemon
 * (uid 0, kernel domain).
 */
static void note(const char *what, long rc)
{
    printf("  %-34s rc=%-5ld errno=%d %s\n", what, rc, rc < 0 ? errno : 0,
           rc < 0 ? strerror(errno) : "OK");
    fflush(stdout);
}

static void ident(void)
{
    char link[64], tgt[128];
    int i;
    const char *names[2] = { "net", "mnt" };

    printf("  id: uid=%d euid=%d gid=%d\n", getuid(), geteuid(), getgid());
    for (i = 0; i < 2; i++) {
        ssize_t n;
        snprintf(link, sizeof link, "/proc/self/ns/%s", names[i]);
        n = readlink(link, tgt, sizeof tgt - 1);
        if (n > 0) {
            tgt[n] = 0;
            printf("  ns/%s -> %s\n", names[i], tgt);
        }
    }
    {
        FILE *f = fopen("/proc/self/status", "r");
        char l[256];
        if (f) {
            while (fgets(l, sizeof l, f))
                if (!strncmp(l, "CapEff", 6) || !strncmp(l, "Seccomp", 7))
                    fputs(l, stdout);
            fclose(f);
        }
    }
}

int main(int argc, char **argv)
{
    int fd, s;
    struct sockaddr_un a;
    struct sockaddr_in in;

    printf("=== ubind (argv1=%s) ===\n", argc > 1 ? argv[1] : "-");
    ident();

    /* 1. plain TCP bind on a free port, same process, as a control */
    s = socket(AF_INET, SOCK_STREAM, 0);
    note("socket AF_INET", s);
    if (s >= 0) {
        memset(&in, 0, sizeof in);
        in.sin_family = AF_INET;
        in.sin_addr.s_addr = htonl(INADDR_ANY);
        in.sin_port = htons(21456);
        note("bind tcp 0.0.0.0:21456", bind(s, (struct sockaddr *) &in, sizeof in));
        close(s);
    }

    /* 2. abstract unix socket */
    s = socket(AF_UNIX, SOCK_STREAM, 0);
    note("socket AF_UNIX", s);
    if (s >= 0) {
        memset(&a, 0, sizeof a);
        a.sun_family = AF_UNIX;
        a.sun_path[0] = 0;
        memcpy(a.sun_path + 1, "ubind.abs", 9);
        note("bind abstract @ubind.abs",
             bind(s, (struct sockaddr *) &a, sizeof(a.sun_family) + 1 + 9));
        note("listen abstract", listen(s, 4));
        close(s);
    }

    /* 3. file sockets in each candidate directory, with the dir ops logged */
    {
        const char *dirs[2] = { "/data/local/tmp/.ubind", "/dev/.ubind" };
        int i;

        for (i = 0; i < 2; i++) {
            char path[128];
            snprintf(path, sizeof path, "%s/s.sock", dirs[i]);
            note("mkdir dir", mkdir(dirs[i], 0777));
            note("chmod dir", chmod(dirs[i], 0777));
            unlink(path);
            fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0777);
            note("creat plain file in dir", fd);
            if (fd >= 0)
                close(fd);
            s = socket(AF_UNIX, SOCK_STREAM, 0);
            if (s >= 0) {
                memset(&a, 0, sizeof a);
                a.sun_family = AF_UNIX;
                strncpy(a.sun_path, path, sizeof a.sun_path - 1);
                note("bind file socket", bind(s, (struct sockaddr *) &a, sizeof a));
                note("listen file socket", listen(s, 4));
                close(s);
            }
            note("unlink file socket", unlink(path));
            note("rmdir", rmdir(dirs[i]));
        }
    }
    printf("=== done ===\n");
    (void)fd;
    return 0;
}
