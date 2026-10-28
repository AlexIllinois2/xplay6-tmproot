/* Minimal init-domain accept probe: which step goes EBADF? */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>

static void nb(int fd) { int fl = fcntl(fd, F_GETFL); fcntl(fd, F_SETFL, fl | O_NONBLOCK); }

int main(int argc, char **argv)
{
    int port = argc > 1 ? atoi(argv[1]) : 5044;
    int s = socket(AF_INET, SOCK_STREAM, 0);
    printf("socket fd=%d errno=%d\n", s, s < 0 ? errno : 0);
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    a.sin_addr.s_addr = INADDR_ANY;
    int one = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    int b = bind(s, (struct sockaddr *)&a, sizeof a);
    printf("bind(fd=%d) = %d errno=%d\n", s, b, b ? errno : 0);
    int l = listen(s, 1);
    printf("listen(fd=%d) = %d errno=%d\n", s, l, l ? errno : 0);
    nb(s);

    /* accept in a child after a client connects from adb shell */
    pid_t p = fork();
    if (p == 0) {
        int c = accept(s, NULL, NULL);
        printf("child accept(fd=%d) = %d errno=%d\n", s, c, c < 0 ? errno : 0);
        fflush(stdout);
        _exit(c < 0 ? 1 : 0);
    }
    sleep(6);   /* window for the tester to connect from host */
    int st;
    waitpid(p, &st, 0);
    printf("child exit=%d\n", WEXITSTATUS(st));
    close(s);
    return 0;
}
