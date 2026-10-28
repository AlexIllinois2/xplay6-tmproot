/* closefds: close every inherited fd above stdio, then exec the rest of the
 * command line.
 *
 *   closefds <exec-path> [args...]
 *
 * WHY: the tmproot root shell (sud) leaks fds across its lifetime -- binder
 * fds from the escalation ladder (intentionally never closed there: closing
 * touches UAF-freed kernel state) plus assorted pipes / an eventpoll / the
 * sud.stage staging file from the command plumbing.  Any long-lived child
 * (gdbserver's event loop, a module daemon) that inherits the pile
 * misbehaves -- gdbserver's accept() returns EBADF with all of them present,
 * not just with the binder ones (measured 2026-10-28: close-binder-only left
 * ~20 pipes + an eventpoll + a stage file, and accept still went EBADF).
 *
 * SAFETY: every fd closed here is a COPY.  The original references stay open
 * in the root daemon (sud), and binder_release only fires when the LAST
 * reference to a file is closed -- so none of the poisoned binder state is
 * walked from here.  (Never wrap the daemon's own spawn chain in this: there
 * the copies ARE the last references.)
 *
 * Closes 3..1023 unconditionally; the child opens whatever it needs (its own
 * sockets, epoll) after exec.  Keeping the filter logic is not worth it: any
 * fd above stdio that the child needed would have to be passed explicitly,
 * and nothing does.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

int main(int argc, char **argv)
{
    int fd, closed_n = 0;

    if (argc < 2) {
        fprintf(stderr, "usage: %s <exec-path> [args...]\n", argv[0]);
        return 2;
    }
    for (fd = 3; fd < 1024; fd++) {
        if (close(fd) == 0)
            closed_n++;
    }
    fprintf(stderr, "closefds: closed %d inherited fds\n", closed_n);
    fflush(stderr);
    execv(argv[1], argv + 1);
    fprintf(stderr, "closefds: exec %s: %s\n", argv[1], strerror(errno));
    return 1;
}
