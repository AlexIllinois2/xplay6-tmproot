#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <poll.h>
#include <sys/syscall.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>

/* su client for the Xplay6 temp-root path: this is the binary that lands at
 * /system/xbin/su (delivered by sud's MOUNT, i.e. tmpfs+bind, never a partition
 * write).  Apps that expect root call exec("su -c <cmd>") or exec("su 0 ..."),
 * so those two shapes are what we accept; everything else is passed through.
 *
 * /data and /cache are mounted nosuid on this device, so a setuid binary is
 * impossible by design -- the privilege lives in the daemon and this client only
 * carries bytes.
 *
 * usage: su [-c <cmd>] [uid]        su - (interactive)        su (root shell)
 */
#define SOCKPATH "/dev/.sud/sud.sock"

/* Channels, in order.  On this device the daemon lives in u:r:kernel:s0, which
 * cannot bind AF_UNIX at all (measured: EPERM for abstract and filesystem
 * sockets, even permissive), so the working transport is TCP on loopback; the
 * unix attempts are kept because they succeed for any other domain and because
 * they are what a Magisk-style client would expect. */
static int tcp_channel(void)
{
    struct sockaddr_in in;
    int fd = socket(AF_INET, SOCK_STREAM, 0);

    if (fd < 0)
        return -1;
    memset(&in, 0, sizeof in);
    in.sin_family = AF_INET;
    in.sin_addr.s_addr = htonl(0x7f000001);
    in.sin_port = htons(12346);
    if (connect(fd, (struct sockaddr *) &in, sizeof in) == 0)
        return fd;
    close(fd);
    return -1;
}

/* Reverse-direction channel: WE listen, the daemon connects.  This is the only
 * shape that works on this device -- the daemon's domain cannot bind AF_UNIX and
 * cannot see our TCP row -- and it is also the strongest: the request travels
 * with SCM_CREDENTIALS, which the kernel fills in from the sending task, so the
 * uid the grant list is checked against cannot be forged by an unprivileged app.
 */
#define REQ_DIR "/data/local/tmp/.sud/req"

static int peer_channel(const char *req, int timeout_ms)
{
    struct sockaddr_un a;
    char name[48], path[256];
    struct iovec io;
    char cbuf[CMSG_SPACE(sizeof(struct ucred))];
    struct msghdr mh;
    struct cmsghdr *cm;
    struct timeval tv;
    fd_set rf;
    size_t nl;
    int ls, csock, fd;

    ls = socket(AF_UNIX, SOCK_STREAM, 0);
    if (ls < 0)
        return -1;
    snprintf(name, sizeof name, "trq%d.%ld", getuid(), (long) getpid());
    nl = strlen(name);
    memset(&a, 0, sizeof a);
    a.sun_family = AF_UNIX;
    a.sun_path[0] = 0;
    memcpy(a.sun_path + 1, name, nl);
    if (bind(ls, (struct sockaddr *) &a, (socklen_t) (sizeof(a.sun_family) + 1 + nl)) < 0) {
        fprintf(stderr, "su: abstract bind: %s\n", strerror(errno));
        close(ls);
        return -1;
    }
    if (listen(ls, 1) < 0) {
        close(ls);
        return -1;
    }
    mkdir(REQ_DIR, 01777);   /* best effort: the daemon owns this dir and re-modes it each start */
    snprintf(path, sizeof path, "%s/req-%d", REQ_DIR, getpid());
    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (fd < 0) {
        fprintf(stderr, "su: cannot publish request name: %s\n", strerror(errno));
        close(ls);
        return -1;
    }
    if (write(fd, name, nl) != (ssize_t) nl || write(fd, "\n", 1) != 1) {
        close(fd);
        close(ls);
        return -1;
    }
    close(fd);

    FD_ZERO(&rf);
    FD_SET(ls, &rf);
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    if (select(ls + 1, &rf, NULL, NULL, &tv) <= 0) {
        fprintf(stderr, "su: daemon did not call back (%s)\n", strerror(errno));
        unlink(path);
        close(ls);
        return -1;
    }
    csock = accept(ls, NULL, NULL);
    close(ls);
    if (csock < 0)
        return -1;

    memset(&mh, 0, sizeof mh);
    memset(cbuf, 0, sizeof cbuf);
    io.iov_base = (void *) req;
    io.iov_len = strlen(req);
    mh.msg_iov = &io;
    mh.msg_iovlen = 1;
    mh.msg_control = cbuf;
    mh.msg_controllen = sizeof cbuf;
    cm = CMSG_FIRSTHDR(&mh);
    cm->cmsg_level = SOL_SOCKET;
    cm->cmsg_type = SCM_CREDENTIALS;
    cm->cmsg_len = CMSG_LEN(sizeof(struct ucred));
    {
        struct ucred *uc = (struct ucred *) CMSG_DATA(cm);
        uc->pid = getpid();
        uc->uid = getuid();
        uc->gid = getgid();
    }
    mh.msg_controllen = cm->cmsg_len;
    if (sendmsg(csock, &mh, 0) < 0) {
        fprintf(stderr, "su: sendmsg: %s\n", strerror(errno));
        close(csock);
        return -1;
    }
    return csock;
}

static int open_channel(void)
{
    const char *files[2] = { "/dev/.sud/sud.sock", "/data/local/tmp/.sud/sud.sock" };
    int i, fd;

    for (i = 0; i < 3; i++) {
        struct sockaddr_un a;

        fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd < 0)
            break;
        memset(&a, 0, sizeof a);
        a.sun_family = AF_UNIX;
        if (i == 0) {
            a.sun_path[0] = 0;
            memcpy(a.sun_path + 1, "sud", 3);
            if (connect(fd, (struct sockaddr *) &a, sizeof(a.sun_family) + 1 + 3) == 0)
                return fd;
        } else {
            strncpy(a.sun_path, files[i - 1], sizeof a.sun_path - 1);
            if (connect(fd, (struct sockaddr *) &a, sizeof a) == 0)
                return fd;
        }
        close(fd);
    }
    fd = tcp_channel();
    if (fd >= 0)
        return fd;
    fprintf(stderr, "su: no sud channel (%s) -- escalate first (is SELinux permissive?)\n",
            strerror(errno));
    return -1;
}

/* Interactive sessions must stay *incremental*: Shizuku's shell handshake writes
 * `echo SHELL_TEST` and blocks until that exact line comes back, so anything that
 * holds back a whole tail of bytes (an earlier draft kept the last 256) makes the
 * caller time out and report "no root".  So pass every complete line straight
 * through and only ever hold back a trailing marker line -- the daemon's trailer
 * ("\n@SUD_EXIT=<n>\n") is always the last thing it writes. */
#define HOLDCAP 4096
static char hold[HOLDCAP];
static int hold_len, exit_seen, exit_code;

static void emit_drain(int upto)
{
    if (upto <= 0)
        return;
    if (write(1, hold, (size_t) upto) < 0)
        return;
    if (upto < hold_len)
        memmove(hold, hold + upto, (size_t) (hold_len - upto));
    hold_len -= upto;
}

/* Remove a complete "@SUD_EXIT=<n>" line from the buffer and remember the code. */
static void emit_scan_marker(void)
{
    int i, e, nl, from;

    for (i = 0; i + 10 <= hold_len; i++) {
        if (hold[i] != '@' || (i > 0 && hold[i - 1] != '\n'))
            continue;
        if (memcmp(hold + i, "@SUD_EXIT=", 10) != 0)
            continue;
        e = i + 10;
        while (e < hold_len && hold[e] >= '0' && hold[e] <= '9')
            e++;
        if (e == i + 10)
            continue;
        nl = e;
        while (nl < hold_len && hold[nl] != '\n')
            nl++;
        if (nl == hold_len)
            return;                     /* line not complete yet: wait for the \n */
        exit_code = atoi(hold + i + 10);
        exit_seen = 1;
        from = i > 0 ? i - 1 : i;       /* swallow the newline that opened it */
        memmove(hold + from, hold + nl + 1, (size_t) (hold_len - nl - 1));
        hold_len -= (nl + 1 - from);
        return;
    }
}

static void emit_flush(const char *buf, int n)
{
    int last_nl = -1, i, take, upto;

    while (n > 0) {
        if (hold_len == HOLDCAP) {
            emit_scan_marker();
            if (hold_len == HOLDCAP)
                emit_drain(HOLDCAP / 2);
        }
        take = n < HOLDCAP - hold_len ? n : HOLDCAP - hold_len;
        memcpy(hold + hold_len, buf, (size_t) take);
        hold_len += take;
        buf += take;
        n -= take;
    }
    emit_scan_marker();
    for (i = hold_len - 1; i >= 0; i--)
        if (hold[i] == '\n') {
            last_nl = i;
            break;
        }
    upto = last_nl + 1;
    /* a marker split across reads must never reach the caller's stdout */
    if (upto >= 10 && hold[0] == '@' && !memcmp(hold, "@SUD_EXIT=", 10))
        upto = 0;
    emit_drain(upto);
}

static int emit_close(void)
{
    emit_scan_marker();
    emit_drain(hold_len);
    return exit_seen ? exit_code : 0;
}

int main(int argc, char **argv)
{
    char req[4200], out[8192];
    struct pollfd pf[2];
    int fd, uid = 0, i, interactive = 0;
    const char *cmd = NULL;

    /* Diagnostic: `sux --rawexec <path> [args...]` calls execve through the raw
     * syscall instead of libc's wrapper.  There is no "su" string anywhere in this
     * kernel image, so if the name guard lives in bionic's execve() the raw call
     * gets through while every libc caller is refused -- that distinction decides
     * whether third-party root apps can ever work here. */
    if (argc > 2 && !strcmp(argv[1], "--rawexec")) {
        extern char **environ;
        char **ra = &argv[2];

        fprintf(stderr, "rawexec: trying syscall(222) %s\n", ra[0]);
        syscall(SYS_execve, ra[0], ra, environ);
        fprintf(stderr, "rawexec: FAILED errno=%d %s\n", errno, strerror(errno));
        return 126;
    }

    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-c") && i + 1 < argc) {
            cmd = argv[++i];
        } else if (!strcmp(argv[i], "-")) {
            interactive = 1;
        } else if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) {
            printf("usage: su [-c <cmd>] [uid]   (temp-root sud client)\n");
            return 0;
        } else if (argv[i][0] >= '0' && argv[i][0] <= '9') {
            uid = atoi(argv[i]);
        }
    }
    if (cmd == NULL)
        interactive = 1;

    snprintf(req, sizeof req, interactive && !cmd ? "SU %d -\n" : "SU %d %s\n",
             uid, cmd ? cmd : "");

    /* peer first (kernel-backed identity).  peer_channel() sends the request
     * itself, together with SCM_CREDENTIALS, so it must not be sent twice. */
    int req_sent = 0;

    fd = peer_channel(req, 8000);
    if (fd >= 0)
        req_sent = 1;
    else
        fd = open_channel();
    if (fd < 0)
        return 127;
    if (!req_sent && write(fd, req, strlen(req)) < 0) {
        fprintf(stderr, "su: write request: %s\n", strerror(errno));
        return 127;
    }

    /* two-way relay until either side closes; stdin is only a poll participant in
     * an interactive session (with -c the daemon's child reads nothing from us).
     * With -c we buffer instead of streaming, because the daemon appends
     * "@SUD_EXIT=<n>" -- a socket carries no wait status -- and that trailer must
     * not reach the caller's stdout. */
    {
        char *acc = NULL;
        size_t acc_len = 0, acc_cap = 0;
        int exit_code = 0;

        if (cmd != NULL) {
            acc_cap = 1u << 19;
            acc = malloc(acc_cap);
        }
        pf[0].fd = fd;
        pf[0].events = POLLIN;
        pf[1].fd = 0;
        pf[1].events = interactive ? POLLIN : 0;
        for (;;) {
            int r = poll(pf, 2, -1);
            int n;

            if (r < 0) {
                if (errno == EINTR)
                    continue;
                break;
            }
            if (pf[0].revents & (POLLIN | POLLHUP | POLLERR)) {
                n = read(fd, out, sizeof out);
                if (n <= 0)
                    break;
                if (acc != NULL && acc_len + (size_t) n < acc_cap) {
                    memcpy(acc + acc_len, out, (size_t) n);
                    acc_len += (size_t) n;
                    acc[acc_len] = 0;
                } else {
                    emit_flush(out, n);
                }
            }
            if (pf[1].revents & (POLLIN | POLLHUP)) {
                n = read(0, out, sizeof out);
                if (n <= 0) {
                    shutdown(fd, SHUT_WR);
                    pf[1].events = 0;
                    continue;
                }
                if (write(fd, out, (size_t) n) < 0)
                    break;
            }
        }
        close(fd);
        if (acc != NULL) {
            /* search the tail unconditionally: `exit 7` produces almost no output,
             * and a length threshold here used to skip the marker entirely */
            char *mark = strstr(acc + (acc_len > 64 ? acc_len - 64 : 0), "@SUD_EXIT=");

            if (mark != NULL) {
                exit_code = atoi(mark + 10);
                acc_len = (size_t) (mark - acc);   /* drop the trailer from the length too */
                acc[acc_len] = 0;
                while (acc_len > 0 && (acc[acc_len - 1] == '\n' || acc[acc_len - 1] == '\r'))
                    acc[--acc_len] = 0;
            }
            if (acc_len > 0)
                write(1, acc, acc_len);
            write(1, "\n", 1);
            free(acc);
        } else {
            exit_code = emit_close();
        }
        return exit_code;
    }
}
