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

/* Channel kinds, so the caller knows which transports carry an attributable
 * identity.  On the unix sockets the daemon reads SO_PEERCRED and our uid is
 * kernel-given; on TCP the daemon's /proc/net/tcp view cannot see our row at
 * all (different network namespace view), so the request needs either a TOK=
 * (which only relayd appends) or the peer hand-off below. */
#define CH_UNIX 1
#define CH_TCP 2

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

static int open_channel(int *kind)
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
            if (connect(fd, (struct sockaddr *) &a, sizeof(a.sun_family) + 1 + 3) == 0) {
                if (kind != NULL)
                    *kind = CH_UNIX;
                return fd;
            }
        } else {
            strncpy(a.sun_path, files[i - 1], sizeof a.sun_path - 1);
            if (connect(fd, (struct sockaddr *) &a, sizeof a) == 0) {
                if (kind != NULL)
                    *kind = CH_UNIX;
                return fd;
            }
        }
        close(fd);
    }
    fd = tcp_channel();
    if (fd >= 0) {
        if (kind != NULL)
            *kind = CH_TCP;
        return fd;
    }
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

/* ---- V2 channel --------------------------------------------------------
 * The daemon used to hand us one merged byte stream (stdout and stderr on the
 * same socket), which libsu rejects: its ShellImpl reads both streams through
 * separate threads and only finishes a job when BOTH have seen the job's UUID
 * marker (`echo <uuid>; echo <uuid> >&2`).  With stderr merged into stdout the
 * stderr reader never sees anything, the shell check times out, and the app
 * reports "no root" even though the command ran.
 *
 * So we ask for `XSU2`/`XSU2B`, which makes the daemon answer with frames:
 *   [type][len:4 BE][payload], type 1=stdout 2=stderr 3=exit 4=ready 5=retry
 * The verb deliberately does not start with "SU", so a daemon that does not
 * know it (an older build, or route 8's shell responder) refuses immediately
 * with `ERR unknown request` instead of running anything -- that is what makes
 * the V1 fallback in main() safe.  Type 5 means "I could not attribute you on
 * this channel": retry over the peer hand-off, which carries SCM_CREDENTIALS.
 */
#define F_OUT   1
#define F_ERR   2
#define F_EXIT  3
#define F_READY 4
#define F_RETRY 5

static int read_exact(int fd, void *buf, size_t n)
{
    unsigned char *p = buf;

    while (n > 0) {
        ssize_t r = read(fd, p, n);

        if (r <= 0)
            return -1;
        p += r;
        n -= (size_t) r;
    }
    return 0;
}

/* Returns the command's exit code; *retry is set when the daemon asked for the
 * peer hand-off.  Output is streamed: there is no "@SUD_EXIT" trailer to strip
 * here, the exit status travels in its own frame. */
static int relay_v2(int fd, int interactive, int *retry)
{
    struct pollfd pf[2];
    char buf[4096];
    unsigned char h[5];
    int code = 0;

    *retry = 0;
    pf[0].fd = fd;
    pf[0].events = POLLIN;
    pf[1].fd = 0;
    pf[1].events = interactive ? POLLIN : 0;
    for (;;) {
        int type;
        long len;

        if (poll(pf, 2, -1) < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        if (pf[1].revents & (POLLIN | POLLHUP)) {
            int n = read(0, buf, sizeof buf);

            if (n <= 0) {
                shutdown(fd, SHUT_WR);
                pf[1].events = 0;
            } else if (write(fd, buf, (size_t) n) < 0) {
                break;
            }
        }
        if (!(pf[0].revents & (POLLIN | POLLHUP | POLLERR)))
            continue;
        if (read_exact(fd, h, 5) != 0)
            break;
        type = h[0];
        len = ((long) h[1] << 24) | ((long) h[2] << 16) | ((long) h[3] << 8) | h[4];
        if (len < 0 || len > (1 << 22))
            break;
        if (type == F_RETRY) {
            *retry = 1;
            return 0;
        }
        while (len > 0) {
            int take = len > (long) sizeof buf ? (int) sizeof buf : (int) len;

            if (read_exact(fd, buf, (size_t) take) != 0)
                return code;
            if (type == F_OUT) {
                if (write(1, buf, (size_t) take) < 0)
                    ;
            } else if (type == F_ERR) {
                if (write(2, buf, (size_t) take) < 0)
                    ;
            } else if (type == F_EXIT) {
                char t[32];
                int k = take < 31 ? take : 31;

                memcpy(t, buf, (size_t) k);
                t[k] = 0;
                code = atoi(t);
            }
            len -= take;
        }
    }
    return code;
}

/* Root apps probe the client before they run anything: `su -v` / `su -V` are
 * Magisk's version queries, and a client that answers them by opening an
 * interactive shell makes the probe time out and the app report "no root".
 * The strings below are the ones libsu/Magisk-aware detectors look for. */
#define MAGISK_VER_STR "MAGISKSU"
#define MAGISK_VER_CODE "30700"

static void usage(FILE *o)
{
    fprintf(o,
        "Usage: su [options] [--] [user [command [args...]]]\n"
        "\n"
        "Options:\n"
        "  -c, --command COMMAND    pass COMMAND to the login shell\n"
        "  -s, --shell SHELL        use SHELL instead of /system/bin/sh\n"
        "  -u, --user USER          run as USER (name or uid; default root)\n"
        "  -l, --login              login shell (accepted, no-op here)\n"
        "  -p, --preserve-environment  keep the caller environment (default)\n"
        "  -m, --mount-master       run in the global mount namespace (accepted)\n"
        "  -v, --version            print the version string\n"
        "  -V                       print the numeric version code\n"
        "  -h, --help               print this help\n"
        "\n"
        "Exit status of COMMAND is returned; 127 means the root channel is down.\n");
}

/* Encode a request payload so newlines and NUL-free binary-ish text survive the
 * line-based SU protocol.  Commands with real newlines used to be truncated at
 * the first one, which silently turned multi-line backup scripts into a single
 * bogus line. */
static void b64enc(const char *in, char *out)
{
    static const char T[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const unsigned char *p = (const unsigned char *) in;
    size_t n = strlen(in), i, o = 0;

    for (i = 0; i + 2 < n; i += 3) {
        unsigned v = (p[i] << 16) | (p[i + 1] << 8) | p[i + 2];
        out[o++] = T[(v >> 18) & 63];
        out[o++] = T[(v >> 12) & 63];
        out[o++] = T[(v >> 6) & 63];
        out[o++] = T[v & 63];
    }
    if (i < n) {
        unsigned v = p[i] << 16;
        if (i + 1 < n) v |= p[i + 1] << 8;
        out[o++] = T[(v >> 18) & 63];
        out[o++] = T[(v >> 12) & 63];
        out[o++] = i + 1 < n ? T[(v >> 6) & 63] : '=';
        out[o++] = '=';
    }
    out[o] = 0;
}

/* Append one argv element to a command string, single-quoting it so the shell
 * receives it verbatim. */
static void append_arg(char *dst, size_t cap, const char *a)
{
    size_t l = strlen(dst), k;

    if (l >= cap - 1)
        return;
    if (l)
        dst[l++] = ' ';
    dst[l++] = '\'';
    for (k = 0; a[k] && l < cap - 3; k++) {
        if (a[k] == '\'') {
            if (l < cap - 5) {
                dst[l++] = '\'';
                dst[l++] = '\\';
                dst[l++] = '\'';
                dst[l++] = '\'';
            }
        } else {
            dst[l++] = a[k];
        }
    }
    if (l < cap - 1)
        dst[l++] = '\'';
    dst[l] = 0;
}

int main(int argc, char **argv)
{
    char req[12288], req1[12288], out[8192], cmdbuf[6144], b64[9216];
    struct pollfd pf[2];
    int fd, uid = 0, i, interactive = 0, chan = 0, uid_set = 0, cmd_set = 0;
    const char *cmd = NULL;
    char *pos[32];
    int npos = 0;

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
        const char *a = argv[i];

        if (!strcmp(a, "-c") || !strcmp(a, "--command")) {
            if (i + 1 < argc) {
                cmd = argv[++i];
                cmd_set = 1;
            }
        } else if (!strncmp(a, "--command=", 10)) {
            cmd = a + 10;
            cmd_set = 1;
        } else if (!strcmp(a, "-s") || !strcmp(a, "--shell") ||
                   !strcmp(a, "-u") || !strcmp(a, "--user") ||
                   !strcmp(a, "-g") || !strcmp(a, "--group") ||
                   !strcmp(a, "-G") || !strcmp(a, "--supp-group")) {
            const char *v = i + 1 < argc ? argv[++i] : NULL;

            if (v != NULL && (!strcmp(a, "-u") || !strcmp(a, "--user"))) {
                if (!strcmp(v, "root"))
                    uid = 0, uid_set = 1;
                else if (!strcmp(v, "shell"))
                    uid = 2000, uid_set = 1;
                else if (v[0] >= '0' && v[0] <= '9')
                    uid = atoi(v), uid_set = 1;
            }
        } else if (!strcmp(a, "-v") || !strcmp(a, "--version")) {
            printf("%s\n", MAGISK_VER_STR);
            return 0;
        } else if (!strcmp(a, "-V")) {
            printf("%s\n", MAGISK_VER_CODE);
            return 0;
        } else if (!strcmp(a, "--help") || !strcmp(a, "-h")) {
            usage(stdout);
            return 0;
        } else if (!strcmp(a, "-l") || !strcmp(a, "--login") ||
                   !strcmp(a, "-p") || !strcmp(a, "--preserve-environment") ||
                   !strcmp(a, "-m") || !strcmp(a, "-mm") || !strcmp(a, "-M") ||
                   !strcmp(a, "--mount-master")) {
            /* accepted for compatibility; this client already keeps the caller's
             * environment and there is only one mount namespace that matters */
        } else if (!strcmp(a, "--")) {
            for (i++; i < argc && npos < 32; i++)
                pos[npos++] = argv[i];
            break;
        } else if (!strcmp(a, "-")) {
            interactive = 1;
        } else if (a[0] == '-' && a[1] != 0) {
            /* unknown option: keep old behaviour (ignore) rather than turning a
             * working root call into a usage error */
        } else if (npos < 32) {
            pos[npos++] = argv[i];
        }
    }

    /* Positional shapes root apps actually use:
     *   su 0 id            -> uid 0, command "id"
     *   su root id -u      -> uid 0, command "id -u"
     *   su id              -> command "id" as root
     *   su -c "cmd" args   -> command "cmd" with args appended */
    cmdbuf[0] = 0;
    if (cmd != NULL) {
        snprintf(cmdbuf, sizeof cmdbuf, "%s", cmd);
        cmd = NULL;
    }
    if (npos > 0) {
        int first_is_user = 0;

        if (!uid_set) {
            const char *p0 = pos[0];

            if (!strcmp(p0, "root"))
                uid = 0, first_is_user = 1;
            else if (!strcmp(p0, "shell"))
                uid = 2000, first_is_user = 1;
            else if (p0[0] >= '0' && p0[0] <= '9') {
                char *end = NULL;
                long v = strtol(p0, &end, 10);

                if (end != NULL && *end == 0)
                    uid = (int) v, first_is_user = 1;
            }
        }
        for (i = first_is_user ? 1 : 0; i < npos; i++) {
            append_arg(cmdbuf, sizeof cmdbuf, pos[i]);
            cmd_set = 1;
        }
    }
    if (cmd_set)
        cmd = cmdbuf;
    else
        cmd = NULL;
    if (cmd == NULL)
        interactive = 1;

    /* Two shapes for the same request.  `req` asks for the separated V2
     * channels; `req1` is the original line, kept for daemons that predate V2
     * (route 8's shell responder among them).  See the V2 comment above. */
    if (cmd != NULL && strchr(cmd, '\n') == NULL && strlen(cmd) < 3800) {
        snprintf(req, sizeof req, "XSU2 %d %s\n", uid, cmd);
        snprintf(req1, sizeof req1, "SU %d %s\n", uid, cmd);
    } else if (cmd != NULL) {
        b64enc(cmd, b64);
        snprintf(req, sizeof req, "XSU2B %d %s\n", uid, b64);
        snprintf(req1, sizeof req1, "SUX %d %s\n", uid, b64);
    } else {
        snprintf(req, sizeof req, "XSU2 %d -\n", uid);
        snprintf(req1, sizeof req1, "SU %d -\n", uid);
    }

    /* @sud first: when the manager's relay is up (route 7 and route 8 both run it) the
     * connection is immediate.  Peer hand-off is only for a route where the daemon itself
     * cannot bind a stream listener -- there the connect fails at once and we fall back
     * below.  This order matters because the peer wait used to run for its full timeout on
     * every call even when @sud was answering (measured 2026-10-23: 8 s per su, which is
     * what pushed Snub's foreground services past their 5 s startForeground deadline). */
    int req_sent = 0;

    fd = open_channel(&chan);
    if (fd < 0) {
        fd = peer_channel(req, 1500);
        if (fd >= 0)
            req_sent = 1;
    }
    if (fd < 0)
        return 127;
    if (!req_sent && write(fd, req, strlen(req)) < 0) {
        fprintf(stderr, "su: write request: %s\n", strerror(errno));
        return 127;
    }
    /* Does this daemon speak V2?  A daemon that knows XSU2 sends FRAME_READY
     * before it forks, so this wait cannot mistake a slow command for an old
     * daemon.  One that does not know the verb answers `ERR unknown request`
     * immediately (it does not start with "SU", so nothing runs) and we resend
     * in the original shape.  Resending is only safe precisely because a V2
     * daemon has already answered READY by then. */
    {
        int v2 = 0;
        struct pollfd p;
        unsigned char b = 0;

        p.fd = fd;
        p.events = POLLIN;
        if (poll(&p, 1, 5000) > 0 && recv(fd, &b, 1, MSG_PEEK) == 1 &&
            b >= 1 && b <= 5)
            v2 = 1;
        if (v2) {
            int retry = 0;
            int code = relay_v2(fd, interactive, &retry);

            close(fd);
            if (retry) {
                fd = peer_channel(req, 2000);
                if (fd < 0)
                    return 127;
                code = relay_v2(fd, interactive, &retry);
                close(fd);
                if (retry) {
                    fprintf(stderr, "su: daemon cannot attribute caller\n");
                    return 127;
                }
            }
            return code;
        }
        /* old daemon: redo the request in the shape it understands */
        close(fd);
        req_sent = 0;
        fd = open_channel(&chan);
        if (fd < 0) {
            fd = peer_channel(req1, 1500);
            if (fd >= 0)
                req_sent = 1;
        }
        if (fd < 0)
            return 127;
        if (!req_sent && write(fd, req1, strlen(req1)) < 0) {
            fprintf(stderr, "su: write request: %s\n", strerror(errno));
            return 127;
        }
    }
    /* A TCP caller has no attributable identity on the daemon's side: its socket
     * row is invisible there and only relayd callers carry a TOK.  When the
     * daemon answers with its attribution error, redo the request over the peer
     * hand-off, whose SCM_CREDENTIALS carry our uid straight from the kernel.
     * The peek never blocks a working call: the daemon answers an unattributable
     * request at once, so a short receive timeout covers the whole error path,
     * and a normal run's first output simply arrives later than the timeout --
     * nothing is consumed (MSG_PEEK), so the relay loop below reads it as usual. */
    if (!req_sent && chan == CH_TCP) {
        char probe[80];
        struct timeval tv;
        ssize_t pn;

        tv.tv_sec = 0;
        tv.tv_usec = 500 * 1000;
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        pn = recv(fd, probe, sizeof probe - 1, MSG_PEEK);
        tv.tv_usec = 0;
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        if (pn > 0) {
            probe[pn] = 0;
            if (strncmp(probe, "ERR cannot attribute caller", 27) == 0) {
                close(fd);
                fd = peer_channel(req1, 2000);
                if (fd < 0)
                    return 127;
                req_sent = 1;
            }
        }
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
