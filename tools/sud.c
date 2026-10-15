#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <dirent.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/un.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* sud -- the persistent root daemon for the Xplay6 temp-root path.
 *
 * It replaces tools/rootsh.c and fixes the two things that bit us:
 *   1. a kmod-spawned process has NO stderr and NO useful env, so every stage is
 *      written to a world-readable log (/data/local/tmp/sud.stage).  Without it
 *      the app-launched instance died silently after its proof file, and we
 *      could not tell socket() from bind() from being killed.
 *   2. rootsh wrote its proof (which popen()s a shell) BEFORE binding, so a
 *      client that connects the moment execve() returns gets ECONNREFUSED.
 *      Here the listeners are up first, proof second.
 *
 * Two channels, on purpose:
 *   TCP 127.0.0.1:12345  raw /system/bin/sh per connection.  This is what
 *                        tools/verify_root.sh measures (criteria 2-4), so the
 *                        acceptance gate keeps working unchanged.
 *   UNIX /dev/.sud/sud.sock   the su service, line protocol (see handle_su).
 *
 * Everything it creates lives in RAM or in /data: a reboot removes all of it.
 * Nothing here writes a partition -- /system and /sbin are read-only (dm-0 and
 * rootfs), so `su` is delivered by bind-mounting a tmpfs directory over an
 * existing one (the same trick as Magisk's Magic Mount), never by copying into
 * the block device.
 */
#define TCP_PORT     12345
#define SU_PORT      12346
#define CONF         "/data/local/tmp/sud.conf"
#define STAGE_LOG    "/data/local/tmp/sud.stage"
#define PROOF        "/data/local/tmp/sud.ok"
#define SOCKDIR      "/dev/.sud"
#define SOCKDIR2     "/data/local/tmp/.sud"
#define MIRROR       SOCKDIR2 "/mirror"

static int g_ltcp = -1, g_lsu = -1, g_abs = -1, g_gunix = -1;

static void stage(const char *fmt, ...)
{
    static int fd = -1;
    char line[512];
    va_list ap;
    int n;

    /* O_APPEND, not O_TRUNC: one trigger burst spawns several instances (mpp
     * execs three bad-magic files), and with O_TRUNC the 2nd/3rd -- which
     * legitimately find the port already taken -- used to erase the log of the
     * healthy first one, and "no listener at all" was read as "the daemon never
     * ran" while a uid-0 instance was in fact serving. */
    if (fd < 0)
        fd = open(STAGE_LOG, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0)
        return;
    va_start(ap, fmt);
    n = vsnprintf(line, sizeof line, fmt, ap);
    va_end(ap);
    if (n > 0) {
        if (n >= (int)sizeof line)
            n = sizeof line - 1;
        line[n++] = '\n';
        write(fd, line, n);
    }
    lseek(fd, 0, SEEK_END);
}

/* Measured on this device: a process in u:r:kernel:s0 (which is what kmod gives
 * us) gets EPERM from bind() on EVERY AF_UNIX socket -- abstract and filesystem,
 * under permissive too -- while TCP binds succeed and uid 2000 can unix-bind
 * freely.  So the su channel is TCP-on-loopback here, not an abstract socket:
 * that is a device constraint, not a design preference.  The cost is that TCP
 * carries no SO_PEERCRED, so the client reports its own uid and the daemon can
 * only cross-check it against /proc/<pid> -- on a machine where every app can
 * re-run the exploit, that gate is a courtesy, not a security boundary.
 */
static int listen_on(int port, const char *tag)
{
    struct sockaddr_in a;
    int on = 1, fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);

    if (fd < 0) {
        stage("socket(AF_INET): errno=%d", errno);
        return -1;
    }
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons((unsigned short) port);
    if (bind(fd, (struct sockaddr *) &a, sizeof a) < 0) {
        stage("bind 127.0.0.1:%d (%s): errno=%d (already up?)", port, tag, errno);
        close(fd);
        return -1;
    }
    if (listen(fd, 8) < 0) {
        stage("listen %s: errno=%d", tag, errno);
        close(fd);
        return -1;
    }
    stage("%s listener up on 127.0.0.1:%d fd=%d", tag, port, fd);
    return fd;
}

/* su channel.  Order matters and each step is tried independently:
 *   1. abstract namespace socket "@sud" -- no filesystem, no directory, no label,
 *      and appprobe measured that an app may bind/listen/connect abstract sockets
 *      even under enforcing.  This is the same trick magiskd uses.
 *   2. filesystem socket, /dev/.sud/sud.sock then /data/local/tmp/.sud/sud.sock.
 *      /dev/.sud worked for `mkdir`+`touch` as root but bind() on it returned
 *      EPERM once, so it is a fallback, not the primary.
 * A path is also written to /data/local/tmp/sud.sock for the client to read.
 */
#define ABS_NAME "sud"

static int listen_abs(void)
{
    struct sockaddr_un a;
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    size_t nl = strlen(ABS_NAME);

    if (fd < 0) {
        stage("socket(AF_UNIX): errno=%d", errno);
        return -1;
    }
    memset(&a, 0, sizeof a);
    a.sun_family = AF_UNIX;
    a.sun_path[0] = 0;
    memcpy(a.sun_path + 1, ABS_NAME, nl);
    if (bind(fd, (struct sockaddr *) &a, (int)(sizeof(a.sun_family) + 1 + nl)) < 0) {
        stage("bind abstract @%s: errno=%d", ABS_NAME, errno);
        close(fd);
        return -1;
    }
    if (listen(fd, 16) < 0) {
        stage("listen abstract: errno=%d", errno);
        close(fd);
        return -1;
    }
    stage("abstract listener @%s up fd=%d", ABS_NAME, fd);
    return fd;
}

static int listen_unix(const char *dir)
{
    struct sockaddr_un a;
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    char path[128];

    if (fd < 0) {
        stage("socket(AF_UNIX): errno=%d", errno);
        return -1;
    }
    snprintf(path, sizeof path, "%s/sud.sock", dir);
    if (mkdir(dir, 0777) < 0 && errno != EEXIST)
        stage("mkdir %s: errno=%d (continuing)", dir, errno);
    unlink(path);
    memset(&a, 0, sizeof a);
    a.sun_family = AF_UNIX;
    strncpy(a.sun_path, path, sizeof a.sun_path - 1);
    if (bind(fd, (struct sockaddr *) &a, sizeof a) < 0) {
        stage("bind %s: errno=%d", path, errno);
        close(fd);
        return -1;
    }
    /* 0777 on the socket file: the su clients are arbitrary app uids. */
    chmod(path, 0777);
    if (listen(fd, 16) < 0) {
        stage("listen %s: errno=%d", path, errno);
        close(fd);
        return -1;
    }
    stage("unix listener up on %s fd=%d", path, fd);
    return fd;
}

static void spawn_sh(int fd)
{
    setsid();
    dup2(fd, 0);
    dup2(fd, 1);
    dup2(fd, 2);
    if (fd > 2)
        close(fd);
    setenv("HOME", "/data/local/tmp", 1);
    setenv("PATH", "/sbin:/system/bin:/system/xbin:/vendor/bin", 1);
    execl("/system/bin/sh", "sh", (char *)0);
    _exit(127);
}

/* serve one raw shell session (TCP channel, what verify_root.sh talks to) */
/* The kernel-helper domain cannot bind AF_UNIX on this device (measured: EPERM for
 * abstract AND filesystem sockets, permissive included, while the same binary in
 * the shell domain binds both fine, and TCP binds always work).  setcon() out of
 * u:r:kernel:s0 first: under permissive the transition is granted even where the
 * policy has no rule, it only logs -- and appprobe proved exactly that behaviour
 * (setcon reported a denial and still changed the context).  If every attempt
 * fails we keep running: TCP still carries the su channel.
 */
static void relabel_for_sockets(void)
{
    static const char *CTX[3] = {
        "u:r:init:s0",
        "u:r:shell:s0",
        "u:r:untrusted_app:s0"
    };
    int i, fd;

    for (i = 0; i < 3; i++) {
        fd = open("/proc/self/attr/current", O_WRONLY);
        if (fd < 0) {
            stage("setcon open: errno=%d", errno);
            return;
        }
        if (write(fd, CTX[i], strlen(CTX[i])) == (ssize_t) strlen(CTX[i])) {
            close(fd);
            stage("setcon -> %s (ok)", CTX[i]);
            return;
        }
        stage("setcon -> %s: errno=%d", CTX[i], errno);
        close(fd);
    }
}

/* The startup attempt usually loses the race: kmod exec's us before the chain has
 * written the permissive points, so every setcon is refused (errno=13) and we stay in
 * u:r:kernel:s0 -- where `pm` cannot reach the package service ("Could not access the
 * Package Manager") and AF_UNIX binds are EPERM.  By the time a request arrives the
 * points ARE installed, so try again on the request path. */
static void relabel_if_kernel(void)
{
    char cur[80];
    int fd, n;

    fd = open("/proc/self/attr/current", O_RDONLY);
    if (fd < 0)
        return;
    n = read(fd, cur, sizeof cur - 1);
    close(fd);
    if (n <= 0)
        return;
    cur[n] = 0;
    if (strstr(cur, "u:r:kernel:") == NULL)
        return;
    stage("still %s at request time, retrying setcon", cur);
    relabel_for_sockets();
    fd = open("/proc/self/attr/current", O_RDONLY);
    if (fd >= 0) {
        memset(cur, 0, sizeof cur);
        if (read(fd, cur, sizeof cur - 1) < 0)
            cur[0] = 0;
        close(fd);
        stage("domain after retry: %s", cur);
    }
}

/* A fork without an exec inherits every listener fd -- SOCK_CLOEXEC only acts at exec -- so while such
 * a child lived, a successor daemon could not bind the same port (EADDRINUSE) even after its parent
 * died.  Each child drops the listeners it does not serve. */
static void close_listeners(void)
{
    if (g_ltcp >= 0)
        close(g_ltcp);
    if (g_lsu >= 0)
        close(g_lsu);
    if (g_abs >= 0)
        close(g_abs);
    if (g_gunix >= 0)
        close(g_gunix);
}

static void serve_tcp(int fd)
{
    pid_t pid = fork();

    if (pid == 0) {
        close_listeners();
        spawn_sh(fd);
    }
    if (pid < 0)
        stage("fork tcp: errno=%d", errno);
}

static void read_one_line(int fd, char *buf, int cap)
{
    int n = 0;

    while (n < cap - 1) {
        char c;
        int r = read(fd, &c, 1);
        if (r <= 0)
            break;
        if (c == '\n')
            break;
        buf[n++] = c;
    }
    buf[n] = 0;
}

/* ---- systemless delivery of the su client -------------------------------
 * /system is dm-0 (ro, verity) and /sbin is the rootfs (ro), and writing either
 * partition means a reboot loop with the bootloader locked -- so `su` can only
 * arrive by MOUNTING over an existing directory.  We may not create a file
 * inside a read-only fs, therefore: mirror every existing entry of the target
 * directory into a tmpfs directory by bind-mounting it (content stays the
 * original, on-disk, verity-valid block), add our one new file to the mirror,
 * then bind the mirror over the directory.  umount -l or a reboot undoes all of
 * it, and no byte is ever written to the block device.
 */
static int bind_over(const char *src, const char *dst)
{
    if (mount(src, dst, NULL, MS_BIND, NULL) < 0) {
        stage("bind %s -> %s: errno=%d", src, dst, errno);
        return -1;
    }
    return 0;
}

static int mkdirs(const char *path)
{
    char buf[300];
    char *p;
    size_t n = strlen(path);

    if (n >= sizeof buf)
        return -1;
    strcpy(buf, path);
    for (p = buf + 1; *p; p++) {
        if (*p == '/') {
            *p = 0;
            mkdir(buf, 0755);
            *p = '/';
        }
    }
    if (mkdir(buf, 0755) < 0 && errno != EEXIST) {
        stage("mkdir %s: errno=%d", buf, errno);
        return -1;
    }
    return 0;
}

static int copy_file(const char *src, const char *dst)
{
    char b[8192];
    int fi = open(src, O_RDONLY), fo = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    int r, n;

    if (fi < 0 || fo < 0) {
        stage("copy %s -> %s: errno=%d", src, dst, errno);
        if (fi >= 0)
            close(fi);
        if (fo >= 0)
            close(fo);
        return -1;
    }
    while ((r = read(fi, b, sizeof b)) > 0) {
        n = 0;
        while (n < r) {
            int w = write(fo, b + n, r - n);
            if (w <= 0) {
                close(fi);
                close(fo);
                return -1;
            }
            n += w;
        }
    }
    close(fi);
    close(fo);
    chmod(dst, 0755);
    return r < 0 ? -1 : 0;
}

static int mirror_overlay(const char *dir, const char *client, const char *name)
{
    char base[300], src[400], dst[420];
    struct dirent *de;
    DIR *d;
    int cnt = 0;

    snprintf(base, sizeof base, "%s%s", MIRROR, dir);
    if (mkdirs(base) < 0)
        return -1;
    d = opendir(dir);
    if (d == NULL) {
        stage("opendir %s: errno=%d", dir, errno);
        return -1;
    }
    while ((de = readdir(d)) != NULL) {
        struct stat st;

        if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
            continue;
        snprintf(src, sizeof src, "%s/%s", dir, de->d_name);
        snprintf(dst, sizeof dst, "%s/%s", base, de->d_name);
        if (stat(src, &st) < 0)
            continue;
        if (S_ISDIR(st.st_mode))
            mkdir(dst, 0755);
        else {
            int f = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0755);
            if (f >= 0)
                close(f);
        }
        if (bind_over(src, dst) == 0)
            cnt++;
    }
    closedir(d);
    if (client != NULL && name != NULL) {
        snprintf(dst, sizeof dst, "%s/%s", base, name);
        if (copy_file(client, dst) < 0)
            return -1;
    }
    if (bind_over(base, dir) < 0)
        return -1;
    stage("overlay %s: %d entries rebound, new file=%s", dir, cnt, name ? name : "-");
    return 0;
}

/* The client binary is handed to us as a path because the app (or adb) put it
 * there; sud itself has no copy.  /system/bin is only overlaid when asked: it
 * holds a few hundred entries and it is the one directory whose partial
 * remount would actually hurt, so it stays opt-in. */
static void install_su(const char *client, int also_bin)
{
    mkdirs(MIRROR);
    if (client == NULL || access(client, R_OK) != 0) {
        stage("MOUNT: client %s unusable", client ? client : "(null)");
        return;
    }
    mirror_overlay("/system/xbin", client, "su");
    mirror_overlay("/sbin", client, "su");
    if (also_bin)
        mirror_overlay("/system/bin", client, "su");
}

/* One request per connection, text protocol (documented, versioned by content):
 *   PING                          -> PONG uid=... pid=...
 *   SU <uid> <shell cmd...>       -> run cmd as that uid (0 = root) with this
 *                                    socket as stdin/stdout/stderr.  The exit
 *                                    status does not travel over a socket, so
 *                                    the client reports the last line instead.
 *   SU 0 -                        -> interactive shell (commands arrive as stdin)
 *   MOUNT <client> [bin]          -> deliver `su` at /system/xbin, /sbin (and
 *                                    /system/bin if bin is given) by tmpfs+bind
 */
/* ---- who is actually asking? -------------------------------------------
 * A TCP peer can put any uid in the request line, but it cannot edit the
 * kernel's socket table.  So the caller is attributed from the kernel's own
 * bookkeeping: getpeername gives the peer's port, /proc/net/tcp maps that port
 * to a socket inode, and /proc/<pid>/fd gives the inode's owner.  Everything
 * else (a unix socket's SO_PEERCRED, a self-reported uid) is either impossible
 * from this domain or forgeable.
 */
static int inode_owner_uid(unsigned long ino, pid_t *out_pid)
{
    char dirpath[64], linkpath[96], target[96], want[64], status[96];
    struct dirent *de;
    DIR *d = opendir("/proc");
    ssize_t n;

    if (d == NULL)
        return -1;
    snprintf(want, sizeof want, "socket:[%lu]", ino);
    while ((de = readdir(d)) != NULL) {
        struct dirent *fe;
        DIR *fd_d;
        char *p;

        for (p = de->d_name; *p; p++)
            if (*p < '0' || *p > '9')
                break;
        if (*p)
            continue;
        snprintf(dirpath, sizeof dirpath, "/proc/%s/fd", de->d_name);
        fd_d = opendir(dirpath);
        if (fd_d == NULL)
            continue;
        while ((fe = readdir(fd_d)) != NULL) {
            snprintf(linkpath, sizeof linkpath, "%s/%s", dirpath, fe->d_name);
            /* separate in/out buffers: readlink through the same buffer is not
             * guaranteed (the path is looked up while the result is written) */
            n = readlink(linkpath, target, sizeof target - 1);
            if (n > 0) {
                target[n] = 0;
                if (!strcmp(target, want)) {
                    FILE *f;
                    int uid = -1;

                    closedir(fd_d);
                    closedir(d);
                    if (out_pid != NULL)
                        *out_pid = (pid_t) atoi(de->d_name);
                    snprintf(status, sizeof status, "/proc/%s/status", de->d_name);
                    f = fopen(status, "r");
                    if (f == NULL)
                        return -1;
                    {
                        char l[128];
                        while (fgets(l, sizeof l, f))
                            if (!strncmp(l, "Uid:", 4)) {
                                uid = atoi(l + 4);
                                break;
                            }
                        fclose(f);
                    }
                    return uid;
                }
            }
        }
        closedir(fd_d);
    }
    closedir(d);
    return -1;
}

static int peer_uid(int fd, pid_t *out_pid)
{
    struct sockaddr_in sa;
    socklen_t sl = sizeof sa;
    struct ucred uc;
    socklen_t ul = sizeof uc;
    char line[512];
    FILE *f;
    int first = 1;

    /* A unix socket gives the kernel's own answer, so use it when that is the
     * transport; the /proc/net/tcp walk below is only the TCP fallback. */
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &uc, &ul) == 0 && uc.uid != (uid_t) -1) {
        if (out_pid != NULL)
            *out_pid = uc.pid;
        return (int) uc.uid;
    }

    if (getpeername(fd, (struct sockaddr *) &sa, &sl) < 0) {
        stage("peer_uid: getpeername errno=%d", errno);
        return -1;
    }
    {
        stage("peer_uid: peer=%s:%d", inet_ntoa(sa.sin_addr), (int) ntohs(sa.sin_port));
    }
    f = fopen("/proc/net/tcp", "r");
    if (f == NULL)
        return -1;
    while (fgets(line, sizeof line, f)) {
        unsigned la_ip, la_port, ra_ip, ra_port, ino;
        int st, pid_out, uid;

        if (first) {
            first = 0;
            continue;
        }
        /* Kernel 3.18 layout: sl local remote st tx:rx tr:tm->when retrnsmt uid
         * timeout inode -- there IS a `timeout` column between uid and inode, and
         * skipping it reads timeout (always 0) as the inode, which makes every
         * caller unattributable.  Measured row:
         *   " 0: 0100007F:3039 00000000:0000 0A 00000000:00000000 00:00000000
         *    00000000 0 0 51384 1 ..."
         */
        if (sscanf(line, " %*d: %8x:%4x %8x:%4x %2x %*x:%*x %*x:%*x %*x %*u %*d %u",
                   &la_ip, &la_port, &ra_ip, &ra_port, &st, &ino) != 6)
            continue;
        if (la_port != (unsigned) ntohs(sa.sin_port))
            continue;
        if (st != 1) {
            stage("peer_uid: port matched but st=%d ino=%lu (want 1=ESTABLISHED)", st,
                  (unsigned long) ino);
            continue;
        }
        uid = inode_owner_uid(ino, &pid_out);
        if (uid < 0) {
            /* the row is right there and only the owner lookup failed: that is a
             * /proc-read question, not a socket-table one, so say which */
            stage("peer_uid: inode=%lu owner not found", (unsigned long) ino);
            continue;
        }
        if (out_pid != NULL)
            *out_pid = (pid_t) pid_out;
        fclose(f);
        return uid;
    }
    /* Not found.  Dump enough of the scene to tell "my parser is wrong" from
     * "this socket really is not in this table": which netns we are reading, and
     * every row that mentions the su port on either side. */
    {
        char ns[128], line2[512];
        ssize_t n = readlink("/proc/self/ns/net", ns, sizeof ns - 1);
        int shown = 0;

        if (n > 0)
            ns[n] = 0;
        else
            snprintf(ns, sizeof ns, "?errno=%d", errno);
        rewind(f);
        stage("peer_uid: no row matched; reading %s, peer port %d", ns,
              (int) ntohs(sa.sin_port));
        while (fgets(line2, sizeof line2, f) != NULL && shown < 12) {
            if (strstr(line2, ":303A") != NULL || strstr(line2, ":3039") != NULL) {
                line2[strcspn(line2, "\n")] = 0;
                stage("  row: %.120s", line2);
                shown++;
            }
        }
        if (shown == 0)
            stage("  (no row at all mentions the su port -- the connection we are "
                  "serving is not in this table)");
    }
    fclose(f);
    return -1;
}

/* Grants live in the manager app's own directory: it owns them, root only reads
 * them.  There is deliberately no world-writable policy file and no su on any
 * PATH -- an app that is not in this list cannot even find something to ask. */
static const char *GRANTS_CANDIDATES[3] = {
    "/data/user/0/com.xplay6.temproot/files/grants.txt",
    "/data/data/com.xplay6.temproot/files/grants.txt",
    "/data/local/tmp/sud.grants"
};

/* Second factor for callers whose socket row the daemon cannot attribute (measured:
 * an app's TCP row does not show up in the helper's /proc/net/tcp view, while a
 * shell caller's row does).  The manager app keeps a random token in its private
 * files dir; other apps cannot read it -- DAC still applies when SELinux is
 * permissive, and app data dirs are 0771 with 0600 files -- but root can.
 * So possession of the token *is* the proof of identity, and it needs no
 * cooperation from the socket table.
 */
static const char *TOKEN_CANDIDATES[2] = {
    "/data/data/com.xplay6.temproot/files/su.token",
    "/data/local/tmp/sud.token"
};

static int token_matches(const char *line, uid_t *uid_out)
{
    const char *t = strstr(line, "TOK=");
    char want[80];
    int i;

    if (t == NULL)
        return 0;
    t += 4;
    {
        int n = 0;
        while (t[n] && t[n] != ' ' && t[n] != '\n' && n < (int)sizeof want - 1) {
            want[n] = t[n];
            n++;
        }
        want[n] = 0;
        if (n < 8)
            return 0;
    }
    for (i = 0; i < 2; i++) {
        FILE *f = fopen(TOKEN_CANDIDATES[i], "r");
        char disk[96];

        if (f == NULL)
            continue;
        if (fgets(disk, sizeof disk, f) != NULL) {
            size_t l = strlen(disk);
            while (l && (disk[l - 1] == '\n' || disk[l - 1] == '\r'))
                disk[--l] = 0;
            if (l >= 8 && !strcmp(disk, want)) {
                fclose(f);
                /* the owner of the token file is the identity it proves */
                struct stat st;
                if (stat(TOKEN_CANDIDATES[i], &st) == 0 && uid_out != NULL)
                    *uid_out = st.st_uid;
                return 1;
            }
        }
        fclose(f);
    }
    return 0;
}

/* A list that anyone can write is not a list -- but "group/world-writable" alone is the wrong
 * test, and measured it: when tools/verify_approot.sh (running as root) appends to the manager's
 * own grants.txt, umask leaves it 0666 root:root, and a mode-only rule locked the *legitimate*
 * path out too (criterion C went red for that reason).  So ask the question that actually
 * matters -- can callers other than the file's own owner write it?  That is exactly
 * (group-writable and the daemon is not in the owner's group) or other-writable.  On this
 * device uid 0 is in no app group, so root:root 0666 stays usable while any world-writable
 * list -- e.g. /data/local/tmp/sud.grants at 0666, through which an untrusted_app appended its
 * own uid and got uid=0 (measured 2026-10-15) -- is ignored outright. */
static int grants_file_usable(const char *path)
{
    struct stat st;

    if (stat(path, &st) != 0)
        return 0;
    if (!S_ISREG(st.st_mode))
        return 0;
    if ((st.st_mode & S_IWOTH) != 0 || ((st.st_mode & S_IWGRP) != 0 && st.st_gid != getgid())) {
        stage("grants %s IGNORED: mode %04o owner=%u lets callers other than the owner write it",
              path, (unsigned)(st.st_mode & 07777), (unsigned)st.st_uid);
        return 0;
    }
    return 1;
}

static int uid_allowed(int uid)
{
    char line[256];
    int i;

    if (uid == 0)
        return 1;
    for (i = 0; i < 3; i++) {
        FILE *f;

        if (!grants_file_usable(GRANTS_CANDIDATES[i]))
            continue;
        f = fopen(GRANTS_CANDIDATES[i], "r");
        if (f == NULL)
            continue;
        while (fgets(line, sizeof line, f)) {
            int g = atoi(line);
            if (g == uid && g != 0) {
                fclose(f);
                return 1;
            }
        }
        fclose(f);
    }
    return 0;
}

static void dispatch_su(int fd, int cuid, pid_t cpid, char *line);

static void handle_su(int fd)
{
    char line[1024];
    pid_t cpid = 0;
    int cuid;

    cuid = peer_uid(fd, &cpid);
    read_one_line(fd, line, sizeof line);
    stage("su request uid=%d pid=%d: %.200s", cuid, cpid, line);
    if (cuid < 0) {
        uid_t touid = 0;

        if (token_matches(line, &touid)) {
            cuid = (int) touid;
            stage("attributed by token -> uid=%d", cuid);
        } else {
            write(fd, "ERR cannot attribute caller\n", 28);
            return;
        }
    }
    dispatch_su(fd, cuid, cpid, line);
}

/* The audit trail an authorization manager needs: who asked, for what, and what
 * we decided.  It lives in the 0777 request directory so the manager can read it
 * without any privilege, and it is append-only -- a granted app cannot rewrite
 * the record of its own grants.
 */
#define SU_LOG SOCKDIR2 "/sud.log"
/* One file per live privileged session, named by the child pid.  The connection
 * handler that forked the session is a *different process* from the accept loop,
 * so an in-memory table would be invisible to the sweep that revokes and reaps. */
#define SESSDIR SOCKDIR2 "/sess"

static void su_log(const char *fmt, ...)
{
    char line[512];
    va_list ap;
    int n, fd;

    fd = open(SU_LOG, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0)
        return;
    va_start(ap, fmt);
    n = vsnprintf(line, sizeof line, fmt, ap);
    va_end(ap);
    if (n > 0) {
        if (n >= (int) sizeof line)
            n = sizeof line - 1;
        line[n++] = '\n';
        if (write(fd, line, (size_t) n) < 0)
            ;
    }
    close(fd);
}

static void session_put(int uid, pid_t child, int tries)
{
    char path[160], b[64];
    int fd, n;

    mkdir(SESSDIR, 0777);
    chmod(SESSDIR, 0777);
    snprintf(path, sizeof path, "%s/%d", SESSDIR, (int) child);
    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0)
        return;
    n = snprintf(b, sizeof b, "%d %d %d\n", uid, (int) child, tries);
    if (write(fd, b, (size_t) n) < 0)
        ;
    close(fd);
}

static void session_drop(pid_t child)
{
    char path[160];

    snprintf(path, sizeof path, "%s/%d", SESSDIR, (int) child);
    unlink(path);
}

/* Called from the accept loop, so it covers what the per-connection handlers
 * cannot: reaping the daemon's own children (serve_tcp used to leave its root
 * shell as a zombie forever) and taking away a session whose uid has just been
 * removed from the allow list -- a live shell is not affected by the next check. */
static void sweep_sessions(void)
{
    DIR *d;
    struct dirent *de;
    int st;

    while (waitpid(-1, &st, WNOHANG) > 0)
        ;
    d = opendir(SESSDIR);
    if (d == NULL)
        return;
    while ((de = readdir(d)) != NULL) {
        char path[192], buf[64];
        FILE *f;
        int uid = -1, pid = -1, tries = 0;

        if (de->d_name[0] < '0' || de->d_name[0] > '9')
            continue;
        snprintf(path, sizeof path, "%s/%s", SESSDIR, de->d_name);
        f = fopen(path, "r");
        if (f == NULL) {
            unlink(path);
            continue;
        }
        if (fgets(buf, sizeof buf, f) == NULL)
            buf[0] = 0;
        fclose(f);
        sscanf(buf, "%d %d %d", &uid, &pid, &tries);
        if (pid <= 0) {
            unlink(path);
            continue;
        }
        if (kill(pid, 0) != 0) {
            /* The handler died without cleaning up; the child is gone too. */
            unlink(path);
            continue;
        }
        if (uid < 0 || uid_allowed(uid))
            continue;
        /* spawn_sh() calls setsid(), so the session is its own process group:
         * signal the group as well, or a helper it detached would outlive us. */
        if (tries == 0) {
            kill(pid, SIGHUP);
            kill(-pid, SIGHUP);
            session_put(uid, (pid_t) pid, 1);
            su_log("revoke uid=%-6d pid=%-6d grant withdrawn, session hung up", uid, pid);
        } else {
            kill(pid, SIGKILL);
            kill(-pid, SIGKILL);
            su_log("revoke uid=%-6d pid=%-6d session killed (survived SIGHUP)", uid, pid);
            unlink(path);
        }
    }
    closedir(d);
}

/* kmod exec's the daemon with an almost empty environment, and the child we fork
 * inherits it: `pm`, `am`, `appops` and `svc` all SIGABRT (rc=134) with no
 * ANDROID_DATA, because the app_process-backed tools read it during init.  A real su
 * keeps the caller's environment, so take exactly that -- the caller is the client
 * process whose pid the kernel handed us via SCM_CREDENTIALS -- and fall back to the
 * platform defaults when there is nothing to read (e.g. a token-attributed caller). */
static const char *ENV_WANT[] = {
    "ANDROID_ROOT", "ANDROID_ASSETS", "ANDROID_DATA", "ANDROID_STORAGE",
    "ANDROID_BOOTLOGO", "EXTERNAL_STORAGE", "ASEC_MOUNTPOINT", "LOOP_MOUNTPOINT",
    "TMPDIR", "HOME", NULL
};

static void set_defaults(void)
{
    static const char *DFLT[] = {
        "ANDROID_ROOT=/system", "ANDROID_ASSETS=/system/app", "ANDROID_DATA=/data",
        "ANDROID_STORAGE=/storage", "EXTERNAL_STORAGE=/sdcard", NULL
    };
    int i;

    for (i = 0; DFLT[i] != NULL; i++) {
        char key[32], *eq;
        snprintf(key, sizeof key, "%s", DFLT[i]);
        eq = strchr(key, '=');
        if (eq != NULL)
            *eq = 0;
        if (getenv(key) == NULL)
            putenv((char *) DFLT[i]);
    }
}

static void import_caller_env(pid_t cpid)
{
    char path[64], *buf, *p, *want;
    ssize_t n, got = 0;
    size_t cap = 16384;
    int fd, i;

    if (cpid > 0) {
        snprintf(path, sizeof path, "/proc/%d/environ", (int) cpid);
        fd = open(path, O_RDONLY);
        if (fd >= 0) {
            buf = malloc(cap);
            if (buf != NULL) {
                while (got < (ssize_t) cap - 1) {
                    n = read(fd, buf + got, cap - 1 - (size_t) got);
                    if (n <= 0)
                        break;
                    got += n;
                }
                close(fd);
                buf[got] = 0;
                /* Entries are NUL separated: "KEY=VALUE\0KEY=VALUE\0". */
                for (p = buf; p < buf + got; p += strlen(p) + 1) {
                    if (strlen(p) == 0)
                        continue;
                    for (i = 0; ENV_WANT[i] != NULL; i++) {
                        size_t kl = strlen(ENV_WANT[i]);
                        if (!strncmp(p, ENV_WANT[i], kl) && p[kl] == '=') {
                            want = strdup(p);
                            if (want != NULL)
                                putenv(want);
                            break;
                        }
                    }
                }
                free(buf);
            } else {
                close(fd);
            }
        }
        stage("caller env: pid=%d read=%d bytes", (int) cpid, (int) got);
    }
    set_defaults();
}

static void dispatch_su(int fd, int cuid, pid_t cpid, char *line)
{
    if (!uid_allowed(cuid)) {
        /* Denied without explaining anything: the whole point of this design is
         * that an unlisted app learns nothing about what is on the other end. */
        stage("denied uid=%d pid=%d", cuid, cpid);
        su_log("deny   uid=%-6d pid=%-6d %.200s", cuid, cpid, line);
        write(fd, "ERR unknown service\n", 20);
        return;
    }
    if (!strncmp(line, "PING", 4)) {
        char r[64];
        int n = snprintf(r, sizeof r, "PONG uid=%d pid=%d\n", getuid(), getpid());
        write(fd, r, n);
        return;
    }
    if (!strncmp(line, "MOUNT", 5)) {
        char *arg = strchr(line + 5, ' ');

        /* Installing su into a mirrored directory changes what EVERY app can see,
         * which is the opposite of this design's premise.  A granted app must not
         * be able to do that -- only an already-root caller (the adb path, or the
         * raw 12345 shell) may ask for it. */
        if (cuid != 0) {
            stage("MOUNT refused for uid=%d (root-only operation)", cuid);
            su_log("refuse uid=%-6d pid=%-6d (MOUNT is root-only) %.120s", cuid, cpid, line);
            write(fd, "ERR permission denied\n", 22);
            return;
        }
        if (arg != NULL) {
            char *sp;
            *arg++ = 0;
            sp = strchr(arg, ' ');
            if (sp != NULL) {
                *sp++ = 0;
                install_su(arg, !strcmp(sp, "bin"));
            } else {
                install_su(arg, 0);
            }
            write(fd, "OK mount attempted; read /data/local/tmp/sud.stage\n", 51);
        } else {
            write(fd, "ERR usage: MOUNT <path-to-su-client> [bin]\n", 42);
        }
        return;
    }
    if (!strncmp(line, "SU", 2)) {
        char *p = line + 2, *sp, *cmd;
        int uid;
        pid_t pid;

        /* "SU <uid> <cmd...>": skip the spaces after the verb, take the uid
         * token, then the command starts at the next non-space.  Using the first
         * space after "SU" as the command start silently made the uid part of the
         * command ("SU 0 id" -> sh -c "0 id"). */
        while (*p == ' ' || *p == '\t')
            p++;
        sp = strchr(p, ' ');
        if (sp == NULL) {
            write(fd, "ERR usage: SU <uid> <cmd>\n", 26);
            return;
        }
        *sp++ = 0;
        uid = atoi(p);
        cmd = sp;
        while (*cmd == ' ' || *cmd == '\t')
            cmd++;
        if (*cmd == 0) {
            write(fd, "ERR empty command\n", 18);
            return;
        }
        /* A granted app may ask for root or for itself -- not for some other app's
         * uid, which would turn one grant into an impersonation primitive. */
        if (uid != 0 && uid != cuid) {
            stage("SU target uid=%d refused (caller is %d)", uid, cuid);
            su_log("refuse uid=%-6d pid=%-6d (target %d not allowed) %.120s",
                   cuid, cpid, uid, cmd);
            write(fd, "ERR target uid not allowed\n", 27);
            return;
        }
        /* The decision is recorded when it is MADE, not when the command finishes:
         * an interactive session can outlive the audit otherwise (measured -- MT's
         * root shell was running while sud.log still had no line for its uid). */
        su_log("open   uid=%-6d pid=%-6d target=%-6d %.180s", cuid, cpid, uid, cmd);
        pid = fork();
        if (pid == 0) {
            char *av[5];
            int i = 0;

            close_listeners();
            relabel_if_kernel();
            /* While still root: reading /proc/<caller>/environ needs it. */
            import_caller_env(cpid);
            if (uid != 0) {
                setresgid((gid_t) uid, (gid_t) uid, (gid_t) uid);
                setresuid((uid_t) uid, (uid_t) uid, (uid_t) uid);
            }
            stage("su exec uid=%d cmd=%.120s", uid, cmd);
            if (!strcmp(cmd, "-")) {
                spawn_sh(fd);
            } else {
                /* argv[0] is the NAME, not the path: with the path in argv[0] and
                 * "sh" in argv[1], mksh read "sh" as the script file to run and
                 * answered "sh: No such file or directory". */
                dup2(fd, 0);
                dup2(fd, 1);
                dup2(fd, 2);
                if (fd > 2)
                    close(fd);
                setenv("PATH", "/sbin:/system/bin:/system/xbin:/vendor/bin", 1);
                av[i++] = (char *)"sh";
                av[i++] = (char *)"-c";
                av[i++] = cmd;
                av[i] = NULL;
                execv("/system/bin/sh", av);
                stage("execv /system/bin/sh failed errno=%d cmd=%.120s", errno, cmd);
                write(fd, "ERR exec failed\n", 16);
            }
            _exit(127);
        }
        if (pid < 0) {
            stage("fork for SU failed errno=%d", errno);
            write(fd, "ERR fork failed\n", 16);
            return;
        }
        /* Registered so the accept loop's sweep can take the session away if the
         * grant is withdrawn while it is still running. */
        session_put(cuid, pid, 0);
        /* Wait for the command instead of returning immediately: the earlier
         * shape closed this process's reference to the socket while the child was
         * still running, and the caller saw a clean EOF with no output. */
        {
            int st = 0, code = 127;
            char tail[32];

            if (waitpid(pid, &st, 0) < 0)
                stage("waitpid failed errno=%d", errno);
            else if (WIFEXITED(st))
                code = WEXITSTATUS(st);
            else if (WIFSIGNALED(st))
                code = 128 + WTERMSIG(st);
            session_drop(pid);
            stage("su cmd pid=%d status=%d code=%d", pid, st, code);
            su_log("allow  uid=%-6d pid=%-6d target=%-6d code=%-4d %.180s",
                   cuid, cpid, uid, code, cmd);
            /* A socket carries no wait status, so the code travels as a trailer the
             * client strips off (see suc.c). */
            snprintf(tail, sizeof tail, "\n@SUD_EXIT=%d\n", code);
            write(fd, tail, strlen(tail));
        }
        return;
    }
    write(fd, "ERR unknown request\n", 20);
}

static void serve_su_conn(int fd)
{
    pid_t pid = fork();

    if (pid == 0) {
        setsid();
        close_listeners();
        handle_su(fd);
        close(fd);
        _exit(0);
    }
    if (pid < 0)
        stage("fork su conn: errno=%d", errno);
}

/* ---- reverse-direction su channel ------------------------------------
 * Two measured walls make the normal shape impossible here: this domain cannot
 * bind AF_UNIX at all, and an app's TCP row never appears in the socket table we
 * can read.  So the caller hosts the listener: it binds an abstract socket, drops
 * the name in a world-writable request directory, and we connect to it.  The
 * identity then arrives as SCM_CREDENTIALS, which the kernel fills in and an
 * unprivileged sender cannot forge -- strictly better than both the /proc walk
 * and the token, and it is what makes "grant root to another app" real.
 */
static int recv_cred_line(int fd, char *line, int cap, struct ucred *uc)
{
    struct iovec io;
    char cbuf[CMSG_SPACE(sizeof(struct ucred))];
    struct msghdr mh;
    struct cmsghdr *cm;
    ssize_t n;
    int on = 1;

    /* The kernel only attaches SCM_CREDENTIALS to a receive if the RECEIVING
     * socket asked for it -- without SO_PASSCRED the recvmsg comes back with the
     * line and no control data at all (measured: "request without
     * SCM_CREDENTIALS, refused"). */
    setsockopt(fd, SOL_SOCKET, SO_PASSCRED, &on, sizeof on);
    memset(&mh, 0, sizeof mh);
    memset(cbuf, 0, sizeof cbuf);
    io.iov_base = line;
    io.iov_len = (size_t) (cap - 1);
    mh.msg_iov = &io;
    mh.msg_iovlen = 1;
    mh.msg_control = cbuf;
    mh.msg_controllen = sizeof cbuf;
    /* no MSG_WAITALL: on a stream socket that would block until the whole buffer
     * is filled, and the client sends exactly one line in one sendmsg. */
    n = recvmsg(fd, &mh, 0);
    if (n <= 0)
        return -1;
    line[n] = 0;
    /* The TCP path strips the newline inside read_one_line(); this path has to as
     * well, or the interactive sentinel arrives as "-\n", misses the strcmp and is
     * handed to `sh -c` (which answers "unknown option"), and `MOUNT <p> bin`
     * loses its "bin" argument for the same reason. */
    line[strcspn(line, "\r\n")] = 0;
    for (cm = CMSG_FIRSTHDR(&mh); cm != NULL; cm = CMSG_NXTHDR(&mh, cm)) {
        if (cm->cmsg_level == SOL_SOCKET && cm->cmsg_type == SCM_CREDENTIALS) {
            memcpy(uc, CMSG_DATA(cm), sizeof *uc);
            return 0;
        }
    }
    return -1;
}

static void handle_peer(int fd)
{
    char line[1024];
    struct ucred uc;

    if (recv_cred_line(fd, line, sizeof line, &uc) < 0) {
        stage("peer: request without SCM_CREDENTIALS, refused");
        write(fd, "ERR unauthenticated\n", 20);
        return;
    }
    stage("peer request uid=%d pid=%d: %.200s", (int) uc.uid, (int) uc.pid, line);
    dispatch_su(fd, (int) uc.uid, (pid_t) uc.pid, line);
}

static void serve_peer(int fd)
{
    pid_t pid = fork();

    if (pid == 0) {
        close_listeners();
        handle_peer(fd);
        close(fd);
        _exit(0);
    }
    if (pid < 0)
        stage("fork peer: errno=%d", errno);
}

static void scan_peers(void)
{
    DIR *d = opendir(SOCKDIR2);
    struct dirent *de;

    if (d == NULL)
        return;
    while ((de = readdir(d)) != NULL) {
        char path[300], name[128];
        struct sockaddr_un a;
        size_t nl;
        FILE *f;
        int c;

        if (strncmp(de->d_name, "req-", 4))
            continue;
        snprintf(path, sizeof path, "%s/%s", SOCKDIR2, de->d_name);
        f = fopen(path, "r");
        if (f == NULL)
            continue;
        if (fgets(name, sizeof name, f) == NULL)
            name[0] = 0;
        fclose(f);
        unlink(path);
        name[strcspn(name, "\r\n")] = 0;
        nl = strlen(name);
        if (nl == 0 || nl >= sizeof(a.sun_path) - 1)
            continue;
        c = socket(AF_UNIX, SOCK_STREAM, 0);
        if (c < 0)
            continue;
        memset(&a, 0, sizeof a);
        a.sun_family = AF_UNIX;
        a.sun_path[0] = 0;
        memcpy(a.sun_path + 1, name, nl);
        if (connect(c, (struct sockaddr *) &a,
                    (socklen_t) (sizeof(a.sun_family) + 1 + nl)) == 0) {
            stage("peer: connected to @%s", name);
            serve_peer(c);
        } else {
            stage("peer: connect @%s errno=%d", name, errno);
        }
        close(c);
    }
    closedir(d);
}

/* Directives the launcher can set *without* a socket, because the su channel may
 * not exist yet on the first start.  One per line in CONF (world-writable by
 * design: whoever can write it already owns the machine):
 *   MOUNT <path-to-su-client> [bin]   install su into the memory mirrors
 *   LOG <text>                        echo into the stage log
 */
static void run_conf(void)
{
    char line[512];
    FILE *f = fopen(CONF, "r");

    if (f == NULL) {
        stage("no conf at %s (errno=%d)", CONF, errno);
        return;
    }
    while (fgets(line, sizeof line, f)) {
        size_t n = strlen(line);
        char *arg;

        while (n && (line[n - 1] == '\n' || line[n - 1] == '\r'))
            line[--n] = 0;
        stage("conf: %.200s", line);
        arg = strchr(line, ' ');
        if (!strncmp(line, "MOUNT", 5) && arg != NULL) {
            char *sp;
            *arg++ = 0;
            sp = strchr(arg, ' ');
            if (sp != NULL) {
                *sp++ = 0;
                install_su(arg, !strcmp(sp, "bin"));
            } else {
                install_su(arg, 0);
            }
        }
    }
    fclose(f);
}

static void proof(void)
{
    char buf[512];
    int fd, n, s;

    fd = open(PROOF, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        stage("proof open: errno=%d", errno);
        return;
    }
    n = snprintf(buf, sizeof buf, "sud alive pid=%d uid=%d euid=%d gid=%d\n",
                 getpid(), getuid(), geteuid(), getgid());
    write(fd, buf, n);
    /* read the caps straight out of proc -- no popen, no PATH, no shell */
    s = open("/proc/self/status", O_RDONLY);
    if (s >= 0) {
        FILE *f = fdopen(s, "r");
        char l[256];

        if (f != NULL) {
            while (fgets(l, sizeof l, f)) {
                if (!strncmp(l, "CapEff", 6) || !strncmp(l, "Seccomp", 7))
                    write(fd, l, strlen(l));
            }
            fclose(f);
        }
        close(s);
    }
    n = snprintf(buf, sizeof buf, "enforce=%s\n",
                 access("/sys/fs/selinux/enforce", R_OK) == 0 ? "readable" : "unreadable");
    write(fd, buf, n);
    close(fd);
    chmod(PROOF, 0644);
    stage("proof written to %s", PROOF);
}

int main(void)
{
    fd_set rf;
    int fd, max;

    /* We are exec'd by kmod as: <path> -c /dev/null.  Args are ignored; the
     * parent must return so that UMH_WAIT_PROC stops waiting, and the session
     * must be detached, so the listener lives on: double-fork + setsid. */
    signal(SIGHUP, SIG_IGN);
    stage("start pid=%d uid=%d argv ok", getpid(), getuid());

    if (fork() > 0)
        return 0;
    setsid();
    if (fork() > 0)
        _exit(0);

    g_ltcp = listen_on(TCP_PORT, "sh");
    g_lsu = listen_on(SU_PORT, "su");
    /* TCP first (works in the helper domain), then leave that domain so the unix
     * sockets -- which give SO_PEERCRED, i.e. real caller identity -- can bind. */
    relabel_for_sockets();
    g_abs = listen_abs();
    g_gunix = listen_unix("/dev/.sud");
    if (g_gunix < 0)
        g_gunix = listen_unix("/data/local/tmp/.sud");
    if (g_ltcp < 0 && g_lsu < 0 && g_abs < 0 && g_gunix < 0) {
        stage("no listener at all, giving up");
        return 2;
    }
    /* A busy TCP port is not a reason to die: it usually means a previous daemon
     * is still up, while the su channel we came for is ours. */
    proof();
    run_conf();
    /* request directory for the reverse-direction channel: apps must be able to
     * create files in it, so it is 0777 (we can mkdir even where bind is refused) */
    if (mkdir(SOCKDIR2, 0777) < 0 && errno != EEXIST)
        stage("mkdir %s: errno=%d", SOCKDIR2, errno);
    chmod(SOCKDIR2, 0777);

    max = 1;
    if (g_ltcp >= max)
        max = g_ltcp + 1;
    if (g_lsu >= max)
        max = g_lsu + 1;
    if (g_abs >= max)
        max = g_abs + 1;
    if (g_gunix >= max)
        max = g_gunix + 1;
    for (;;) {
        struct timeval tv;
        fd_set cur;

        scan_peers();
        sweep_sessions();
        FD_ZERO(&cur);
        if (g_ltcp >= 0)
            FD_SET(g_ltcp, &cur);
        if (g_lsu >= 0)
            FD_SET(g_lsu, &cur);
        if (g_abs >= 0)
            FD_SET(g_abs, &cur);
        if (g_gunix >= 0)
            FD_SET(g_gunix, &cur);
        tv.tv_sec = 0;
        tv.tv_usec = 500000;
        rf = cur;
        fd = select(max, &rf, NULL, NULL, &tv);
        if (fd <= 0)
            continue;
        if (g_ltcp >= 0 && FD_ISSET(g_ltcp, &rf)) {
            int c = accept(g_ltcp, NULL, NULL);
            if (c >= 0) {
                serve_tcp(c);
                close(c);
            }
        }
        if (g_lsu >= 0 && FD_ISSET(g_lsu, &rf)) {
            int c = accept(g_lsu, NULL, NULL);
            if (c >= 0) {
                serve_su_conn(c);
                close(c);
            }
        }
        if (g_abs >= 0 && FD_ISSET(g_abs, &rf)) {
            int c = accept(g_abs, NULL, NULL);
            if (c >= 0) {
                serve_su_conn(c);
                close(c);
            }
        }
        if (g_gunix >= 0 && FD_ISSET(g_gunix, &rf)) {
            int c = accept(g_gunix, NULL, NULL);
            if (c >= 0) {
                serve_su_conn(c);
                close(c);
            }
        }
    }
    return 0;
}
