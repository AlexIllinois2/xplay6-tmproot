#include <jni.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>

/* The three entry points the APK uses, exported by the ESC_LIB build of
 * tools/clobber.c.  One implementation for both the adb path and the app path,
 * on purpose: what run_temproot.sh proved on-device is then literally what the
 * app runs. */
extern int esc_probe(char *out, int cap);
extern int esc_state(char *out, int cap);
extern int esc_escalate_ex(const char *daemon, int rounds, char *out, int cap, int map_only);
extern int esc_sugate(char *out, int cap);
extern int esc_sugate_revert(char *out, int cap);
extern int esc_sugate7_open(char *out, int cap);
extern int esc_sugate7_restore(const char *orig, char *out, int cap);
extern int esc_sugate7_patch(char *out, int cap);
extern int esc_sugate7_abort(const char *orig, char *out, int cap);
extern int esc_sugate7_revert(char *out, int cap);

/* ---- reverse-direction su client -------------------------------------
 * Java cannot read SCM_CREDENTIALS, so the app's identity has to be carried by
 * native code.  We listen, publish the abstract name where the daemon looks, and
 * let it connect back: the uid it then reads is the kernel's, not ours.
 * Same protocol as tools/suc.c -- kept deliberately small and identical.
 */
#define REQ_DIR "/data/local/tmp/.sud/req"

static int peer_round_trip(const char *req, char *out, int cap)
{
    struct sockaddr_un a;
    struct iovec io;
    struct msghdr mh;
    struct cmsghdr *cm;
    struct ucred *uc;
    char name[48], path[256], cbuf[CMSG_SPACE(sizeof(struct ucred))];
    size_t nl;
    int ls, csock, fd, total = 0;
    struct pollfd pf;

    ls = socket(AF_UNIX, SOCK_STREAM, 0);
    if (ls < 0)
        return -1;
    snprintf(name, sizeof name, "trq%d.%ld", getuid(), (long) getpid());
    nl = strlen(name);
    memset(&a, 0, sizeof a);
    a.sun_family = AF_UNIX;
    a.sun_path[0] = 0;
    memcpy(a.sun_path + 1, name, nl);
    if (bind(ls, (struct sockaddr *) &a, (socklen_t) (sizeof(a.sun_family) + 1 + nl)) < 0
        || listen(ls, 1) < 0) {
        snprintf(out, cap, "bind/listen errno=%d", errno);
        close(ls);
        return -1;
    }
    mkdir(REQ_DIR, 0777);
    snprintf(path, sizeof path, "%s/req-%d", REQ_DIR, getpid());
    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (fd < 0) {
        snprintf(out, cap, "open %s errno=%d", path, errno);
        close(ls);
        return -1;
    }
    write(fd, name, nl);
    write(fd, "\n", 1);
    close(fd);

    pf.fd = ls;
    pf.events = POLLIN;
    if (poll(&pf, 1, 10000) <= 0) {
        snprintf(out, cap, "daemon did not call back (poll errno=%d)", errno);
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
    uc = (struct ucred *) CMSG_DATA(cm);
    uc->pid = getpid();
    uc->uid = getuid();
    uc->gid = getgid();
    mh.msg_controllen = cm->cmsg_len;
    if (sendmsg(csock, &mh, 0) < 0) {
        snprintf(out, cap, "sendmsg errno=%d", errno);
        close(csock);
        return -1;
    }
    for (;;) {
        ssize_t n;
        char b[1024];

        n = read(csock, b, sizeof b);
        if (n <= 0)
            break;
        if (total < cap - 1) {
            int space = cap - 1 - total;
            int cpy = n < space ? (int) n : space;
            memcpy(out + total, b, (size_t) cpy);
            total += cpy;
        }
    }
    out[total] = 0;
    close(csock);
    return total;
}

/* The daemon ends every -c response with "@SUD_EXIT=<n>" because a socket carries
 * no wait status.  suc.c strips it; the JNI path must too, or the manager's own
 * log shows the trailer as if it were command output. */
static int last_peer_exit = 0;

static void strip_exit_trailer(char *out)
{
    char *mark = strstr(out, "@SUD_EXIT=");
    size_t n;

    last_peer_exit = 0;
    if (mark != NULL) {
        last_peer_exit = atoi(mark + 10);
        *mark = 0;
    }
    n = strlen(out);
    while (n > 0 && (out[n - 1] == '\n' || out[n - 1] == '\r'))
        out[--n] = 0;
}

JNIEXPORT jint JNICALL
Java_com_xplay6_temproot_Esc_nativeLastExit(JNIEnv *env, jobject thiz)
{
    (void) env;
    (void) thiz;
    return (jint) last_peer_exit;
}

JNIEXPORT jstring JNICALL
Java_com_xplay6_temproot_Esc_nativePeerSu(JNIEnv *env, jobject thiz, jint toUid, jstring cmd)
{
    char req[4200], out[4096];
    const char *c;

    (void) thiz;
    out[0] = 0;
    c = (*env)->GetStringUTFChars(env, cmd, NULL);
    if (c == NULL)
        return (*env)->NewStringUTF(env, "ERR no command");
    snprintf(req, sizeof req, "SU %d %s\n", (int) toUid, c);
    (*env)->ReleaseStringUTFChars(env, cmd, c);
    if (peer_round_trip(req, out, sizeof out) < 0) {
        char msg[4200];

        /* "xport:" marks a transport failure, so the Java side can tell "the
         * daemon refused me" from "I never reached the daemon" and only fall back
         * to the TCP+token channel in the second case. */
        snprintf(msg, sizeof msg, "xport: %s", out[0] ? out : "peer channel unavailable");
        return (*env)->NewStringUTF(env, msg);
    }
    if (out[0] == 0)
        return (*env)->NewStringUTF(env, "xport: daemon answered nothing");
    strip_exit_trailer(out);
    return (*env)->NewStringUTF(env, out);
}

static jstring report(JNIEnv *env, int rc, const char *buf)
{
    char out[2200];

    snprintf(out, sizeof out, "rc=%d %s", rc, buf);
    return (*env)->NewStringUTF(env, out);
}

JNIEXPORT jstring JNICALL
Java_com_xplay6_temproot_Esc_nativeProbe(JNIEnv *env, jobject thiz)
{
    char buf[1024];

    (void)thiz;
    buf[0] = 0;
    return report(env, esc_probe(buf, sizeof buf), buf);
}

JNIEXPORT jstring JNICALL
Java_com_xplay6_temproot_Esc_nativeState(JNIEnv *env, jobject thiz)
{
    char buf[1024];

    (void)thiz;
    buf[0] = 0;
    return report(env, esc_state(buf, sizeof buf), buf);
}

JNIEXPORT jstring JNICALL
Java_com_xplay6_temproot_Esc_nativeEscalate(JNIEnv *env, jobject thiz, jstring daemon, jint rounds,
                                            jint mapOnly)
{
    char buf[2048];
    const char *d;
    int rc;

    (void)thiz;
    buf[0] = 0;
    d = (*env)->GetStringUTFChars(env, daemon, NULL);
    if (d == NULL)
        return report(env, -1, "daemon path unavailable");
    rc = esc_escalate_ex(d, (int)rounds, buf, sizeof buf, (int)mapOnly);
    (*env)->ReleaseStringUTFChars(env, daemon, d);
    return report(env, rc, buf);
}

JNIEXPORT jstring JNICALL
Java_com_xplay6_temproot_Esc_nativeSugate(JNIEnv *env, jobject thiz)
{
    char buf[2048];

    (void)thiz;
    buf[0] = 0;
    return report(env, esc_sugate(buf, sizeof buf), buf);
}

JNIEXPORT jstring JNICALL
Java_com_xplay6_temproot_Esc_nativeSugateRevert(JNIEnv *env, jobject thiz)
{
    char buf[1024];

    (void)thiz;
    buf[0] = 0;
    return report(env, esc_sugate_revert(buf, sizeof buf), buf);
}

JNIEXPORT jstring JNICALL
Java_com_xplay6_temproot_Esc_nativeSugate7Open(JNIEnv *env, jobject thiz)
{
    char buf[2048];

    (void)thiz;
    buf[0] = 0;
    return report(env, esc_sugate7_open(buf, sizeof buf), buf);
}

JNIEXPORT jstring JNICALL
Java_com_xplay6_temproot_Esc_nativeSugate7Restore(JNIEnv *env, jobject thiz, jstring orig)
{
    char buf[2048];
    const char *o;

    (void)thiz;
    buf[0] = 0;
    o = (*env)->GetStringUTFChars(env, orig, NULL);
    if (o == NULL)
        return report(env, -1, "sugate7-restore: no original path given");
    {
        int rc = esc_sugate7_restore(o, buf, sizeof buf);
        (*env)->ReleaseStringUTFChars(env, orig, o);
        return report(env, rc, buf);
    }
}

JNIEXPORT jstring JNICALL
Java_com_xplay6_temproot_Esc_nativeSugate7Patch(JNIEnv *env, jobject thiz)
{
    char buf[2048];

    (void)thiz;
    buf[0] = 0;
    return report(env, esc_sugate7_patch(buf, sizeof buf), buf);
}

JNIEXPORT jstring JNICALL
Java_com_xplay6_temproot_Esc_nativeSugate7Abort(JNIEnv *env, jobject thiz, jstring orig)
{
    char buf[2048];
    const char *o;

    (void)thiz;
    buf[0] = 0;
    o = (*env)->GetStringUTFChars(env, orig, NULL);
    if (o == NULL)
        return report(env, -1, "sugate7-abort: no original path given");
    {
        int rc = esc_sugate7_abort(o, buf, sizeof buf);
        (*env)->ReleaseStringUTFChars(env, orig, o);
        return report(env, rc, buf);
    }
}

JNIEXPORT jstring JNICALL
Java_com_xplay6_temproot_Esc_nativeSugate7Revert(JNIEnv *env, jobject thiz)
{
    char buf[1024];

    (void)thiz;
    buf[0] = 0;
    return report(env, esc_sugate7_revert(buf, sizeof buf), buf);
}
