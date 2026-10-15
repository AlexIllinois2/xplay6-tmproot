#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdlib.h>

/* Which privileged unix sockets are DAC-reachable from uid 2000 (shell, also in
 * groups log/inet/sdcard_rw)?  An EACCES here means DAC let the connect through and
 * only SELinux is in the way -> those daemons become usable the instant
 * selinux_enforcing is turned off.  ENOENT means the daemon is not running.
 * Names come from the socket directives in the stock ramdisk init*.rc, not from
 * listing /dev/socket (shell has no read permission on that directory). */
static const char *cands[] = {
    "perfd", "iop", "thermal-send-client", "thermal-recv-passive-client",
    "thermal-recv-client", "qvrservice", "netd", "dnsproxyd", "fwmarkd", "mdnsd",
    "dumpstate", "cnd", "backuprestore", "dpmd", "logd", "logdr", "logdw",
    "vold", "cryptd", "lmkd", "installd", "adbd", "zygote", "rild", "rild-debug",
    "qmitest", "vivoEmSvr-service", "wififccutild_server", "pps", "sap_uim_socket1",
    "mpdecision", "thermal_handle", "seempdw",
};

int main(void)
{
    size_t i;

    setvbuf(stdout, NULL, _IONBF, 0);
    for (i = 0; i < sizeof cands / sizeof *cands; i++) {
        struct sockaddr_un a;
        char path[128];
        int fd, rc;

        snprintf(path, sizeof path, "/dev/socket/%s", cands[i]);
        fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd < 0) { perror("socket"); return 1; }
        memset(&a, 0, sizeof a);
        a.sun_family = AF_UNIX;
        strncpy(a.sun_path, path, sizeof a.sun_path - 1);
        errno = 0;
        rc = connect(fd, (struct sockaddr *)&a, sizeof(sa_family_t) + strlen(path) + 1);
        printf("%-28s connect -> %d errno=%d %s\n", cands[i], rc, errno,
               rc == 0 ? "*** CONNECTED (no gate at all) ***" :
               errno == EACCES ? "DAC passed, SELinux blocking" :
               errno == ENOENT ? "absent" :
               errno == ECONNREFUSED ? "socket file exists, nobody listening" :
               errno == EPERM ? "EPERM" : strerror(errno));
        close(fd);
    }
    return 0;
}
