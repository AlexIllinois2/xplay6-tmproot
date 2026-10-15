#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/tty.h>

/* from include/uapi/asm-generic/ioctls.h (arm64 uses the generic table); bionic has no stropts.h */
#ifndef TIOCSETD
#define TIOCSETD 0x5423
#endif

/* Which line disciplines can an unprivileged shell SELECT on a pty?
 *
 * Why this is the last cheap door: /dev/ptmx is in my writable-node list, and
 * TIOCSETD needs NO capability -- so merely *selecting* an ldisc runs its
 * open() as uid 2000.  The 2017 tty CVE family is all ldisc-specific
 * (n_gsm TIOCSETD teardown race, n_tracer uninit kfree, n_hdlc (needs
 * CAP_NET_RAW), slip/slcan...).  If GSM/SLCAN/etc. are selectable here, those
 * bugs become reachable; if only N_TTY/N_PTKC/N_PTMX work, the whole family
 * dies at the permission layer the same way af_packet/xfrm/key did.
 *
 * One ldisc per PROCESS, chosen on argv: an ldisc open can take the box down,
 * and the last printed line then names the culprit unambiguously.
 */

static struct { int n; const char *name; } ld[] = {
    { 0, "N_TTY" }, { 1, "N_SLIPI" }, { 2, "N_KISS" }, { 3, "N_MCT" }, { 4, "N_CAIF" },
    { 5, "N_COOK" }, { 6, "N_PTS" }, { 7, "N_UCB" }, { 8, "N_8SCC" }, { 9, "N_X25" },
    { 10, "N_NACS" }, { 11, "N_S100" }, { 12, "N_C101" }, { 13, "N_GSM0710" },
    { 14, "N_IRDA" }, { 15, "N_BPAUTOFS" }, { 16, "N_AMD" }, { 17, "N_SLCAN" },
    { 18, "N_19" }, { 19, "N_PPS" }, { 21, "N_CAIF?" }, { 22, "N_NFC" },
    { 23, "N_LLC" }, { 24, "N_24" }, { 25, "N_MOUSE" }, { 26, "N_VIOUS" },
    { 27, "N_PTP" }, { 28, "N_X25_ASY" }, { 29, "N_RXRPC" },
};

int main(int argc, char **argv)
{
    int mfd, sfd, n, i;
    char sn[64];

    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc < 2) {
        printf("usage: %s <ldisc-n>   (try one per process)\n", argv[0]);
        for (i = 0; i < (int)(sizeof ld / sizeof ld[0]); i++)
            printf("  %2d %s\n", ld[i].n, ld[i].name);
        return 0;
    }
    n = atoi(argv[1]);

    mfd = posix_openpt(O_RDWR | O_NOCTTY);
    if (mfd < 0) { printf("posix_openpt: %s\n", strerror(errno)); return 1; }
    if (grantpt(mfd) || unlockpt(mfd)) { printf("grant/unlock: %s\n", strerror(errno)); return 1; }
    ptsname_r(mfd, sn, sizeof sn);
    sfd = open(sn, O_RDWR | O_NOCTTY);
    if (sfd < 0) { printf("open %s: %s\n", sn, strerror(errno)); return 1; }
    printf("pty master=%d slave=%d(%s)\n", mfd, sfd, sn);

    errno = 0;
    if (ioctl(sfd, TIOCSETD, &n) == 0)
        printf("RESULT: slave accepts ldisc %d -- OPEN SUCCEEDED (ldisc open ran as uid 2000)\n", n);
    else
        printf("RESULT: ldisc %d rejected errno=%d (%s)\n", n, errno, strerror(errno));

    { int back = 0; ioctl(sfd, TIOCSETD, &back); }
    close(sfd);
    close(mfd);
    return 0;
}
