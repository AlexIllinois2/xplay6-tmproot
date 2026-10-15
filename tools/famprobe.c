#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/socket.h>

#ifndef AF_QIPCRTR
#define AF_QIPCRTR 42
#endif

static const char *fam_name(int f)
{
    switch (f) {
    case 0: return "UNSPEC";
    case 1: return "UNIX";
    case 2: return "INET";
    case 3: return "AX25";
    case 4: return "IPX";
    case 5: return "APPLETALK";
    case 6: return "NETROM";
    case 7: return "BRIDGE";
    case 15: return "PF_KEY";
    case 16: return "BPF";
    case 17: return "INET6";
    case 18: return "ROOT";
    case 19: return "ATMPVC";
    case 20: return "X25";
    case 22: return "IPSVCS";
    case 23: return "RDS";
    case 24: return "CONG";
    case 25: return "NLM";
    case 26: return "UNIX";
    case 27: return "ASH";
    case 28: return "WIRELESS";
    case 29: return "TPS";
    case 30: return "DCCP";
    case 31: return "LLC";
    case 32: return "WHY";
    case 33: return "PACKET";
    case 34: return "PHONET";
    case 35: return "IEEE802154";
    case 36: return "BLUETOOTH";
    case 37: return "ISCSI";
    case 38: return "TIPC";
    case 39: return "IUCV";
    case 40: return "CAN";
    case 41: return "NL80211";
    case 42: return "QIPCRTR";
    case 43: return "VSOCK";
    case 44: return "KEYS";
    case 45: return "NFC";
    default: return "?";
    }
}

int main(int argc, char **argv)
{
    static const int fams[] = { 15,16,17,20,22,23,24,25,26,27,28,29,30,31,32,
                                33,34,35,36,37,38,39,40,41,42,43,44,45,
                                3,4,5,6,7,18,19 };
    int n = (int)(sizeof fams / sizeof fams[0]);
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("socket-family reachability (fork + alarm(2) watchdog)\n");
    for (int i = 0; i < n; i++) {
        int f = fams[i];
        fflush(stdout);
        pid_t pid = fork();
        if (pid == 0) {
            alarm(2);
            int r = socket(f, SOCK_DGRAM, 0);
            int e = errno;
            if (r >= 0) close(r);
            dprintf(1, "  AF_%-11d %-11s fd=%d errno=%d %s\n",
                    f, fam_name(f), r, r < 0 ? e : 0,
                    r < 0 ? strerror(e) : "OPEN_OK");
            _exit(0);
        }
        int st = 0;
        if (waitpid(pid, &st, 0) < 0) perror("waitpid");
        if (WIFSIGNALED(st)) printf("  AF_%-11d %-11s *** KILLED by signal %d (blocked/hung) ***\n",
                                    f, fam_name(f), WTERMSIG(st));
    }
    (void)argc; (void)argv;
    return 0;
}
