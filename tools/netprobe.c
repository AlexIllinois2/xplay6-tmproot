/*
 * netprobe - reachability gate for the 2016-11..2017-06 "net/" patch gaps.
 *
 * Ranked audit says the two surviving kernel-write candidates (CVE-2017-7979 /
 * CVE-2017-8233 in net/core/filter.c: sk_filter() charges a u32 len, the len is both a
 * size and an index, and the fix (SK_FILTER_MAX_LEN caps) is absent here) are entered
 * from *plain sockets* via setsockopt(SO_ATTACH_FILTER / SO_ATTACH_BPF) -- which needs no
 * capability, no device node, and no slab-reclaim race. So the first thing to establish
 * on the device is that entry point.
 *
 * errno reading (the triangle used all over this project):
 *   0      -> reachable
 *   EACCES -> SELinux denies the socket class
 *   EPERM  -> needs a capability we do not have
 *   EAFNOSUPPORT/EPFNOSUPPORT/ENOPROTOOPT -> not compiled in
 * Every test runs in a forked child with a 2 s alarm, because bind()/connect() on
 * AF_ALG/AF_NFC/AF_IEEE802154 can block in-kernel (loadmodule / raw_proto bind).
 */
#define _GNU_SOURCE
#include <errno.h>
#include <linux/filter.h>
#include <linux/if_packet.h>
#include <linux/netlink.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef AF_ALG
#define AF_ALG 38
#endif
#ifndef AF_NFC
#define AF_NFC 39
#endif
#ifndef AF_IEEE802154
#define AF_IEEE802154 36
#endif
#ifndef AF_TIPC
#define AF_TIPC 30
#endif
#ifndef AF_CAN
#define AF_CAN 29
#endif
#ifndef AF_KEY
#define AF_KEY 19
#endif
#ifndef SOL_SOCKET
#define SOL_SOCKET 1
#endif
#ifndef SO_ATTACH_BPF
#define SO_ATTACH_BPF 56
#endif

static volatile int g_err;
static const char *g_what;

static void onalrm(int s)
{
	(void)s;
	(void)g_err;
	(void)g_what;
	_exit(3);			/* parent prints BLOCKED; no printf in a handler */
}

/* run one tagged test in a child so no kernel path can hang the sweep */
static void guarded(const char *tag, void (*fn)(void))
{
	pid_t p;
	int st;

	fflush(stdout);
	p = fork();
	if (p == 0) {
		signal(SIGALRM, onalrm);
		alarm(2);
		fn();
		if (g_err == -1000) {
			printf("%-26s %s\n", tag, g_what);
			_exit(3);
		}
		_exit(0);
	}
	waitpid(p, &st, 0);
	if (WIFSIGNALED(st))
		printf("%-26s KILLED(sig %d)\n", tag, WTERMSIG(st));
	else if (WEXITSTATUS(st) == 3)
		printf("%-26s BLOCKED(in-kernel, timed out)\n", tag);
}

static int g_fd = -1;
static int g_family, g_type, g_protocol, g_nlproto;
static void open_nl(void)
{
	struct sockaddr_nl sa;
	int rc;

	g_fd = socket(AF_NETLINK, SOCK_RAW, g_nlproto);
	if (g_fd < 0) {
		printf("%-26s %s\n", g_what, strerror(errno));
		return;
	}
	memset(&sa, 0, sizeof sa);
	sa.nl_family = AF_NETLINK;
	rc = bind(g_fd, (struct sockaddr *)&sa, sizeof sa);
	printf("%-26s %s\n", g_what, rc ? strerror(errno) : "OPEN+BOUND");
	if (g_fd >= 0)
		close(g_fd);
}
static void open_fam(void)
{
	int fd = socket(g_family, g_type, g_protocol);

	printf("%-26s %s\n", g_what, fd < 0 ? strerror(errno) : "OPEN");
	if (fd >= 0)
		close(fd);
}

/* the CVE-2017-7979 / 8233 entry point: attach a classic filter to an inet socket */
static void try_attach_filter(void)
{
	struct sock_filter prog[4] = {
		{ 0x06, 0, 0, 0xffffffff },	/* ret allow */
		{ 0x06, 0, 0, 0 },		/* ret drop  */
		{ 0x20, 0, 0, 0x0000000c },	/* ld proto */
		{ 0x15, 0, 1, 6 },		/* jeq tcp  */
	};
	struct sock_fprog fp;
	int fd, rc;

	fp.len = sizeof prog / sizeof prog[0];
	fp.filter = prog;
	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		printf("%-26s socket: %s\n", g_what, strerror(errno));
		return;
	}
	rc = setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &fp, sizeof fp);
	printf("%-26s %s\n", g_what, rc ? strerror(errno) : "REACHABLE (filter attached)");
	close(fd);
}

static void try_attach_bpf(void)
{
	int fd, prog[2] = { 0x05000000, 0x00000000 };
	unsigned char at[128];
	unsigned int cnt = 2;
	unsigned long long insns = (unsigned long long)(unsigned long)prog;
	int rc;

	/* union bpf_attr for BPF_PROG_LOAD, by offset: prog_type@0 insn_cnt@4 insns@8 */
	memset(at, 0, sizeof at);
	memcpy(at + 0, &(unsigned int){ 1 }, 4);	/* BPF_PROG_TYPE_SOCKET_FILTER */
	memcpy(at + 4, &cnt, 4);
	memcpy(at + 8, &insns, 8);
	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		printf("%-26s socket: %s\n", g_what, strerror(errno));
		return;
	}
	rc = syscall(280, 5 /*BPF_PROG_LOAD*/, at, sizeof at);
	if (rc < 0) {
		printf("%-26s bpf(): %s\n", g_what, strerror(errno));
		close(fd);
		return;
	}
	{
		int pfd = rc;

		rc = setsockopt(fd, SOL_SOCKET, SO_ATTACH_BPF, &pfd, 4);
	}
	printf("%-26s %s\n", g_what, rc ? strerror(errno) : "BPF attached");
	close(fd);
}

int main(void)
{
	int i;
	struct { const char *t; int p; } nls[] = {
		{ "NETLINK_ROUTE", 0 }, { "NETLINK_SOCK_DIAG", 4 }, { "NETLINK_XFRM", 6 },
		{ "NETLINK_AUDIT", 9 }, { "NETLINK_NETFILTER", 12 },
		{ "NETLINK_KOBJ_UEVENT", 15 }, { "NETLINK_GENERIC", 17 },
		{ "NETLINK_FIB_LOOKUP", 10 }, { "NETLINK_CONNECTOR", 11 },
		{ "NETLINK_ISCSI", 8 }, { "NETLINK_RDMA", 20 }, { "NETLINK_CRYPTO", 21 },
	};
	struct { const char *t; int f, ty, p; } fams[] = {
		{ "AF_INET TCP", AF_INET, SOCK_STREAM, 0 },
		{ "AF_INET UDP", AF_INET, SOCK_DGRAM, 0 },
		{ "AF_INET6 UDP", 10, SOCK_DGRAM, 0 },
		{ "AF_PACKET RAW", AF_PACKET, SOCK_RAW, 3 },
		{ "AF_PACKET DGRAM", AF_PACKET, SOCK_DGRAM, 3 },
		{ "AF_KEY(XFRM) RAW", AF_KEY, SOCK_RAW, 0 },
		{ "AF_ALG SEQPACKET", AF_ALG, SOCK_SEQPACKET, 0 },
		{ "AF_BLUETOOTH", 31, SOCK_RAW, 1 },
		{ "AF_CAN", AF_CAN, SOCK_RAW, 1 },
		{ "AF_TIPC", AF_TIPC, SOCK_SEQPACKET, 0 },
		{ "AF_NFC RAW", AF_NFC, SOCK_RAW, 0 },
		{ "AF_IEEE802154", AF_IEEE802154, SOCK_RAW, 0 },
	};

	for (i = 0; i < (int)(sizeof nls / sizeof nls[0]); i++) {
		g_nlproto = nls[i].p;
		g_what = nls[i].t;
		g_err = 0;
		guarded(nls[i].t, open_nl);
	}
	for (i = 0; i < (int)(sizeof fams / sizeof fams[0]); i++) {
		g_family = fams[i].f;
		g_type = fams[i].ty;
		g_protocol = fams[i].p;
		g_what = fams[i].t;
		g_err = 0;
		guarded(fams[i].t, open_fam);
	}
	g_what = "SO_ATTACH_FILTER(inet)";
	g_err = 0;
	guarded("SO_ATTACH_FILTER", try_attach_filter);
	g_what = "SO_ATTACH_BPF(inet)";
	g_err = 0;
	guarded("SO_ATTACH_BPF", try_attach_bpf);
	return 0;
}
