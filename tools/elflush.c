/* tools/elflush.c -- can EL0 clean/invalidate one line by VA on this SoC, and does that
 * actually make a patched instruction visible?  This is the precise replacement for
 * icache_sync's eviction sweeps: instead of dirtying 8 MB and executing 6 MB and hoping
 * the gate's line got thrown out, we name the line.
 *
 * The ARMv8 self-modifying-code sequence is, on the core that did the store:
 *     dc cvau, va ; dsb ish ; ic ivau, va ; dsb ish ; isb
 * (clean D-cache to the Point of Unification, then discard the stale L1I line, then
 * synchronize the pipeline).  Both ops are legal at EL0 on Armv8 -- *if* the kernel
 * left SCTLR_EL1.UCI/UCT permissive -- otherwise they take an undefined-instruction
 * trap at EL1 and we get SIGILL.  That question is worth one zero-risk device run,
 * because it decides how the gate patch (§175 alias + one instruction word) converges:
 *   ALLOWED  -> per-core, per-line flush of the *original* gate VA.  Deterministic,
 *               and CPU0 (which can never be offlined, §178) converges like the rest.
 *   SIGILL   -> keep icache_sync + the cpuN/online cycle as the only convergence path.
 *
 * selftest is the part that proves the ops have an *effect*, not just that they execute:
 * the same physical page is mapped twice (RX at one VA, RW at another -- exactly the
 * alias geometry we use on the kernel side), the RX side is warmed so its line is
 * cached, the RW side then overwrites the instruction, and we count how many of the
 * following calls still return the OLD value.  Four phases (none / d-only / i-only /
 * full) turn "it ran" into "it changed behaviour"; a phase that cannot fail is not a
 * control.
 *
 * usage:
 *   elflush selftest [file]                     # user-space only, no kernel target
 *   elflush probe  <hex-va>                     # harmless: clean+invalidate a mapped
 *                                               # kernel text line (invalidation only)
 *   elflush sync   <hex-va> [hex-va...]         # the convergence step, pin per CPU
 *   ELF_WARM=20000 ELF_CALLS=2000 elflush selftest
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sched.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#define PAGE 4096
#define LINE 64

#define MOV_W0_0x11 0x52800220u /* movz w0, #0x11 -> 17 */
#define MOV_W0_0x22 0x52800440u /* movz w0, #0x22 -> 34 */
#define RET_WORD 0xd65f03c0u

static sigjmp_buf jb;
static volatile sig_atomic_t caught;

static void on_sig(int sn)
{
	caught = sn;
	siglongjmp(jb, 1);
}

/* Run fn with SIGILL/SIGSEGV/SIGBUS turned into a return value, so a trapped cache op
 * reports instead of killing the run silently. */
static int guarded(void (*fn)(void *, void *), void *a, void *b)
{
	struct sigaction sa, old_ill, old_seg, old_bus;
	caught = 0;
	memset(&sa, 0, sizeof sa);
	sa.sa_handler = on_sig;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_NODEFER;
	sigaction(SIGILL, &sa, &old_ill);
	sigaction(SIGSEGV, &sa, &old_seg);
	sigaction(SIGBUS, &sa, &old_bus);
	if (sigsetjmp(jb, 1) == 0)
		fn(a, b);
	else
		fprintf(stderr, "    trapped: signal %d\n", (int)caught);
	sigaction(SIGILL, &old_ill, NULL);
	sigaction(SIGSEGV, &old_seg, NULL);
	sigaction(SIGBUS, &old_bus, NULL);
	return (int)caught;
}

static inline void dc_cvau(void *va)
{
	__asm__ volatile("dc cvau, %0" :: "r"(va));
}
static inline void ic_ivau(void *va)
{
	__asm__ volatile("ic ivau, %0" :: "r"(va));
}
static inline void dsb_ish(void)
{
	__asm__ volatile("dsb ish" ::: "memory");
}
static inline void isb_(void)
{
	__asm__ volatile("isb" ::: "memory");
}

/* phases: 0 none, 1 dc only, 2 ic only, 3 full sequence */
static void do_phase(void *a, void *line)
{
	int p = (int)(uintptr_t)a;
	if (p == 1 || p == 3)
		dc_cvau(line);
	if (p >= 2)
		ic_ivau(line);
	dsb_ish();
	if (p >= 2)
		isb_();
}

static void flush_line(void *va, void *unused)
{
	(void)unused;
	dc_cvau((void *)((uintptr_t)va & ~(uintptr_t)(LINE - 1)));
	ic_ivau((void *)((uintptr_t)va & ~(uintptr_t)(LINE - 1)));
	dsb_ish();
	isb_();
}

typedef int (*fn_t)(void);

static long envl(const char *k, long d)
{
	const char *v = getenv(k);
	return (v && *v) ? strtol(v, NULL, 10) : d;
}

/* Call f n times, count how many return `stale`, and record where the answer changed.
 * The compiler barrier keeps the loop from collapsing into one hoisted call. */
static void measure(fn_t f, int stale_val, int n, long *stale, long *first_new)
{
	long s = 0, i;
	*first_new = -1;
	for (i = 0; i < n; i++) {
		int r;
		__asm__ volatile("" ::: "memory");
		r = f();
		if (r == stale_val) {
			s++;
		} else if (*first_new < 0) {
			*first_new = i;
		}
	}
	*stale = s;
}

static int selftest(const char *path)
{
	const long warm = envl("ELF_WARM", 20000);
	const long calls = envl("ELF_CALLS", 2000);
	int fd, ph;
	void *rx, *rw;
	fn_t f;
	uint32_t *w;
	int sigc[4] = { 0, 0, 0, 0 };
	long stalec[4] = { 0, 0, 0, 0 };

	fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0755);
	if (fd < 0) {
		printf("SELFTEST SKIP: open %s: %s\n", path, strerror(errno));
		return 2;
	}
	if (ftruncate(fd, PAGE) != 0) {
		printf("SELFTEST SKIP: ftruncate: %s\n", strerror(errno));
		return 2;
	}

	printf("selftest: one physical page, mapped RX at one VA and RW at another; %ld warm "
	       "calls then a patch then %ld measured calls per phase\n",
	       warm, calls);
	printf("phase    result after patch                    verdict\n");
	for (ph = 0; ph < 4; ph++) {
		long stale, first_new, ok;
		int sig = 0;
		rw = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
		if (rw == MAP_FAILED) {
			printf("  mmap RW failed: %s\n", strerror(errno));
			return 2;
		}
		/* old bytes, written through the RW mapping so no writeback path is involved */
		w = rw;
		w[0] = MOV_W0_0x11;
		w[1] = RET_WORD;
		munmap(rw, PAGE);

		rx = mmap(NULL, PAGE, PROT_READ | PROT_EXEC, MAP_SHARED, fd, 0);
		if (rx == MAP_FAILED) {
			printf("  mmap RX failed: %s (exec of %s is what the shell domain must allow)\n",
			       strerror(errno), path);
			return 2;
		}
		rw = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
		if (rw == MAP_FAILED) {
			printf("  mmap RW (2nd) failed: %s\n", strerror(errno));
			munmap(rx, PAGE);
			return 2;
		}
		f = (fn_t)rx;
		/* warm: put the OLD line in this core's L1I and prove it is the cached one */
		for (ok = 0; ok < warm; ok++)
			if (f() != 0x11)
				break;

		w = rw;
		w[0] = MOV_W0_0x22; /* patch, same core, no syscall in between */

		if (ph)
			sig = guarded(do_phase, (void *)(uintptr_t)ph, (void *)rx);
		measure(f, 0x11, (int)calls, &stale, &first_new);
		sigc[ph] = sig;
		stalec[ph] = stale;
		printf("  %s %-4s stale=%ld/%ld first_new=%ld  warm_ok=%ld/%ld %s\n",
		       ph ? "flush" : "none", ph == 1 ? "(dc)" : ph == 2 ? "(ic)" : ph == 3 ? "(both)" : "    ",
		       stale, calls, first_new, ok, warm,
		       stale == 0 ? "-> sees the new bytes" : "-> L1I still holds the old line");
		munmap(rx, PAGE);
		munmap(rw, PAGE);
	}
	printf("verdict:\n");
	printf("  ops at EL0: %s\n", (sigc[1] | sigc[2] | sigc[3])
				       ? "TRAPPED -- user space cannot flush a kernel line here"
				       : "ALLOWED (no signal on dc cvau / ic ivau)");
	printf("  ruler has teeth: %s (unflushed phase kept %ld/%ld calls on the old instruction)\n",
	       stalec[0] > 0 ? "YES" : "NO -- nothing got cached, this run cannot decide", stalec[0], calls);
	printf("  flush changes behaviour: %s\n", (stalec[0] > 0 && (stalec[2] == 0 || stalec[3] == 0))
						       ? "YES (ic ivau made the new bytes visible)"
						       : stalec[0] == 0 ? "INCONCLUSIVE (no staleness to remove)"
									: "NO -- the ops ran but stale lines survived");
	printf("  note: 'ALLOWED' only means not trapped.  Whether the op actually reaches a\n"
	       "  privileged (TTBR1) line is decided by the on-device verdict ruler, not here.\n");
	close(fd);
	return 0;
}

int main(int argc, char **argv)
{
	const char *mode = argc > 1 ? argv[1] : "";
	const char *cpus = getenv("CPU");

	/* This device's taskset is the toybox one: it takes a MASK and prints a usage message
	 * for "-c N" -- so a pinned call that "ran" may have run nothing.  Pin ourselves. */
	if (cpus && *cpus) {
		cpu_set_t set;
		int cpu = atoi(cpus);
		CPU_ZERO(&set);
		CPU_SET(cpu, &set);
		if (sched_setaffinity(0, sizeof set, &set) != 0)
			printf("  pin cpu%d failed: %s\n", cpu, strerror(errno));
	}

	if (!strcmp(mode, "selftest"))
		return selftest(argc > 2 ? argv[2] : "/data/local/tmp/elf.bin");

	if (!strcmp(mode, "probe") || !strcmp(mode, "sync")) {
		int i, rc = 0;
		if (argc < 3) {
			printf("need at least one VA\n");
			return 2;
		}
		for (i = 2; i < argc; i++) {
			unsigned long long va = strtoull(argv[i], NULL, 16);
			int sig = guarded(flush_line, (void *)(uintptr_t)va, NULL);
			printf("  %s dc cvau+ic ivau 0x%llx -> %s\n",
			       strcmp(mode, "probe") ? "sync" : "probe", va,
			       sig ? "TRAPPED" : "ALLOWED");
			if (sig)
				printf("      signal %d -- EL0 cache maintenance is not permitted here\n", sig);
			rc |= sig;
		}
		if (rc)
			printf("VERDICT: EL0 ops TRAPPED -> use icache_sync + cpu hotplug for convergence\n");
		else
			printf("VERDICT: EL0 ops ALLOWED and no fault on those VAs\n");
		return rc ? 1 : 0;
	}

	printf("usage: elflush selftest [file] | probe <hex-va> | sync <hex-va> [hex-va...]\n");
	return 2;
}
