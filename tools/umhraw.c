/* No-libc witness for "does a kmod-exec'd task ever reach userspace on this kernel".
 *
 * On official 7.1.1 the helper is spawned and the ELF loader runs (dmesg shows
 * { execute } { read open } { execute_no_trans } for the payload, all permissive=1), yet
 * neither kmodmark nor rootsh -- both -static bionic binaries that run fine from adb shell --
 * creates its proof file or issues a single syscall.  That leaves two very different stories
 * ("userspace starts but bionic init dies" vs "exec never transfers control"), and no libc
 * payload can tell them apart because libc init is exactly what's in question.  So this one
 * has no startup code at all: the first instruction issues getuid(), and the first observable
 * is a file created by a raw openat().  No PT_INTERP, no .init_array, no errno, no stdio.
 *
 * Record layout: four little-endian int64 -- uid, euid, pid, ppid.  If the file exists the
 * helper ran; if it lists uid=0 the credentials came through.
 *
 * Build (not in build_all.sh's PIECES, which compiles everything with -static against libc):
 *   $CC -target aarch64-linux-android21 -O2 -Wall -nostdlib -static -Wl,-e,_start \
 *       -o tools/umhraw tools/umhraw.c
 */
#include <fcntl.h>
#include <sys/syscall.h>

static long sc1(long n, long a)
{
	register long x8 __asm__("x8") = n;
	register long x0 __asm__("x0") = a;

	__asm__ volatile("svc #0" : "+r"(x0) : "r"(x8)
			 : "memory", "x1", "x2", "x3", "x4", "x5", "x6", "x7");
	return x0;
}

static long sc3(long n, long a, long b, long c)
{
	register long x8 __asm__("x8") = n;
	register long x0 __asm__("x0") = a;
	register long x1 __asm__("x1") = b;
	register long x2 __asm__("x2") = c;

	__asm__ volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2)
			 : "memory", "x3", "x4", "x5", "x6", "x7");
	return x0;
}

static long sc4(long n, long a, long b, long c, long d)
{
	register long x8 __asm__("x8") = n;
	register long x0 __asm__("x0") = a;
	register long x1 __asm__("x1") = b;
	register long x2 __asm__("x2") = c;
	register long x3 __asm__("x3") = d;

	__asm__ volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2), "r"(x3)
			 : "memory", "x4", "x5", "x6", "x7");
	return x0;
}

static const char path[] = "/data/local/tmp/umhraw.ok";

void _start(void)
{
	long rec[4];

	rec[0] = sc1(__NR_getuid, 0);
	rec[1] = sc1(__NR_geteuid, 0);
	rec[2] = sc1(__NR_getpid, 0);
	rec[3] = sc1(__NR_getppid, 0);

	long fd = sc4(__NR_openat, AT_FDCWD, (long)path,
		      O_WRONLY | O_CREAT | O_TRUNC, 0666);

	if (fd >= 0) {
		sc3(__NR_write, fd, (long)rec, sizeof rec);
		sc1(__NR_close, fd);
	}
	sc1(__NR_exit, 0);
	for (;;)
		;
}
