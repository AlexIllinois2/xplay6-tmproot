/* appprobe.c -- run the exploit's *syscall face* inside a real app context and
 * report, per step, whether it is reachable.
 *
 * Why this exists: the APK route (boot-time self-escalation) must do the whole
 * clobber chain from an `untrusted_app` process, i.e. from a SELinux domain we
 * do not control and with a non-root uid.  Everything in the chain except the
 * kernel write itself goes through ordinary syscalls, so each one is either
 * permitted to appdomain or not -- and if any is not, the APK plan is dead and
 * we need the adb path only.
 *
 * How we measure it without flipping the enforcing flag: this kernel logs AVC
 * decisions even in permissive mode ("... permissive=1", verified on-device),
 * so we setcon() to u:r:untrusted_app:s0, drop to a real app uid, run the ops,
 * then read the denials for comm="appprobe" out of the kmsg buffer.  rc/errno
 * gives the DAC+MAC *effect*, the logged denial gives the *would-be* decision.
 *
 * usage: appprobe <uid> [context]      (default context u:r:untrusted_app:s0)
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/epoll.h>
#include <sys/un.h>
#include <sys/inotify.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <netinet/in.h>

#ifndef BINDER_VERSION
/* <linux/binder.h> is not in the NDK headers; the two ioctls we need, from
 * 3.18's Binder.h: _IOR('b', 9, struct binder_version) and the transaction size. */
struct binder_version { int protocol_version; };
#define BINDER_VERSION _IOR('b', 9, struct binder_version)
#define BINDER_WRITE_READ _IOWR('b', 1, struct binder_write_read)
#endif

struct binder_write_read {
	long unsigned write_size;
	long unsigned write_consumed;
	long unsigned read_size;
	long unsigned consumed_buffer;
	long unsigned write_buffer;
	long unsigned read_buffer;
};

static void step(const char *name, long rc, int e)
{
	printf("STEP %-28s rc=%ld errno=%d %s\n", name, rc, e,
	       rc < 0 ? (e == EACCES ? "PERM_DENIED" : e == EPERM ? "OPERATION_NOT_PERMITTED" :
	                 e == ENOENT ? "NOENT" : e == EAFNOSUPPORT ? "AF_NOSUPPORT" :
	                 e == ENODEV ? "NODEV" : strerror(e)) : "OK");
	fflush(stdout);
}

static void run(const char *name, long rc)
{
	step(name, rc, rc < 0 ? errno : 0);
}

int main(int argc, char **argv)
{
	int uid = argc > 1 ? atoi(argv[1]) : 10132;
	const char *ctx = argc > 2 ? argv[2] : "u:r:untrusted_app:s0";
	char idbuf[256];
	int fd, s, ep, n;
	struct epoll_event ev;
	struct binder_version bv;
	pid_t pid = getpid();

	printf("=== appprobe pid=%d start uid=%d ctx=%s ===\n", pid, uid, ctx);

	/* 1. become the app domain (permissive lets this through and logs it) */
	fd = open("/proc/self/attr/current", O_WRONLY);
	if (fd < 0)
		step("setcon-open", -1, errno);
	else {
		n = write(fd, ctx, strlen(ctx));
		step("setcon", n < 0 ? -1 : 0, n < 0 ? errno : 0);
		close(fd);
	}
	fd = open("/proc/self/attr/current", O_RDONLY);
	if (fd >= 0) {
		n = read(fd, idbuf, sizeof idbuf - 1);
		if (n > 0) {
			idbuf[n] = 0;
			printf("selfcon now: %s\n", idbuf);
		}
		close(fd);
	}

	/* 2. drop DAC to the app uid */
	if (setgroups(0, NULL) < 0)
		step("setgroups(0)", -1, errno);
	gid_t g = (gid_t) uid;
	run("setresgid", setresgid(g, g, g));
	run("setresuid", setresuid((uid_t) uid, (uid_t) uid, (uid_t) uid));
	printf("id now: uid=%d euid=%d gid=%d\n", getuid(), geteuid(), getgid());

	/* 3. the exploit's dependencies, in the order clobber.c touches them */
	fd = open("/dev/binder", O_RDWR);
	step("open /dev/binder", fd, fd < 0 ? errno : 0);
	if (fd >= 0) {
		memset(&bv, 0, sizeof bv);
		run("ioctl BINDER_VERSION", ioctl(fd, BINDER_VERSION, &bv));
		if (bv.protocol_version)
			printf("  binder protocol_version=%d\n", bv.protocol_version);
		memset(&bv, 0, sizeof bv);
		/* the real chain's BC_TRANSACTION goes through BINDER_WRITE_READ; use a
		 * deliberately empty write buffer so this probe cannot change any state:
		 * the driver must at least accept the ioctl shape (rc==0) or EINVAL it,
		 * and either way SELinux has already granted/denied chr_file:ioctl. */
		struct binder_write_read bwr;
		memset(&bwr, 0, sizeof bwr);
		run("ioctl BINDER_WRITE_READ(empty)", ioctl(fd, BINDER_WRITE_READ, &bwr));
		run("read /dev/binder", read(fd, &bv, sizeof bv));

		ep = epoll_create1(0);
		step("epoll_create1", ep, ep < 0 ? errno : 0);
		if (ep >= 0) {
			memset(&ev, 0, sizeof ev);
			ev.events = EPOLLIN;
			ev.data.fd = fd;
			run("epoll_ctl ADD binder", epoll_ctl(ep, EPOLL_CTL_ADD, fd, &ev));
			run("epoll_ctl DEL binder", epoll_ctl(ep, EPOLL_CTL_DEL, fd, NULL));
			close(ep);
		}
		close(fd);
	}

	int p[2];
	if (pipe(p) < 0) {
		step("pipe", -1, errno);
	} else {
		run("fcntl F_SETPIPE_SZ", fcntl(p[0], F_SETPIPE_SZ, 4096));
		char b[8];
		struct iovec io = { b, sizeof b };
		run("writev(pipe)", writev(p[1], &io, 1));
		run("readv(pipe)", readv(p[0], &io, 1));
		close(p[0]);
		close(p[1]);
	}

	/* the iovec array the chain smashes lives in malloc'd memory; prove an app
	 * can get the pages at all, then prove an anonymous exec mapping (which the
	 * chain does NOT need, but the later stages might). */
	void *m = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	step("mmap rw anon", (long) (m != MAP_FAILED ? 0 : -1), m == MAP_FAILED ? errno : 0);
	void *x = mmap(NULL, 4096, PROT_READ | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	step("mmap rx anon", (long) (x != MAP_FAILED ? 0 : -1), x == MAP_FAILED ? errno : 0);

	/* 4. the su channel shapes we might use after escalation */
	s = socket(AF_UNIX, SOCK_STREAM, 0);
	step("socket AF_UNIX", s, s < 0 ? errno : 0);
	if (s >= 0) {
		struct sockaddr_un a;
		memset(&a, 0, sizeof a);
		a.sun_family = AF_UNIX;
		a.sun_path[0] = 0;
		strcpy(a.sun_path + 1, "appprobe.abs");
		run("bind abstract unix", bind(s, (struct sockaddr *) &a, sizeof(sa_family_t) + 1 + 14));
		run("listen", listen(s, 1));
		close(s);
	}
	s = socket(AF_INET, SOCK_STREAM, 0);
	step("socket AF_INET", s, s < 0 ? errno : 0);
	if (s >= 0) {
		struct sockaddr_in a;
		memset(&a, 0, sizeof a);
		a.sin_family = AF_INET;
		a.sin_port = htons(12345);
		a.sin_addr.s_addr = htonl(0x7f000001);
		/* expected to fail (connection refused or MAC denial): the point is the
		 * errno pair -- EACCES/EPERM means the *socket* is blocked, anything else
		 * means only the peer was absent. */
		step("connect 127.0.0.1:12345(root daemon)", connect(s, (struct sockaddr *) &a, sizeof a), errno);
		close(s);
	}
	s = socket(AF_PACKET, SOCK_RAW, htons(3));
	step("socket AF_PACKET raw", s, s < 0 ? errno : 0);
	if (s >= 0)
		close(s);
	s = socket(AF_NETLINK, SOCK_RAW, 0 /* KNL */);
	step("socket AF_NETLINK knl", s, s < 0 ? errno : 0);
	if (s >= 0)
		close(s);

	/* 5. DAC/MAC controls that must be denied to a real app */
	run("open /data/system/packages.xml", open("/data/system/packages.xml", O_RDONLY));
	run("open /data/local/tmp/clobber", open("/data/local/tmp/clobber", O_RDONLY));
	run("write /data/local/tmp/appprobe.w", open("/data/local/tmp/appprobe.w", O_WRONLY | O_CREAT | O_TRUNC, 0644));
	DIR *d = opendir("/data/data");
	step("opendir /data/data", (long) (d ? 0 : -1), d ? 0 : errno);
	if (d)
		closedir(d);

	printf("=== appprobe done (uid now %d) ===\n", getuid());
	return 0;
}
