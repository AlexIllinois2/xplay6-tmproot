/* Why did the daemon's three AF_UNIX listeners fail with errno=1 while both TCP ones came up?
 * Run this AS the daemon would run it -- root, inside the permissive window, after the ladder's
 * cred swap -- because none of the interesting causes (domain, namespace, stale file, capability
 * clamp) are visible from adb shell.  Written to /data/local/tmp/bindprobe.txt, which is readable
 * without any privilege.  Dev-only tool: it is not an APK asset. */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <grp.h>
#include <sys/capability.h>
#include <linux/capability.h>
#include <unistd.h>

static void one(const char *label, int abstract, const char *path, int cloexec)
{
	struct sockaddr_un a;
	int fd, flags, len;

	flags = SOCK_STREAM | (cloexec ? SOCK_CLOEXEC : 0);
	fd = socket(AF_UNIX, flags, 0);
	if (fd < 0) {
		printf("%s: socket() errno=%d (%s)\n", label, errno, strerror(errno));
		return;
	}
	memset(&a, 0, sizeof a);
	a.sun_family = AF_UNIX;
	if (abstract) {
		len = (int)(sizeof(a.sun_family) + 1 + strlen(path));
		a.sun_path[0] = 0;
		memcpy(a.sun_path + 1, path, strlen(path));
	} else {
		len = (int)sizeof(a.sun_family) + (int)strlen(path) + 1;
		strncpy(a.sun_path, path, sizeof a.sun_path - 1);
	}
	errno = 0;
	if (bind(fd, (struct sockaddr *)&a, len) < 0) {
		printf("%s: bind errno=%d (%s)  after unlink? %s\n", label, errno, strerror(errno),
		       abstract ? "n/a (abstract)" : "yes");
		close(fd);
		return;
	}
	if (listen(fd, 4) < 0)
		printf("%s: bind OK but listen errno=%d (%s)\n", label, errno, strerror(errno));
	else
		printf("%s: BIND+LISTEN OK\n", label);
	close(fd);
	if (!abstract)
		unlink(path);
}


static int bind_once(int type, int abstract, const char *path)
{
	struct sockaddr_un a;
	int fd, len, rc;

	fd = socket(AF_UNIX, type, 0);
	if (fd < 0) { printf("  socket errno=%d (%s)\n", errno, strerror(errno)); return -1; }
	memset(&a, 0, sizeof a);
	a.sun_family = AF_UNIX;
	if (abstract) {
		len = (int)(sizeof(a.sun_family) + 1 + strlen(path));
		a.sun_path[0] = 0;
		memcpy(a.sun_path + 1, path, strlen(path));
	} else {
		len = (int)sizeof(a.sun_family) + (int)strlen(path) + 1;
		strncpy(a.sun_path, path, sizeof a.sun_path - 1);
	}
	rc = bind(fd, (struct sockaddr *)&a, len);
	printf("  %s %s: %s (errno=%d)\n", type == SOCK_DGRAM ? "DGRAM" : "STREAM",
	       abstract ? path : "as path", rc == 0 ? "OK" : "FAILED", rc == 0 ? 0 : errno);
	if (rc == 0 && !abstract)
		unlink(path);
	close(fd);
	return rc;
}

/* What actually separates this task from adb shell?  Not the domain (both bind fine as shell and
 * fail as us), not SELinux (the window has enforcing off), not the mount namespace.  So ask the
 * kernel directly: same task, same cred lineage, only the ids changed. */

/* Raise the capability sets as far as this cred lets us (CAP_SETPCAP is inside the clamp we
 * installed: 0x3f0000fffe = caps 1..15 + 32..37, so MAC_OVERRIDE(24)/SYS_ADMIN(21)/CHOWN(0) are
 * the notable ABSENT ones -- a vendor LSM that asks "root but no MAC override?" would produce an
 * EPERM that SELinux cannot explain, because the window has enforcing off). */
static void try_cap_raise(void)
{
	struct __user_cap_header_struct h = { _LINUX_CAPABILITY_VERSION_3, 0 };
	struct __user_cap_data_struct d[2];
	int e;

	if (capget(&h, d) < 0) { printf("capget errno=%d (%s)\n", errno, strerror(errno)); return; }
	printf("cap before: eff=%08x:%08x perm=%08x:%08x\n",
	       d[0].effective, d[1].effective, d[0].permitted, d[1].permitted);
	e = bind_once(SOCK_STREAM, 1, "sudtest.beforecap");
	d[0].effective |= 0xfffffffeu;          /* caps 1..31, cap_chown(0) added below */
	d[0].permitted |= 0xfffffffeu;
	d[0].inheritable |= 0xfffffffeu;
	d[1].effective |= 0xffffffffu;          /* caps 32..63 */
	d[1].permitted |= 0xffffffffu;
	d[1].inheritable |= 0xffffffffu;
	d[0].effective |= 1u; d[0].permitted |= 1u;   /* CAP_CHOWN */
	if (capset(&h, d) < 0)
		printf("capset errno=%d (%s) -- cannot test the capability theory\n",
		       errno, strerror(errno));
	else {
		printf("after capset: bind result was %d, retry:\n", e);
		bind_once(SOCK_STREAM, 1, "sudtest.aftercap");
		bind_once(SOCK_STREAM, 0, "/data/local/tmp/probe.aftercap");
	}
}

static void who_can_bind(void)
{
	uid_t r, e, s;
	gid_t g[32];
	int n;

	printf("--- same task, ids varied ---\n");
	try_cap_raise();
	getresuid(&r, &e, &s);
	printf("start ruid=%u euid=%u suid=%u\n", r, e, s);
	bind_once(SOCK_STREAM, 1, "sudtest.uid0");
	if (setregid((gid_t) -1, (gid_t) -1) < 0)
		printf("setregid noop errno=%d\n", errno);
	n = getgroups(32, g);
	printf("ngroups=%d\n", n);
	if (setgroups(1, g ? g : (gid_t[]){3003}) < 0)
		printf("setgroups errno=%d (%s)\n", errno, strerror(errno));
	printf("after setgroups: ngroups=%d\n", getgroups(32, g));
	bind_once(SOCK_STREAM, 1, "sudtest.ng0");
	if (setresuid(2000, 2000, 2000) == 0) {
		printf("now ruid=2000 (same domain, same lineage):\n");
		bind_once(SOCK_STREAM, 1, "sudtest.uid2000");
		bind_once(SOCK_DGRAM, 1, "sudtest.dgram");
		bind_once(SOCK_STREAM, 0, "/data/local/tmp/probe.uid2000");
		if (setresuid(0, 0, 0) == 0) {
			printf("back to uid 0:\n");
			bind_once(SOCK_STREAM, 1, "sudtest.uid0again");
		} else
			printf("setresuid back to 0 errno=%d (%s)\n", errno, strerror(errno));
	} else
		printf("setresuid(2000) errno=%d (%s) -- cannot run this discriminator\n",
		       errno, strerror(errno));
}

static void ctx_and_ns(void)
{
	char buf[256];
	FILE *f;
	int fd;

	f = fopen("/proc/self/attr/current", "r");
	if (f) {
		buf[0] = 0;
		if (fgets(buf, sizeof buf, f))
			printf("context=%s", buf);
		fclose(f);
	}
	f = fopen("/proc/self/status", "r");
	if (f) {
		while (fgets(buf, sizeof buf, f))
			if (!strncmp(buf, "NSpid", 5) || !strncmp(buf, "CapEff", 6) || !strncmp(buf, "Uid", 3))
				printf("status:%s", buf);
		fclose(f);
	}
	fd = open("/proc/self/ns/mnt", O_RDONLY);
	if (fd >= 0) {
		struct stat st;

		if (fstat(fd, &st) == 0)
			printf("mnt ns inode=%llu\n", (unsigned long long) st.st_ino);
		close(fd);
	}
	fd = open("/proc/1/ns/mnt", O_RDONLY);
	if (fd >= 0) {
		struct stat st;

		if (fstat(fd, &st) == 0)
			printf("init mnt ns inode=%llu\n", (unsigned long long) st.st_ino);
		close(fd);
	}
}

/* The daemon relabels BEFORE it binds (sud.c: relabel_for_sockets() then listen_abs()), and the
 * shell-domain probe above already proved abstract binds work on this kernel -- so reproduce the
 * daemon's own state: setcon to init, then bind. */
static void try_setcon(const char *ctx)
{
	int fd = open("/proc/self/attr/current", O_WRONLY);

	if (fd < 0) { printf("setcon open errno=%d (%s)\n", errno, strerror(errno)); return; }
	if (write(fd, ctx, strlen(ctx)) < 0)
		printf("setcon %s errno=%d (%s)\n", ctx, errno, strerror(errno));
	else
		printf("setcon %s ok\n", ctx);
	close(fd);
}

int main(void)
{
	setvbuf(stdout, NULL, _IOLBF, 0);
	printf("=== absprobe: can this task bind AF_UNIX at all? ===\n");
	ctx_and_ns();
	try_setcon("u:r:init:s0");
	ctx_and_ns();
	one("abstract @sudtest (AFTER setcon init)", 1, "sudtest", 1);
	one("path /data/local/tmp/.sud/probe2.sock (AFTER setcon init)", 0, "/data/local/tmp/.sud/probe2.sock", 1);
	one("abstract @sudtest (CLOEXEC)", 1, "sudtest", 1);
	one("abstract @sudtest (plain)", 1, "sudtest", 0);
	one("abstract @trq1234.5678 (what the client uses)", 1, "trq1234.5678", 1);
	mkdir("/data/local/tmp/.sud", 0711);
	one("path /data/local/tmp/.sud/probe.sock", 0, "/data/local/tmp/.sud/probe.sock", 1);
	one("path /data/local/tmp/probe.sock", 0, "/data/local/tmp/probe.sock", 1);
	mkdir("/dev/.sud", 0711);
	one("path /dev/.sud/probe.sock", 0, "/dev/.sud/probe.sock", 1);
	who_can_bind();
	printf("ABSProbeDone\n");
	return 0;
}
