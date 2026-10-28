/* magisk_abs.c -- LD_PRELOAD shim that moves Magisk's daemon socket from the
 * filesystem namespace into the abstract (unnamed) namespace.
 *
 * WHY THIS EXISTS
 * ---------------
 * Magisk 30.7's daemon listens on a FILESYSTEM unix socket:
 *
 *     <magisk_tmp>/.magisk/device/socket        (MAIN_SOCKET)
 *
 * and the client connects to the same path.  On this device (vivo Xplay6,
 * Android 7.1.1, kernel 3.18.31) bind(2) on a filesystem AF_UNIX path fails
 * with EPERM in EVERY directory, in BOTH enforcing and permissive SELinux mode,
 * and produces NO avc entry -- i.e. it is a kernel-level hook, not a policy
 * decision.  The abstract namespace is unaffected: bind/listen/connect all work
 * there (measured with tools/mgabsprobe.c).
 *
 * So we translate the one path Magisk cares about into an abstract socket whose
 * name is derived from the path.  Both sides (daemon and client) run under the
 * same LD_PRELOAD, so they agree on the translated name without any change to
 * Magisk itself.
 *
 * The name is hashed to keep it short (abstract names are capped at 108 bytes)
 * and to avoid collisions with the system's other abstract sockets (@sud,
 * @suilst, @resmon, ...).
 *
 * WHAT IS HOOKED
 * --------------
 *   bind(2)      AF_UNIX + path ends with the Magisk socket suffix -> abstract
 *   connect(2)   AF_UNIX + same match                             -> abstract
 *   chmod/lstat/setxattr on the socket path are left alone: Magisk calls them
 *   with .log_ok(), so a failure there is tolerated, whereas bind() failing
 *   kills the daemon outright (daemon.rs: "let Ok(sock) = ... else { exit(1) }").
 *
 * Build (static .so, aarch64):
 *   clang -target aarch64-linux-android21 -O2 -fPIC -shared \
 *         -o magisk_abs.so magisk_abs.c
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>

typedef int (*bind_fn)(int, const struct sockaddr *, socklen_t);
typedef int (*connect_fn)(int, const struct sockaddr *, socklen_t);

/* The tail of Magisk's socket path.  MAIN_SOCKET is ".magisk/device/socket"
 * and it is always appended to the magisk tmp root, so matching the tail is
 * enough and it stays correct no matter which tmp root the daemon picked. */
static const char MAGISK_SOCK_SUFFIX[] = ".magisk/device/socket";

/* Every abstract socket we create gets this prefix so we never collide with
 * the system's own abstract names. */
static const char ABS_PREFIX[] = "magisk_abs_";

/* Magisk's tmp root resolves to "" on this device (neither /sbin/.magisk nor
 * /debug_ramdisk/.magisk exists), so MAIN_SOCKET stays a RELATIVE path and is
 * resolved against the process CWD.  That would make the daemon and its
 * clients agree only if they happened to run in the same directory, which is
 * not something we can guarantee for arbitrary callers.  So a relative path is
 * re-based onto this fixed directory before hashing: both sides then derive
 * the same abstract name no matter where they run.  The daemon itself still
 * runs with its CWD pinned here, because the log FIFO is created with the same
 * relative path and is not a socket (so the shim does not touch it).
 *
 * The base directory must match the one the module's service.sh uses as the
 * daemon's working directory, and it must be readable by an ordinary app:
 * /data/adb is 0700 root, so a client living in another app's sandbox could
 * not exec the daemon binary at all.  /data/local/tmp is 0771 and shell can
 * execute from it, so the runtime lives there.
 *
 * Both sides derive the abstract name from this exact string, so changing it
 * here means changing it in build_magisk_module.sh as well. */
static const char ABS_BASE[] = "/data/local/tmp/magisk_rt";

static bind_fn real_bind;
static connect_fn real_connect;

static void resolve(void)
{
	if (!real_bind)
		real_bind = (bind_fn)dlsym(RTLD_NEXT, "bind");
	if (!real_connect)
		real_connect = (connect_fn)dlsym(RTLD_NEXT, "connect");
}

/* FNV-1a over the path; the result gives a stable, collision-resistant
 * abstract name for the same path on both sides. */
static unsigned long long hash_path(const char *p)
{
	unsigned long long h = 14695981039346656037ULL;
	for (; *p; p++) {
		h ^= (unsigned char)*p;
		h *= 1099511628211ULL;
	}
	return h;
}

/* Build the abstract sockaddr for a given filesystem path.
 * Returns 0 on success, -1 if the name does not fit. */
static int make_abstract(const struct sockaddr_un *in, struct sockaddr_un *out)
{
	memset(out, 0, sizeof(*out));
	out->sun_family = AF_UNIX;

	const char *path = in->sun_path;

	/* Re-base a relative path onto ABS_BASE so daemon and clients agree
	 * regardless of their CWD. */
	char rebased[PATH_MAX];
	if (path[0] != '/') {
		if ((size_t)snprintf(rebased, sizeof(rebased), "%s/%s", ABS_BASE, path)
				>= sizeof(rebased))
			return -1;
		path = rebased;
	}

	unsigned long long h = hash_path(path);

	char name[sizeof(out->sun_path) - 1];
	int n = snprintf(name, sizeof(name), "%s%016llx", ABS_PREFIX, h);
	if (n < 0 || (size_t)n >= sizeof(name))
		return -1;

	/* Leading NUL byte = abstract namespace. */
	out->sun_path[0] = '\0';
	memcpy(out->sun_path + 1, name, (size_t)n);
	return 0;
}

static int is_magisk_sock(const struct sockaddr *sa)
{
	if (!sa || sa->sa_family != AF_UNIX)
		return 0;
	const struct sockaddr_un *un = (const struct sockaddr_un *)sa;
	if (un->sun_path[0] == '\0')
		return 0; /* already abstract: leave it alone */
	size_t plen = strnlen(un->sun_path, sizeof(un->sun_path));
	size_t slen = strlen(MAGISK_SOCK_SUFFIX);
	if (plen < slen)
		return 0;
	return strcmp(un->sun_path + plen - slen, MAGISK_SOCK_SUFFIX) == 0;
}

int bind(int fd, const struct sockaddr *addr, socklen_t len)
{
	resolve();
	if (is_magisk_sock(addr)) {
		struct sockaddr_un abs;
		if (make_abstract((const struct sockaddr_un *)addr, &abs) == 0)
			return real_bind(fd, (struct sockaddr *)&abs, sizeof(abs));
	}
	return real_bind(fd, addr, len);
}

int connect(int fd, const struct sockaddr *addr, socklen_t len)
{
	resolve();
	if (is_magisk_sock(addr)) {
		struct sockaddr_un abs;
		if (make_abstract((const struct sockaddr_un *)addr, &abs) == 0)
			return real_connect(fd, (struct sockaddr *)&abs, sizeof(abs));
	}
	return real_connect(fd, addr, len);
}
