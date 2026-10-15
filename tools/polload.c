/* Executed as modprobe_path (lands in whatever domain the payload's label selects),
 * so this measures "can THIS domain load a policy" -- and under permissive we can tell
 * MAC-refused-but-tolerated (an avc line is logged) from genuinely allowed (no line).
 * Appends its reading to /data/local/tmp/polload.out because stdout is /dev/null here. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

static int out;
static void say(const char *fmt, ...)
{
	char b[400];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(b, sizeof b, fmt, ap);
	va_end(ap);
	write(out, b, strlen(b));
}

int main(int argc, char **argv)
{
	unsigned char *buf;
	struct stat st;
	char con[128], have[64];
	const char *p;
	int f, fd, i;
	size_t cap, len;
	ssize_t n, r;

	out = open("/data/local/tmp/polload.out", O_WRONLY | O_CREAT | O_APPEND, 0666);
	if (out < 0)
		return 1;
	f = open("/proc/self/attr/current", O_RDONLY);
	if (f >= 0) {
		r = read(f, con, sizeof con - 1);
		if (r > 0) { con[r] = 0; while (r > 0 && (con[r-1]=='\n'||con[r-1]==0)) con[--r]=0; }
		close(f);
	} else
		snprintf(con, sizeof con, "(unreadable)");
	say("---- polload uid=%d ctx=%s\n", getuid(), con);
	/* kmod calls us AS modprobe_path, so argv is the kernel's module-autoload
	 * argument vector, not ours: fall back to a built-in policy path. */
	for (i = 0; i < argc && i < 5; i++)
		say("argv[%d]=%s\n", i, argv[i]);
	if (argc < 2) {
		snprintf(have, sizeof have, "/data/local/tmp/p2.bin");
		p = have;
	} else
		p = argv[1];
	fd = open(p, O_RDONLY);
	if (fd < 0) {
		/* Self-sufficient path: take the policy straight from the kernel so this
		 * measures both read_policy and load_policy for THIS domain without any
		 * file whose label could be the reason for an earlier errno. */
		say("open %s errno=%d -- falling back to /sys/fs/selinux/policy\n", p, errno);
		fd = open("/sys/fs/selinux/policy", O_RDONLY);
		if (fd < 0) { say("open policy dump errno=%d\n", errno); close(out); return 3; }
	}
	if (fstat(fd, &st) != 0) { say("fstat errno=%d\n", errno); close(out); return 4; }
	/* a sysfs attribute reports no useful size, so read into a fixed buffer to EOF */
	cap = (st.st_size > 0) ? (size_t)st.st_size + 1 : 4u * 1024 * 1024;
	buf = malloc(cap);
	if (!buf) { say("malloc %zu errno=%d\n", cap, errno); close(out); return 5; }
	len = 0;
	for (;;) {
		r = read(fd, buf + len, cap - len);
		if (r < 0) { say("read errno=%d\n", errno); close(out); return 6; }
		if (r == 0)
			break;
		len += r;
		if (len == cap) { say("buffer too small\n"); close(out); return 9; }
	}
	close(fd);
	say("policy bytes read=%zu magic=0x%02x%02x%02x%02x\n", len,
	    len > 3 ? buf[3] : 0, len > 2 ? buf[2] : 0, len > 1 ? buf[1] : 0, buf[0]);
	f = open("/sys/fs/selinux/load", O_WRONLY);
	if (f < 0) { say("open load errno=%d\n", errno); close(out); return 7; }
	n = write(f, buf, st.st_size);
	say("size=%lld write rc=%zd errno=%d %s\n", (long long)st.st_size, n, errno,
	    n == (ssize_t)len ? "LOADED" : "REFUSED");
	close(f);
	close(out);
	return n == (ssize_t)len ? 0 : 8;
}
