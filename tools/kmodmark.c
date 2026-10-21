/* Witness for "did kmod exec the helper at all, and as whom".
 *
 * rootsh writes its proof file as its very first action, so a missing proof means the exec
 * never happened -- but that conflates "helper not spawned" with "binary failed".  This one
 * records argv/cwd/uid/caps (the kernel gives the helper argv = path -q --install <name>)
 * and then sleeps, so `ps` can see it under its own comm.  No privileged action, no write
 * anywhere except its own log.
 */
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

#define LOG "/data/local/tmp/kmodmark.log"

int main(int argc, char **argv)
{
	char buf[4096];
	char cwd[256];
	int fd, n, i;
	FILE *f;

	n = 0;
	fd = open("/proc/self/status", O_RDONLY);
	if (fd >= 0) {
		n = read(fd, buf, sizeof buf - 1);
		close(fd);
	}
	if (n > 0)
		buf[n] = 0;
	else
		buf[0] = 0;

	f = fopen(LOG, "w");
	if (!f)
		return 1;
	fprintf(f, "ran: uid=%d euid=%d gid=%d egid=%d pid=%d\n",
		getuid(), geteuid(), getgid(), getegid(), (int)getpid());
	fprintf(f, "argv:");
	for (i = 0; i < argc; i++)
		fprintf(f, " [%s]", argv[i]);
	fprintf(f, "\ncwd: %s\n", getcwd(cwd, sizeof cwd) ? cwd : "(none)");
	fprintf(f, "--- /proc/self/status ---\n%s\n", buf);
	fflush(f);
	fsync(fileno(f));
	fclose(f);

	sleep(20);
	return 0;
}
