/* Dev-only bootstrap for the Android 7 route.  The ladder execs $DAEMON7 as the root task it just
 * became, and that exec is the ONLY root entry this ROM gives us without a screen tap, so pointing
 * DAEMON7 here temporarily adds adb's uid to the daemon's grant list and then chains into the real
 * daemon.  It is never an APK asset (build.sh packs broot7/sud/libesc.so only) and the shipped
 * shape -- which is what tools/verify_approot.sh judges -- grants the manager app alone.
 * Revert after use: rewrite grants.txt to the single line the app wrote and prove the channel
 * denies adb again (`su7x -c id` must answer `ERR unknown service`). */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <unistd.h>

#define GRANTS "/data/user/0/com.xplay6.temproot/files/grants.txt"
#define DAEMON "/data/local/tmp/sudd"

int main(void)
{
	char buf[4096], out[4096];
	int fd, n, wp, keep = 0, have2000 = 0;

	/* Written canonically, never appended: a previous run's `printf '10151\n'` came through the
	 * daemon's command splitting as `printf 10151n`, which left the list holding the line
	 * `10151n` -- a line that names NO uid, so the manager app lost its own grant (measured
	 * 2026-10-20: `grantsh: grants before=[10151n]`).  So this helper rebuilds the file from the
	 * well-formed numeric lines it finds plus adb's uid. */
	fd = open(GRANTS, O_RDWR);
	if (fd < 0) {
		printf("grantsh: open %s failed errno=%d (%s)\n", GRANTS, errno, strerror(errno));
	} else {
		n = read(fd, buf, sizeof buf - 24);
		if (n < 0) {
			printf("grantsh: read failed errno=%d, list untouched\n", errno);
			n = 0;
		}
		buf[n] = 0;
		wp = 0;
		out[0] = 0;
		{
			char *save = NULL, *ln = strtok_r(buf, "\n", &save);

			while (ln) {
				int digits = 0, i;

				for (i = 0; ln[i]; i++)
					if (ln[i] >= '0' && ln[i] <= '9')
						digits++;
				if (digits == (int)strlen(ln) && digits > 0) {
					if (atoi(ln) == 2000)
						have2000 = 1;
					else
						wp += snprintf(out + wp, sizeof out - wp, "%s\n", ln);
					keep++;
				} else {
					printf("grantsh: dropping malformed line [%s]\n", ln);
				}
				ln = strtok_r(NULL, "\n", &save);
			}
		}
		if (!have2000)
			wp += snprintf(out + wp, sizeof out - wp, "2000\n");
		if (ftruncate(fd, 0) < 0)
			printf("grantsh: ftruncate failed errno=%d\n", errno);
		else if (lseek(fd, 0, SEEK_SET) < 0 || write(fd, out, wp) != wp)
			printf("grantsh: rewrite failed errno=%d\n", errno);
		printf("grantsh: rewrote list kept=%d adb_granted=%d content=[%s]\n", keep, !have2000, out);
		fsync(fd);
		close(fd);
	}
	fflush(stdout);
	/* Dev-only: the same process is the closest thing we get to the daemon's own context (uid 0 in
	 * the ladder's patched cred, inside the permissive window, before sud relabels), so run the bind
	 * probe here -- the daemon's three AF_UNIX listeners failed with errno=1 while adb shell binds
	 * abstract names happily (measured 2026-10-20), and that difference is what decides whether a
	 * third-party app can be authenticated at all on this ROM. */
	{
		pid_t k = fork();

		if (k == 0) {
			int fd = open("/data/local/tmp/bindprobe-root.txt", O_WRONLY | O_CREAT | O_TRUNC, 0644);

			if (fd >= 0) {
				dup2(fd, 1);
				dup2(fd, 2);
				close(fd);
			}
			execl("/data/local/tmp/absprobe", "absprobe", (char *)0);
			_exit(127);
		} else if (k > 0)
			waitpid(k, NULL, 0);
		fflush(stdout);
	}
	execl(DAEMON, DAEMON, (char *)0);
	printf("grantsh: exec %s failed errno=%d (%s)\n", DAEMON, errno, strerror(errno));
	fflush(stdout);
	return 1;
}
