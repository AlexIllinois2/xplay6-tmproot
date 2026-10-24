/* unix-stream relay for the su channel, to be run by the MANAGER APP, not by root.

 * Why it exists (art/ledger-20261016.md 623-625, measured on PD1610_D_7.12.15): after the route-7
 * escalation the borrowed credential can create/connect/accept AF_UNIX sockets but its
 * `bind()` of a SOCK_STREAM socket returns EPERM -- while SOCK_DGRAM binds fine, and an ordinary
 * unprivileged process (adb shell, and the manager app itself when it publishes `@trq<uid>.<pid>`)
 * binds stream sockets on this very kernel.  So the daemon, which is the borrowed task, can never
 * own the `@sud` stream listener that third-party apps would connect to, and without a stream
 * socket there is no SO_PEERCRED, so an external app has no kernel-given identity on the su
 * channel.  The fix keeps the trust model intact by moving only the LISTEN side to a process that
 * is allowed to bind: this relay takes the peer's uid from the kernel, applies the manager's own
 * allow list, and then asks sud over TCP with the manager's token -- `SU 0 <cmd> TOK=<token>` --
 * exactly the way Chain.java already asks it.  sud and its protocol are unchanged.

 * Identity stays kernel-given: the uid we authorize is getsockopt(SO_PEERCRED)'s, never anything
 * the caller says.  Authorization is still the manager's list (grants.txt), so revoking a uid
 * takes effect on the next connection.

 * usage:
 *   relayd --serve [--sock NAME] [--grants FILE] [--token FILE] [--up tcp:PORT|echo] [--log FILE]
 *   relayd --client [--sock NAME] <command...>
 *   relayd --selftest                      (serve+client in one process group; no sud needed)
 */
#include <errno.h>
#include <stdarg.h>
#include <fcntl.h>
#include <grp.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#define APP_UID_MIN 10000

static const char *g_grants = "/data/local/tmp/relayd-grants.txt";
static const char *g_token = "/data/local/tmp/relayd-token.txt";
static const char *g_log = "/data/local/tmp/relayd.log";
static const char *g_sock = "sud";
static int g_up_port = 12346;
static int g_echo;
static int g_hold;		/* selftest only: a request that stays open, like an interactive su */
static int g_if_free;

static void logf(const char *fmt, ...)
{
	char buf[512];
	va_list ap;
	FILE *f;
	int n;

	__builtin_va_start(ap, fmt);
	n = vsnprintf(buf, sizeof buf, fmt, ap);
	__builtin_va_end(ap);
	(void)n;
 fputs(buf, stdout);
	fflush(stdout);
	f = fopen(g_log, "a");
	if (f) {
		fputs(buf, f);
		fclose(f);
	}
}

static int write_all(int fd, const char *b, size_t n)
{
	while (n) {
		ssize_t k = write(fd, b, n);

		if (k <= 0)
			return -1;
		b += k;
		n -= (size_t) k;
	}
	return 0;
}

/* the manager's allow list, one uid per line; ours to write, ours to read */
static int allowed(uid_t uid)
{
	char line[64];
	FILE *f = fopen(g_grants, "r");

	if (!f)
		return 0;
	while (fgets(line, sizeof line, f))
		if (atoi(line) == (int) uid) {
			fclose(f);
			return 1;
		}
	fclose(f);
	return 0;
}

/* Relay both directions until BOTH sides are done.  A client that closes its write side
 * immediately -- suc does exactly that: interactive `su` writes the command, gets EOF on
 * stdin and shuts the socket down -- must still receive everything the responder prints;
 * tearing down on the first EOF (what this did until 2026-10-23) closed the upstream socket
 * before the shell had even run, so every app-side root call came back empty with exit 0. */
static void copy_both(int a, int b)
{
	fd_set r;
	int n, hi = a > b ? a : b;
	int a_open = 1, b_open = 1;

	while (a_open || b_open) {
		FD_ZERO(&r);
		if (a_open)
			FD_SET(a, &r);
		if (b_open)
			FD_SET(b, &r);
		n = select(hi + 1, &r, NULL, NULL, NULL);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return;
		}
		if (a_open && FD_ISSET(a, &r)) {
			char buf[4096];
			ssize_t k = read(a, buf, sizeof buf);

			if (k <= 0) {
				a_open = 0;
				shutdown(b, SHUT_WR);
			} else if (write_all(b, buf, (size_t) k) < 0)
				return;
		}
		if (b_open && FD_ISSET(b, &r)) {
			char buf[4096];
			ssize_t k = read(b, buf, sizeof buf);

			if (k <= 0) {
				b_open = 0;
				shutdown(a, SHUT_WR);
			} else if (write_all(a, buf, (size_t) k) < 0)
				return;
		}
	}
}

/* one accepted caller: kernel-given uid, allow list, then sud (or the test echo) */
static void serve_one(int c)
{
	struct ucred uc;
	char req[2048], rest[2048], out[2100];
	socklen_t l = sizeof uc;
 gid_t grp[32];
	int n, sfd = -1, tok = 0;
	size_t got = 0, restlen = 0;
	int nl = -1;
	FILE *tf;

	if (getsockopt(c, SOL_SOCKET, SO_PEERCRED, &uc, &l) < 0) {
		logf("relayd: SO_PEERCRED failed errno=%d (%s) -- refusing caller\n", errno, strerror(errno));
		write_all(c, "ERR cannot attribute caller\n", 28);
		close(c);
		return;
	}
	n = getgroups(32, grp);
	logf("relayd: caller pid=%d uid=%d gid=%d ngroups=%d\n", (int) uc.pid, (int) uc.uid,
	     (int) uc.gid, n);
	if (!g_echo) {
		/* a caller that is not an installed app is either root or a system uid; the manager's
		 * list is what decides, but refuse the ones that should never be asking us */
		if (uc.uid != 0 && uc.uid < APP_UID_MIN)
			logf("relayd: note: caller uid=%d is not an app uid\n", (int) uc.uid);
	}
	/* Read the request LINE and keep whatever follows it.  An interactive `su` (Snub's HShell
	 * writes its command, then closes stdin) sends "SU 0 -" and the first command in one TCP
	 * segment.  Truncating at the newline -- what this did until 2026-10-23 -- threw those
	 * bytes away, so the shell the responder exec'd got no input: every root call from an app
	 * returned empty output with exit code 0. */
	while (got < sizeof req - 1) {
		char *p;
		ssize_t k = read(c, req + got, sizeof req - 1 - got);

		if (k <= 0)
			break;
		p = memchr(req + got, '\n', (size_t) k);
		got += (size_t) k;
		if (p) {
			nl = (int) (p - req);
			break;
		}
	}
	if (got == 0) {
		close(c);
		return;
	}
	if (nl < 0) {
		nl = (int) strcspn(req, "\r\n");
	} else {
		restlen = got - (size_t) nl - 1;
		memcpy(rest, req + nl + 1, restlen);
	}
	req[nl] = 0;
	if (nl > 0 && req[nl - 1] == '\r')
		req[nl - 1] = 0;
	if (!allowed(uc.uid)) {
		/* same bytes the daemon sends for an unknown service: an unlisted app learns nothing */
		logf("relayd: deny uid=%d cmd=%.160s\n", (int) uc.uid, req);
		write_all(c, "ERR unknown service\n", 20);
		close(c);
		return;
	}
	if (g_hold && !strncmp(req, "HOLD", 4)) {
		/* selftest only: hold this connection open like an interactive session does, so a
		 * second caller can prove the relay is not serialized behind us. */
		char drain[16];

		logf("relayd: hold uid=%d -- keeping this caller open\n", (int) uc.uid);
		fflush(stdout);
		while (read(c, drain, sizeof drain) > 0)
			;
		close(c);
		return;
	}
	if (g_echo) {
		snprintf(out, sizeof out, "echo uid=%d %s\n", (int) uc.uid, req);
		write_all(c, out, strlen(out));
		close(c);
		return;
	}
	sfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sfd < 0) {
		close(c);
		return;
	}
	{
		struct sockaddr_in a;

		memset(&a, 0, sizeof a);
		a.sin_family = AF_INET;
		a.sin_port = htons((uint16_t) g_up_port);
		a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		if (connect(sfd, (struct sockaddr *) &a, sizeof a) < 0) {
			logf("relayd: upstream connect errno=%d (%s)\n", errno, strerror(errno));
			write_all(c, "ERR no daemon\n", 14);
			close(sfd);
			close(c);
			return;
		}
	}
	tf = fopen(g_token, "r");
	if (tf) {
		char t[128];

		if (fgets(t, sizeof t, tf)) {
			t[strcspn(t, "\r\n")] = 0;
			tok = snprintf(out, sizeof out, "%s TOK=%s\n", req, t);
		}
		fclose(tf);
	}
	if (!tok) {
		/* no token file: forward as-is and let sud's own attribution decide -- better than
		 * inventing a refusal here, since sud is the one that holds the allow list too */
		tok = snprintf(out, sizeof out, "%s\n", req);
		logf("relayd: note: no token at %s, forwarding unauthenticated\n", g_token);
	}
	if (write_all(sfd, out, (size_t) tok) < 0 ||
	    (restlen && write_all(sfd, rest, restlen) < 0)) {
		close(sfd);
		close(c);
		return;
	}
	logf("relayd: allow uid=%d -> sud (%.120s)\n", (int) uc.uid, req);
	copy_both(c, sfd);
	close(sfd);
	close(c);
}


/* Is somebody already listening on @name?  A stream connect that SUCCEEDS means a listener exists.
 * We use this before binding: on the 6.0.1 route the daemon itself binds @sud, and an app-side
 * relay must not take that over -- whoever gets there first owns the name, and we simply stand down. */
static int somebody_listens(const char *name)
{
	struct sockaddr_un a;
	int fd, len = (int) (sizeof(a.sun_family) + 1 + strlen(name)), rc;

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0)
		return 1;		/* cannot know -- treat as taken, we are the one standing down */
	memset(&a, 0, sizeof a);
	a.sun_family = AF_UNIX;
	a.sun_path[0] = 0;
	memcpy(a.sun_path + 1, name, strlen(name));
	rc = connect(fd, (struct sockaddr *) &a, len);
	close(fd);
	if (rc == 0)
		return 1;
	return 0;
}

static int listen_stream(const char *name)
{
	struct sockaddr_un a;
	int fd, len = (int) (sizeof(a.sun_family) + 1 + strlen(name));

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		logf("relayd: socket errno=%d (%s)\n", errno, strerror(errno));
		return -1;
	}
	memset(&a, 0, sizeof a);
	a.sun_family = AF_UNIX;
	a.sun_path[0] = 0;
	memcpy(a.sun_path + 1, name, strlen(name));
	if (bind(fd, (struct sockaddr *) &a, len) < 0) {
		logf("relayd: REFUSE: bind @%s errno=%d (%s)\n", name, errno, strerror(errno));
		close(fd);
		return -1;
	}
	if (listen(fd, 16) < 0) {
		logf("relayd: listen errno=%d (%s)\n", errno, strerror(errno));
		close(fd);
		return -1;
	}
	logf("relayd: listening on @%s (uid=%d)\n", name, (int) getuid());
	fflush(stdout);
	return fd;
}

static int connect_stream(const char *name)
{
	struct sockaddr_un a;
	int fd, len = (int) (sizeof(a.sun_family) + 1 + strlen(name));

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0)
		return -1;
	memset(&a, 0, sizeof a);
	a.sun_family = AF_UNIX;
	a.sun_path[0] = 0;
	memcpy(a.sun_path + 1, name, strlen(name));
	if (connect(fd, (struct sockaddr *) &a, len) < 0) {
		logf("relayd: client connect @%s errno=%d (%s)\n", name, errno, strerror(errno));
		close(fd);
		return -1;
	}
	return fd;
}

static int serve(const char *name, int if_free)
{
	int lfd;

	if (if_free && somebody_listens(name)) {
		logf("relayd: @%s is already listened to by somebody else -- standing down\n", name);
		fflush(stdout);
		return 0;
	}
	lfd = listen_stream(name);

	if (lfd < 0)
		return 1;
	for (;;) {
		int c = accept(lfd, NULL, NULL);

		if (c >= 0) {
			/* One connection per child.  Served inline, a caller that simply *stays open* --
			 * which is exactly what an interactive `su` session is (Shizuku holds one) --
			 * blocks accept() forever: later callers sit in the backlog, never get a log line,
			 * and never get a reply (measured 2026-10-20, ledger 667). */
			pid_t k = fork();

			if (k == 0) {
				close(lfd);
				serve_one(c);
				_exit(0);
			}
			if (k < 0) {
				logf("relayd: fork errno=%d (%s) -- serving this one inline\n", errno, strerror(errno));
				serve_one(c);
			}
			close(c);
			while (waitpid(-1, NULL, WNOHANG) > 0)
				;
		} else if (errno != EINTR)
			logf("relayd: accept errno=%d (%s)\n", errno, strerror(errno));
	}
	return 0;
}

/* run `relayd --serve-if-free --sock <name>` in a child and require it to say it stood down */
static int pipe_standdown_check(const char *name)
{
	int p[2], k, rc = 0;
	char buf[256];

	if (pipe(p) < 0)
		return 1;
	k = fork();
	if (k == 0) {
		close(p[0]);
		dup2(p[1], 1);
		close(p[1]);
		execl("/proc/self/exe", "relayd", "--serve-if-free", "--sock", name, (char *)0);
		_exit(127);
	}
	close(p[1]);
	if (read(p[0], buf, sizeof buf - 1) > 0) {
		buf[strcspn(buf, "\r\n")] = 0;
		printf("stand-down reply: [%s]\n", buf);
		if (!strstr(buf, "standing down"))
			rc = 1;
	} else
		printf("SELFTEST FAIL: the stand-down arm printed nothing\n");
	close(p[0]);
	usleep(200000);
	kill(k, SIGKILL);
	waitpid(k, NULL, 0);
	return rc;
}

/* the checks that used to be only prose: bind, kernel-given uid, allow list both ways */
static int selftest(void)
{
	pid_t k;
	int rc = 0, fd;
	char buf[256];
 FILE *f;

	unlink(g_log);
	f = fopen(g_grants, "w");
	if (!f) {
		printf("SELFTEST FAIL: cannot write %s errno=%d\n", g_grants, errno);
		return 1;
	}
	fprintf(f, "%d\n", (int) getuid());
	fclose(f);
	f = fopen(g_token, "w");
	if (f) {
		fprintf(f, "selftest-token\n");
		fclose(f);
	}
	g_echo = 1;
	g_hold = 1;		/* the concurrency arm needs a request shape that never answers */
	k = fork();
	if (k == 0) {
		serve("sudselftest", 0);
		_exit(1);
	}
	usleep(700000);
	/* allowed caller: our own uid, which the server must read back from the kernel */
	fd = connect_stream("sudselftest");
	if (fd < 0) {
		printf("SELFTEST FAIL: connect to our own listener failed (bind happened? see above)\n");
		return 1;
	}
	write_all(fd, "SU 0 id\n", 8);
	if (read(fd, buf, sizeof buf - 1) > 0) {
		buf[strcspn(buf, "\r\n")] = 0;
		printf("allowed-caller reply: [%s]\n", buf);
		if (strstr(buf, "ERR") || !strstr(buf, "echo uid="))
			rc = 1;
	} else {
		printf("SELFTEST FAIL: no reply from the relay\n");
		rc = 1;
	}
	close(fd);
	/* concurrency arm (ledger 667): a caller that stays open must not stop the next one.
	 * This is the shape an interactive `su` has -- Shizuku keeps its session open for the
	 * whole life of the app -- and the old serialized accept() loop answered it by letting
	 * the second caller sit in the backlog forever (no log line, no reply). */
	{
		int a = connect_stream("sudselftest"), b;
		struct timeval tv = { 2, 0 };

		if (a < 0) {
			printf("SELFTEST FAIL: the holding caller cannot connect\n");
			rc = 1;
		} else {
			write_all(a, "HOLD\n", 5);
			usleep(200000);
			b = connect_stream("sudselftest");
			if (b < 0) {
				printf("SELFTEST FAIL: second caller cannot connect while one session is held open\n");
				rc = 1;
			} else {
				setsockopt(b, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
				write_all(b, "SU 0 id\n", 8);
				memset(buf, 0, sizeof buf);
				if (read(b, buf, sizeof buf - 1) > 0) {
					buf[strcspn(buf, "\r\n")] = 0;
					printf("second-caller-while-held reply: [%s]\n", buf);
					if (!strstr(buf, "echo uid="))
						rc = 1;
				} else {
					printf("SELFTEST FAIL: second caller got nothing while a session was held open "
					       "(relay is serialized behind one caller)\n");
					rc = 1;
				}
				close(b);
			}
			close(a);
		}
	}
	/* denied caller: the SAME request sent through the same socket, but the allow list is
		 emptied first -- proves revocation is live, not cached at listen() */
	fd = connect_stream("sudselftest");
	write_all(fd, "SU 0 id\n", 8);
	{
		int c2 = connect_stream("sudselftest");

		f = fopen(g_grants, "w");
		fclose(f);
		if (c2 >= 0) {
			write_all(c2, "SU 0 id\n", 8);
			memset(buf, 0, sizeof buf);
			if (read(c2, buf, sizeof buf - 1) > 0) {
				buf[strcspn(buf, "\r\n")] = 0;
				printf("after-revoke reply: [%s]\n", buf);
				if (!strstr(buf, "ERR unknown service"))
					rc = 1;
			} else {
				printf("SELFTEST FAIL: denied caller got no reply at all\n");
				rc = 1;
			}
			close(c2);
		}
	}
	close(fd);
	/* the stand-down arm: while OUR listener is still up, a --serve-if-free on the same name must
	 * refuse to bind (this is what keeps us from hijacking the 6.0.1 daemon's @sud) */
	{
		int c = connect_stream("sudselftest");

		if (c < 0) {
			printf("SELFTEST FAIL: our own listener disappeared before the stand-down arm\n");
			rc = 1;
		}
		close(c);
		if (pipe_standdown_check("sudselftest"))
			rc = 1;
	}
	kill(k, SIGKILL);
	waitpid(k, NULL, 0);
	printf(rc ? "SELFTEST FAIL\n" : "selftest: relay binds, uid is kernel-given, revoke is live\n");
	return rc;
}

int main(int argc, char **argv)
{
	int i;

	setvbuf(stdout, NULL, _IOLBF, 0);
	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--selftest"))
			return selftest();
		if (!strcmp(argv[i], "--serve"))
			continue;
		if (!strcmp(argv[i], "--client")) {
			int fd;

			if (i + 1 >= argc) {
				printf("usage: relayd --client <command...>\n");
				return 2;
			}
			fd = connect_stream(g_sock);
			if (fd < 0)
				return 1;
			{
				char line[1600];
				int n = 0;

				for (i = i + 1; i < argc; i++)
					n += snprintf(line + n, sizeof line - n, "%s ", argv[i]);
				line[n] = 0;
				if (strncmp(line, "SU ", 3))
					n = snprintf(line, sizeof line, "SU 0 %s", line);
				strcat(line, "\n");
				write_all(fd, line, strlen(line));
			}
			{
				char buf[4096];
				ssize_t k;

				while ((k = read(fd, buf, sizeof buf)) > 0)
					fwrite(buf, 1, (size_t) k, stdout);
			}
			close(fd);
			return 0;
		}
		if (!strcmp(argv[i], "--sock") && i + 1 < argc) {
			g_sock = argv[++i];
			continue;
		}
		if (!strcmp(argv[i], "--grants") && i + 1 < argc) {
			g_grants = argv[++i];
			continue;
		}
		if (!strcmp(argv[i], "--token") && i + 1 < argc) {
			g_token = argv[++i];
			continue;
		}
		if (!strcmp(argv[i], "--log") && i + 1 < argc) {
			g_log = argv[++i];
			continue;
		}
		if (!strcmp(argv[i], "--serve-if-free")) {
			g_if_free = 1;
			continue;
		}
		if (!strcmp(argv[i], "--echo")) {
			g_echo = 1;
			continue;
		}
		if (!strcmp(argv[i], "--hold")) {
			g_hold = 1;
			continue;
		}
		if (!strcmp(argv[i], "--up") && i + 1 < argc) {
			char *v = argv[++i];

			if (!strncmp(v, "tcp:", 4))
				g_up_port = atoi(v + 4);
			continue;
		}
		printf("usage: relayd --serve|--selftest|--client <cmd> [--sock NAME] [--grants F] [--token F] [--up tcp:PORT] [--echo]\n");
		return 2;
	}
	return serve(g_sock, g_if_free);
}
