/* Probe 2: can we bind an ABSTRACT unix socket (Linux namespace, "\0name")?
 *
 * The Xplay6 kernel refuses bind(2) on a FILESYSTEM unix socket path with
 * EPERM regardless of SELinux mode (measured 2026-10-27, permissive included,
 * no AVC entry -> kernel-level hook, not policy).  Magisk's daemon uses
 * std::os::unix::net::UnixListener::bind() with a real path, so it cannot
 * start as-is.  Abstract sockets live in a different namespace and are not
 * subject to path permissions, so they are the candidate escape hatch.
 *
 * usage: mgabsprobe <name>
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <sys/stat.h>

int main(int argc, char **argv)
{
	if (argc < 2) {
		fprintf(stderr, "usage: %s <name>\n", argv[0]);
		return 2;
	}

	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		printf("socket() failed: %s\n", strerror(errno));
		return 1;
	}

	struct sockaddr_un addr;
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	/* abstract namespace: leading NUL byte, name follows */
	addr.sun_path[0] = '\0';
	strncpy(addr.sun_path + 1, argv[1], sizeof(addr.sun_path) - 2);

	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
		printf("abstract bind() failed: errno=%d (%s)\n", errno, strerror(errno));
		close(fd);
		return 1;
	}
	printf("abstract bind() OK (@%s)\n", argv[1]);

	if (listen(fd, 5) != 0)
		printf("listen() failed: errno=%d (%s)\n", errno, strerror(errno));
	else
		printf("listen() OK\n");

	/* can a client connect? */
	int c = socket(AF_UNIX, SOCK_STREAM, 0);
	if (c < 0) {
		printf("client socket() failed: %s\n", strerror(errno));
	} else {
		if (connect(c, (struct sockaddr *)&addr, sizeof(addr)) == 0)
			printf("client connect() OK\n");
		else
			printf("client connect() failed: errno=%d (%s)\n", errno, strerror(errno));
		close(c);
	}

	close(fd);
	return 0;
}
