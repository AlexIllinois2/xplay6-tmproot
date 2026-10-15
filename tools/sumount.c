/* tools/sumount.c -- send one MOUNT request to sud, so `su` lands in the mirrored
 * /system/xbin and /sbin the way a third-party root manager expects to find it.
 *
 * Nothing here is part of the delivery artifacts: it is a lab tool.  sud attributes the
 * caller from the kernel's own socket bookkeeping, so run this THROUGH the root channel
 * (the raw 12345 shell) -- from uid 2000 the request is refused, which is the designed
 * policy (an unlisted or unprivileged caller must not be able to change what every app
 * sees).  The client-side socket is owned by this process, so a root-run instance is
 * attributed as uid 0.
 *
 * usage: sumount [path-to-su-client=/data/local/tmp/su] [bin]
 */
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

int main(int argc, char **argv)
{
	const char *client = argc > 1 ? argv[1] : "/data/local/tmp/su";
	char req[512], buf[4096];
	struct sockaddr_in in;
	int fd, n;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		perror("socket");
		return 1;
	}
	memset(&in, 0, sizeof in);
	in.sin_family = AF_INET;
	in.sin_port = htons(12346);
	in.sin_addr.s_addr = htonl(0x7f000001);
	if (connect(fd, (struct sockaddr *) &in, sizeof in) != 0) {
		printf("connect 127.0.0.1:12346: %s (sud not listening?)\n", strerror(errno));
		return 1;
	}
	n = snprintf(req, sizeof req, "MOUNT %s%s\n", client, argc > 2 ? " bin" : "");
	if (write(fd, req, n) != n) {
		perror("write request");
		return 1;
	}
	while ((n = read(fd, buf, sizeof buf - 1)) > 0) {
		buf[n] = 0;
		fputs(buf, stdout);
	}
	close(fd);
	return 0;
}
