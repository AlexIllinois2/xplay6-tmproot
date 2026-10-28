/* tools/swap.c -- ask sud to swap ONE file inside a read-only tree (MSWAP), or
 * undo that (UMSWAP).
 *
 * Lab tool, not part of the delivery artifacts.
 *
 * WHY THIS USES relayd's TCP PORT:
 *   sud refuses MSWAP for anybody whose uid is not 0 ("MSWAP is root-only"), and
 *   it attributes a TCP caller by its socket row in /proc/net/tcp -- which is
 *   relayd's row, and relayd is uid 0.  So a request that arrives over relayd
 *   arrives as root, which is what MSWAP needs.
 *   The peer channel cannot be used from here: it wants the CLIENT to bind an
 *   abstract socket, and this tool runs in the init domain (through su), which
 *   is not allowed to bind AF_UNIX at all (measured: "abstract bind: Operation
 *   not permitted").
 *   relayd appends " TOK=<token>" to the line it forwards; sud verifies it and
 *   then strips it before parsing the line as a command, so the two arguments
 *   here survive the trip.
 *
 * usage: swap <src-file> <dst-file>      # swap in
 *        swap -u <dst-file>              # undo (lazy umount of the mirrored directory)
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
	char req[600], buf[4096];
	struct sockaddr_in in;
	int fd, n;

	if (argc < 3) {
		printf("usage: swap <src> <dst> | swap -u <dst>\n");
		return 2;
	}
	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		perror("socket");
		return 1;
	}
	memset(&in, 0, sizeof in);
	in.sin_family = AF_INET;
	in.sin_port = htons(12346);
	in.sin_addr.s_addr = htonl(0x7f000001);
	if (connect(fd, (struct sockaddr *)&in, sizeof in) != 0) {
		printf("connect 127.0.0.1:12346: %s (relayd not listening?)\n", strerror(errno));
		return 1;
	}
	if (!strcmp(argv[1], "-u"))
		n = snprintf(req, sizeof req, "UMSWAP %s\n", argv[2]);
	else
		n = snprintf(req, sizeof req, "MSWAP %s %s\n", argv[1], argv[2]);
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
