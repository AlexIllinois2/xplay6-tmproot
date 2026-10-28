/* Probe: can we bind a unix socket in a given directory, and with which
 * SELinux label?  Prints the exact errno so the Magisk daemon's
 * "UnixListener::bind().log() else { exit(1) }" failure can be attributed.
 *
 * usage: mgsockprobe <dir> [label]
 *   label: optional SELinux context to set on the socket (e.g. u:object_r:adb_data_file:s0)
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/xattr.h>

int main(int argc, char **argv)
{
	if (argc < 2) {
		fprintf(stderr, "usage: %s <dir> [label]\n", argv[0]);
		return 2;
	}
	const char *dir = argv[1];
	const char *label = argc > 2 ? argv[2] : NULL;

	char path[256];
	snprintf(path, sizeof(path), "%s/probe.sock", dir);

	unlink(path);

	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		printf("socket() failed: %s\n", strerror(errno));
		return 1;
	}

	struct sockaddr_un addr;
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path);

	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
		printf("bind() failed: errno=%d (%s)\n", errno, strerror(errno));
		close(fd);
		return 1;
	}
	printf("bind() OK\n");

	if (label) {
		if (setxattr(path, "security.selinux", label, strlen(label) + 1, 0) != 0)
			printf("setxattr failed: errno=%d (%s)\n", errno, strerror(errno));
		else
			printf("setxattr OK: %s\n", label);
	}

	if (listen(fd, 5) != 0)
		printf("listen() failed: errno=%d (%s)\n", errno, strerror(errno));
	else
		printf("listen() OK\n");

	struct stat st;
	if (stat(path, &st) == 0)
		printf("socket file exists, mode=%o\n", st.st_mode & 07777);

	close(fd);
	unlink(path);
	return 0;
}
