/*
 * dmstop.c -- get /system off dm-verity so it can be mounted read-write.
 *
 * The situation on this 7.1.1 build:
 *   /system is "/dev/block/dm-0", a dm-verity target over the real partition
 *   /dev/block/sde18 (by-name/system -> sde18).  "mount -o remount,rw /system"
 *   fails with EPERM: the mount points at the *dm* device and the verity target
 *   is read-only.
 *
 * Two ways out, and this tool does both:
 *   1. "dmstop rm dm-0"    remove the dm target (DM_DEV_REMOVE), so the partition
 *                           underneath is free and can be mounted rw directly.
 *   2. "dmstop over dm-0 /dev/block/sde18 /system"
 *                           overmount the raw partition on top of the verity
 *                           mount.  Needs the verity device released first, so
 *                           it umounts -l (lazy) first.
 *
 * device-mapper on this ROM has no /dev/mapper/control, but it does register a
 * misc device ("device-mapper" in /proc/misc, minor 236) and we can mknod it.
 * DM_DEVICE_INFO is served by the *block* device (/dev/block/dm-N), not by the
 * misc control node -- that is why the two are opened separately.
 *
 * usage:
 *   dmstop --list
 *   dmstop rm <dm-name>                       e.g. dmstop rm dm-0
 *   dmstop over <dm-name> <raw-dev> <mountpoint>
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

/* --- device-mapper uapi (include/uapi/linux/dm-ioctl.h) --- */
#define DM_IOCTL 0xfd0000

struct dm_ioctl {
	unsigned int version[2];
	unsigned int data_start;
	unsigned int next_target;
	unsigned int target_type;
	unsigned int flags;
	unsigned int event_nr;
	unsigned int reserved[5];
};

struct dm_dev_info {
	unsigned int device_id;
	unsigned int data_start;
	unsigned int len;
	unsigned char data[24];
};

#define DM_DEV_REMOVE _IOWR(DM_IOCTL, 3, struct dm_ioctl)
#define DM_DEVICE_INFO _IOWR(DM_IOCTL, 19, struct dm_dev_info)

static const char *MISC_PATH = "/dev/device-mapper";

static int open_dm(void)
{
	int fd = open(MISC_PATH, O_RDWR);
	if (fd < 0)
		fprintf(stderr, "open %s: %s\n", MISC_PATH, strerror(errno));
	return fd;
}

/* "dm-0" -> 0 */
static int dm_minor(const char *name)
{
	if (!strncmp(name, "dm-", 3))
		return atoi(name + 3);
	if (name[0] >= '0' && name[0] <= '9')
		return atoi(name);
	return -1;
}

static void list_devices(void)
{
	char cmd[] = "for d in /sys/block/dm-*; do "
		    "n=$(cat $d/dm/name 2>/dev/null); "
		    "u=$(cat $d/uevent 2>/dev/null | grep DEVNUM); "
		    "echo \"$(basename $d) name=$n $u\"; done";
	char buf[4096];
	FILE *p = popen(cmd, "r");
	if (!p)
		return;
	while (fgets(buf, sizeof buf, p))
		fputs(buf, stdout);
	pclose(p);
}

/* the internal device id for a minor: DM_DEVICE_INFO is served by the block node */
static unsigned int query_device_id(int minor)
{
	char path[64];
	struct dm_dev_info info;
	int fd;

	snprintf(path, sizeof path, "/dev/block/dm-%d", minor);
	fd = open(path, O_RDWR | O_NONBLOCK);
	if (fd < 0) {
		fprintf(stderr, "open %s: %s\n", path, strerror(errno));
		return (unsigned int)minor;
	}
	memset(&info, 0, sizeof info);
	info.device_id = (unsigned int)minor;
	if (ioctl(fd, DM_DEVICE_INFO, &info) < 0) {
		fprintf(stderr, "DM_DEVICE_INFO on %s: %s\n", path, strerror(errno));
		close(fd);
		return (unsigned int)minor;
	}
	close(fd);
	return info.device_id;
}

static int remove_target(const char *name)
{
	int fd, minor;
	unsigned int dev_id;

	minor = dm_minor(name);
	if (minor < 0) {
		fprintf(stderr, "cannot parse dm name '%s'\n", name);
		return 2;
	}
	fd = open_dm();
	if (fd < 0)
		return 1;

	dev_id = query_device_id(minor);
	printf("dm-%d -> device_id %u\n", minor, dev_id);

	struct dm_ioctl io;
	memset(&io, 0, sizeof io);
	io.version[0] = 3;               /* DM_VERSION */
	io.version[1] = sizeof io;
	io.data_start = sizeof io;
	io.target_type = dev_id;
	if (ioctl(fd, DM_DEV_REMOVE, &io) < 0) {
		fprintf(stderr, "DM_DEV_REMOVE failed: %s\n", strerror(errno));
		close(fd);
		return 1;
	}
	printf("removed dm-%d\n", minor);
	close(fd);
	return 0;
}

static int overmount(const char *name, const char *raw, const char *mp)
{
	char cmd[512];
	int minor = dm_minor(name);

	if (minor < 0)
		return 2;

	/* lazy unmount: detach the tree now, drop the references when they go */
	snprintf(cmd, sizeof cmd, "umount -l %s 2>&1", mp);
	if (system(cmd) == -1)
		perror("umount");

	/* release the verity device so the partition is free for a rw open */
	snprintf(cmd, sizeof cmd, "/data/local/tmp/dmstop rm %s 2>&1", name);
	int rc = system(cmd);
	if (rc != 0)
		fprintf(stderr, "(dm remove reported %d -- trying the mount anyway)\n", rc);

	/* mount the raw partition read-write over the old mountpoint */
	snprintf(cmd, sizeof cmd,
		 "mount -o rw,seclabel,relatime,discard,data=ordered %s %s 2>&1",
		 raw, mp);
	rc = system(cmd);
	printf("mount rc=%d\n", rc);

	snprintf(cmd, sizeof cmd, "grep ' %s ' /proc/mounts", mp);
	if (system(cmd) == -1)
		perror("grep");
	return rc == 0 ? 0 : 1;
}

int main(int argc, char **argv)
{
	if (argc > 1 && !strcmp(argv[1], "--list")) {
		list_devices();
		return 0;
	}
	if (argc >= 3 && !strcmp(argv[1], "rm")) {
		return remove_target(argv[2]);
	}
	if (argc >= 5 && !strcmp(argv[1], "over")) {
		return overmount(argv[2], argv[3], argv[4]);
	}
	fprintf(stderr,
		"usage: %s --list\n"
		"       %s rm <dm-name>\n"
		"       %s over <dm-name> <raw-dev> <mountpoint>\n",
		argv[0], argv[0], argv[0]);
	return 2;
}
