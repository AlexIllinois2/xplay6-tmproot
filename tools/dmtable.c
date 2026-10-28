/* Dump the active dm table of a device-mapper device via DM_TABLE_STATUS.
 *
 * usage: dmtable </dev/block/dm-N>
 * Prints the same table string the kernel would use to recreate the targets,
 * which for dm-verity reveals the hash device, hash offset, algorithm and
 * digest -- i.e. where fs_mgr got its parameters from.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <linux/dm-ioctl.h>

static void hdr_init(struct dm_ioctl *io, size_t sz, int flags)
{
    memset(io, 0, sz);
    io->version[0] = DM_VERSION_MAJOR;
    io->version[1] = 0;
    io->version[2] = 0;
    io->data_size = sz;
    io->data_start = sizeof(*io);
    io->flags = flags;
}

int main(int argc, char **argv)
{
    if (argc < 2) { fprintf(stderr, "usage: %s /dev/block/dm-N\n", argv[0]); return 2; }

    int fd = open(argv[1], O_RDONLY);
    if (fd < 0) { perror(argv[1]); return 1; }
    struct stat st;
    if (fstat(fd, &st) < 0) { perror("fstat"); return 1; }

    size_t bufsz = 256 * 1024;
    struct dm_ioctl *io = malloc(bufsz);

    /* DM_VERSION handshake (also tells us the kernel's version) */
    hdr_init(io, bufsz, 0);
    if (ioctl(fd, DM_VERSION, io) < 0) { perror("DM_VERSION"); return 1; }
    printf("dm driver version: %u.%u.%u (data_size returned %u)\n",
           io->version[0], io->version[1], io->version[2], io->data_size);

    /* point the header at the target device: either the dm node itself
     * (st_rdev) or, when talking to /dev/mapper/control, an explicit
     * major:minor given as argv[2] */
    hdr_init(io, bufsz, DM_STATUS_TABLE_FLAG);
    if (argc > 2) {
        unsigned mj = 0, mn = 0;
        sscanf(argv[2], "%u:%u", &mj, &mn);
        io->dev = (mj << 8) | mn;   /* new_dev_t packing on 32-bit */
    } else {
        io->dev = st.st_rdev;
    }
    io->name[0] = 0;

    if (ioctl(fd, DM_TABLE_STATUS, io) < 0) { perror("DM_TABLE_STATUS"); return 1; }

    printf("target_count=%u flags=0x%x event_nr=%u\n",
           io->target_count, io->flags, io->event_nr);

    /* targets start at data_start, each is a dm_target_spec followed by
     * a NUL-terminated status string padded to 8 bytes */
    unsigned char *p = (unsigned char *)io + io->data_start;
    for (unsigned i = 0; i < io->target_count && p < (unsigned char *)io + io->data_size; i++) {
        struct dm_target_spec *t = (struct dm_target_spec *)p;
        printf("target %u: sector_start=%llu length=%llu type=%s\n",
               i, (unsigned long long)t->sector_start,
               (unsigned long long)t->length, t->target_type);
        const char *s = (const char *)(p + sizeof(*t));
        printf("  args: %s\n", s);
        size_t slen = strnlen(s, 4096);
        size_t adv = sizeof(*t) + ((slen + 1 + 7) & ~7UL);
        p += adv;
    }
    return 0;
}
