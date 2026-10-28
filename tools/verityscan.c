/* Locate the dm-verity metadata superblock at the tail of a block device.
 *
 * AOSP's fs_mgr (Nougat, pre-AVB) stores the verity metadata as 4096-byte
 * superblocks near the end of the partition: a primary and usually a backup
 * copy.  Each one starts with a 4-byte magic:
 *
 *   0x56444549  ("IEVD" in memory order)  -> verity ENABLED
 *   0x56444550  (one more)                -> verity DISABLED
 *
 * followed by a version word, an RSA-PSS signature (256 bytes) and the
 * dm-verity table string.  `adb disable-verity` works by flipping that last
 * magic byte; this tool only READS -- it finds and prints the superblocks so
 * we know the exact byte offsets before any write is ever considered.
 *
 * usage: verityscan <blockdev> [scan-tail-bytes]
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>

#define SB_MAGIC_ENABLED  0x56444549u
#define SB_MAGIC_DISABLED 0x56444550u
#define SB_SIZE 4096
#define CHUNK (1024 * 1024)

static void hexdump(const unsigned char *p, int n)
{
    for (int i = 0; i < n; i += 16) {
        printf("  %06d  ", i);
        for (int j = 0; j < 16 && i + j < n; j++)
            printf("%02x ", p[i + j]);
        printf("\n");
    }
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <blockdev> [tail-bytes]\n", argv[0]);
        return 2;
    }
    const char *dev = argv[1];
    long long tail = argc > 2 ? atoll(argv[2]) : (128LL << 20);

    long long size = lseek64(open(dev, O_RDONLY), 0, SEEK_END);
    if (size < 0) { perror("lseek"); return 1; }
    if (tail > size) tail = size;

    int fd = open(dev, O_RDONLY);
    if (fd < 0) { perror(dev); return 1; }

    long long start = size - tail;
    /* keep one SB_SIZE of overlap so a superblock straddling a chunk
     * boundary is still seen whole */
    if (lseek64(fd, start, SEEK_SET) < 0) { perror("seek"); return 1; }

    static unsigned char buf[CHUNK + SB_SIZE];
    long long pos = start;
    int carry = 0, found = 0;
    ssize_t n;

    while (pos < size && (n = read(fd, buf + carry, CHUNK)) > 0) {
        long long have = carry + n;
        for (long long i = 0; i + 12 <= have; i += 4) {
            uint32_t magic;
            memcpy(&magic, buf + i, 4);
            if (magic != SB_MAGIC_ENABLED && magic != SB_MAGIC_DISABLED)
                continue;
            long long off = pos - carry + i;
            /* plausible superblock: version word == 1 at +8, table length
             * at +4 in a sane range (< SB_SIZE) */
            uint32_t len, ver;
            memcpy(&len, buf + i + 4, 4);
            memcpy(&ver, buf + i + 8, 4);
            if (ver != 1 || len == 0 || len > SB_SIZE)
                continue;
            found++;
            printf("SUPERBLOCK at byte %lld (from-end %lld): magic=%s "
                   "table_len=%u version=%u\n",
                   off, size - off,
                   magic == SB_MAGIC_ENABLED ? "ENABLED" : "DISABLED",
                   len, ver);
            int show = (int)(have - i < 112 ? have - i : 112);
            hexdump(buf + i, show);
            /* print the dm table string that follows the signature */
            {
                char tbl[512];
                long long tbl_off = i + 4 + 4 + 4 + 256;
                long long tbl_len = len; /* length covers the table string */
                if (tbl_len > (int)sizeof(tbl) - 1) tbl_len = sizeof(tbl) - 1;
                if (tbl_off + tbl_len <= have) {
                    memcpy(tbl, buf + tbl_off, (size_t)tbl_len);
                    tbl[tbl_len] = 0;
                    printf("  table: %s\n", tbl);
                }
            }
        }
        carry = SB_SIZE;
        memmove(buf, buf + n, (size_t)carry);
        pos += n;
    }
    if (!found)
        printf("no verity superblock found in last %lld bytes\n", tail);
    return found ? 0 : 1;
}
