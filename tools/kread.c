#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/uio.h>
#include <sys/fcntl.h>

/* NEGATIVE RESULT, kept because the header comment on this file used to claim the
 * opposite and I believed it once (ledger S74).  Measured on device 2026-10-13:
 * every target below returns `writev: errno=14 Bad address`.
 *
 * The user iovec array IS validated at entry (rw_copy_check_uvector/import_iovec do
 * access_ok on each iov_base), so pointing iov_base at a kernel VA fails the whole
 * syscall.  The binder leak works only because EPOLL_CTL_DEL's __list_del rewrites
 * the kernel's *own* copy of the array *after* that check, so those 8 bytes are never
 * re-validated.  => there is no bug-free arbitrary kernel read here; the readable
 * window starts at freed-slot+0x50 and its length comes from that same kernel value.
 *
 * usage: kread <hex-addr>:<len> [...]   -- prints EFAULT for kernel addresses by design
 */
#define CHUNK 4096

static int rd(unsigned long addr, int len, unsigned char *out)
{
    int pfd[2], rc;
    unsigned char primer[8];
    struct iovec iov[2];

    if (pipe(pfd)) { perror("pipe"); return -1; }
    /* one 8-byte segment first: if the target faults, the pipe still holds these bytes
     * and the short copy is visible as a smaller total */
    memset(primer, 0xA7, sizeof primer);
    iov[0].iov_base = primer;
    iov[0].iov_len = sizeof primer;
    iov[1].iov_base = (void *)(uintptr_t)addr;
    iov[1].iov_len = len;

    rc = (int)writev(pfd[1], iov, 2);
    if (rc < 0) {
        printf("    writev: errno=%d %s\n", errno, strerror(errno));
        close(pfd[0]); close(pfd[1]);
        return -1;
    }
    int got = 0;
    while (got < rc) {
        ssize_t n = read(pfd[0], out + got, rc - got);
        if (n <= 0) { if (n < 0 && errno == EINTR) continue; break; }
        got += (int)n;
    }
    close(pfd[0]); close(pfd[1]);
    if (got < sizeof primer) return got;
    memmove(out, out + sizeof primer, got - sizeof primer);
    return got - sizeof primer;
}

static void show(unsigned long addr, int len, unsigned char *b, int n)
{
    int i, pr = 0;
    char ascii[128];
    printf("  %016lx len=%d -> %d bytes:", addr, len, n);
    for (i = 0; i < n && i < 32; i++)
        printf(" %02x", b[i]);
    if (n >= 4) {
        unsigned int v32 = 0;
        unsigned long v64 = 0;
        memcpy(&v32, b, 4);
        if (n >= 8) memcpy(&v64, b, 8);
        printf("   | u32=%u u64=0x%lx", v32, v64);
    }
    for (i = 0; i < n && i < 63; i++)
        ascii[i] = (b[i] >= 32 && b[i] < 127) ? b[i] : '.';
    ascii[i < 63 ? i : 63] = 0;
    if (strspn(ascii, ".") < (size_t)i) { printf("\n    ascii: \"%s\"", ascii); pr = 1; }
    (void)pr;
    printf("\n");
}

int main(int argc, char **argv)
{
    unsigned char buf[CHUNK + 16];
    int i;

    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc < 2) {
        /* defaults: the three addresses the exploit depends on */
        static const char *spec[] = {
            "0xffffffc00189be74:16",   /* selinux_enforcing  -- expect u32 == 1 */
            "0xffffffc001635a30:32",   /* modprobe_path      -- expect "/sbin/modprobe" */
            "0xffffffc001636d80:16",   /* init_cred          -- expect usage == 4 */
            "0xffffffc00162deb8:64",   /* init_uts_ns        -- expect "Linux"/nodename */
            "0x1000:16",               /* negative control: unmapped user VA */
        };
        for (i = 0; i < (int)(sizeof spec / sizeof *spec); i++) {
            unsigned long a = strtoul(spec[i], NULL, 16);
            int l = atoi(strchr(spec[i], ':') + 1);
            int n = rd(a, l, buf);
            show(a, l, buf, n);
        }
        return 0;
    }
    for (i = 1; i < argc; i++) {
        unsigned long a = strtoul(argv[i], NULL, 16);
        char *c = strchr(argv[i], ':');
        int l = c ? atoi(c + 1) : 32;
        int n;
        if (l > CHUNK) l = CHUNK;
        n = rd(a, l, buf);
        show(a, l, buf, n);
    }
    return 0;
}
