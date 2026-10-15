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

/* CVE-2016-5195 (Dirty COW) presence probe, content-preserving.
 *
 * The bug lives in the FOLL_FORCE/FOLL_WRITE fault path that ptrace uses:
 * access_process_vm(FOLL_WRITE) -> get_user_pages() -> on a read-only private mapping
 * of a file the vulnerable kernel returns the PAGE-CACHE page without copying it, so
 * the poke lands in shared memory.  After the fix (Android 2016-12-01) the same poke
 * is refused and PTRACE_POKEDATA returns -1/EIO (it checks vma_is_writable-ish).
 *
 * So the return code alone answers the question -- and because we poke back the word we
 * just read, the file's cached content is unchanged even in the vulnerable case.
 * Two controls keep the ruler honest:
 *   negative: poke a PROT_READ anonymous mapping  -> must be refused either way
 *   positive: poke a mapping that really is writable (PROT_WRITE private anon) -> must
 *             succeed, otherwise our ptrace itself is blocked (SELinux) and the result
 *             below would be meaningless.
 *
 * usage: dcow_probe [path]        default /system/bin/toolbox (root-owned 0755)
 */
#define PAGE 0x1000

static long poke(int fd_child_pid_unused, pid_t ch, unsigned long addr, unsigned long val)
{
    errno = 0;
    return ptrace(PTRACE_POKEDATA, ch, (caddr_t)addr, (caddr_t)val);
}

int main(int argc, char **argv)
{
    const char *path = argc > 1 ? argv[1] : "/system/bin/toolbox";
    int fd, status;
    pid_t ch;
    unsigned char *fm, *am_ro, *am_rw;
    unsigned long word;
    struct stat st;
    int verdict = 2;

    setvbuf(stdout, NULL, _IONBF, 0);
    if (stat(path, &st)) { printf("stat %s: %s\n", path, strerror(errno)); return 1; }
    printf("target %s size=%lld mode=%o uid=%d owner-can-write-by-dac=%s\n", path,
           (long long)st.st_size, st.st_mode, st.st_uid, "no (we are shell)");

    /* anonymous mappings, mapped in the parent and inherited across fork */
    am_ro = mmap(NULL, PAGE, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    am_rw = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (am_ro == MAP_FAILED || am_rw == MAP_FAILED) { perror("anon mmap"); return 1; }
    memset(am_rw, 0x4D, PAGE);

    fd = open(path, O_RDONLY);
    if (fd < 0) { printf("open %s: %s\n", path, strerror(errno)); return 1; }
    fm = mmap(NULL, PAGE, PROT_READ, MAP_PRIVATE, fd, st.st_size > 3 * PAGE ? 2 * PAGE : 0);
    if (fm == MAP_FAILED) { printf("mmap %s: %s\n", path, strerror(errno)); close(fd); return 1; }
    memcpy(&word, fm, 8);
    printf("first word of the mapped page = %016lx\n", word);

    ch = fork();
    if (ch < 0) { perror("fork"); return 1; }
    if (ch == 0) {
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL)) { perror("TRACEME"); _exit(3); }
        raise(SIGSTOP);
        pause();                      /* keep the mappings alive */
        /* after the pokes: report what the file mapping looks like to us now */
        {
            unsigned long now;
            memcpy(&now, fm, 8);
            printf("CHILD: file map word now = %016lx (was %016lx) %s\n", now, word,
                   now == word ? "unchanged" : "*** CHANGED ***");
            printf("CHILD: anon RO word = %016lx, anon RW word = %016lx\n",
                   *(unsigned long *)am_ro, *(unsigned long *)am_rw);
        }
        _exit(0);
    }
    waitpid(ch, &status, WUNTRACED);
    if (!WIFSTOPPED(status)) { printf("child did not stop: status=%d\n", status); return 1; }

    /* control 1: a mapping we are allowed to write must succeed, or ptrace is blocked */
    errno = 0;
    if (poke(0, ch, (unsigned long)am_rw, 0x4D4D4D4D4D4D4D4DUL) == 0)
        printf("control positive (anon RW map): POKEDATA ok  -> ptrace works\n");
    else
        printf("control positive (anon RW map): POKEDATA FAILED errno=%d %s -> "
               "ptrace itself blocked, result below meaningless\n", errno, strerror(errno));

    /* control 2: read-only anonymous mapping must be refused on both kernels */
    errno = 0;
    printf("control negative (anon RO map): POKEDATA -> %ld errno=%d %s\n",
           poke(0, ch, (unsigned long)am_ro, 0x1122334455667788UL), errno, strerror(errno));

    /* the test: poke the SAME word back into the read-only private file mapping */
    errno = 0;
    if (poke(0, ch, (unsigned long)fm, word) == 0) {
        printf("TEST (read-only private FILE map, same bytes back): POKEDATA OK\n");
        printf("==> DIRTY COW PRESENT (kernel copied no page for a FOLL_FORCE write)\n");
        verdict = 0;
    } else {
        printf("TEST (read-only private FILE map): POKEDATA -> errno=%d %s\n",
               errno, strerror(errno));
        if (errno == EIO) {
            printf("==> patched (get_user_pages refuses to write a !VM_WRITE vma)\n");
            verdict = 1;
        } else
            verdict = 2;
    }
    ptrace(PTRACE_DETACH, ch, NULL, NULL);
    kill(ch, SIGCONT);
    waitpid(ch, &status, 0);
    printf("verdict=%d\n", verdict);
    close(fd);
    return verdict;
}
