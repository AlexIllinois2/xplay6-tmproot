// tools/sugate_probe.c -- read-only fingerprint of the exec-time "su" name gate.
//
// Why this exists: the offline numeric sweep (tools/immscan.py, 100% coverage of fw/Image)
// found no "su" string with a terminator and no function containing both 's'(0x73) and
// 'u'(0x75) immediates, and /proc/modules is empty (no .ko loaded).  So the gate is not the
// "per-character immediate compare" that section 103 assumed.  What decides the remedy is
// what the rule keys on:
//   user path string -> must patch kernel code/data
//   resolved dentry  -> bind-mounting a *symlink* named su is enough (no patch at all)
//   inode            -> renaming cannot help
// Each case is one fork+execve as uid 2000; nothing here writes kernel state.
//
// Output line per case: "CASE <label> -> RAN | errno=N(...) | no-output"
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

#define D "/data/local/tmp/sgt"
#define PAY "/data/local/tmp/sgt_pay"

static char *av[] = {"sgt-run", NULL};

static void copy_payload(const char *dst)
{
    char buf[4096];
    int in = open(PAY, O_RDONLY);
    if (in < 0) {
        printf("SETUP-FAIL open payload for %s: %s\n", dst, strerror(errno));
        return;
    }
    int out = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (out < 0) {
        printf("SETUP-FAIL create %s: %s\n", dst, strerror(errno));
        close(in);
        return;
    }
    ssize_t n;
    while ((n = read(in, buf, sizeof buf)) > 0) {
        if (write(out, buf, n) != n) {
            printf("SETUP-FAIL short write %s: %s\n", dst, strerror(errno));
            break;
        }
    }
    close(in);
    close(out);
    chmod(dst, 0755);
}

static int run_exec(const char *label, const char *path)
{
    int p[2];
    if (pipe(p) < 0) {
        printf("CASE %-30s -> pipe=%s\n", label, strerror(errno));
        return -1;
    }
    pid_t pid = fork();
    if (pid < 0) {
        printf("CASE %-30s -> fork=%s\n", label, strerror(errno));
        return -1;
    }
    if (pid == 0) {
        close(p[0]);
        if (dup2(p[1], 2) < 0)
            _exit(9);
        close(p[1]);
        execve(path, av, environ);
        dprintf(2, "errno=%d(%s)\n", errno, strerror(errno));
        _exit(1);
    }
    close(p[1]);
    /* Read the child's whole stderr, not just its first line: the Android loader can emit
     * its own chatter ("WARNING: linker: ... unsupported flags DT_FLAGS_1=...") before the
     * payload gets a word in, and a verdict taken from whatever came first then reports the
     * loader instead of the gate.  The marker is matched line-wise, and the printed verdict
     * is always a single line so the driver's per-case grep stays parseable. */
    char buf[512];
    ssize_t off = 0, n;
    memset(buf, 0, sizeof buf);
    while (off < (ssize_t)sizeof buf - 1 &&
           (n = read(p[0], buf + off, sizeof buf - 1 - off)) > 0)
        off += n;
    buf[off] = 0;
    close(p[0]);
    int st = 0;
    waitpid(pid, &st, 0);
    char verdict[192];
    char *line = buf, *found;
    verdict[0] = 0;
    while (line && *line) {
        char *eol = strchr(line, '\n');
        if (eol)
            *eol = 0;
        if (!strcmp(line, "RAN"))
            snprintf(verdict, sizeof verdict, "RAN");
        else if (!strncmp(line, "errno=", 6) && !verdict[0])
            snprintf(verdict, sizeof verdict, "%s", line);
        line = eol ? eol + 1 : NULL;
    }
    if (!verdict[0]) {
        found = strchr(buf, '\n');
        if (found)
            *found = 0;
        snprintf(verdict, sizeof verdict, "no-output waitstatus=0x%x first=%s", st, buf);
    }
    printf("CASE %-30s -> %s\n", label, verdict);
    fflush(stdout);
    return 0;
}

static void mkdir_p(const char *path)
{
    if (mkdir(path, 0777) == 0)
        chmod(path, 0777);
}

int main(int argc, char **argv)
{
    /* Per-CPU measurement is the only way to tell "the patch did not land" from "some core
     * still executes a stale line", and this device's taskset is the toybox one -- it takes
     * a MASK and rejects "-c N" with a usage message, which silently ran nothing.  Pin here
     * instead (affinity is inherited by the forked execve, so the gate really runs on the
     * core we name).  NB: present/possible on this kernel is 0-3, not 0-7. */
    if (argc > 1) {
        int cpu = atoi(argv[1]);
        cpu_set_t set;
        CPU_ZERO(&set);
        CPU_SET(cpu, &set);
        if (sched_setaffinity(0, sizeof set, &set) != 0)
            printf("SETUP-FAIL pin cpu%d: %s\n", cpu, strerror(errno));
        else
            printf("PIN cpu=%d ran_on=%d\n", cpu, sched_getcpu());
    }
    mkdir_p(D);
    mkdir_p(D "/l1");
    mkdir_p(D "/s2");
    mkdir_p(D "/sudir");
    mkdir_p(D "/a");
    mkdir_p(D "/a/su");       /* a DIRECTORY whose basename is exactly su */
    mkdir_p(D "/b");
    mkdir_p(D "/b/sux");      /* control: same depth, dir basename is sux */

    const char *names[] = {"su", "sux", "sux_real", "su2", "sU", "SU", ".su", "su.sh",
                           "xsu", "asu", "su-", "su ", "s", "u", "s2/su", "su_script",
                           "sudir/pay", "a/su/p", "b/sux/p", NULL};
    for (int i = 0; names[i]; i++) {
        char path[512];
        snprintf(path, sizeof path, "%s/%s", D, names[i]);
        copy_payload(path);
    }
    /* "script named su": a #!-led text file with the denied name, to see whether the rule
       sits before binfmt dispatch (name) or inside an ELF handler (content) */
    int sf = open(D "/su_script", O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (sf >= 0) {
        dprintf(sf, "#!/system/bin/sh\n");
        close(sf);
    }

    printf("== controls (name only) ==\n");
    run_exec("control_sux", D "/sux");
    run_exec("control_su", D "/su");

    printf("== name vs inode ==\n");
    unlink(D "/su_alt");
    printf("SETUP link(su -> su_alt) rc=%d %s\n", link(D "/su", D "/su_alt"), strerror(errno));
    run_exec("hardlink_su_as_su_alt", D "/su_alt");
    unlink(D "/l1/hard_named_su");
    printf("SETUP link(su -> l1/hard_named_su) rc=%d %s\n",
           link(D "/su", D "/l1/hard_named_su"), strerror(errno));
    run_exec("hardlink_named_su_other_dir", D "/l1/hard_named_su");

    printf("== dentry vs user-string (the decisive pair) ==\n");
    unlink(D "/l1/su");
    printf("SETUP symlink(l1/su -> sux_real) rc=%d %s\n",
           symlink(D "/sux_real", D "/l1/su"), strerror(errno));
    run_exec("symlink_NAMED_su_to_sux_real", D "/l1/su");
    unlink(D "/l1/sux");
    printf("SETUP symlink(l1/sux -> su) rc=%d %s\n",
           symlink(D "/su", D "/l1/sux"), strerror(errno));
    run_exec("symlink_named_sux_to_su", D "/l1/sux");

    int fd = open(D "/su", O_RDONLY);
    printf("SETUP open(/su) fd=%d %s\n", fd, fd < 0 ? strerror(errno) : "ok");
    if (fd >= 0) {
        char fdpath[64];
        snprintf(fdpath, sizeof fdpath, "/proc/self/fd/%d", fd);
        run_exec("fdexec_proc_self_fd_of_su", fdpath);
        close(fd);
    }

    printf("== which component is matched ==\n");
    run_exec("file_su_in_subdir", D "/s2/su");
    run_exec("pay_under_dir_named_su", D "/a/su/p");
    run_exec("pay_under_dir_named_sux", D "/b/sux/p");
    run_exec("pay_in_sudir", D "/sudir/pay");

    printf("== string shape ==\n");
    run_exec("dotdot_normalisation", D "/s2/../su");
    run_exec("dot_component", D "/./su");
    run_exec("double_slash", D "//su");
    run_exec("trailing_slash", D "/su/");
    chdir(D);
    run_exec("relative_dot_slash", "./su");
    run_exec("relative_bare", "su");
    chdir("/");

    printf("== near-miss names ==\n");
    const char *v[] = {"su2", "sU", "SU", ".su", "su.sh", "xsu", "asu", "su-", "su ", "s", "u", NULL};
    for (int i = 0; v[i]; i++) {
        char path[512];
        snprintf(path, sizeof path, "%s/%s", D, v[i]);
        run_exec(path, path);
    }

    printf("== script vs elf ==\n");
    run_exec("script_named_su", D "/su_script");

    printf("== non-exec surfaces ==\n");
    int rfd = open(D "/su", O_RDONLY);
    printf("CASE open_rdonly_su           -> %s\n", rfd >= 0 ? "ok" : strerror(errno));
    if (rfd >= 0)
        close(rfd);
    printf("CASE access_X_OK_su           -> %s\n", access(D "/su", X_OK) == 0 ? "ok" : strerror(errno));
    printf("CASE access_X_OK_sux          -> %s\n", access(D "/sux", X_OK) == 0 ? "ok" : strerror(errno));
    struct stat sb;
    printf("CASE stat_su                  -> rc=%d mode=%o ino=%llu\n",
           stat(D "/su", &sb) == 0 ? 0 : -1, sb.st_mode, (unsigned long long)sb.st_ino);
    printf("CASE stat_sux                 -> rc=%d mode=%o ino=%llu\n",
           stat(D "/sux", &sb) == 0 ? 0 : -1, sb.st_mode, (unsigned long long)sb.st_ino);

    printf("== caller state ==\n");
    FILE *f = fopen("/proc/self/status", "r");
    char ln[256];
    while (f && fgets(ln, sizeof ln, f))
        if (!strncmp(ln, "Seccomp", 7) || !strncmp(ln, "Tracer", 6) || !strncmp(ln, "Uid", 3) ||
            !strncmp(ln, "CapEff", 6) || !strncmp(ln, "Groups", 6))
            fputs(ln, stdout);
    if (f)
        fclose(f);
    return 0;
}
