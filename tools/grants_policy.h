/* tools/grants_policy.h -- who a grants line authorizes.
 *
 * The manager used to store one uid per granted app, so all packages sharing a uid
 * became root together, and an app clone (same package, different user id) was
 * invisible.  A line may now be either a plain uid (the old shape, kept so every
 * existing grants.txt and verify_approot.sh keep working) or
 *
 *     pkg <package.name>
 *
 * For a package line the caller is identified from the kernel's process tree: an
 * app runs su from its own process, or from a shell it spawned, so walking the
 * parent chain of the SO_PEERCRED pid finds the process whose cmdline is the
 * package name.  That is also what makes shared uids and multi-user/clone copies
 * work without trusting anything the caller says about itself.
 *
 * Included by both sud.c and relayd.c so the two enforcement points cannot drift.
 */
#ifndef GRANTS_POLICY_H
#define GRANTS_POLICY_H

#include <ctype.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static void gp_trim(char *s)
{
    char *p = s;
    size_t n;

    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')
        p++;
    if (p != s)
        memmove(s, p, strlen(p) + 1);
    n = strlen(s);
    while (n && (s[n - 1] == ' ' || s[n - 1] == '\t' || s[n - 1] == '\r' || s[n - 1] == '\n'))
        s[--n] = 0;
}

/* First NUL-terminated field of /proc/<pid>/cmdline. */
static int gp_cmdline(pid_t pid, char *out, size_t cap)
{
    char path[64];
    int fd;
    ssize_t n;

    if (pid <= 0 || cap == 0)
        return 0;
    snprintf(path, sizeof path, "/proc/%d/cmdline", (int) pid);
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return 0;
    n = read(fd, out, cap - 1);
    close(fd);
    if (n <= 0)
        return 0;
    out[n] = 0;
    /* cmdline is NUL separated; the first field is the process name. */
    return out[0] != 0;
}

static int gp_name_is_package(const char *name, const char *pkg)
{
    size_t l = strlen(pkg);

    if (strncmp(name, pkg, l) != 0)
        return 0;
    /* "com.foo" and "com.foo:service" belong to com.foo; "com.foobar" does not. */
    return name[l] == 0 || name[l] == ':';
}

static pid_t gp_ppid(pid_t pid)
{
    char path[64], buf[512];
    char *p, *q;
    int fd;
    ssize_t n;

    snprintf(path, sizeof path, "/proc/%d/stat", (int) pid);
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return 0;
    n = read(fd, buf, sizeof buf - 1);
    close(fd);
    if (n <= 0)
        return 0;
    buf[n] = 0;
    /* field 2 (comm) may contain spaces and parentheses; skip past the last ')'. */
    q = strrchr(buf, ')');
    if (q == NULL)
        return 0;
    p = q + 1;
    while (*p == ' ')
        p++;
    if (*p == 0)
        return 0;
    return (pid_t) atoi(p);
}

/* Does pid, or one of its ancestors, run as this package?  Depth is bounded so a
 * pathological process tree cannot turn an authorization check into a walk. */
static int gp_pid_is_package(pid_t pid, const char *pkg, int max_depth)
{
    int depth;

    for (depth = 0; pid > 1 && depth < max_depth; depth++) {
        char name[512];

        if (gp_cmdline(pid, name, sizeof name) && gp_name_is_package(name, pkg))
            return 1;
        pid = gp_ppid(pid);
    }
    return 0;
}

/* Sweep path: no pid is available, so fall back to "does this uid own this package
 * in any user's package list".  This is deliberately only used for revocation of
 * live sessions -- a fresh request always has a pid and gets the stricter check. */
static int gp_uid_has_package(int uid, const char *pkg)
{
    char path[256];
    DIR *d;
    int hit = 0;

    snprintf(path, sizeof path, "/data/system/packages.list");
    {
        FILE *f = fopen(path, "r");

        if (f != NULL) {
            char name[256];
            int u;

            while (fscanf(f, "%255s %d", name, &u) == 2) {
                if (u == uid && !strcmp(name, pkg)) {
                    hit = 1;
                    break;
                }
            }
            fclose(f);
        }
    }
    if (hit)
        return 1;
    d = opendir("/data/system/users");
    if (d == NULL)
        return 0;
    {
        struct dirent *e;

        while ((e = readdir(d)) != NULL) {
            FILE *f;
            char name[256];
            int u;

            if (e->d_name[0] < '0' || e->d_name[0] > '9')
                continue;
            snprintf(path, sizeof path, "/data/system/users/%s/packages.list", e->d_name);
            f = fopen(path, "r");
            if (f == NULL)
                continue;
            while (fscanf(f, "%255s %d", name, &u) == 2) {
                if (u == uid && !strcmp(name, pkg)) {
                    hit = 1;
                    break;
                }
            }
            fclose(f);
            if (hit)
                break;
        }
    }
    closedir(d);
    return hit;
}

/* Fallback for a caller whose parent chain was severed (a double-forked helper has
 * ppid 1, so no ancestor names the app).  Only a uid that owns exactly one package
 * may use it: with a shared uid the answer would be ambiguous, and guessing there is
 * the over-grant this change exists to remove. */
static int gp_uid_package_unique(int uid, const char *pkg)
{
    char path[256];
    char only[256] = "";
    char name[256];
    int seen = 0, u;
    FILE *f;
    DIR *d;

    snprintf(path, sizeof path, "/data/system/packages.list");
    f = fopen(path, "r");
    if (f != NULL) {
        while (fscanf(f, "%255s %d", name, &u) == 2) {
            if (u != uid)
                continue;
            if (seen && strcmp(only, name) != 0) {
                fclose(f);
                return 0;
            }
            if (!seen)
                snprintf(only, sizeof only, "%s", name);
            seen = 1;
        }
        fclose(f);
    }
    d = opendir("/data/system/users");
    if (d != NULL) {
        struct dirent *e;

        while ((e = readdir(d)) != NULL) {
            if (e->d_name[0] < '0' || e->d_name[0] > '9')
                continue;
            snprintf(path, sizeof path, "/data/system/users/%s/packages.list", e->d_name);
            f = fopen(path, "r");
            if (f == NULL)
                continue;
            while (fscanf(f, "%255s %d", name, &u) == 2) {
                if (u != uid)
                    continue;
                if (seen && strcmp(only, name) != 0) {
                    fclose(f);
                    closedir(d);
                    return 0;
                }
                if (!seen)
                    snprintf(only, sizeof only, "%s", name);
                seen = 1;
            }
            fclose(f);
        }
        closedir(d);
    }
    return seen && !strcmp(only, pkg);
}

/* One grants line, one caller.  pid < 0 means "no caller process" (sweep). */
static int gp_line_allows(const char *raw, int uid, pid_t pid)
{
    char line[300];
    char *name;

    snprintf(line, sizeof line, "%s", raw);
    gp_trim(line);
    if (line[0] == 0 || line[0] == '#')
        return 0;
    if (!strncmp(line, "pkg ", 4) || !strncmp(line, "pkg=", 4)) {
        name = line + 4;
        gp_trim(name);
        if (name[0] == 0)
            return 0;
        if (pid > 0) {
            if (gp_pid_is_package(pid, name, 8))
                return 1;
            return gp_uid_package_unique(uid, name);
        }
        return gp_uid_has_package(uid, name);
    }
    if (!strncmp(line, "uid ", 4) || !strncmp(line, "uid=", 4))
        return atoi(line + 4) == uid;
    return atoi(line) == uid;
}

#endif /* GRANTS_POLICY_H */
