/* tools/grants_rule_test.c -- arms for the rule that decides which uid list may grant root.
 * Compiled against tools/grants_rule.h, i.e. THE TEXT sud.c ships with -- not a re-implementation.
 * Build and run: cc -Wall -Wextra -o /tmp/grants_rule_test tools/grants_rule_test.c && /tmp/grants_rule_test
 *
 * Each shape appears twice -- once that must be trusted, once that must be refused -- so a rule
 * that stopped discriminating turns the run red rather than passing quietly.
 * Cases 4/5 are the hole found while auditing the 7.1.1 delivery: a list planted by an
 * unprivileged caller in a directory that caller can write passes every MODE test, and used to be
 * accepted (it hands root to whichever uids that caller types).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "grants_rule.h"

static int fails;

static void mk(struct stat *st, mode_t mode, uid_t uid, gid_t gid, int isdir)
{
    memset(st, 0, sizeof *st);
    st->st_mode = mode | (isdir ? S_IFDIR : S_IFREG);
    st->st_uid = uid;
    st->st_gid = gid;
}

static void check(const char *what, const struct stat *dir, const struct stat *file, gid_t self_gid,
                  int must_be_root, int want)
{
    int got = grants_file_usable_stat(dir, file, self_gid, must_be_root);

    if (got != want) {
        printf("FAIL  %-58s got %d want %d\n", what, got, want);
        fails++;
    } else
        printf("ok    %-58s %d\n", what, got);
}

int main(void)
{
    struct stat d_priv, d_shared, f_app, f_root0666, f_grp0666, f_planted, f_root0600, f_as_dir;
    struct stat f_root0660, f_other0660, d_app771, f_root0600b;

    mk(&d_priv, 0771, 10151, 10151, 1); /* the manager's own files/ directory */
    mk(&d_shared, 0777, 0, 0, 1);      /* a directory anyone can write */
    mk(&f_app, 0600, 10151, 10151, 0);
    mk(&f_root0666, 0666, 0, 0, 0);    /* root appended with the daemon's umask still 0666 */
    mk(&f_grp0666, 0666, 0, 3003, 0); /* world-writable list */
    mk(&f_planted, 0600, 2000, 3003, 0); /* an attacker's own list, tidy mode */
    mk(&f_root0600, 0600, 0, 0, 0);
    mk(&f_as_dir, 0700, 0, 0, 1);
    mk(&f_root0660, 0660, 0, 0, 0);            /* the shape verify_approot's root append leaves */
    mk(&f_other0660, 0660, 0, 3003, 0);       /* group write, group is not ours */
    mk(&d_app771, 0771, 10151, 10151, 1);    /* the manager's files/ dir as measured on device */
    mk(&f_root0600b, 0600, 0, 0, 0);         /* the grants.txt as measured on device */

    /* the legitimate shapes: this is what a mode-only rule used to lock out (criterion C) */
    check("1 app-private dir, 0600 list owned by that app", &d_priv, &f_app, 0, 0, 1);
    check("2 root:root 0666 -- OTHER may write, so refused", &d_priv, &f_root0666, 0, 0, 0);
    check("2b root:root 0660 while daemon is in group 0 -- usable", &d_priv, &f_root0660, 0, 0, 1);
    check("2c 0660 owned by another group -- refused", &d_priv, &f_other0660, 0, 0, 0);
    /* the refusals that were already in place */
    check("3 0666 list whose group is not ours", &d_priv, &f_grp0666, 0, 0, 0);
    check("4 list in a world-writable dir owned by someone else", &d_shared, &f_planted, 0, 0, 0);
    /* the hole closed now: /data/local/tmp/sud.grants planted by uid 2000 */
    check("5 shared-dir rule, list owned by uid 2000", &d_priv, &f_planted, 0, 1, 0);
    check("6 shared-dir rule, 0600 list owned by root", &d_shared, &f_root0600, 0, 1, 1);
    check("7 shared-dir rule, root list but 0666", &d_shared, &f_grp0666, 0, 1, 0);
    check("8 directory planted where the list is read", &d_shared, &f_as_dir, 0, 1, 0);
    /* the delivered layout, arm by arm: root writes the list inside the app's own 0771 dir */
    check("9 0771 app dir + root-owned 0600 list (real layout)", &d_app771, &f_root0600b, 0, 0, 1);
    check("9b same shape but a shared-dir candidate, owner not root", &d_app771, &f_planted, 0, 1, 0);
    check("9c same shape, group-writable parent, root file, shared rule", &d_app771, &f_root0600b,
          0, 1, 1);

    /* wiring: the same rule reached through real files, so a broken path split shows up */
    {
        char dir[] = "/tmp/grt-XXXXXX", path[64];
        struct stat sd, sf;
        FILE *fh;
        int a, b, c;

        if (!mkdtemp(dir)) { perror("mkdtemp"); return 2; }
        snprintf(path, sizeof path, "%s/grants.txt", dir);
        fh = fopen(path, "w");
        if (!fh) { perror("fopen"); return 2; }
        fprintf(fh, "10151\n");
        fclose(fh);
        chmod(path, 0600);
        chmod(dir, 0700);
        a = grants_file_usable_at(path, getgid(), 0);
        chmod(dir, 0777);
        b = grants_file_usable_at(path, getgid(), 0);
        c = grants_file_usable_at(path, getgid(), 1);
        stat(dir, &sd);
        stat(path, &sf);
        printf("wiring  private-dir 0600=%d (want 1) | 0777-dir same owner=%d | shared rule on it=%d (want 0)\n",
               a, b, c);
        printf("        dir uid=%u mode=%04o, file uid=%u mode=%04o\n",
               (unsigned) sd.st_uid, (unsigned) (sd.st_mode & 0777),
               (unsigned) sf.st_uid, (unsigned) (sf.st_mode & 0777));
        if (!a || c) fails++;
        unlink(path);
        rmdir(dir);
    }

    printf("%s: %d failure(s)\n", fails ? "GRANTS RULE TEST FAILED" : "grants rule: all arms pass", fails);
    return fails != 0;
}
