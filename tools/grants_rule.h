/* tools/grants_rule.h -- the one rule that decides whether a uid list may grant root.
 *
 * It lives in a header so tools/grants_rule_test.c compiles THE SAME TEXT the daemon uses;
 * a copy of a predicate in a test is not a test of the predicate (ledger 585).
 *
 * Where the shape of this rule comes from, and one thing it corrects:
 *  * the group clause is conditional on PURPOSE: rejecting any group-writable list locked the
 *    legitimate path out once (criterion C went red), so group write counts only when the daemon
 *    is not in that group.  An older comment here claimed "0666 root:root stays usable" -- that is
 *    NOT what the rule does and it was never what the rule should do: 0666 means "other" can
 *    write, and the live file is 0600 root:root (measured on the device, ledger 585).  The arm in
 *    tools/grants_rule_test.c is what caught the stale sentence.
 *  * the mode of a file says nothing about who may REPLACE it.  A caller who can write the
 *    containing directory can install their own list at 0600, owned by themselves, and a mode-only
 *    test accepts it -- handing root to whichever uids that caller types.  So the directory is part
 *    of the rule, and a list in a directory other uids reach must have been planted by root.
 */
#ifndef GRANTS_RULE_H
#define GRANTS_RULE_H

#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

/* Returns 1 when the list may be trusted.  owner_must_be_root is set by the caller for the
 * candidates that live in a directory other uids can reach (/data/local/tmp). */
static int grants_file_usable_stat(const struct stat *parent, const struct stat *st,
                                   gid_t self_gid, int owner_must_be_root)
{
    if (!S_ISREG(st->st_mode))
        return 0;
    if (owner_must_be_root && st->st_uid != 0)
        return 0;
    if ((st->st_mode & S_IWOTH) != 0 ||
        ((st->st_mode & S_IWGRP) != 0 && st->st_gid != self_gid))
        return 0;
    /* Only the OTHER-writable directory is refused outright: anyone at all may swap a file there,
     * and when the directory's owner is not the file's owner, that owner is the one who can.
     * A GROUP-writable directory is NOT refused -- measured reason: the manager's own files/ dir is
     * 0771 app:app and the grants list inside it is created by ROOT (0600 root:root) because
     * tools/verify_approot.sh writes it through the daemon; refusing group-writable parents would
     * have broken the delivered path (this was caught by arm 2b against the real layout, ledger 585). */
    if (parent != NULL && S_ISDIR(parent->st_mode)) {
        if ((parent->st_mode & S_IWOTH) != 0 && parent->st_uid != st->st_uid)
            return 0;
    } else if (!owner_must_be_root) {
        /* an unresolvable directory is only acceptable where the file itself must be root's */
        return 0;
    }
    return 1;
}

static int grants_file_usable_at(const char *path, gid_t self_gid, int owner_must_be_root)
{
    struct stat st, par;
    char dir[512];
    const char *slash;
    size_t n;

    if (stat(path, &st) != 0)
        return 0;
    slash = strrchr(path, '/');
    n = slash ? (size_t) (slash - path) : 0;
    if (n == 0 || n >= sizeof dir)
        return grants_file_usable_stat(NULL, &st, self_gid, 1);
    memcpy(dir, path, n);
    dir[n] = 0;
    if (stat(dir, &par) != 0)
        return grants_file_usable_stat(NULL, &st, self_gid, 1);
    return grants_file_usable_stat(&par, &st, self_gid, owner_must_be_root);
}

#endif /* GRANTS_RULE_H */
