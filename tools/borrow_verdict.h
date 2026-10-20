/* Did the credential borrow actually take?  Shared by broot7's win_open() and its host arms.
 *
 * Why this is a separate file with tests (ledger 599 / task 516): the shipped verdict was
 *     if (getuid() != 0 || prctl(PR_GET_SECUREBITS) != SBMARK) -> "borrow did not take"
 * and on the BACKLATE path that fires on a run that SUCCEEDED: after the final swap the task is
 * ALREADY init_cred, so re-writing task->cred changes nothing, uid was already 0, and init_cred's
 * real securebits are 0 while SBMARK defaults to 0x40 -- so a genuine borrow was reported as
 * `borrow did not take (uid=0 sb=0)` and the ladder exited rc=2.  rc=2 then looked like "the
 * exemption did not survive Enforcing", which is a capability claim, from a ruler artefact.
 *
 * The direct evidence is the pointer itself: read task->cred back through the same channel and
 * compare it with the value we wrote.  uid and securebits are kept as AUXILIARY readings and are
 * reported, never required, because both can be already-satisfied before the write.
 */
#ifndef BORROW_VERDICT_H
#define BORROW_VERDICT_H

#define BORROW_NOCHANGE 0      /* write did not land: cred still the old one */
#define BORROW_TOOK     1      /* write landed: task->cred == the borrowed cred */
#define BORROW_AUX      2      /* readback unavailable -> decided on uid/securebits only */

/* cred_after/cred_before are read through the kernel read channel; 0 means "could not read".
 * expect_cred is the credential we tried to install (init_cred).  uid_before/uid_after and sb
 * are the auxiliary faces.  *why receives a one-line reason (never NULL). */
static int borrow_took(unsigned long long cred_before, unsigned long long cred_after,
                       unsigned long long expect_cred, int uid_before, int uid_after,
                       int sb, int sbmark, int *already_borrowed)
{
    (void)uid_before;
    (void)sb;      /* reported by the caller, never decisive: init_cred's real
               securebits are 0, so the marker cannot prove or disprove a borrow */
    (void)sbmark;
    *already_borrowed = 0;
    if (cred_after && cred_after == expect_cred) {
        *already_borrowed = (cred_before == expect_cred);
        return BORROW_TOOK;
    }
    if (cred_after && cred_after != expect_cred)
        return BORROW_NOCHANGE;
    /* No readback available (the channel itself failed): fall back, but the caller must say
     * that is what it did -- uid==0 alone cannot prove the write landed. */
    return uid_after == 0 ? BORROW_AUX : BORROW_NOCHANGE;
}

#endif /* BORROW_VERDICT_H */
