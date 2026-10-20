/* Arms for tools/borrow_verdict.h -- host-native, no device needed.
 *
 * The regression being closed is a measured one: on the BACKLATE path the ladder printed
 * `L7: borrow did not take (uid=0 sb=0)` and exited rc=2 on a run where the borrow HAD taken
 * (ledger 599 / task 516).  Arm "teeth" reproduces the shipped predicate against that exact
 * reading so the fix cannot be passing merely because the test is weak.
 *
 * build & run: cc -Wall -Wextra -Werror -O1 -o /tmp/borrow_verdict_test \
 *              tools/borrow_verdict_test.c && /tmp/borrow_verdict_test
 */
#include <stdio.h>

#include "borrow_verdict.h"

#define INIT_CRED 0xffffffc001a4ad08ULL
#define OWN_CRED  0xffffffc012345600ULL
#define SBMARK    0x40

static int fails;

/* the predicate the shipped win_open() uses today */
static int old_verdict(int uid_after, int sb)
{
    return (uid_after != 0 || sb != SBMARK) ? 0 : 1;   /* 1 = "took" */
}

static void arm(const char *name, int cond)
{
    printf("  %s %s\n", cond ? "ok  " : "FAIL", name);
    if (!cond)
        fails++;
}

int main(void)
{
    int ab, got;

    /* 1 -- the reading actually seen on the phone this boot: already root, securebits 0,
     *      and the pointer that says the write landed */
    got = borrow_took(INIT_CRED, INIT_CRED, INIT_CRED, 0, 0, 0, SBMARK, &ab);
    arm("already-borrowed: uid=0 sb=0 with cred readback == init_cred is a TAKE",
        got == BORROW_TOOK && ab == 1);
    arm("teeth: the shipped predicate calls that same reading a failure (this is the bug)",
        old_verdict(0, 0) == 0);

    /* 2 -- the ordinary fresh window: uid moves, pointer moves */
    got = borrow_took(OWN_CRED, INIT_CRED, INIT_CRED, 10151, 0, SBMARK, SBMARK, &ab);
    arm("fresh borrow: uid 10151->0 and cred readback == init_cred is a TAKE",
        got == BORROW_TOOK && ab == 0);

    /* 3 -- write genuinely did not land */
    got = borrow_took(OWN_CRED, OWN_CRED, INIT_CRED, 10151, 10151, 0, SBMARK, &ab);
    arm("no-take: readback still the own cred is NOT a take", got == BORROW_NOCHANGE);

    /* 4 -- readback channel dead, uid says root: must be flagged as auxiliary, not proof */
    got = borrow_took(0, 0, INIT_CRED, 10151, 0, SBMARK, SBMARK, &ab);
    arm("aux-only: with no readback, uid==0 is reported as AUX not TAKE", got == BORROW_AUX);
    got = borrow_took(0, 0, INIT_CRED, 10151, 10151, 0, SBMARK, &ab);
    arm("refuse: no readback and uid!=0 is NOT a take", got == BORROW_NOCHANGE);

    /* 5 -- marker mismatch must never veto a pointer-confirmed take */
    got = borrow_took(OWN_CRED, INIT_CRED, INIT_CRED, 10151, 0, 0, SBMARK, &ab);
    arm("securebits 0 (init_cred's real value) does not veto a pointer-confirmed take",
        got == BORROW_TOOK);

    printf("borrow_verdict: %d arm(s) failed\n", fails);
    return fails ? 1 : 0;
}
