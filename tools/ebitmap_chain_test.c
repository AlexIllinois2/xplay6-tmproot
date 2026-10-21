/* Host arms for the ebitmap chain-legality predicate the on-device walker uses (tools/ebitmap_map.h:
 * ebmp_chain_step) and for the builder's promise that it never EMITS an illegal chain.
 *
 * Why a separate binary: the same predicate decides, on the phone, whether a read of
 * policydb.permissive_map is trusted at all.  A judgement that only runs on the device cannot be
 * arm-tested, and both of today's false verdicts (a merge that read zero and silently dropped the
 * vendor's exemptions; a correct plant accused of missing bit 192) came from trusting a bad read.
 *
 * build+run: cc -O2 -Wall -o /tmp/ebmpchain tools/ebitmap_chain_test.c && /tmp/ebmpchain
 */
#include <stdio.h>
#include <string.h>
#include "ebitmap_map.h"

static int fails;

static void expect(const char *what, int got, int want)
{
    if (got == want) {
        printf("  ok   %s\n", what);
        return;
    }
    printf("  FAIL %s: got %d want %d\n", what, got, want);
    fails++;
}

/* Every window the builder produces must be legal after the previous one, and every bit that went in
 * must read back as exempt while a neighbour that did not go in must not. */
static void check_set(const char *label, const unsigned int *bits, int n)
{
    struct ebmp_window win[EBMP_MAX_NODES];
    unsigned char nodes[EBMP_MAX_NODES * EBMP_NODE_BYTES], head[16];
    unsigned int sorted[64];
    int i, j, nw, bad = 0;

    if (n > 64) {
        printf("  FAIL %s: too many bits for the arm\n", label);
        fails++;
        return;
    }
    for (i = 0; i < n; i++)
        sorted[i] = bits[i];
    for (i = 1; i < n; i++)
        for (j = i - 1; j >= 0 && sorted[j] > sorted[i]; j--) {
            unsigned int t = sorted[j + 1];
            sorted[j + 1] = sorted[j];
            sorted[j] = t;
        }
    nw = ebmp_windows(sorted, n, win);
    if (nw < 0) {
        printf("  ok   %s: refused -- %u bits need more than %d windows\n", label,
               (unsigned)n, EBMP_MAX_NODES);
        return;
    }
    for (i = 1; i < nw; i++)
        if (ebmp_chain_step(win[i - 1].startbit, 1, win[i].startbit) != EBMP_CHAIN_OK)
            bad++;
    if (bad)
        printf("  FAIL %s: builder emitted %d illegal window step(s)\n", label, bad);
    else
        printf("  ok   %s: %d windows, every step legal\n", label, nw);
    fails += bad;

    nw = ebmp_build(sorted, n, 0xffffffc001a419c0ULL, nodes, head);
    for (i = 0; i < n; i++)
        if (!ebmp_get_bit(nodes, nw, head, sorted[i])) {
            printf("  FAIL %s: bit %u went in but does not read exempt\n", label, sorted[i]);
            fails++;
        }
    /* a neighbour that was NOT in the set must not read exempt -- otherwise the arms below would pass
     * on a builder that sets whole words */
    for (i = 0; i < n; i++) {
        unsigned int off = sorted[i] + 1;
        int k, is_member = 0;

        for (k = 0; k < n; k++)
            if (sorted[k] == off)
                is_member = 1;
        if (!is_member && ebmp_get_bit(nodes, nw, head, off)) {
            printf("  FAIL %s: %u leaks into %u, which was never asked for\n", label, sorted[i], off);
            fails++;
        }
    }
}

/* The device never sees node BYTES: getgroups hands back 16 u32 units and permmap_read_once rebuilds
 * each maps[] word from a (low, high) unit pair.  That rebuild is where type 192 went missing for
 * three boots -- the shipped expression took nd[3 + j*2 + 1] as the high half, which is the NEXT
 * word's low half, and read unit 14 (startbit) as maps[5]'s high half, manufacturing 247/361/364 out
 * of a node that really held 9/192/279.  So: the units view must decode to exactly the same set as
 * the byte view the builder wrote.  Input must be sorted and duplicate-free, as the plant leaves it.
 */
static void check_units_view(const char *label, const unsigned int *bits, int n)
{
    unsigned char nodes[EBMP_MAX_NODES * EBMP_NODE_BYTES], head[16];
    unsigned int got[128];
    int i, j, k, nw, ng = 0, b, bad = 0;

    nw = ebmp_build(bits, n, 0xffffffc001a419c0ULL, nodes, head);
    if (nw < 0) {
        printf("  FAIL %s: builder refused (%d bits do not fit)\n", label, n);
        fails++;
        return;
    }
    for (j = 0; j < nw; j++) {
        unsigned int nd[16], startbit;

        memcpy(nd, nodes + EBMP_NODE_BYTES * j, sizeof nd);
        startbit = nd[14];
        for (i = 0; i < 6; i++) {
            unsigned long long word = ebmp_maps_word(nd, i);

            for (k = 0; k < 64 && startbit + i * 64 + k <= 4095; k++)
                if ((word >> k) & 1) {
                    if (ng < (int)(sizeof got / sizeof *got))
                        got[ng] = startbit + i * 64 + k;
                    ng++;
                }
        }
    }
    for (b = 0; b < 2000; b++) {
        int w = 0, in_units = 0, in_bytes;

        for (i = 0; i < n; i++)
            if (bits[i] == (unsigned int)b)
                w = 1;
        for (i = 0; i < ng && i < (int)(sizeof got / sizeof *got); i++)
            if (got[i] == (unsigned int)b)
                in_units = 1;
        in_bytes = ebmp_get_bit(nodes, nw, head, (unsigned int)b);
        if (w == in_units && w == in_bytes)
            continue;
        printf("  FAIL %s: bit %d asked=%d byte-view=%d units-view=%d\n", label, b, w, in_bytes, in_units);
        bad = 1;
    }
    if (bad) {
        fails++;
        return;
    }
    printf("  ok   %s: %d bit(s), byte view and units view agree\n", label, n);
}

int main(void)
{    const unsigned int shipped[] = { 9, 192, 279, 593, 743, 1083, 1156 };
    const unsigned int withvendor[] = { 9, 192, 247, 279, 361, 364, 593, 711, 743,
                                        945, 949, 951, 954, 1083, 1124, 1156, 1435, 1445 };
    const unsigned int crowded[] = { 1, 200, 400, 600, 800, 1000, 1200, 1400, 1600 };
    const unsigned int aligned[] = { 128, 200, 512, 900, 1300 };

    printf("ebmp_chain_step:\n");
    expect("first node is always acceptable", ebmp_chain_step(0, 0, 4000), EBMP_CHAIN_OK);
    expect("gap >= span is legal", ebmp_chain_step(9, 1, 593), EBMP_CHAIN_OK);
    expect("exactly span away is legal", ebmp_chain_step(0, 1, EBMP_SPAN), EBMP_CHAIN_OK);
    expect("equal startbit is rejected", ebmp_chain_step(593, 1, 593), EBMP_CHAIN_BAD_ORDER);
    expect("lower startbit is rejected", ebmp_chain_step(593, 1, 9), EBMP_CHAIN_BAD_ORDER);
    expect("one above previous is rejected (would shadow)", ebmp_chain_step(9, 1, 10), EBMP_CHAIN_BAD_SHADOW);
    expect("span-1 above is rejected", ebmp_chain_step(0, 1, EBMP_SPAN - 1), EBMP_CHAIN_BAD_SHADOW);

    printf("ebmp_walk_verdict (the walk the device trusts):\n");
    expect("3 of 3 planted nodes, terminated, bits found", ebmp_walk_verdict(3, 1, 3, 1156, 7), EBMP_WALK_OK);
    expect("a plain read of a 2-node vendor chain is accepted", ebmp_walk_verdict(2, 1, -1, 1445, 21), EBMP_WALK_OK);
    expect("the off-by-one that accused a correct plant is now OK", ebmp_walk_verdict(3, 1, 3, 1156, 7), EBMP_WALK_OK);
    expect("one node short of what was planted is refused", ebmp_walk_verdict(2, 1, 3, 1156, 5), EBMP_WALK_COUNT);
    expect("a walk that never hit NULL next is refused", ebmp_walk_verdict(12, 0, -1, 1445, 30), EBMP_WALK_TRUNCATED);
    expect("highbit>0 with no bit decoded is refused", ebmp_walk_verdict(0, 1, -1, 1445, 0), EBMP_WALK_EMPTY);
    expect("an actually-empty map (highbit 0) is accepted", ebmp_walk_verdict(0, 1, EBMP_JUST_READING, 0, 0), EBMP_WALK_OK);
    expect("the calling-convention trap: nwant=0 with a 3-node chain is refused", ebmp_walk_verdict(3, 1, 0, 1445, 21), EBMP_WALK_COUNT);

    printf("builder never emits an illegal chain, and never sets a bit it was not given:\n");
    check_set("shipped 7-bit set", shipped, (int)(sizeof shipped / sizeof *shipped));
    check_set("shipped merged with a vendor-like 18-bit spread", withvendor,
              (int)(sizeof withvendor / sizeof *withvendor));
    check_set("128-aligned vendor style", aligned, (int)(sizeof aligned / sizeof *aligned));
    check_set("nine bits across 1600 (capacity must refuse or be legal)", crowded,
              (int)(sizeof crowded / sizeof *crowded));

    printf("the read-back units view decodes what the byte view holds:\n");
    {
        const unsigned int onehigh[] = { 192 };                    /* mask lives only in a word's high half */
        const unsigned int eachword[] = { 1, 65, 129, 193, 257, 321 };

        check_units_view("shipped 7-bit set", shipped, (int)(sizeof shipped / sizeof *shipped));
        check_units_view("one high-half bit (type 192 alone)", onehigh,
                         (int)(sizeof onehigh / sizeof *onehigh));
        check_units_view("one bit per maps word", eachword, (int)(sizeof eachword / sizeof *eachword));
        check_units_view("vendor-like spread", withvendor, (int)(sizeof withvendor / sizeof *withvendor));
    }

    printf("%s\n", fails ? "EBITMAP CHAIN TEST FAIL" : "EBITMAP CHAIN TEST OK");
    return fails != 0;
}
