/* Host check for the permissive_map builder: compiles the SAME header the on-device escalation uses
 * and prints its bytes in exactly the format tools/bootstrap3.sh emits, so the two can be diffed.
 * bootstrap3.sh's payloads are the ones measured to work on the device, so byte equality here means
 * "the C path plants what the verified python path plants" -- without a phone in the loop.
 *
 * build+run: cc -O2 -o /tmp/mapcheck tools/mapcheck.c && /tmp/mapcheck
 */
#include <stdio.h>
#include "ebitmap_map.h"

static const unsigned int bits[] = { 164, 241, 494, 627 };   /* sorted ascending, as esc_exempt is */
#define NBITS ((int)(sizeof bits / sizeof *bits))
#define NODE_BASE 0xffffffc001635a78ULL

int main(void)
{
    unsigned char nodes[EBMP_MAX_NODES * EBMP_NODE_BYTES], head[16];
    int nw, i, b, bad = 0;

    nw = ebmp_build(bits, NBITS, NODE_BASE, nodes, head);
    if (nw < 0) {
        printf("builder needs more than %d nodes\n", EBMP_MAX_NODES);
        return 1;
    }
    for (i = 0; i < nw; i++) {
        printf("NODE_HEX_%d=", i);
        {
            int k;

            for (k = 0; k < EBMP_NODE_BYTES; k++)
                printf("%02x", nodes[i * EBMP_NODE_BYTES + k]);
        }
        printf("\nNODE_ADDR_%d=%#llx\n", i, (unsigned long long)(NODE_BASE + 64 * i));
        printf("NODE_BITS_%d=", i);
        {
            const unsigned char *n = nodes + i * EBMP_NODE_BYTES;
            unsigned int startbit = (unsigned int)n[56] | ((unsigned int)n[57] << 8)
                                    | ((unsigned int)n[58] << 16) | ((unsigned int)n[59] << 24);
            int first = 1;

            for (b = 0; b < 2000; b++)
                if (ebmp_get_bit(nodes, nw, head, (unsigned int)b)) {
                    printf("%s%d", first ? "" : "_", b);
                    first = 0;
                }
            printf("  (startbit=%u)\n", startbit);
        }
    }
    printf("HEAD_HEX=");
    for (i = 0; i < 16; i++)
        printf("%02x", head[i]);
    printf("\n");

    /* the claim under test: exactly the intended bits resolve to 1 */
    for (b = 0; b < 2000; b++) {
        int want = 0, k;

        for (k = 0; k < NBITS; k++)
            if (bits[k] == (unsigned int)b)
                want = 1;
        if (ebmp_get_bit(nodes, nw, head, (unsigned int)b) != want) {
            printf("MISMATCH at bit %d: got %d want %d\n", b,
                   ebmp_get_bit(nodes, nw, head, (unsigned int)b), want);
            bad = 1;
        }
    }
    printf("%s\n", bad ? "FAIL: bytes do not decode to exactly the exempt set"
                       : "OK: bytes decode to exactly {164,241,494,627}");
    return bad;
}
