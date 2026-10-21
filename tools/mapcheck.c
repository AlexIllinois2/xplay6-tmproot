/* Host check for the permissive_map builder: compiles the SAME header the on-device escalation uses
 * and prints its bytes in exactly the format tools/bootstrap3.sh emits, so the two can be diffed.
 * bootstrap3.sh's payloads are the ones measured to work on the device, so byte equality here means
 * "the C path plants what the verified python path plants" -- without a phone in the loop.
 *
 * The bit set is an argument now, because the set the Android 7 line ships is NOT the 6.0.1 one, and
 * an on-device plant computed by tools/permmap7.py only certifies the SHIPPED bytes if the C builder
 * that produces them agrees byte-for-byte (ledger 2026-10-21 §708).
 *
 * build+run:  cc -O2 -o /tmp/mapcheck tools/mapcheck.c
 *             /tmp/mapcheck                                   # 6.0.1 default
 *             /tmp/mapcheck --bits 9,192,279 --base 0xffffffc001a419c0
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ebitmap_map.h"

static const unsigned int default_bits[] = { 164, 241, 494, 627 };  /* sorted, as esc_exempt is */
#define DEFAULT_BASE 0xffffffc001635a78ULL
#define MAXB         64
#define SCAN_BITS    2000

int main(int argc, char **argv)
{
    unsigned int bits[MAXB];
    int nbits = 0, i, nw, b, bad = 0;
    unsigned long long base = DEFAULT_BASE;
    unsigned char nodes[EBMP_MAX_NODES * EBMP_NODE_BYTES], head[16];

    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--bits") && i + 1 < argc) {
            char *list = strdup(argv[++i]), *tok, *save = NULL;
            for (tok = strtok_r(list, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
                if (nbits == MAXB) {
                    printf("REFUSE: more than %d bits\n", MAXB);
                    return 2;
                }
                bits[nbits++] = (unsigned int)strtoul(tok, NULL, 0);
            }
        } else if (!strcmp(argv[i], "--base") && i + 1 < argc) {
            base = strtoull(argv[++i], NULL, 0);
        } else {
            printf("usage: %s [--bits a,b,c] [--base 0xADDR]\n", argv[0]);
            return 2;
        }
    }
    if (!nbits) {
        memcpy(bits, default_bits, sizeof default_bits);
        nbits = (int)(sizeof default_bits / sizeof *default_bits);
    }
    for (i = 0; i < nbits - 1; i++) {          /* ebmp_build expects ascending order */
        int j;
        for (j = i + 1; j < nbits; j++)
            if (bits[j] < bits[i]) {
                unsigned int t = bits[i];
                bits[i] = bits[j];
                bits[j] = t;
            }
    }

    nw = ebmp_build(bits, nbits, base, nodes, head);
    if (nw < 0) {
        printf("REFUSE: builder needs more than %d nodes for bits {", EBMP_MAX_NODES);
        for (i = 0; i < nbits; i++)
            printf("%s%u", i ? "," : "", bits[i]);
        printf("}\n");
        return 1;
    }
    for (i = 0; i < nw; i++) {
        const unsigned char *n = nodes + i * EBMP_NODE_BYTES;
        unsigned int startbit = (unsigned int)n[56] | ((unsigned int)n[57] << 8)
                                | ((unsigned int)n[58] << 16) | ((unsigned int)n[59] << 24);
        int k, first = 1;

        printf("NODE_HEX_%d=", i);
        for (k = 0; k < EBMP_NODE_BYTES; k++)
            printf("%02x", n[k]);
        printf("\nNODE_ADDR_%d=%#llx\nNODE_BITS_%d=", i,
               (unsigned long long)(base + EBMP_NODE_BYTES * (unsigned long long)i), i);
        for (b = 0; b < SCAN_BITS; b++)
            if (ebmp_get_bit(nodes, nw, head, (unsigned int)b)) {
                printf("%s%d", first ? "" : "_", b);
                first = 0;
            }
        printf("  (startbit=%u)\n", startbit);
    }
    printf("HEAD_HEX=");
    for (i = 0; i < 16; i++)
        printf("%02x", head[i]);
    printf("\n");

    /* the claim under test: exactly the intended bits resolve to 1, and nothing else does */
    for (b = 0; b < SCAN_BITS; b++) {
        int want = 0, got = ebmp_get_bit(nodes, nw, head, (unsigned int)b), k;

        for (k = 0; k < nbits; k++)
            if (bits[k] == (unsigned int)b)
                want = 1;
        if (got != want) {
            printf("MISMATCH at bit %d: got %d want %d\n", b, got, want);
            bad = 1;
        }
    }
    printf("%s\n", bad ? "FAIL: bytes do not decode to exactly the exempt set" : "OK");
    return bad;
}
