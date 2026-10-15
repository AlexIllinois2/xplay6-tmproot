/* tools/statedec_probe.c -- run the *extracted kernel bytes* of the PowerMo status
 * decoder (fw/Image 0x32bcbc..0x32bdb0) under qemu-aarch64, so the Python model in
 * tools/sugate_solve.py is checked against real machine code instead of my reading
 * of it.  Reads "raw0 raw1 raw2 raw3" hex tuples on stdin, prints the decoded u32.
 *
 * The decoder reaches its input through `adrp x10, <.bss page>` + `add #0x910` +
 * `add x2,x10,#0x18`, so the data page position is derived from wherever the code
 * actually lands -- that is why CODE_VA is not hardcoded.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#include "statedec.h"

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100
#endif

int main(void)
{
    unsigned char *code = NULL;
    uint32_t *raw = NULL;

    for (unsigned long hint = 0x20000000UL; hint < 0x60000000UL; hint += 0x1000000UL) {
        code = mmap((void *)hint, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (code == MAP_FAILED)
            continue;
        if ((unsigned long)code != hint) {          /* kernel ignored the hint */
            munmap(code, 0x1000);
            continue;
        }
        unsigned long bss = (((unsigned long)code + dec_adrp_off) & ~0xfffUL) + dec_adrp_delta;
        unsigned long rawa = bss + dec_bss_add + dec_raw_add;
        void *d = mmap((void *)(rawa & ~0xfffUL), 0x2000, PROT_READ | PROT_WRITE,
                       MAP_FIXED_NOREPLACE | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (d == MAP_FAILED) {
            munmap(code, 0x1000);
            continue;
        }
        raw = (uint32_t *)rawa;
        break;
    }
    if (!raw) {
        fprintf(stderr, "no usable code/data address pair\n");
        return 1;
    }
    memcpy(code, dec_bytes, dec_len);
    __builtin___clear_cache((char *)code, (char *)code + dec_len);

    unsigned a, b, c, d;
    while (scanf("%x %x %x %x", &a, &b, &c, &d) == 4) {
        raw[0] = a;
        raw[1] = b;
        raw[2] = c;
        raw[3] = d;
        uint32_t out = 0;
        ((void (*)(void *))code)(&out);
        printf("%08x\n", out);
        if (fflush(stdout) != 0)
            return 1;
    }
    return 0;
}
