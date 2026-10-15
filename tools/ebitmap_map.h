/* policydb.permissive_map builder, shared by the on-device escalation (clobber.c) and the host
 * check (mapcheck.c) so "the bytes C writes" and "the bytes the verified python wrote" can be
 * compared without a phone in the loop.
 *
 * Layout, from this tree's own kernel source (fw/ksrc/.../security/selinux/ss/ebitmap.h):
 *   struct ebitmap_node { next(8) ; maps[6](48) ; startbit(4) ; pad(4) }   -- 64 B on 64-bit
 *   ebitmap_get_bit(e, bit):
 *       if (e->highbit < bit) return 0;
 *       for (n = e->node; n && n->startbit <= bit; n = n->next)
 *           if (n->startbit + 384 > bit) return test_bit(bit - n->startbit, n->maps);
 *       return 0;
 * Two consequences this file relies on:
 *   - a node's startbit need NOT be 64-aligned, so one node can span an arbitrary 384-bit window
 *     ({164,241,494} fits in a node whose startbit is 164);
 *   - bits below the first node's startbit read as 0, so a window that starts high exempts nothing
 *     underneath it.
 */
#ifndef EBMP_MAP_H
#define EBMP_MAP_H

#include <string.h>

#define EBMP_NODE_BYTES 64
#define EBMP_SPAN       384   /* EBITMAP_UNIT_NUMS(6) * 64 */
#define EBMP_MAX_NODES  4     /* what fits in modprobe_path's tail (256 - 0x48) */

struct ebmp_window {
    unsigned int startbit;
    unsigned int first;    /* index into the sorted bit array */
    unsigned int count;
};

static inline void ebmp_put64(unsigned char *p, unsigned long long v)
{
    int i;

    for (i = 0; i < 8; i++)
        p[i] = (unsigned char)(v >> (8 * i));
}

static inline void ebmp_put32(unsigned char *p, unsigned int v)
{
    int i;

    for (i = 0; i < 4; i++)
        p[i] = (unsigned char)(v >> (8 * i));
}

/* Greedy ascending windows over a SORTED bit array.  Returns the window count, or -1 if the bits
 * need more nodes than the tail can hold. */
static inline int ebmp_windows(const unsigned int *bits, int n, struct ebmp_window *out)
{
    int i = 0, w = 0;

    while (i < n) {
        unsigned int s = bits[i], j = i;

        while ((int)j < n && bits[j] - s < EBMP_SPAN)
            j++;
        if (w >= EBMP_MAX_NODES)
            return -1;
        out[w].startbit = s;
        out[w].first = (unsigned int)i;
        out[w].count = (unsigned int)(j - i);
        i = (int)j;
        w++;
    }
    return w;
}

static inline void ebmp_node(unsigned char *node, unsigned long long next, const struct ebmp_window *win,
                      const unsigned int *bits)
{
    int k;

    memset(node, 0, EBMP_NODE_BYTES);
    ebmp_put64(node + 0, next);
    ebmp_put32(node + 56, win->startbit);
    for (k = 0; k < (int)win->count; k++) {
        unsigned int off = bits[win->first + k] - win->startbit;

        /* maps[] is an array of little-endian 64-bit words: byte = word*8 + (off%64)/8. */
        node[8 + (off / 64) * 8 + (off % 64) / 8] |= (unsigned char)(1u << (off % 8));
    }
}

/* Emit node bytes (nw * 64) and the 16-byte head.  base is where node 0 will live; nodes are
 * chained contiguously at base + 64*i. */
static inline int ebmp_build(const unsigned int *bits, int n, unsigned long long base,
                      unsigned char *nodes, unsigned char *head)
{
    struct ebmp_window win[EBMP_MAX_NODES];
    unsigned int maxb = 0;
    int i, nw;

    for (i = 0; i < n; i++)
        if (bits[i] > maxb)
            maxb = bits[i];
    nw = ebmp_windows(bits, n, win);
    if (nw < 0)
        return nw;
    for (i = 0; i < nw; i++) {
        unsigned long long next = (i + 1 < nw) ? base + EBMP_NODE_BYTES * (unsigned long long)(i + 1) : 0ULL;

        ebmp_node(nodes + EBMP_NODE_BYTES * i, next, &win[i], bits);
    }
    ebmp_put64(head, base);
    ebmp_put32(head + 8, maxb);
    ebmp_put32(head + 12, 0);
    return nw;
}

/* Mirror of the kernel's ebitmap_get_bit, over buffers built by ebmp_build -- so a test can assert
 * "exactly these bits read as permissive" from the bytes, not from the loop that made them. */
static inline int ebmp_get_bit(const unsigned char *nodes, int nw, const unsigned char *head,
                        unsigned int bit)
{
    int i;
    unsigned long long headnode;
    unsigned int highbit;

    headnode = 0;
    {
        int k;

        for (k = 7; k >= 0; k--)
            headnode = (headnode << 8) | head[k];
    }
    highbit = 0;
    for (i = 3; i >= 0; i--)
        highbit = (highbit << 8) | head[8 + i];
    if (highbit < bit)
        return 0;
    (void)headnode;
    for (i = 0; i < nw; i++) {
        const unsigned char *node = nodes + EBMP_NODE_BYTES * i;
        unsigned int startbit = 0;
        unsigned long long w;
        unsigned int off;
        int k;

        for (k = 3; k >= 0; k--)
            startbit = (startbit << 8) | node[56 + k];
        if (startbit > bit)
            break;
        if (startbit + EBMP_SPAN > bit) {
            off = bit - startbit;
            w = 0;
            for (k = 7; k >= 0; k--)
                w = (w << 8) | node[8 + (off / 64) * 8 + k];
            return (w >> (off % 64)) & 1u;
        }
    }
    return 0;
}

#endif /* EBMP_MAP_H */
