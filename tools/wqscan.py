#!/usr/bin/env python3
"""Scan a broot leak dump for wait_queue_entry objects: {flags, private=current, func, task_list}.

Why this finds the prize: binder_thread.wait's task_list gets an entry from epoll's
ep_ptable_queue_proc, which does init_waitqueue_func_entry() -> .private = current.  So any
such object that shows up inside the leaked window hands us a task_struct VA -- the one
address route B (task->cred = init_cred) was missing.  No kernel read is needed to *spot*
it: the shape is self-describing (flags tiny, private in the linear map, func in .text,
and the two list pointers pointing back into a head).

usage: tools/wqscan.py <dump> [--base <hex stream-start VA>]
"""
import argparse
import os
import re
import struct
import sys

# Both segments exist on this box: _text=0xffffffc000080000 (high segment) while stack /
# thread_info pages come back as 0xffff8020f0000000 etc (PAGE_OFFSET=0xffff800000000000
# segment, measured in art/wq/real1.bin).  So the "is this a kernel VA" floor is 0xffff....
LIN_LO = 0xFFFF000000000000
LIN_HI = 0xFFFFFFFFFFFFFFFF
TEXT_LO = 0xFFFFFFC000080000
TEXT_HI = 0xFFFFFFC001400000


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dump")
    ap.add_argument("--base", default=None)
    ap.add_argument("--quiet", action="store_true")
    a = ap.parse_args()
    data = open(a.dump, "rb").read()
    base = int(a.base, 16) if a.base else None

    n = len(data) // 8
    w = lambda i: struct.unpack_from("<Q", data, i * 8)[0]
    kq = sum(1 for i in range(n) if LIN_LO <= w(i) < LIN_HI)
    hits = []
    for i in range(1, n - 5):
        flags, private, func, l1, l2 = w(i - 1), w(i), w(i + 1), w(i + 2), w(i + 3)
        if flags > 0x100:
            continue
        if not (LIN_LO <= private < LIN_HI):
            continue
        if not (TEXT_LO <= func < TEXT_HI):
            continue
        if not (LIN_LO <= l1 < LIN_HI and LIN_LO <= l2 < LIN_HI):
            continue
        hits.append((i, flags, private, func, l1, l2))

    if not a.quiet:
        print("# %s size=%d kernelVA-qwords=%d shaped-sites=%d base=%s" %
              (os.path.basename(a.dump), len(data), kq, len(hits), hex(base) if base else "?"))
    else:
        print("%s kq=%d wq=%d" % (os.path.basename(a.dump), kq, len(hits)))
    for i, flags, private, func, l1, l2 in hits[:25]:
        off = i * 8
        print("  WQ off=%-6d flags=%-4d task=%#x func=%#x list=(%#x,%#x)%s" %
              (off, flags, private, func, l1, l2,
               "  streamVA=%#x" % (base + off) if base else ""))
    if not hits:
        print("  none" + ("" if kq else "  <-- AND no kernel qwords: this dump is filler, not a leak"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
