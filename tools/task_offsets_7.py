#!/usr/bin/env python3
"""task_struct / cred field offsets for the official 7.1.1 kernel (3.18.31-perf-g9dce1fbc9).

Every row is derived from a *named* kallsyms function that dereferences the field with a
constant offset -- not from byte-shape guessing inside the leak window, and not from kallsyms
globals, because this ROM filters the names an escalation needs (`init_cred`, `commit_creds`,
`prepare_kernel_cred`, `selinux_enforcing`, `do_execveat_common`, `call_usermodehelper_exec`
are all absent from /proc/kallsyms -- ledger 479).

The table is self-witnessing: for each row we re-decode the instruction at
<witness_fn + insn_off> in the Image and require it to be the claimed load/store with
`#<field_off>` in it.  A row that does not decode as claimed aborts the whole run, so a
stale kallsyms or a hand-typed offset cannot be published.  Coverage is reported as N/M.

--selftest runs the same check over mutated tables; both arms must go red, otherwise the
ruler is not the thing deciding the verdict and we refuse to publish.

Usage: tools/task_offsets_7.py [--tsv] [--selftest]
"""
import os
import re
import sys

from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, Cs

IMG = os.environ.get("KS_IMG", "/home/v/.local/project/xplay6/fw/7/Image")
KALL = os.environ.get("KS_KALL", "/home/v/.local/project/xplay6/art/kallsyms-7-real.txt")
# foff = VA - TEXT_BASE: the Image file begins at _text (the arm64 header is the first byte).
# Using 0xffffffc000000000 here instead decodes every site 0x80000 bytes off -- the exact two
# bases that made 470 mis-read a symbol address.
TEXT_BASE = int(os.environ.get("KS_TEXT_BASE", "0xFFFFFFC000080000"), 0)

# (struct, field, offset, width, witness function, insn offset, expected mnemonic)
ROWS = [
    ("task_struct", "thread_info->task", 0x10, 8, "override_creds", 0x18, "ldr"),
    ("task_struct", "cred", 0x4C0, 8, "override_creds", 0x1C, "ldr"),
    ("task_struct", "real_cred", 0x658, 8, "get_task_cred", 0x18, "ldr"),
    ("task_struct", "real_cred", 0x658, 8, "exit_creds", 0x18, "ldr"),
    ("task_struct", "cred", 0x4C0, 8, "exit_creds", 0x10, "ldr"),
    ("task_struct", "real_cred", 0x658, 8, "proc_pid_status", 0x428, "ldr"),
    ("cred", "uid", 0x04, 4, "proc_pid_status", 0x1CC, "ldr"),
    ("cred", "gid", 0x08, 4, "proc_pid_status", 0x220, "ldr"),
    ("cred", "euid", 0x0C, 4, "proc_pid_status", 0x1F8, "ldr"),
    ("cred", "egid", 0x10, 4, "proc_pid_status", 0x248, "ldr"),
    ("cred", "suid", 0x14, 4, "proc_pid_status", 0x1E4, "ldr"),
    ("cred", "sgid", 0x18, 4, "proc_pid_status", 0x234, "ldr"),
    ("cred", "fsuid", 0x1C, 4, "proc_pid_status", 0x20C, "ldr"),
    ("cred", "fsgid", 0x20, 4, "proc_pid_status", 0x25C, "ldr"),
    ("cred", "cap_inheritable", 0x28, 8, "proc_pid_status", 0x504, "ldr"),
    ("cred", "cap_permitted", 0x30, 8, "proc_pid_status", 0x50C, "ldr"),
    ("cred", "cap_effective", 0x38, 8, "proc_pid_status", 0x514, "ldr"),
    ("cred", "cap_bset", 0x40, 8, "proc_pid_status", 0x51C, "ldr"),
    # binder_open is the one named function that walks the whole identity chain we need, and it
    # does so with literal displacements:
    #   +0xd0 mov x0,sp / +0xd4 and x0,#~0x3fff   -> thread_info = 16 KiB-aligned stack base
    #   +0xd8 ldr x0,[x1,#0x10]                   -> thread_info->task
    #   +0xdc ldr w20,[x0,#0x54] / +0xe0 sub w20,#0x78  -> task_nice() = static_prio - 120
    #   +0xa8 str x0,[x19,#0x48]  (x19 = the kzalloc'd proc, x0 = the same task)
    #   +0xe8 str x20,[x19,#0x1d0]               -> proc->default_priority
    # static_prio is what makes a *reversible identity probe* possible: it is the one task field
    # whose value we can read back from the user side (/proc/<pid>/stat field 18) for every pid.
    ("task_struct", "thread_info->task", 0x10, 8, "binder_open", 0xD8, "ldr"),
    ("task_struct", "static_prio", 0x54, 4, "binder_open", 0xDC, "ldr"),
    ("binder_proc", "tsk", 0x48, 8, "binder_open", 0xA8, "str"),
    ("binder_proc", "default_priority", 0x1D0, 8, "binder_open", 0xE8, "str"),
    # binder_get_thread() compares and copies `current->pid` (drivers/staging/android/binder.c),
    # and the compiler kept it as a direct field load at three sites -> offsetof(task_struct,pid).
    ("task_struct", "pid", 0x490, 4, "binder_get_thread", 0x40, "ldr"),
    # The getgroups() read channel (ledger 494): SyS_getgroups walks
    #   task->cred -> cred->group_info -> group_info->ngroups -> group_info->blocks[i/1024][i%1024]
    # and the block pointer is dereferenced as a *kernel* address, so a group_info parked in .data
    # turns getgroups(2) into a 4-bytes-at-a-time read of any kernel address.  groups_free is the
    # row witness because it is the one function that loads blocks[0] with a literal displacement
    # (and it is also why a fork is fatal while cred points at our object: put_group_info ->
    # groups_free -> kfree(blocks[0]) on a pointer that is not a slab object).
    ("task_struct", "cred", 0x4C0, 8, "SyS_getgroups", 0x10, "ldr"),
    ("cred", "group_info", 0x88, 8, "SyS_getgroups", 0x1C, "ldr"),
    ("thread_info", "addr_limit", 0x08, 8, "SyS_getgroups", 0x58, "ldr"),
    ("group_info", "ngroups", 0x04, 4, "groups_search", 0x0C, "ldr"),
    ("group_info", "nblocks", 0x08, 4, "groups_free", 0x38, "ldr"),
    ("group_info", "small_block", 0x0C, 4, "groups_free", 0x10, "add"),
    ("group_info", "blocks", 0x90, 8, "groups_free", 0x18, "ldr"),
]

# Rows we refuse to publish as settled: get_task_comm reads two 16-byte-looking name fields
# and only one of them is task->comm, so a name-based identity fingerprint is not derived yet.
UNRESOLVED = [
    ("task_struct", "comm", "get_task_comm+0xc gives +0xac8 (strlen over it) but +0x2c gives "
     "+0x640 (strlcpy of 16 bytes + strim over it) -- which one is comm is UNRESOLVED"),
]


def syms():
    out = {}
    for ln in open(KALL):
        p = ln.split()
        if len(p) < 3:
            continue
        try:
            out.setdefault(" ".join(p[2:]), int(p[0], 16))
        except ValueError:
            pass
    return out


def verify(rows, S, data, md, verbose=True):
    ok, bad, skipped = [], [], []
    for struct, field, off, width, fn, ioff, want in rows:
        if ioff is None:
            skipped.append((struct, field, off, fn, "no witness row supplied"))
            continue
        if fn not in S:
            bad.append((struct, field, off, fn, "witness symbol not in kallsyms"))
            continue
        va = S[fn] + ioff
        foff = va - TEXT_BASE
        ins = next(md.disasm(data[foff:foff + 4], va), None)
        if ins is None:
            bad.append((struct, field, off, fn, "undecodable at %#x" % va))
            continue
        txt = "%s %s" % (ins.mnemonic, ins.op_str)
        # capstone writes the displacement in hex for a load/store (`ldr x1, [x19, #0x90]`) and in
        # decimal for an address computation (`add x0, x0, #0xc`), so both spellings count -- but
        # only as a whole literal: `#0xc` must not be allowed to witness `#0xcc`.
        claimed = re.search(r"#(?:0x%x|%d)(?![0-9a-f])" % (off, off), txt) is not None
        if ins.mnemonic != want or not claimed:
            bad.append((struct, field, off, "%s: got `%s`" % (fn, txt.strip()), "displacement"))
            continue
        ok.append((struct, field, "0x%x" % off, str(width), fn, "%s+%#x" % (fn, ioff), txt.strip()))

    if verbose:
        print("witnessed %d/%d rows (skipped %d, failing %d)"
              % (len(ok), len(rows), len(skipped), len(bad)))
        for r in skipped:
            print("  SKIP  %-12s %-16s +%s  (%s: %s)" % (r[0], r[1], hex(r[2]), r[3], r[4]))
        for r in bad:
            print("  FAIL  %-12s %-16s +%s  %s -> %s" % (r[0], r[1], hex(r[2]), r[3], r[4]))
    return ok, bad, skipped


def main():
    S = syms()
    data = open(IMG, "rb").read()
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)

    if "--selftest" in sys.argv:
        # arm 1: shift one claimed field offset by 4 -- that row must go red
        mut = [list(r) for r in ROWS]
        mut[0][2] += 4
        _, bad1, _ = verify(mut, S, data, md, verbose=False)
        print("selftest arm1 (shift a claimed offset by +4): %d row(s) red -> %s"
              % (len(bad1), "OK" if bad1 else "RULER IS BLIND"))
        # arm 2: move one witness site by one instruction -- that row must go red
        mut = [list(r) for r in ROWS]
        mut[5][5] += 4
        _, bad2, _ = verify(mut, S, data, md, verbose=False)
        print("selftest arm2 (move a witness site by +4):    %d row(s) red -> %s"
              % (len(bad2), "OK" if bad2 else "RULER IS BLIND"))
        # arm 3: a witness symbol that does not exist must be refused, not silently dropped
        mut = [list(r) for r in ROWS]
        mut[6][4] = "no_such_fn"
        _, bad3, _ = verify(mut, S, data, md, verbose=False)
        print("selftest arm3 (unknown witness symbol):       %d row(s) red -> %s"
              % (len(bad3), "OK" if bad3 else "RULER IS BLIND"))
        # arm 4: the matcher accepts a bare `#0xc` (capstone drops the bracket for an `add`), so it
        # must still refuse the *prefix* case -- claiming +0xcc from a site that computes +0xc.
        mut = [list(r) for r in ROWS]
        mut[28][2] = 0xCC
        _, bad4, _ = verify(mut, S, data, md, verbose=False)
        print("selftest arm4 (claim #0xcc from a #0xc site): %d row(s) red -> %s"
              % (len(bad4), "OK" if bad4 else "RULER IS BLIND"))
        return 0 if (bad1 and bad2 and bad3 and bad4) else 1

    ok, bad, skipped = verify(ROWS, S, data, md, verbose="--tsv" not in sys.argv)
    if not bad and not skipped and "--tsv" not in sys.argv:
        print("witnessed %d/%d rows (skipped 0, failing 0)" % (len(ok), len(ROWS)))
    if bad:
        print("refusing to publish: %d row(s) did not decode as claimed" % len(bad))
        return 1
    if skipped:
        print("refusing to publish: %d row(s) have no witness" % len(skipped))
        return 1

    if "--tsv" in sys.argv:
        print("\t".join(["struct", "field", "offset", "bytes", "witness_fn", "witness_site", "decoded"]))
        for r in ok:
            print("\t".join(r))
        for f, fld, note in UNRESOLVED:
            print("\t".join([f, fld, "UNRESOLVED", "", "", "", note]))
    else:
        for r in ok:
            print("  %-12s %-16s +%-6s %-2s  %-18s %-28s %s" % r)
        print("unresolved (deliberately not published as offsets): %d" % len(UNRESOLVED))
        for f, fld, note in UNRESOLVED:
            print("  %s.%s: %s" % (f, fld, note))
    return 0


if __name__ == "__main__":
    sys.exit(main())
