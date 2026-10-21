#!/usr/bin/env python3
"""Read vivo's autostart table (com.vivo.permissionmanager/databases/permission.db) off the phone,
and diff two snapshots, so the meaning of `currentstate` can be settled by对照 the ONE row the user
changes in i管家 rather than by guessing from other packages' values.

Requires the memory-state root channel (the daemon's raw shell on TCP 12345) -- run the app's 提权
first.  Nothing here writes to the device except a throwaway copy under /data/local/tmp.

usage:  python3 tools/vivo_bgstart.py            # snapshot + print our rows
        python3 tools/vivo_bgstart.py --diff     # same, plus what changed since last snapshot
"""
import hashlib
import os
import sqlite3
import subprocess
import sys
import time

SER = os.environ.get("SER", "3e5a38a5")
PKG = "com.xplay6.temproot"
DB = "/data/data/com.vivo.permissionmanager/databases/permission.db"
TMP = "/data/local/tmp/permission.bg.db"
HIST = "/tmp/vivo_bgstart.last.tsv"
TABLES = ("bg_start_up_apps", "start_bg_activity", "float_window_apps",
          "control_locked_screen_action")


def rootsh(cmds):
    """one command per line through the daemon's raw root shell.  The commands have to go OUT on the
    socket (fd 3) before reading it back -- an earlier version only read, so the daemon waited for
    input and this side waited for output, forever."""
    subprocess.run(["adb", "-s", SER, "forward", "tcp:12345", "tcp:12345"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    p = subprocess.Popen(["bash", "-c",
                          "exec 3<>/dev/tcp/127.0.0.1/12345; cat >&3; sleep 3; cat <&3"],
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    out, _ = p.communicate(("\n".join(cmds) + "\nexit\n").encode(), timeout=60)
    return out.decode(errors="replace").replace("\r", "")


def pull():
    got = rootsh(["id", "cp %s %s" % (DB, TMP), "chmod 666 %s" % TMP,
                  "md5sum %s" % TMP])
    dev = None
    for line in got.splitlines():
        if line.startswith("uid=0"):
            continue
        parts = line.split()
        if len(parts) == 2 and parts[1] == TMP:
            dev = parts[0]
    if not dev:
        sys.exit("ABORT: no md5 back from the root channel -- is the daemon up?\n" + got)
    local = "/tmp/permission.bg.db"
    subprocess.run(["adb", "-s", SER, "pull", TMP, local], check=True,
                   stdout=subprocess.DEVNULL)
    with open(local, "rb") as f:
        mine = hashlib.md5(f.read()).hexdigest()
    if mine != dev:
        sys.exit("ABORT: md5 mismatch device=%s host=%s -- the copy is torn" % (dev, mine))
    return local


def rows(local):
    """all rows of the four autostart-ish tables, as (table, id, pkg, uid, setbyuser, state)"""
    out = []
    c = sqlite3.connect("file:%s?mode=ro" % local, uri=True)
    tabs = {r[0] for r in c.execute("select name from sqlite_master where type='table'")}
    for t in TABLES:
        if t not in tabs:
            continue
        for r in c.execute("select * from %s" % t):
            f = list(r)
            out.append((t, f[0], f[1], f[2], f[3], f[4]))
    c.close()
    return out


def main():
    local = pull()
    cur = rows(local)
    print("snapshot of %s: %d rows across %d table(s)"
          % (os.path.basename(DB), len(cur), len({r[0] for r in cur})))
    for r in cur:
        if PKG in r[2] or "xplay6" in r[2]:
            print("  OURS %-28s id=%-3s pkg=%-24s uid=%-6s setbyuser=%s state=%s"
                  % (r[0], r[1], r[2], r[3], r[4], r[5]))
    prev = {}
    if os.path.exists(HIST):
        with open(HIST) as f:
            for line in f:
                p = line.rstrip("\n").split("\t")
                if len(p) == 6:
                    prev[(p[0], p[1])] = p[2:]
    with open(HIST, "w") as f:
        for r in cur:
            f.write("\t".join(str(x) for x in r) + "\n")
    if "--diff" in sys.argv:
        if not prev:
            print("no previous snapshot at %s -- run once, change the switch, run again with --diff" % HIST)
            return
        changed = 0
        for r in cur:
            k = (r[0], str(r[1]))
            if k in prev and prev[k] != [str(x) for x in r[2:]]:
                changed += 1
                print("  CHANGED %-28s %s: %s -> %s" % (r[0], r[2], prev[k], [str(x) for x in r[2:]]))
        for k in prev:
            if not any((r[0], str(r[1])) == k for r in cur):
                changed += 1
                print("  REMOVED %s id=%s %s" % (k[0], k[1], prev[k]))
        for r in cur:
            if (r[0], str(r[1])) not in prev:
                changed += 1
                print("  ADDED   %-28s %s" % (r[0], r[2:]))
        print("diff vs %s: %d change(s)" % (HIST, changed))
        if not changed:
            print("NOTHING MOVED -- the switch you flipped is not this DB (or it is cached in RAM "
                  "and only written on the permissionmanager's own exit)")


if __name__ == "__main__":
    main()
