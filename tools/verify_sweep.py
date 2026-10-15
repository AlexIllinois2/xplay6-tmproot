#!/usr/bin/env python3
"""Ruler for the three session properties added to tools/sud.c (ledger 202):

  1  a grant is audited when it is MADE  ("open" line), not only when it ends
  2  withdrawing a grant kills the session it already opened  (sweep_sessions)
  3  root shells never pile up as zombies (serve_tcp used to leave them)

Preconditions: the device is escalated and the su name gate is patched, so `su`
works from an adb shell (uid 2000), and 2000 is listed in /data/local/tmp/sud.grants.

Step 2 revokes from the RAW shell (127.0.0.1:12345 via tools/rsh.sh), not from `su`:
the raw path is not grant-gated and registers no session, so the revoker cannot be
killed by the very sweep under test -- which is exactly what an earlier draft of this
ruler did to itself (ledger 202).
"""
import re
import subprocess
import sys
import time

FAILS = []


def sh(cmd, timeout=90):
    p = subprocess.run(['adb', 'shell', cmd], capture_output=True, timeout=timeout)
    return p.stdout.decode('utf-8', 'replace').replace('\r', '')


def rsh(cmd, timeout=40):
    """One command through the root daemon's raw shell -- needs no grant."""
    p = subprocess.run(['bash', 'tools/rsh.sh', cmd], capture_output=True, timeout=timeout)
    return p.stdout.decode('utf-8', 'replace').replace('\r', '')


def check(name, ok, evidence):
    print(('PASS  ' if ok else 'FAIL  ') + name + '   [' +
          str(evidence).strip().replace('\n', ' | ')[:150] + ']')
    if not ok:
        FAILS.append(name)


def num(out, key):
    for tok in out.split():
        if tok.startswith(key + '='):
            try:
                return int(tok.split('=')[1])
            except ValueError:
                return -1
    return None


def main():
    if not sh('su -c "id -u"').strip().startswith('0'):
        print('ABORT: su as shell does not work (gate not patched?)')
        return 2
    if '0' not in rsh('id -u').split():
        print('ABORT: the raw shell on 12345 is not reachable (tools/rsh.sh failed)')
        return 2

    # -- 1: the decision is recorded at decision time ------------------------------
    before = rsh('tail -20 /data/local/tmp/.sud/sud.log')
    sh('su -c "id -u"')
    time.sleep(1)
    after = rsh('tail -20 /data/local/tmp/.sud/sud.log')
    new = [l for l in after.split('\n') if l and l not in before]
    opened = [l for l in new if l.startswith('open')]
    allowed = [l for l in new if l.startswith('allow') and 'code=' in l]
    check('1a open line written when the decision is made', bool(opened), ' ; '.join(opened))
    check('1b completion line still written with code=', bool(allowed), ' ; '.join(allowed))

    # -- 3: no zombie accumulation -------------------------------------------------
    z0 = rsh('sh /data/local/tmp/sweep_root.sh zombies')
    for _ in range(3):
        sh('su -c "true"')
    for _ in range(3):
        sh('printf "true\\nexit\\n" | su')
    time.sleep(2)
    z1 = rsh('sh /data/local/tmp/sweep_root.sh zombies')
    check('3  root zombies stay at zero across 6 sessions',
          num(z0, 'root_zombies') == 0 and num(z1, 'root_zombies') == 0,
          'before=' + z0.strip() + ' after=' + z1.strip())

    # -- 2: revocation kills the live session --------------------------------------
    # `su -c "sleep 120"` is registered by dispatch_su and stays open for two
    # minutes, so the session under test needs no detached script (an earlier draft
    # used `nohup ... &` and the holder never survived adb's controlling terminal).
    holder = subprocess.Popen(['adb', 'shell', 'su -c "sleep 120"'],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(4)
    reg = rsh('for f in /data/local/tmp/.sud/sess/*; do test -f "$f" && '
              'echo ENTRY=$(basename $f) $(cat $f); done').strip()
    m = re.search(r'ENTRY=(\d+)', reg)
    pid = m.group(1) if m else None
    alive = rsh('kill -0 %s 2>/dev/null && echo ALIVE || echo GONE' % pid) if pid else 'no-pid'
    check('2a session registered in the table and alive', bool(pid) and 'ALIVE' in alive,
          'registry: ' + reg.replace('\n', ' ; ') + ' | ' + alive)
    if not pid:
        holder.kill()
        print('     (no session to revoke -- stopping here rather than asserting on a bogus pid)')
        print('=== summary: %d fail(s) -> %s' % (len(FAILS), ', '.join(FAILS)))
        return 1

    out = rsh("G=/data/local/tmp/sud.grants; grep -v '^2000$' $G > /data/local/tmp/g.tmp;"
              ' cat /data/local/tmp/g.tmp >$G; rm -f /data/local/tmp/g.tmp;'
              ' echo REVOKED list=[$(tr "\\n" " " <$G)]; sleep 4;'
              ' kill -0 %s 2>/dev/null && echo SESSION=ALIVE || echo SESSION=GONE;'
              ' echo REG=[$(ls /data/local/tmp/.sud/sess 2>&1 | tr "\\n" " ")];'
              ' tail -4 /data/local/tmp/.sud/sud.log;'
              ' echo 2000 >>$G; echo RESTORED list=[$(tr "\\n" " " <$G)]' % pid, timeout=60)
    print('     ' + out.strip().replace('\n', '\n     '))

    check('2b the live session died once the grant was withdrawn', 'SESSION=GONE' in out, out)
    check('2c the sweep recorded the revocation', 'revoke uid=2000' in out,
          ' ; '.join(l for l in out.split('\n') if 'revoke' in l))
    check('2d the registry entry was cleaned up', 'REG=[]' in out,
          ' ; '.join(l for l in out.split('\n') if 'REG=' in l))
    time.sleep(2)
    gone = holder.poll() is not None
    check('2e the su client came back when the session was taken away', gone,
          'holder exit=%s' % holder.poll())
    if not gone:
        holder.kill()
    time.sleep(1)
    check('2f grant restored -> su works again', sh('su -c "id -u"').strip().startswith('0'),
          'id -u -> ' + sh('su -c "id -u"').strip())

    # -- 4: the interactive shell is INCREMENTAL (Shizuku's handshake) --------------
    # Shizuku writes `echo SHELL_TEST` into `su` and blocks until that exact line
    # comes back before it will run its starter. A client that holds back a tail of
    # bytes (an earlier draft kept the last 256) makes it time out and report
    # "no root" -- so this arm must stay, and it must not close stdin first.
    import selectors
    sel = selectors.DefaultSelector()
    proc = subprocess.Popen(['adb', 'shell', 'su'], stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    sel.register(proc.stdout, selectors.EVENT_READ)
    proc.stdin.write('echo SHELL_TEST\n')
    proc.stdin.flush()
    got, line = False, ''
    deadline = time.time() + 8
    while time.time() < deadline:
        if not sel.select(0.5):
            continue
        line = proc.stdout.readline().strip()
        if line == 'SHELL_TEST':
            got = True
            break
    proc.stdin.write('exit 9\n')
    proc.stdin.flush()
    proc.stdin.close()
    try:
        rc = proc.wait(timeout=15)
    except subprocess.TimeoutExpired:
        proc.kill()
        rc = -1
    sel.close()
    check('4  interactive output arrives line-by-line (not held back)', got,
          'first line back=%r' % line)
    # the exit code must be read ON the device: `adb shell` does not carry the remote
    # status across its own transport (measured: client returns 9, adb reports 0).
    rcdev = sh('printf "echo SHELL_TEST\\nexit 9\\n" | su >/dev/null 2>&1; echo ondevice=$?')
    check('4b interactive exit code still travels (read on device)', 'ondevice=9' in rcdev, rcdev)

    print('=== summary: %d fail(s)%s' % (len(FAILS), (' -> ' + ', '.join(FAILS)) if FAILS else ''))
    return 1 if FAILS else 0


if __name__ == '__main__':
    sys.exit(main())
