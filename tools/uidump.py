#!/usr/bin/env python3
"""Print the current UI as text+bounds (uiautomator dump), for driving taps by hand.
Usage: python3 tools/uidump.py [filter-substring]
"""
import re
import subprocess
import sys

subprocess.run(['adb', 'shell', 'uiautomator dump /sdcard/u.xml >/dev/null 2>&1'], capture_output=True)
subprocess.run(['adb', 'shell', 'cp /sdcard/u.xml /data/local/tmp/u.xml'], capture_output=True)
p = subprocess.run(['adb', 'pull', '/data/local/tmp/u.xml', '/tmp/u.xml'], capture_output=True)
if p.returncode != 0:
    print('dump failed:', p.stderr.decode('utf-8', 'replace'))
    sys.exit(1)

xml = open('/tmp/u.xml', encoding='utf-8').read()
want = sys.argv[1] if len(sys.argv) > 1 else ''
for node in re.finditer(r'<node[^>]*>', xml):
    s = node.group(0)
    t = re.search(r'text="([^"]*)"', s)
    d = re.search(r'content-desc="([^"]*)"', s)
    b = re.search(r'bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"', s)
    rid = re.search(r'resource-id="([^"]*)"', s)
    label = (t.group(1) if t and t.group(1) else (d.group(1) if d else '')) or ''
    if not label and not (rid and 'fab' in rid.group(1)):
        continue
    if want and want not in label and not (rid and want in rid.group(1)):
        continue
    x1, y1, x2, y2 = (int(v) for v in b.groups()) if b else (0, 0, 0, 0)
    print('%-28s (%4d,%4d)-(%4d,%4d) c=(%4d,%4d) %s' % (
        label[:28], x1, y1, x2, y2, (x1 + x2) // 2, (y1 + y2) // 2,
        rid.group(1).split('/')[-1] if rid else ''))
