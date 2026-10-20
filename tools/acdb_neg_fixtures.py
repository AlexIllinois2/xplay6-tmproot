#!/usr/bin/env python3
"""tools/acdb_neg_fixtures.py -- the four NEGATIVE controls for port_check.sh acdb (ledger 274).

They exist so the gate's red states stay reproducible after a reboot, and they encode what the arms
actually assert:
  content arm  = "some directory on the machine holds a byte-identical copy", so doctoring ONE
                 dir does NOT go red (a sibling dir still matches) -- the red case deletes the file
                 from BOTH vivo dirs;
  delta arm    = one slot per loaded cal file, expected size 0; overlay / missing-slot /
                 unparsable column shape / absent directory are four different reds on purpose.

Usage: python3 tools/acdb_neg_fixtures.py
       DELTA=/tmp/delta-bad.txt  tools/port_check.sh acdb     # expect rc=1
       DELTA=/tmp/delta-shape.txt tools/port_check.sh acdb    # expect NO-ANSWER
       ADB=/tmp/fakeadb_md5 DELTA=/tmp/delta-clean.txt tools/port_check.sh acdb  # expect rc=1
Fixtures are written to /tmp only -- nothing under art/ is touched, so a fake can never be indexed
as a baseline artifact by mistake."""
import csv
import os
import stat

META = "art/audio-6.0.1/acdb-meta.PD1610.tsv"
rows = [r for r in csv.DictReader(open(META), delimiter="\t") if r["dir"] == "PD1610"]
names = [r["file"] for r in rows]
md5 = {r["file"]: r["md5"] for r in rows}

bad = []
for d in ("PD1610", "PD1610LG4"):
    for n in names:
        h = md5[n]
        if n.startswith("Speaker"):
            continue                          # the injected defect: baseline file nowhere on device
        bad.append(f"{h}  /system/etc/acdbdata/{d}/{n}")   # md5sum prints HASH then path
for n in names:                               # stock dirs, never matching the baseline names
    bad.append(md5[n] + f"  /system/etc/acdbdata/Fluid/Fluid_{n}")

fake = "/tmp/fakeadb_md5"
with open(fake, "w") as f:
    f.write("#!/usr/bin/env bash\n")
    f.write('if [ "${1:-}" = shell ]; then\n  case "$*" in\n    *md5sum*)\n')
    for ln in bad:
        f.write('      printf "%%s\\n" "%s"\n' % ln)
    f.write("      ;;\n    *) printf \"%%s\\n\" \"$@\" ;;\n  esac\nfi\n")
os.chmod(fake, os.stat(fake).st_mode | stat.S_IEXEC | stat.S_IXGRP)

head = ["total 0", "drwxrwx--- media    audio             1970-01-01 08:04 .",
        "drwxrwx--- media    audio             1970-01-01 08:04 .."]
clean = head + ["-rw------- media    audio           0 1970-01-01 08:04 %sdelta" % n for n in names]
open("/tmp/delta-clean.txt", "w").write("\n".join(clean) + "\n")
over = [l.replace("0 1970-01-01 08:04 Speaker_cal.acdbdelta",
                  "1200 1970-01-01 08:04 Speaker_cal.acdbdelta") for l in clean]
over = [l for l in over if "Hdmi_cal" not in l]          # plus one slot never created
open("/tmp/delta-bad.txt", "w").write("\n".join(over) + "\n")
open("/tmp/delta-shape.txt", "w").write("total 8\nuid  gid  something-else\n")
open("/tmp/delta-none.txt", "w").write("ls: /data/misc/audio/acdbdata/delta: No such file or directory\n")
print("fixtures ready: %d baseline files; PD1610/Speaker_cal.acdb removed from both vivo dirs" % len(names))


# --- ledger 275: the case the OLD content arm cannot see. The landing dir holds a corrupt file and
# a SIBLING directory holds an intact one, so "some directory matches" stays green while "the copy in
# use matches" goes red. Synthetic ACDBDIR capture (no device needed) plus a fake adb md5 list.
split = []
for d in ("PD1610", "PD1610LG4"):
    for n in names:
        h = "f" * 32 if (d == "PD1610" and n.startswith("Speaker")) else md5[n]
        split.append(f"{h}  /system/etc/acdbdata/{d}/{n}")
for n in names:
    split.append(md5[n] + f"  /system/etc/acdbdata/Liquid/Liquid_{n}")   # noise from stock dirs
f2 = "/tmp/fakeadb_split"
with open(f2, "w") as f:
    f.write("#!/usr/bin/env bash\nif [ \"${1:-}\" = shell ]; then\n  case \"$*\" in\n    *md5sum*)\n")
    for ln in split:
        f.write('      printf "%%s\\n" "%s"\n' % ln)
    f.write("      ;;\n    *) : ;;\n  esac\nfi\n")
os.chmod(f2, os.stat(f2).st_mode | stat.S_IEXEC | stat.S_IXGRP)
open("/tmp/dir-PD1610.txt", "w").write(
    "ACDBDIR inputs model=PD1610 platform=QCOM8996 hw_platform=Surf "
    "node=/sys/devices/soc0/hw_platform device=PD1610 etcroot=/system/etc\n"
    "ACDBDIR exists /etc/acdbdata/PD1610 acdb=7 src=PD1610\n"
    "ACDBDIR exists /system/etc/acdbdata/PD1610 acdb=7 src=PD1610\n"
    "ACDBDIR_DONE\n")
print("also wrote the 275 split case: /tmp/fakeadb_split + /tmp/dir-PD1610.txt "
      "(expect content rc=0 but landing rc=1)")
