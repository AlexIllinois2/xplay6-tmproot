#!/usr/bin/env bash
# SU names the privileged-exec client.  The official 7.1.1 firmware refuses execve of any path # whose last component is exactly "su" (ledger 579), so on that machine run these tools with SU=sux.
SU=${SU:-su}
# tools/grab_settings_tables.sh -- dump the three Android settings tables (name/value) as captured
# live state (ledger 414).  Read-only on the device; writes only into the output directory.
#
# Why: the audio UI keeps a second whitelist copy named `hifi_whitelist.from.secure.xml`, which
# invites the assumption "the authoritative list lives in Settings.Secure".  That is only testable by
# listing what the tables actually hold -- and here it is falsifiable in one query.
#
# The counters parse `Row: N name=X, value=Y` lines; the earlier draft counted "=" AFTER stripping
# the "name="/"value=" markers, i.e. it deleted its own witness and then reported "unreadable" --
# a blind reader dressed up as a gate.
set -u
ROOT=${AUDIO_PORT_ROOT:-/home/v/.local/project/xplay6}
OUT=${1:-$ROOT/art/audio-6.0.1/live}
mkdir -p "$OUT"
fail=0
for t in secure system global; do
  adb exec-out "$SU -c 'content query --uri content://settings/$t --projection name:value'" 2>/dev/null \
    | tr -d '\r' > "$OUT/settings-$t.raw.txt"
  python3 - "$OUT/settings-$t.raw.txt" "$OUT/settings-$t.tsv" "$t" <<'PY' || fail=1
import re, sys
raw, out, table = sys.argv[1], sys.argv[2], sys.argv[3]
rows = []
for line in open(raw, encoding="utf-8", errors="replace"):
    m = re.match(r"^Row: \d+ name=(.*?), value=(.*)$", line.rstrip("\n"))
    if m:
        rows.append((m.group(1), m.group(2)))
    elif line.strip():
        # some tables print `name=` lines without a value column; record them as empty rather than lose them
        m2 = re.match(r"^Row: \d+ name=(.*)$", line.rstrip("\n"))
        if m2:
            rows.append((m2.group(1), ""))
unparsed = sum(1 for l in open(raw, encoding="utf-8", errors="replace") if l.strip()) - len(rows)
if len(rows) < 20:
    sys.exit("gate: settings %s parsed %d rows (%d non-empty lines, %d unparsed) -- the query or the "
             "reader is blind, refusing to record the table" % (table, len(rows), len(rows) + unparsed, unparsed))
with open(out, "w", encoding="utf-8") as f:
    f.write("name\tvalue\n")
    for n, v in rows:
        f.write("%s\t%s\n" % (n, v))
audio = [n for n, v in rows if re.search(r"hifi|white|audio|sound|dnse|speaker|media|bluetooth", n, re.I)]
print("settings %s: %d rows, %d unparsed, audio-ish keys: %s" % (table, len(rows), unparsed,
                                                                 " ".join(audio[:8]) or "(none)"))
PY
done
echo "whitelist-in-secure test: $(grep -icE 'hifi|white' "$OUT/settings-secure.tsv" 2>/dev/null || echo 0) secure keys mention hifi/white"
exit $fail
