#!/usr/bin/env bash
# SU names the privileged-exec client.  The official 7.1.1 firmware refuses execve of any path # whose last component is exactly "su" (ledger 579), so on that machine run these tools with SU=sux.
SU=${SU:-su}
# tools/grab_literal_probe.sh -- ask the DEVICE, per library, whether it carries an audio-family
# literal at all (ledger 417).  Read-only: grep -a -c on the device, nothing is written there and
# nothing is transferred.  The answer is what lets the census say "not chased" with a measurement
# instead of my judgement about which libraries "look" like framework transport.
#
# Why it exists: the unfiltered maps of mediaserver hold 194 libraries and the extract holds a
# fraction.  Chasing all of them is not the objective (they are graphics/camera/unicode transport),
# but "I decided they don't matter" is not a boundary -- so each candidate is asked, on the device,
# for the count of audio-family literals, and a known audio library is asked in the same run as the
# positive control that the probe can see them at all.
set -u
ROOT=${AUDIO_PORT_ROOT:-/home/v/.local/project/xplay6}
BASE=$ROOT/art/audio-6.0.1
OUT=${1:-$BASE/live/audio-literal-probe.tsv}
LIST=${LIST:-}                      # file of device paths, one per line
CONTROL=${CONTROL:-/system/lib/hw/audio.primary.msm8996.so}
TOKENS="audio ACDB acdb mixer_paths tfa98 es9028 SmartPA HiFi hifi sound_trigger media_codecs gsl"

adb wait-for-device
if [ ! -f "$LIST" ]; then echo "gate: LIST=$LIST is not a file -- pass LIST=<path-list>"; exit 1; fi
n_list=$(grep -c . "$LIST" 2>/dev/null || echo 0)
if [ "$n_list" -lt 1 ]; then echo "gate: the candidate list is empty"; exit 1; fi

probe_count () {   # $1 device path  $2 token  -> integer or empty
  adb exec-out "$SU -c 'grep -a -c -e $2 $1 2>/dev/null'" 2>/dev/null | tr -d "\r" | head -1
}
size_of () {
  local s
  s=$(adb exec-out "$SU -c 'toybox stat -c %s $1'" 2>/dev/null | tr -d "\r" | tr -d " ")
  case "$s" in ''|*[!0-9]*) echo ""; return;; esac
  echo "$s"
}
scan () {          # $1 device path -> "size<TAB>hits<TAB>tokens"
  local p="$1" total=0 found="" s c t
  s=$(size_of "$p")
  [ -z "$s" ] && { echo "MISSING	0	-"; return; }
  # one grep with all patterns: the per-file count is what the boundary needs, and 12 round trips per
  # file would make the whole census cost two minutes
  total=$(adb exec-out "$SU -c 'grep -a -c -e audio -e ACDB -e acdb -e mixer_paths -e tfa98 -e es9028 -e SmartPA -e HiFi -e hifi -e sound_trigger -e media_codecs -e gsl $p 2>/dev/null'" \
          2>/dev/null | tr -d "\r" | head -1)
  case "$total" in ''|*[!0-9]*) total=0;; esac
  for t in $TOKENS; do
    if [ "$total" -gt 0 ]; then c=$(probe_count "$p" "$t"); case "$c" in ''|*[!0-9]*) c=0;; esac
      [ "$c" -gt 0 ] && found="${found:+$found }$t:$c"; fi
  done
  echo "$s	$total	$found"
}

ctl=$(scan "$CONTROL")
ctl_hits=$(echo "$ctl" | cut -f2)
case "$ctl_hits" in ''|*[!0-9]*) ctl_hits=0;; esac
if [ "$ctl_hits" -lt 5 ]; then   # lines matched, not occurrences -- the union of the token set
  echo "gate: the positive control $CONTROL showed only $ctl_hits audio-family literals -- the probe "
  echo "      cannot see them (toybox grep behaviour changed?), so every '0' below would be meaningless"
  exit 1
fi
echo "control OK: $CONTROL size/hits/tokens = $ctl"

tmp=$(mktemp)
printf "device_path\tsize_bytes\taudio_literal_hits\ttokens\n" > "$tmp"
# the positive control is recorded in the artefact itself, so a later reader can see the probe could
# read audio literals in the same run that produced the zeros
printf "%s\t%s\n" "$CONTROL" "$ctl" >> "$tmp"
fail=0
while IFS= read -r p; do
  [ -z "$p" ] && continue
  line=$(scan "$p")
  printf "%s\t%s\n" "$p" "$line" >> "$tmp"
done < "$LIST"
if [ "$(grep -c . "$tmp")" -le 1 ]; then echo "gate: nothing probed"; rm -f "$tmp"; exit 1; fi
missing=$(awk -F'\t' 'NR>1 && $2=="MISSING"' "$tmp" | wc -l)
if [ "$missing" -gt 0 ]; then
  echo "gate: $missing candidate path(s) the device cannot stat -- the list is older than the device"; rm -f "$tmp"; exit 1
fi
mv "$tmp" "$OUT"
echo "wrote $OUT: $(( $(grep -c . "$OUT") - 1 )) probed paths"
awk -F'\t' 'NR>1 {if ($3+0>0) yes++; else no++} END {printf "  with audio literals: %d   without: %d\n", yes, no}' "$OUT"
