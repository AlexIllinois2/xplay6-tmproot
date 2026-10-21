#!/system/bin/sh
# tools/asnap.sh -- dump the /proc/asound surfaces the coverage ruler (tools/surface_coverage.py) found
# uncited on 6.0.1: per-PCM capability (info), live stream params (hw_params/sw_params), owners (status),
# and the card-level nodes.  READ ONLY: every line is a cat of a procfs file.
#
# The dynamic three (hw_params/sw_params/status) read as "closed"/empty while nothing plays, so the
# cross-version reference wants two copies: one idle and one during playback of the use case being
# ported (the same pairing the PA captures use).  ASNP_TAG marks which one this is.
#
# usage: OUT=/data/local/tmp/asnap.txt sh /data/local/tmp/asnap.sh [tag]
OUT=${OUT:-/data/local/tmp/asnap.txt}
TAG=${1:-idle}
: > "$OUT"
echo "ASNP tag=$TAG date=$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$OUT"
echo "## cards" >> "$OUT"; cat /proc/asound/cards >> "$OUT" 2>&1
echo "## devices" >> "$OUT"; cat /proc/asound/devices >> "$OUT" 2>&1
echo "## pcm" >> "$OUT"; cat /proc/asound/pcm >> "$OUT" 2>&1
echo "## version" >> "$OUT"; cat /proc/asound/version >> "$OUT" 2>&1
echo "## hwdep" >> "$OUT"; cat /proc/asound/hwdep >> "$OUT" 2>&1
echo "## timers" >> "$OUT"; cat /proc/asound/timers >> "$OUT" 2>&1
for f in /proc/asound/card*/info; do
    [ -f "$f" ] && { echo "## cardinfo $f" >> "$OUT"; cat "$f" >> "$OUT" 2>&1; }
done
for f in /proc/asound/card*/pcm*/info; do
    echo "## pcminfo $f" >> "$OUT"; cat "$f" >> "$OUT" 2>&1
done
for s in hw_params sw_params status info; do
    for f in /proc/asound/card*/pcm*/sub*/$s; do
        [ -d "$(dirname "$f")" ] || continue
        echo "## sub-$s $f" >> "$OUT"; cat "$f" >> "$OUT" 2>&1
    done
done
# what the ALSA layer says is using each substream, and whether an audio carrier is up at all
echo "## asound-stream-state" >> "$OUT"
cat /proc/asound/card*/pcm*/sub*/status >> "$OUT" 2>&1
N=$(grep -c '^## ' "$OUT")
S=$(wc -c < "$OUT")
echo "ASNP_DONE sections=$N bytes=$S"
