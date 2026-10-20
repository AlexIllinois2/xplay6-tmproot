#!/system/bin/sh
# tools/dtparams.sh -- read-only DT walk, with a positive control baked in.
#   (1) count every property in the running tree whose name starts with 'vivo,'  <- the control:
#       if this is 0 the SEARCH is broken, and 'vivo,params missing' would be a fake finding.
#   (2) list the audio-ish nodes and their property names.
#   (3) dump any vivo,params / vivo,param-num bytes.
BASE=/proc/device-tree/
ALL=$(find "$BASE" -name 'vivo,*' 2>/dev/null | wc -l)
echo "vivo_props_total=$ALL"
for n in vivo,params vivo,param-num; do
    H=$(find "$BASE" -name "$n" 2>/dev/null)
    echo "prop $n -> ${H:-ABSENT}"
done
echo "-- nodes whose name mentions hifi/codec/sound/tfa --"
find "$BASE" -maxdepth 3 -type d 2>/dev/null | grep -iE 'hifi|codec|sound|tfa|es9038' | head -20
echo "-- properties of each such node --"
for d in $(find "$BASE" -maxdepth 3 -type d 2>/dev/null | grep -iE 'hifi-codec|sound-9335'); do
    echo "## $d"
    ls -1 "$d" 2>/dev/null | tr '\n' ' '
    echo ""
done
echo "DT_DONE"
