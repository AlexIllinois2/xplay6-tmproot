#!/system/bin/sh
# tools/dacdtnode.sh -- read-only dump of the DAC's own device-tree node.
# Found on 2026-10-16 while looking for 'vivo,params': the property is NOT on soc/vivo-hifi-codec,
# it is on soc/i2c@75b6000/dac@48 (the ES9038 chip node, I2C addr 0x48) -- a node the 6.0.1 carry
# list had never enumerated.  /proc/device-tree is a symlink, so every find needs the trailing slash.
NODE=/proc/device-tree/soc/i2c@75b6000/dac@48/
if [ ! -d "$NODE" ]; then
    echo "gate: $NODE is not a directory -- the DAC node moved, do not read this as 'no properties'"
    exit 2
fi
echo "== node $NODE"
for f in "$NODE"*; do
    n=$(basename "$f")
    case "$f" in
        */) echo "   [child] $n" ;;
        *)  printf '   %s = %s bytes :' "$n" "$(wc -c < "$f")"; od -An -tx1 "$f" | tr -d '\n'; echo "" ;;
    esac
done
echo "DACSLOT_DONE"
