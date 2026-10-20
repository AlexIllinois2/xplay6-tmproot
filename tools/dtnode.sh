#!/system/bin/sh
# tools/dtnode.sh -- dump the live device-tree node for the SmartPA (and neighbours).
# The board DTB the running kernel actually uses is not the one shipped in fw/dtb.dtb,
# so read it from /sys/firmware/devicetree rather than the host copy.
set -u
BASE=/sys/firmware/devicetree/base
for N in "$BASE/soc/i2c@75b6000/spkamp@34" "$BASE/soc/i2c@75b6000" "$BASE/sound" "$BASE/soundcard"; do
	[ -d "$N" ] || continue
	echo "##### NODE $N"
	for f in "$N"/*; do
		[ -f "$f" ] || continue
		printf '%s = ' "${f##*/}"
		tr -d '\000' < "$f" 2>/dev/null | sed -e 's/^/[/ ' -e 's/$/]/'
		printf '\n'
	done
done
echo "##### i2c parent compat"
for f in "$BASE"/soc/i2c@75b6000/*; do
	[ -f "$f" ] || continue
	case "${f##*/}" in compatible|reg|clock-names|status) printf '%s = ' "${f##*/}"; tr -d '\000' < "$f"; printf '\n';; esac
done
echo "##### hifi / es90xx nodes"
find "$BASE" -maxdepth 5 \( -iname '*es90*' -o -iname '*hifi*' -o -iname '*dac*' \) 2>/dev/null | head -20
echo DTNODE_DONE
