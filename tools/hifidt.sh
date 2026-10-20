#!/system/bin/sh
set -u
B=/sys/firmware/devicetree/base
for N in "$B/soc/vivo-hifi-codec" "$B/soc/sound-9335"; do
	echo "##### NODE $N files=$(find "$N" -maxdepth 1 -type f 2>/dev/null | wc -l | tr -d ' ')"
	[ -d "$N" ] || { echo "ABSENT"; continue; }
	for f in "$N"/*; do
		[ -f "$f" ] || continue
		printf '%s\t%s\t' "${f##*/}" "$(wc -c < "$f" | tr -d ' ')"
		od -An -tx1 -v "$f" | tr -d '\n' | tr -s ' '
		printf '\n'
	done
done
echo HIFIDT_DONE
