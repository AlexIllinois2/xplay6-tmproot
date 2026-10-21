#!/system/bin/sh
# Undo the calibration A/B: the properties are persist.* (they survive a reboot), so
# clearing them is the real revert -- a reboot alone would leave them pointing at /data.
set -u
i=0
while [ $i -lt 7 ]; do
	setprop "persist.audio.calfile$i" ""
	i=$((i+1))
done
echo "props after revert:"
getprop | grep -a calfile
echo "audioserver restart:"
setprop ctl.restart audioserver
echo DONE-REVERT-PROPS
