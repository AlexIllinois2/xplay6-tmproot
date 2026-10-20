#!/system/bin/sh
# tools/acdb_reach.sh -- who on THIS machine can reach the ACDB write channel? Read-only.
#
# libacdbloader.so brings up acph_init + acdb_fts_init (ledger 276), so the file-push endpoint exists
# in the library -- but a channel only matters if some process links the library and some peer owns
# the transport. This answers both from the live process table: every process whose maps contain an
# ACDB library, and every open fd on the diag / audio-calibration device nodes. The node list is taken
# from what the kernel actually created (ls /dev), NOT from the name a log string prints: the HAL logs
# "open msm_acdb failed" while the real node on this board is /dev/msm_audio_cal.
#
# No writes at all (cat/ls/readlink/grep). No awk on this device.
set -u
U=$(cut -d' ' -f1 /proc/uptime)
echo "REACH uptime=$U"
echo "-- device nodes"
for n in /dev/diag /dev/msm_audio_cal /dev/msm_rtac /dev/adsprpc-smd /dev/msm_acdb /dev/audio_acdb; do
	[ -e "$n" ] && echo "REACH node $n $(ls -ld "$n")"
done
grep -E "diag|acdb" /proc/devices 2>/dev/null | while read -r L; do echo "REACH procdevices $L"; done
echo "-- processes mapping ACDB libraries"
for d in /proc/[0-9]*; do
	p=${d#/proc/}
	if grep -qE "libaudcal\.so|libacdb-fts\.so|libacdbloader\.so|libacdbrtac\.so" "$d/maps" 2>/dev/null; then
		c=$(cat "$d/comm" 2>/dev/null)
		l=$(grep -oE "/[^ ]*(libaudcal|libacdb[a-z-]*|libacdbrtac)\.so" "$d/maps" 2>/dev/null | sort -u | tr '\n' ',')
		s=$(cat "$d/attr/current" 2>/dev/null)
		h=$(grep -c "audio\.primary[^ ]*\.so" "$d/maps" 2>/dev/null)
		g=$(grep -c "/libdiag\.so" "$d/maps" 2>/dev/null)
		echo "REACH maps pid=$p comm=$c hal_loaded=$h diag_mapped=$g ctx=$s libs=$l"
	fi
done
echo "-- processes mapping the audio HAL (the ACDB client's host)"
for d in /proc/[0-9]*; do
	p=${d#/proc/}
	if grep -q "audio\.primary" "$d/maps" 2>/dev/null; then
		echo "REACH hal pid=$p comm=$(cat "$d/comm" 2>/dev/null) ctx=$(cat "$d/attr/current" 2>/dev/null)"
	fi
done
echo "-- threads blocked in the diag transport reader"
for d in /proc/[0-9]*; do
	for t in "$d"/task/*; do
		w=$(cat "$t/wchan" 2>/dev/null)
		case "$w" in
		*diagchar_read*) echo "REACH diagreader pid=${d#/proc/} tid=$(basename "$t") comm=$(cat "$t/comm" 2>/dev/null) wchan=$w" ;;
		esac
	done
done
echo "-- holders of /dev/diag"
DIAG=0
for d in /proc/[0-9]*; do
	p=${d#/proc/}
	for f in "$d"/fd/*; do
		t=$(readlink "$f" 2>/dev/null)
		case "$t" in
		*/diag|*/msm_audio_cal*|*/msm_acdb*|*/audio_acdb*|*/msm_rtac*)
			DIAG=$((DIAG + 1))
			echo "REACH fd pid=$p comm=$(cat "$d/comm" 2>/dev/null) link=$t" ;;
		esac
	done
done
echo "REACH summary diag_fds=$DIAG"
echo "REACH_DONE"
