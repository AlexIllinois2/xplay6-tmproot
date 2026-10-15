#!/usr/bin/env bash
# Run one command through the root daemon listening on the phone's 127.0.0.1:12345.
# Usage: bash tools/rsh.sh 'id; getenforce'
set -u
SER=${SER:-3e5a38a5}
PORT=${PORT:-12345}
ADB="adb -s ${SER}"
ferr=$(timeout 8 $ADB forward tcp:${PORT} tcp:${PORT} 2>&1) || { printf 'rsh: forward failed: %s\n' "$ferr" >&2; exit 9; }
{ printf '%s\n' "$*"; sleep 2; } | timeout 25 bash -c \
	'exec 3<>/dev/tcp/127.0.0.1/'"${PORT}"'; cat >&3; cat <&3' 2>/dev/null | tr -d '\r'
