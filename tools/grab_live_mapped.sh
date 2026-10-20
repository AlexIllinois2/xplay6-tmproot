#!/usr/bin/env bash
# SU names the privileged-exec client.  The official 7.1.1 firmware refuses execve of any path # whose last component is exactly "su" (ledger 579), so on that machine run these tools with SU=sux.
SU=${SU:-su}
# tools/grab_live_mapped.sh -- close the gap the census finds: pull every library the live audio
# stack maps but the extract does not hold (ledger 409).  Read-only on the device (toybox base64,
# nothing is written on the device), writes only under art/.
#
# Why base64 and not cat: `su -c 'cat file'` through adb exec-out is NOT byte-exact on this device
# (one re-pull of an already-held file came back 14 B longer -- magisk adds newlines), and the
# transport control below caught it.  Text-safe transfer plus a device-side md5sum is what makes
# this reproducible on the 7 side too.
set -u
ROOT=${AUDIO_PORT_ROOT:-/home/v/.local/project/xplay6}
BASE=$ROOT/art/audio-6.0.1
JSON=${1:-/tmp/disp.json}
CONTROL=${CONTROL:-/vendor/lib/libacdbloader.so}   # already in the extract, byte-for-byte checkable

python3 "$ROOT/tools/shipped_disposition.py" --json "$JSON" >/dev/null || { echo "census failed"; exit 1; }

mapfile -t GAPS < <(python3 - "$JSON" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))
for g in d["gaps"]:
    print(g["device_path"])
PY
)
echo "gaps to pull: ${#GAPS[@]}"

pull_one () {   # $1 = device path, $2 = local destination
  mkdir -p "$(dirname "$2")"
  local size
  size=$(adb exec-out "$SU -c 'toybox stat -c %s $1'" 2>/dev/null | tr -d '\r' | tr -d ' ')
  case "$size" in ''|*[!0-9]*) echo "  cannot stat $1"; return 1;; esac
  : > "$2"
  if [ "$size" -le 262144 ]; then
    adb exec-out "$SU -c 'toybox base64 $1'" 2>/dev/null > "$2.b64" || { rm -f "$2.b64" "$2"; return 1; }
    b64_to_file "$2.b64" "$2" || { rm -f "$2.b64" "$2"; return 1; }
    rm -f "$2.b64"
  else
    # exec-out truncates ~1 MB of base64 text (two 600-800 KB libraries failed that way), so large
    # files are read in 256 KiB chunks on the device and stitched here.
    local chunks=$(( (size + 262143) / 262144 )) i
    for ((i=0; i<chunks; i++)); do
      adb exec-out "$SU -c 'toybox dd if=$1 bs=262144 skip=$i count=1 2>/dev/null | toybox base64'" \
        2>/dev/null > "$2.b64" || { rm -f "$2.b64" "$2"; return 1; }
      b64_to_file "$2.b64" "$2.part" || { rm -f "$2.b64" "$2" "$2.part"; return 1; }
      cat "$2.part" >> "$2"; rm -f "$2.b64" "$2.part"
    done
  fi
  local remote local got_size
  got_size=$(stat -c %s "$2")
  remote=$(adb exec-out "$SU -c 'md5sum $1'" 2>/dev/null | tr -d '\r' | cut -d' ' -f1)
  local=$(python3 -c "import hashlib,sys;print(hashlib.md5(open(sys.argv[1],'rb').read()).hexdigest())" "$2")
  if [ "$got_size" != "$size" ]; then
    echo "  SIZE MISMATCH $1 (device=$size pulled=$got_size)"; return 1
  fi
  [ -n "$remote" ] && [ "$remote" = "$local" ] || { echo "  MD5 MISMATCH $1 (device=$remote local=$local)"; return 1; }
  return 0
}

b64_to_file () {
  python3 - "$1" "$2" <<'PY'
import base64, re, sys
raw = re.sub(rb"[^A-Za-z0-9+/=]", b"", open(sys.argv[1], "rb").read())
if len(raw) % 4:
    sys.exit("base64 length %d is not a multiple of 4 -- truncated transport" % len(raw))
open(sys.argv[2], "wb").write(base64.b64decode(raw))
PY
}

tmp=$(mktemp --suffix=.so)
if ! pull_one "$CONTROL" "$tmp"; then
  echo "ABORT transport control failed on $CONTROL -- nothing is recorded"
  exit 1
fi
want=$(python3 - "$BASE" "$CONTROL" <<'PY'
import hashlib, os, sys
p = os.path.join(sys.argv[1], "shipped", sys.argv[2].lstrip("/"))
print(hashlib.md5(open(p, "rb").read()).hexdigest() if os.path.exists(p) else "MISSING-IN-EXTRACT")
PY
)
got=$(python3 -c "import hashlib,sys;print(hashlib.md5(open(sys.argv[1],'rb').read()).hexdigest())" "$tmp")
if [ "$want" != "$got" ]; then
  echo "ABORT transport control: re-pulled $got, extract holds $want"
  exit 1
fi
echo "transport control OK ($CONTROL, md5 $got)"
rm -f "$tmp"

total=0; ok=0
for dev in "${GAPS[@]}"; do
  rel="${dev#/}"
  case "$rel" in system/*|vendor/*) ;; *) echo "  skip (no extract home): $dev"; continue;; esac
  dst="$BASE/shipped/$rel"
  if pull_one "$dev" "$dst"; then
    sz=$(stat -c %s "$dst"); total=$((total+sz)); ok=$((ok+1))
    echo "  ok $dev -> shipped/$rel ($sz B)"
  else
    echo "  FAIL $dev -- partial copy removed"; rm -f "$dst"
  fi
done
echo "pulled $ok of ${#GAPS[@]} gap files, $total bytes written under $BASE"
