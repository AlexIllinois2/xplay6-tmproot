#!/usr/bin/env bash
# Build the throwaway debuggable su-name probe (separate package; the delivery APKs are
# untouched).  Same toolchain as tools/apk/build.sh, minus the native half.
set -eu
SDK=/home/v/Android/Sdk
BT=$SDK/build-tools/35.0.0
PLAT=$SDK/platforms/android-34/android.jar
A=/home/v/.local/project/xplay6/xplay6-tmproot/tools/suprobe
ROOT=/home/v/.local/project/xplay6/tools
S=$A/stage

rm -rf "$S"
mkdir -p "$S/obj" "$S/assets"

echo "[1/5] asset: the marker payload (static, prints RAN)"
cp "$ROOT/sgt_pay" "$S/assets/marker"

echo "[2/5] package manifest + assets"
"$BT/aapt" package -f -M "$A/AndroidManifest.xml" -A "$S/assets" -I "$PLAT" -F "$S/unsigned.apk"

echo "[3/5] java -> dex"
find "$A/src" -name '*.java' > "$S/srcs.txt"
javac -nowarn -source 8 -target 8 -bootclasspath "$PLAT" -d "$S/obj" "@$S/srcs.txt"
"$BT/d8" --lib "$PLAT" --release --min-api 21 --output "$S/obj" $(find "$S/obj" -name '*.class')
cp "$S/obj/classes.dex" "$S/"

echo "[4/5] add dex, align"
( cd "$S" && "$BT/aapt" add unsigned.apk classes.dex )
"$BT/zipalign" -f 4 "$S/unsigned.apk" "$S/aligned.apk"

echo "[5/5] sign with the project debug key"
KS=$ROOT/apk/debug.keystore
"$BT/apksigner" sign --ks "$KS" --ks-pass pass:android --key-pass pass:android \
	--v1-signing-enabled true --v2-signing-enabled false --v3-signing-enabled false \
	--out "$S/suprobe.apk" "$S/aligned.apk"
printf 'built %s/suprobe.apk (%s bytes)\n' "$S" "$(wc -c < "$S/suprobe.apk")"
