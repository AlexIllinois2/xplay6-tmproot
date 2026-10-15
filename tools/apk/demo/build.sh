#!/usr/bin/env bash
# Build the "granted app" demo: no exploit, no root code -- just the client binary
# as an asset, so the only thing that decides its fate is TempRoot's allow list.
set -eu

SDK=/home/v/Android/Sdk
BT=$SDK/build-tools/35.0.0
PLAT=$SDK/platforms/android-34/android.jar
ROOT=/home/v/.local/project/xplay6/tools
D=$ROOT/apk/demo
S=$D/stage

rm -rf "$S"
mkdir -p "$S/obj" "$D/assets"
cp "$ROOT/suc" "$D/assets/sux"

"$BT/aapt" package -f -M "$D/AndroidManifest.xml" -A "$D/assets" -I "$PLAT" -F "$S/unsigned.apk"
javac -nowarn -source 8 -target 8 -bootclasspath "$PLAT" -d "$S/obj" \
	$(find "$D/src" -name '*.java')
"$BT/d8" --lib "$PLAT" --release --min-api 21 --output "$S/obj" \
	$(find "$S/obj" -name '*.class')
cp "$S/obj/classes.dex" "$S/"
( cd "$S" && "$BT/aapt" add unsigned.apk classes.dex )
"$BT/zipalign" -f 4 "$S/unsigned.apk" "$S/aligned.apk"
KS=$ROOT/apk/debug.keystore
"$BT/apksigner" sign --ks "$KS" --ks-pass pass:android --key-pass pass:android \
	--ks-key-alias androiddebugkey --out "$ROOT/granted-demo.apk" "$S/aligned.apk"
ls -l "$ROOT/granted-demo.apk"
echo "APK=$ROOT/granted-demo.apk"
