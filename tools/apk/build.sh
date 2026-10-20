#!/usr/bin/env bash
# Build the escalation APK without gradle: aapt + javac + d8 + zipalign + apksigner.
# The native half is the SAME tools/clobber.c the adb path uses, compiled a second
# way (-DESC_LIB, shared) with a JNI bridge -- not a reimplementation.
set -eu

# Relocatable: ROOT follows this script, and every SDK path is overridable, so the
# source archive builds wherever it is unpacked.
SDK=${SDK:-/home/v/Android/Sdk}
BT=${BT:-$SDK/build-tools/35.0.0}
PLAT=${PLAT:-$SDK/platforms/android-34/android.jar}
NDK_VER=${NDK_VER:-29.0.13846066}
CL=$SDK/ndk/$NDK_VER/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android21-clang
ROOT=${ROOT:-$(cd "$(dirname "$0")/.." && pwd)}
A=$ROOT/apk
S=$A/stage

rm -rf "$S"
mkdir -p "$S/obj" "$S/lib/arm64-v8a" "$A/assets"

echo "[0/6] gate: clobber.c's compiled-in gate constants vs pgdalias' derivations from fw/*/Image"
# The adb route asks pgdalias at run time, so it can never ship a stale address.  The APK route
# carries the same numbers as #defines, so the comparison has to happen HERE, at the entry point that
# produces the shipped binary -- not in a note nobody re-reads after a kernel bump.
if [ "${SKIP_GATE:-0}" = 1 ]; then
	echo "  ★ SKIP_GATE=1 -- the constants were NOT re-derived for this build. Say so in the release notes."
else
	python3 "$ROOT/gate_constants.py" || { echo "  ABORT: clobber.c and pgdalias disagree; nothing was built"; exit 1; }
fi

echo "[1/6] native libesc.so (clobber.c + jni_esc.c)"
"$CL" -target aarch64-linux-android21 -fPIC -shared -O2 -DESC_LIB \
	-o "$S/lib/arm64-v8a/libesc.so" "$ROOT/clobber.c" "$A/jni/jni_esc.c"

echo "[2/6] bundle the daemon the kernel will exec, plus the su client"
# A freshly unpacked source tree holds no binaries.  build_all.sh is the single entry
# point for the native half, so call it here instead of making the reader remember step 0.
if [ ! -x "$ROOT/sud" ] || [ ! -x "$ROOT/suc" ] || [ ! -x "$ROOT/sumount" ] || [ ! -x "$ROOT/relayd" ] || [ ! -x "$ROOT/broot7" ] || [ ! -x "$ROOT/nsmbind" ]; then
	bash "$ROOT/build_all.sh"
fi
cp "$ROOT/sud" "$A/assets/sud"
cp "$ROOT/suc" "$A/assets/su"
# tiny MOUNT sender, so the chain can put su on PATH through the daemon's root channel
cp "$ROOT/sumount" "$A/assets/sumount"
# the 7.1.1 escalation: one self-contained binary (needle + in-process writes/reads + permissive_map
# + in-place cred patch + detached daemon exec).  Route selection lives in Chain.java.
cp "$ROOT/broot7" "$A/assets/broot7"
cp "$ROOT/nsmbind" "$A/assets/nsmbind"
cp "$ROOT/relayd" "$A/assets/relayd"

echo "[3/6] package (manifest + assets)"
"$BT/aapt" package -f -M "$A/AndroidManifest.xml" -A "$A/assets" -I "$PLAT" -F "$S/unsigned.apk"

echo "[4/6] java -> dex"
find "$A/src" -name '*.java' > "$S/srcs.txt"
javac -nowarn -source 8 -target 8 -bootclasspath "$PLAT" -d "$S/obj" "@$S/srcs.txt"
"$BT/d8" --lib "$PLAT" --release --min-api 21 --output "$S/obj" \
	$(find "$S/obj" -name '*.class')
cp "$S/obj/classes.dex" "$S/"

echo "[5/6] add dex + lib, align"
( cd "$S" && "$BT/aapt" add unsigned.apk classes.dex lib/arm64-v8a/libesc.so )
"$BT/zipalign" -f 4 "$S/unsigned.apk" "$S/aligned.apk"

echo "[6/6] sign"
KS=$A/debug.keystore
if [ ! -f "$KS" ]; then
	# -keyalg is not optional here: JDK 17's keytool refuses to guess it in -genkey
	# and the whole step fails silently otherwise.
	keytool -genkey -noprompt -v -keystore "$KS" -storepass android -keypass android \
		-alias androiddebugkey -dname "CN=TempRoot,OU=lab,O=lab,C=CN" \
		-keyalg RSA -keysize 2048 -validity 10000 >/dev/null
fi
"$BT/apksigner" sign --ks "$KS" --ks-pass pass:android --key-pass pass:android \
	--v1-signing-enabled true --v2-signing-enabled false --v3-signing-enabled false \
	--out "$ROOT/temproot.apk" "$S/aligned.apk"
"$BT/apksigner" verify --print-certs "$ROOT/temproot.apk" | head -2
ls -l "$ROOT/temproot.apk"
echo "APK=$ROOT/temproot.apk"
