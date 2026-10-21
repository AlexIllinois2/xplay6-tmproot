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
	# Same reasoning for the exemption set: broot7.c carries hard-coded LIVE type indices, and a
	# missing peer type costs a granted app its binder replies while `getenforce` still reads
	# Enforcing (ledger 707).  The numbers only mean something against the loaded policy table.
	python3 "$ROOT/exempt_bits_check.py" || { echo "  ABORT: the exemption lists disagree with the live policy table; nothing was built"; exit 1; }
	# The ebitmap walk/geometry judgements live in a header BOTH sides compile, so their arms run here
	# rather than only when a phone is attached -- one of them (an off-by-one node count) was found by
	# wasting a boot on 2026-10-21.
	cc -O2 -Wall -o /tmp/ebmpchain-gate "$ROOT/ebitmap_chain_test.c" || { echo "  ABORT: cannot build the ebitmap chain arms"; exit 1; }
	/tmp/ebmpchain-gate >/dev/null || { echo "  ABORT: ebitmap chain/walk arms failed"; exit 1; }
	echo "  ebitmap chain+walk arms: ok"
fi

echo "[1/6] native libesc.so (clobber.c + jni_esc.c)"
"$CL" -target aarch64-linux-android21 -fPIC -shared -O2 -DESC_LIB \
	-o "$S/lib/arm64-v8a/libesc.so" "$ROOT/clobber.c" "$A/jni/jni_esc.c"

echo "[2/6] bundle the daemon the kernel will exec, plus the su client"
# A freshly unpacked source tree holds no binaries.  build_all.sh is the single entry
# point for the native half, so call it here instead of making the reader remember step 0.
# Freshness, not existence: on 2026-10-21 the APK was built with an edited broot7.c and the gate went
# green, because every piece it checks looks at SOURCE lists -- while the packaged assets/broot7 still
# held the previous build's exemption array.  `! -x` alone means "a stale binary is forever correct".
NEED="sud suc sumount relayd broot7 nsmbind"
STALE=""
for p in $NEED; do
	[ -x "$ROOT/$p" ] || { STALE="$STALE $p(missing)"; continue; }
done
if [ -z "$STALE" ]; then
	for src in "$ROOT"/*.c "$ROOT"/*.h; do
		[ -e "$src" ] || continue
		for p in $NEED; do
			[ "$src" -nt "$ROOT/$p" ] && { STALE="$STALE $(basename "$src")>$p"; break; }
		done
		[ -n "$STALE" ] && break
	done
fi
if [ -n "$STALE" ]; then
	echo "  native pieces are older than their sources ($STALE) -- rebuilding via build_all.sh"
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

echo "[7/7] artifact witness: the APK's own assets/broot7 must carry the array the sources say"
# The [0/6] gate reads SOURCE lists; a stale binary passes that while shipping the previous exemption
# set (measured 2026-10-21: assets/broot7 still held {192,279,593,743,1083} after broot7.c was edited).
# This step looks at the bytes that actually go onto the phone.
python3 "$ROOT/exempt_bits_check.py" --verify-apk "$ROOT/temproot.apk" || {
	echo "  ABORT: the APK holds an exemption array that is not the live policy's answer -- DO NOT INSTALL, DO NOT RELEASE" >&2
	exit 1; }
echo "APK=$ROOT/temproot.apk"
