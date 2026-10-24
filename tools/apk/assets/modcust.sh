#!/system/bin/sh
# modcust.sh - run a module's customize.sh the way Magisk would, on a toybox-only
# device.  The zip has ALREADY been extracted by the app into the staging dir
# passed as $1, so the module's verify.sh/extract helpers are served from there:
# Android 8.1 has no `unzip` at all (toybox dropped it), so `unzip` below is a
# shim over $STAGE; `sha256sum` exists but lacks -s, hence the wrapper.
#
# usage: MODDIR=<final-dir> ZIPFILE=<zip> [UNZIPED=1] sh modcust.sh <staging-dir>
# every ui_print line flows back through the su responder into the app's log;
# abort() exits non-zero and the caller rolls the module dir back.

STAGE="$1"
[ -n "$STAGE" ] || { echo "! modcust: staging dir missing"; exit 1; }
[ -d "$STAGE" ] || { echo "! modcust: staging dir gone: $STAGE"; exit 1; }

# Magisk-style environment.  API 27 = Android 8.1, this device's only 64-bit arch.
# MAGISK_VER_CODE makes modules that gate on a root manager take the Magisk
# branch (KSU/APatch would demand kernel patches we do not have).
ARCH=arm64
API=27
IS64BIT=true
BOOTMODE=true
MAGISK_VER=27.0
MAGISK_VER_CODE=27000
MODPATH="$MODDIR"
TMPDIR="${TMPDIR:-/data/local/tmp/modcust.$$}"
rm -rf "$TMPDIR"
mkdir -p "$TMPDIR" || exit 1
export ARCH API IS64BIT BOOTMODE MAGISK_VER MAGISK_VER_CODE MODPATH TMPDIR

# Magisk's installer always hands $TMPDIR/module.prop to customize.sh (default
# argument of grep_prop), even when SKIPUNZIP kept module.prop out of MODPATH.
cp -f "$STAGE/module.prop" "$TMPDIR/module.prop" 2>/dev/null

ui_print() { echo "$1"; }

abort() {
    echo "! $1"
    exit 1
}

# grep_prop <key> [file] - Magisk builtin some modules rely on.
grep_prop() {
    _gp_re="s/^$1=//p"
    shift
    _gp_file="$1"
    [ -n "$_gp_file" ] || _gp_file="$TMPDIR/module.prop"
    sed -n "$_gp_re" "$_gp_file" 2>/dev/null | head -n 1
}

# unzip [-o] [-j|-oj] [-d dir] [-x pattern]... <zip> <pattern>... - reads the
# already-extracted staging dir instead of the archive.  Patterns are shell
# globs matched under $STAGE (one level deep; a matched directory is copied
# recursively, which covers the "webroot/*" style used by real modules).
unzip() {
    _uz_junk=false
    _uz_dir=.
    _uz_excl=
    _uz_zip=
    _uz_pats=
    while [ $# -gt 0 ]; do
        case "$1" in
            -o|-q|-qq|--) shift ;;
            -j|-oj) _uz_junk=true; shift ;;
            -d) _uz_dir="$2"; shift 2 ;;
            -x) _uz_excl="$_uz_excl $2"; shift 2 ;;
            -*) shift ;;
            *)
                if [ -z "$_uz_zip" ]; then
                    _uz_zip="$1"
                else
                    _uz_pats="$_uz_pats $1"
                fi
                shift
                ;;
        esac
    done
    [ -n "$_uz_pats" ] || _uz_pats='*'
    _uz_n=0
    for _uz_pat in $_uz_pats; do
        for _uz_src in "$STAGE"/$_uz_pat; do
            [ -e "$_uz_src" ] || continue
            _uz_rel="${_uz_src#$STAGE/}"
            _uz_skip=false
            for _uz_e in $_uz_excl; do
                case "$_uz_rel" in $_uz_e) _uz_skip=true ;; esac
            done
            [ "$_uz_skip" = true ] && continue
            if [ "$_uz_junk" = true ]; then
                mkdir -p "$_uz_dir"
                cp -rf "$_uz_src" "$_uz_dir/"
            elif [ -d "$_uz_src" ]; then
                mkdir -p "$_uz_dir/$_uz_rel"
                cp -rf "$_uz_src/." "$_uz_dir/$_uz_rel/"
            else
                _uz_d="${_uz_rel%/*}"
                [ "$_uz_d" = "$_uz_rel" ] && _uz_d=.
                mkdir -p "$_uz_dir/$_uz_d"
                cp -f "$_uz_src" "$_uz_dir/$_uz_rel"
            fi
            _uz_n=$((_uz_n + 1))
        done
    done
    [ "$_uz_n" -gt 0 ] || return 11
    return 0
}

# toybox sha256sum has no -s; verify.sh only uses `sha256sum -c -s -`.
sha256sum() {
    _ss_c=false
    _ss_in=false
    _ss_file=
    for _ss_a in "$@"; do
        case "$_ss_a" in
            -s) ;;
            -c) _ss_c=true ;;
            -) _ss_in=true ;;
            *) _ss_file="$_ss_a" ;;
        esac
    done
    if [ "$_ss_c" = true ]; then
        if [ "$_ss_in" = true ]; then
            /system/bin/sha256sum -c -
        else
            /system/bin/sha256sum -c "$_ss_file"
        fi
    else
        /system/bin/sha256sum "$@"
    fi
}

# set_perm <target> <uid> <gid> <perm> [context]
set_perm() {
    if [ -n "$5" ]; then
        chown "$2:$3" "$1" 2>/dev/null
        chmod "$4" "$1"
        chcon "$5" "$1" 2>/dev/null
    else
        chown "$2:$3" "$1" 2>/dev/null
        chmod "$4" "$1"
    fi
    return 0
}

# set_perm_recursive <dir> <uid> <gid> <dperm> <fperm> [context]
set_perm_recursive() {
    chown -R "$2:$3" "$1" 2>/dev/null
    find "$1" -type d -exec chmod "$4" {} + 2>/dev/null
    find "$1" -type f -exec chmod "$5" {} + 2>/dev/null
    [ -n "$6" ] && chcon -R "$6" "$1" 2>/dev/null
    return 0
}

[ -f "$STAGE/customize.sh" ] || exit 0

cd "$STAGE" || abort "cannot cd $STAGE"
# shellcheck disable=SC1090
. "$STAGE/customize.sh"
rc=$?
rm -rf "$TMPDIR"
[ "$rc" = 0 ] || exit "$rc"
echo "customize.sh done"
