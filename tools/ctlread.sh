#!/system/bin/sh
# tools/ctlread.sh -- dump the whole mixer once; per-name queries print the item list for
# ENUM controls (§213), so values must be read out of the full table instead.
set -u
tinymix -D 0 2>&1
echo CTLREAD_DONE
