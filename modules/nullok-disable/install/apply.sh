#!/usr/bin/env bash
# nullok-disable — apply.
#
# Walks /etc/pam.d/*. For every file with a `pam_unix.so` line
# containing `nullok`:
#   - audit profile: LOG the finding
#   - enforce profile: back up to .selfdef-nullok-backup + sed-
#                      remove `nullok` (and `nullok_secure`)
#
# Only operates on FILES (skips dirs, symlinks). Skips files that
# already have a .selfdef-nullok-backup (operator may have
# re-applied; preserve original backup).

set -euo pipefail

MODULE="nullok-disable"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
CONFIG_FILE="${SELFDEF_NULLOK_CONFIG:-/etc/selfdef/modules/nullok-disable.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
PAM_D="${SELFDEF_PAM_D:-/etc/pam.d}"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"

PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "audit")
case "$PROFILE" in
    audit|enforce) ;;
    *) die "profile must be audit|enforce, got '$PROFILE'" ;;
esac

[[ -d "$PAM_D" ]] || die "PAM dir missing: $PAM_D"

audited=0
modified=0
for f in "$PAM_D"/*; do
    [[ -f "$f" ]] || continue
    [[ -L "$f" ]] && continue  # skip symlinks
    # Match `pam_unix.so` (or pam_unix2.so) on the same line as `nullok`.
    if grep -qE 'pam_unix(2)?\.so[[:space:]].*\bnullok' "$f" 2>/dev/null; then
        audited=$((audited + 1))
        n=$(grep -cE 'pam_unix(2)?\.so[[:space:]].*\bnullok' "$f")
        log "FOUND nullok in $f ($n line(s))"
        if [[ "$PROFILE" == "enforce" ]]; then
            backup="${f}.selfdef-nullok-backup"
            # Don't overwrite an existing backup (operator may
            # have re-applied).
            if [[ ! -f "$backup" ]] && [[ "$DRY_RUN" != "1" ]]; then
                cp -p "$f" "$backup"
            fi
            if [[ "$DRY_RUN" == "1" ]]; then
                log "DRY_RUN: would sed-remove nullok from $f"
            else
                # Remove both `nullok` and `nullok_secure` tokens
                # but preserve the rest of the line.
                sed -i.tmp -E \
                    -e 's/[[:space:]]nullok_secure\b//g' \
                    -e 's/[[:space:]]nullok\b//g' \
                    "$f"
                rm -f "${f}.tmp"
            fi
            modified=$((modified + 1))
        fi
    fi
done

emit_status "ok" "nullok-disable profile=$PROFILE audited=$audited modified=$modified"
