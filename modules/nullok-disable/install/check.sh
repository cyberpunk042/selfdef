#!/usr/bin/env bash
# nullok-disable — check. Read-only.

set -euo pipefail

MODULE="nullok-disable"
DRY_RUN=0
CONFIG_FILE="${SELFDEF_NULLOK_CONFIG:-/etc/selfdef/modules/nullok-disable.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
PAM_D="${SELFDEF_PAM_D:-/etc/pam.d}"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"
PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "audit")

drift=0
present_count=0
for f in "$PAM_D"/*; do
    [[ -f "$f" ]] || continue
    [[ -L "$f" ]] && continue
    if grep -qE 'pam_unix(2)?\.so[[:space:]].*\bnullok' "$f" 2>/dev/null; then
        present_count=$((present_count + 1))
        log "nullok still present in: $f"
    fi
done

case "$PROFILE" in
    audit)
        # audit mode doesn't modify — finding nullok is expected.
        log "audit profile: $present_count file(s) with nullok present"
        ;;
    enforce)
        # enforce mode SHOULD have removed all nullok occurrences.
        if [[ "$present_count" -gt 0 ]]; then
            emit_status "drift" "enforce profile: $present_count file(s) still contain nullok — apply.sh may not have run or files were re-edited"
            drift=$((drift + 1))
        fi
        ;;
esac

# Inventory of selfdef-touched files (operator-readable).
touched=$(find "$PAM_D" -maxdepth 1 -name '*.selfdef-nullok-backup' 2>/dev/null | wc -l)
log "files with .selfdef-nullok-backup: $touched"

if [[ "$drift" -gt 0 ]]; then
    emit_status "drift" "nullok-disable profile=$PROFILE drift=$drift"
    exit 1
fi
emit_status "ok" "nullok-disable profile=$PROFILE present=$present_count touched_backups=$touched"
