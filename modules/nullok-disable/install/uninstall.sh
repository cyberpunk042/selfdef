#!/usr/bin/env bash
# nullok-disable — uninstall.
#
# Restores every /etc/pam.d/*.selfdef-nullok-backup to its
# original filename. Operator's PAM stack reverts to the pre-
# apply state (nullok re-introduced where it was).

set -euo pipefail

MODULE="nullok-disable"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
PAM_D="${SELFDEF_PAM_D:-/etc/pam.d}"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

restored=0
for backup in "$PAM_D"/*.selfdef-nullok-backup; do
    [[ -e "$backup" ]] || continue   # glob no-match
    original="${backup%.selfdef-nullok-backup}"
    if [[ "$DRY_RUN" == "1" ]]; then
        log "DRY_RUN: would restore $backup → $original"
    else
        run "restore $(basename "$original")" -- mv "$backup" "$original"
        restored=$((restored + 1))
    fi
done

emit_status "ok" "nullok-disable restored=$restored"
