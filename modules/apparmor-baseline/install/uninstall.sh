#!/usr/bin/env bash
# apparmor-baseline — uninstall.
#
# Flips selfdef-curated profiles BACK to complain mode (safe
# undo — doesn't disable the profile, just stops blocking).
# Removes the curated list file. Does NOT disable AppArmor
# itself (operator may want OS-default profiles to keep running).

set -euo pipefail

MODULE="apparmor-baseline"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

flipped=0
if [[ -f "$SELFDEF_AA_LIST" ]] && command -v aa-complain >/dev/null 2>&1; then
    while IFS= read -r line; do
        profile_name="${line%%#*}"
        profile_name="$(echo "$profile_name" | tr -d ' \t')"
        [[ -z "$profile_name" ]] && continue
        if aa-status 2>/dev/null | grep -qF "$profile_name"; then
            if [[ "$DRY_RUN" == "1" ]]; then
                log "DRY_RUN: would aa-complain $profile_name"
            else
                aa-complain "$profile_name" >/dev/null 2>&1 && \
                    flipped=$((flipped + 1)) || true
            fi
        fi
    done < "$SELFDEF_AA_LIST"
fi

removed=0
if [[ -f "$SELFDEF_AA_LIST" ]]; then
    run "remove $SELFDEF_AA_LIST" -- rm -f "$SELFDEF_AA_LIST"
    removed=$((removed + 1))
fi

emit_status "ok" "apparmor-baseline removed=$removed flipped_to_complain=$flipped (NOTE: apparmor.service + OS-default profiles UNCHANGED)"
