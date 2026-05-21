#!/usr/bin/env bash
# service-account-lock — uninstall.
#
# Walks /etc/selfdef/service-accounts-original.txt + restores
# the original shell for every recorded account via chsh.
# Does NOT passwd -u (operator decides whether to re-enable
# passwords).

set -euo pipefail

MODULE="service-account-lock"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

restored=0
if [[ -f "$ORIGINAL_LOG" ]]; then
    while read -r username original_shell; do
        [[ -z "$username" ]] && continue
        [[ "$username" =~ ^# ]] && continue
        [[ -z "$original_shell" ]] && continue
        # Verify user still exists.
        if id "$username" >/dev/null 2>&1; then
            if [[ "$DRY_RUN" == "1" ]]; then
                log "DRY_RUN: would chsh $username → $original_shell"
            else
                if chsh -s "$original_shell" "$username" >/dev/null 2>&1; then
                    restored=$((restored + 1))
                fi
            fi
        fi
    done < "$ORIGINAL_LOG"

    if [[ "$DRY_RUN" != "1" ]]; then
        rm -f "$ORIGINAL_LOG"
    fi
fi

emit_status "ok" "service-account-lock uninstalled restored=$restored (NOTE: passwd -l NOT undone — operator runs passwd -u <user> to re-enable password if needed)"
