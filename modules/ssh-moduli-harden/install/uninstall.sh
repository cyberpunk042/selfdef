#!/usr/bin/env bash
# ssh-moduli-harden — uninstall.

set -euo pipefail

MODULE="ssh-moduli-harden"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

# Restore the operator's original moduli if we have a backup.
if [[ -f "$BACKUP_FILE" ]]; then
    if [[ "$DRY_RUN" == "1" ]]; then
        log "DRY_RUN: would restore $BACKUP_FILE → $MODULI_FILE"
    else
        cp -a "$BACKUP_FILE" "$MODULI_FILE"
        chmod 0644 "$MODULI_FILE"
        log "restored original $MODULI_FILE from $BACKUP_FILE"
    fi
else
    log "no backup at $BACKUP_FILE — leaving filtered $MODULI_FILE in place (it is still valid, just stronger)"
fi

emit_status "ok" "ssh-moduli-harden uninstalled"
