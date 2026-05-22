#!/usr/bin/env bash
# pam-history — uninstall.

set -euo pipefail

MODULE="pam-history"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

if [[ -f "$PWHISTORY_CONF" ]]; then
    if head -1 "$PWHISTORY_CONF" | grep -qF "$HEADER_MARKER"; then
        if [[ -f "$BACKUP_FILE" ]]; then
            if [[ "$DRY_RUN" == "1" ]]; then
                log "DRY_RUN: would restore $BACKUP_FILE → $PWHISTORY_CONF"
            else
                cp -a "$BACKUP_FILE" "$PWHISTORY_CONF"
                log "restored operator's original $PWHISTORY_CONF from $BACKUP_FILE"
            fi
        else
            if [[ "$DRY_RUN" == "1" ]]; then
                log "DRY_RUN: would remove $PWHISTORY_CONF (no operator backup present)"
            else
                rm -f "$PWHISTORY_CONF"
                log "removed selfdef-managed $PWHISTORY_CONF (no operator backup)"
            fi
        fi
    else
        log "$PWHISTORY_CONF present but lacks selfdef marker — leaving in place (operator-managed)"
    fi
fi

# Note: PAM wiring (if operator ran pam-auth-update --enable
# pwhistory) is NOT auto-undone — that requires another
# pam-auth-update --disable invocation. Document in NOTICE.
log "PAM wiring NOT auto-disabled. To fully revert:"
log "  Debian/Ubuntu: sudo pam-auth-update --disable pwhistory"
log "  Fedora/RHEL:   sudo authselect select sssd without-pwhistory"

emit_status "ok" "pam-history uninstalled"
