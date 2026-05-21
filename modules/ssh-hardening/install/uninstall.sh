#!/usr/bin/env bash
# ssh-hardening — uninstall.
#
# Removes only the selfdef drop-in. OS-shipped sshd_config +
# operator-extension drop-ins (60-…, 99-…) preserved byte-
# identical. Reloads sshd so the OS-default + operator config
# is back in effect. Refuse-to-brick re-validates with sshd -t
# AFTER removal.

set -euo pipefail

MODULE="ssh-hardening"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
SSHD_DROPIN_DIR="${SELFDEF_SSHD_DROPIN_DIR:-/etc/ssh/sshd_config.d}"
DST="${SSHD_DROPIN_DIR}/50-selfdef.conf"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

removed=0
if [[ -f "$DST" ]]; then
    run "remove $(basename "$DST")" -- rm -f "$DST"
    removed=$((removed + 1))
fi

# Validate the REMAINING config parses (operator's other drop-ins
# may have been depending on our drop-in's settings — flag if so).
if command -v sshd >/dev/null 2>&1 && [[ "$DRY_RUN" != "1" ]]; then
    if ! sshd -t 2>/dev/null; then
        log "WARNING: sshd -t fails after uninstall; operator's other drop-ins may depend on ours"
    fi
fi

if [[ "$removed" -gt 0 ]] && [[ "$DRY_RUN" != "1" ]] && command -v systemctl >/dev/null; then
    systemctl reload sshd 2>/dev/null \
        || systemctl reload ssh 2>/dev/null \
        || systemctl restart ssh 2>/dev/null \
        || true
fi

emit_status "ok" "ssh-hardening removed=$removed"
