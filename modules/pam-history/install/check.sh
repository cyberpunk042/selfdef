#!/usr/bin/env bash
# pam-history — check. Read-only.

set -euo pipefail

MODULE="pam-history"
DRY_RUN=0
CONFIG_FILE="${SELFDEF_PWHISTORY_CONFIG:-/etc/selfdef/modules/pam-history.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"
PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "standard")

drift=0
if [[ ! -f "$PWHISTORY_CONF" ]]; then
    emit_status "drift" "missing $PWHISTORY_CONF"
    drift=$((drift + 1))
elif ! head -1 "$PWHISTORY_CONF" | grep -qF "$HEADER_MARKER"; then
    emit_status "drift" "$PWHISTORY_CONF exists but lacks selfdef header marker"
    drift=$((drift + 1))
fi

# Wiring check is INFORMATIONAL, not drift — selfdef cannot
# safely edit /etc/pam.d/* unprompted (it can lock the
# operator out of password change). Same posture as
# pam-pwquality + pam-faillock.
wired=$(detect_pam_wiring)
if [[ -z "$wired" ]]; then
    log "NOTICE: pam_pwhistory.so NOT wired into PAM password stack — operator-pull required"
else
    log "pam_pwhistory.so is wired in: $(echo "$wired" | tr '\n' ' ')"
fi

if [[ "$drift" -gt 0 ]]; then
    emit_status "drift" "pam-history profile=$PROFILE drift=$drift"
    exit 1
fi
emit_status "ok" "pam-history profile=$PROFILE no drift"
