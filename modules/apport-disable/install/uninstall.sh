#!/usr/bin/env bash
# apport-disable — uninstall.

set -euo pipefail

MODULE="apport-disable"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

if command -v systemctl >/dev/null 2>&1 && [[ "$DRY_RUN" != "1" ]]; then
    for unit in "${APPORT_UNITS[@]}"; do
        if systemctl list-unit-files "$unit" >/dev/null 2>&1; then
            systemctl unmask "$unit" 2>/dev/null || true
            systemctl reset-failed "$unit" 2>/dev/null || true
        fi
    done
fi

# Note: core_pattern is NOT restored to the apport pipe —
# operator re-installs/reconfigures apport (dpkg-reconfigure
# apport) to re-wire it if they want crash reporting back.
log "apport units unmasked; core_pattern NOT re-pointed to apport (operator runs 'sudo systemctl enable --now apport' + reconfigure to restore)"

emit_status "ok" "apport-disable uninstalled"
