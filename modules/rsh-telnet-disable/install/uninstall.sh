#!/usr/bin/env bash
# rsh-telnet-disable — uninstall.

set -euo pipefail

MODULE="rsh-telnet-disable"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

if command -v systemctl >/dev/null 2>&1 && [[ "$DRY_RUN" != "1" ]]; then
    for unit in "${LEGACY_UNITS[@]}"; do
        if systemctl list-unit-files "$unit" >/dev/null 2>&1; then
            systemctl unmask "$unit" 2>/dev/null || true
            systemctl reset-failed "$unit" 2>/dev/null || true
        fi
    done
fi

emit_status "ok" "rsh-telnet-disable uninstalled (units unmasked; operator should NOT re-enable cleartext protocols — use ssh/scp instead)"
