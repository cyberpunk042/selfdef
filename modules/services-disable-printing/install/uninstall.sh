#!/usr/bin/env bash
# services-disable-printing — uninstall.

set -euo pipefail

MODULE="services-disable-printing"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

if command -v systemctl >/dev/null 2>&1 && [[ "$DRY_RUN" != "1" ]]; then
    for unit in "${PRINT_UNITS[@]}"; do
        if systemctl list-unit-files "$unit" >/dev/null 2>&1; then
            systemctl unmask "$unit" 2>/dev/null || true
            systemctl reset-failed "$unit" 2>/dev/null || true
        fi
    done
fi

emit_status "ok" "services-disable-printing uninstalled (units unmasked; operator runs systemctl enable to re-activate)"
