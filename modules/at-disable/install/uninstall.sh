#!/usr/bin/env bash
# at-disable — uninstall.
#
# unmask + reset-failed atd.service. Operator can re-enable by
# `systemctl enable atd` after uninstall.

set -euo pipefail

MODULE="at-disable"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

if command -v systemctl >/dev/null 2>&1 && [[ "$DRY_RUN" != "1" ]]; then
    systemctl unmask atd.service 2>/dev/null || true
    systemctl reset-failed atd.service 2>/dev/null || true
fi

emit_status "ok" "at-disable uninstalled — atd.service unmasked (operator runs systemctl enable atd to re-activate)"
