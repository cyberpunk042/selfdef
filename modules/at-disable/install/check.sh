#!/usr/bin/env bash
# at-disable — check. Read-only.

set -euo pipefail

MODULE="at-disable"
DRY_RUN=0
CONFIG_FILE="${SELFDEF_AT_DISABLE_CONFIG:-/etc/selfdef/modules/at-disable.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"
PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "mask")

drift=0
if ! command -v systemctl >/dev/null 2>&1; then
    log "systemctl unavailable; check skipped"
    emit_status "ok" "at-disable (systemctl unavailable)"
    exit 0
fi

# atd.service must NOT be active or enabled.
if systemctl is-active --quiet atd.service 2>/dev/null; then
    emit_status "drift" "atd.service is ACTIVE — should be stopped"
    drift=$((drift + 1))
fi
if systemctl is-enabled --quiet atd.service 2>/dev/null; then
    state=$(systemctl is-enabled atd.service 2>/dev/null || echo "")
    if [[ "$state" != "masked" && "$state" != "disabled" ]]; then
        emit_status "drift" "atd.service is enabled ($state) — should be disabled or masked"
        drift=$((drift + 1))
    fi
fi

if [[ "$PROFILE" == "mask" ]]; then
    state=$(systemctl is-enabled atd.service 2>/dev/null || echo "")
    if [[ "$state" != "masked" ]]; then
        emit_status "drift" "atd.service is not masked ($state) — mask profile requires masked state"
        drift=$((drift + 1))
    fi
fi

# Pending jobs surface — operator-readable but not drift.
if command -v atq >/dev/null 2>&1; then
    pending=$(atq 2>/dev/null | wc -l)
    log "pending at-jobs: $pending"
fi

if [[ "$drift" -gt 0 ]]; then
    emit_status "drift" "at-disable profile=$PROFILE drift=$drift"
    exit 1
fi
emit_status "ok" "at-disable profile=$PROFILE no drift"
