#!/usr/bin/env bash
# nscd-disable — check. Read-only.

set -euo pipefail

MODULE="nscd-disable"
DRY_RUN=0
CONFIG_FILE="${SELFDEF_NSCD_CONFIG:-/etc/selfdef/modules/nscd-disable.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"
PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "mask")

drift=0
acted=0

if ! command -v systemctl >/dev/null 2>&1; then
    emit_status "ok" "nscd-disable (systemctl unavailable)"
    exit 0
fi

for unit in "${NSCD_UNITS[@]}"; do
    if ! systemctl list-unit-files "$unit" >/dev/null 2>&1; then
        continue
    fi
    acted=$((acted + 1))
    if systemctl is-active --quiet "$unit" 2>/dev/null; then
        emit_status "drift" "$unit is ACTIVE — should be stopped"
        drift=$((drift + 1))
    fi
    state=$(systemctl is-enabled "$unit" 2>/dev/null || echo "")
    if [[ "$PROFILE" == "mask" ]] && [[ "$state" != "masked" ]]; then
        emit_status "drift" "$unit is $state — mask profile requires masked"
        drift=$((drift + 1))
    fi
done

if [[ "$acted" -eq 0 ]]; then
    log "nscd not installed on this host"
fi

if [[ "$drift" -gt 0 ]]; then
    emit_status "drift" "nscd-disable profile=$PROFILE drift=$drift"
    exit 1
fi
emit_status "ok" "nscd-disable profile=$PROFILE acted=$acted no drift"
