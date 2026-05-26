#!/usr/bin/env bash
# wwan-disable — check. Read-only.

set -euo pipefail

MODULE="wwan-disable"
DRY_RUN=0
CONFIG_FILE="${SELFDEF_WWAN_CONFIG:-/etc/selfdef/modules/wwan-disable.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"
PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "rfkill")

drift=0

# rfkill: wwan should be soft-blocked.
if command -v rfkill >/dev/null 2>&1; then
    if rfkill list wwan 2>/dev/null | grep -q 'Soft blocked: no'; then
        emit_status "drift" "wwan NOT soft-blocked (rfkill)"
        drift=$((drift + 1))
    fi
fi

# ModemManager should be masked (if present).
if command -v systemctl >/dev/null 2>&1; then
    for unit in "${MM_UNITS[@]}"; do
        systemctl list-unit-files "$unit" >/dev/null 2>&1 || continue
        state=$(systemctl is-enabled "$unit" 2>/dev/null || echo "")
        if [[ "$state" != "masked" ]]; then
            emit_status "drift" "$unit is $state — expected masked"
            drift=$((drift + 1))
        fi
    done
fi

# mask profile: blacklist file present + marked.
if [[ "$PROFILE" == "mask" ]]; then
    if [[ ! -f "$MODPROBE_FILE" ]]; then
        emit_status "drift" "missing $MODPROBE_FILE (mask profile)"
        drift=$((drift + 1))
    elif ! head -1 "$MODPROBE_FILE" | grep -qF "$HEADER_MARKER"; then
        emit_status "drift" "$MODPROBE_FILE lacks selfdef header marker"
        drift=$((drift + 1))
    fi
fi

if [[ "$drift" -gt 0 ]]; then
    emit_status "drift" "wwan-disable profile=$PROFILE drift=$drift"
    exit 1
fi
emit_status "ok" "wwan-disable profile=$PROFILE no drift"
