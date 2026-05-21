#!/usr/bin/env bash
# bluetooth-disable — check. Read-only.

set -euo pipefail

MODULE="bluetooth-disable"
DRY_RUN=0
CONFIG_FILE="${SELFDEF_BLUETOOTH_CONFIG:-/etc/selfdef/modules/bluetooth-disable.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"
PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "mask")

drift=0
acted=0

if ! command -v systemctl >/dev/null 2>&1; then
    emit_status "ok" "bluetooth-disable (systemctl unavailable)"
    exit 0
fi

for unit in "${BT_UNITS[@]}"; do
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

# Modprobe blacklist file presence (mask profile only).
if [[ "$PROFILE" == "mask" ]]; then
    if [[ ! -f "$MODPROBE_BLACKLIST" ]]; then
        emit_status "drift" "missing $MODPROBE_BLACKLIST — mask profile requires kernel-module blacklist"
        drift=$((drift + 1))
    elif ! head -1 "$MODPROBE_BLACKLIST" | grep -qF "$HEADER_MARKER"; then
        emit_status "drift" "$MODPROBE_BLACKLIST exists but lacks selfdef header marker — possible operator-managed"
        drift=$((drift + 1))
    fi
fi

# Are bluetooth modules CURRENTLY loaded?
if [[ -r /proc/modules ]]; then
    for m in "${BT_MODULES[@]}"; do
        if awk -v m="$m" '$1 == m { found=1 } END { exit !found }' /proc/modules; then
            emit_status "drift" "kernel module '$m' is loaded — blacklist takes effect on next reboot"
            drift=$((drift + 1))
        fi
    done
fi

# rfkill soft-block state.
if command -v rfkill >/dev/null 2>&1; then
    if rfkill list bluetooth 2>/dev/null | grep -q 'Soft blocked: no'; then
        emit_status "drift" "rfkill: bluetooth NOT soft-blocked"
        drift=$((drift + 1))
    fi
fi

if [[ "$drift" -gt 0 ]]; then
    emit_status "drift" "bluetooth-disable profile=$PROFILE drift=$drift"
    exit 1
fi
emit_status "ok" "bluetooth-disable profile=$PROFILE units_acted=$acted no drift"
