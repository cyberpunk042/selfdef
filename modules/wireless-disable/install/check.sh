#!/usr/bin/env bash
# wireless-disable — check. Read-only.

set -euo pipefail

MODULE="wireless-disable"
DRY_RUN=0
CONFIG_FILE="${SELFDEF_WIRELESS_CONFIG:-/etc/selfdef/modules/wireless-disable.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"
PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "rfkill")

drift=0

# rfkill: wifi should be soft-blocked.
if command -v rfkill >/dev/null 2>&1; then
    if rfkill list wifi 2>/dev/null | grep -q 'Soft blocked: no'; then
        emit_status "drift" "wifi NOT soft-blocked (rfkill)"
        drift=$((drift + 1))
    fi
fi

# mask: blacklist file present + marked.
if [[ "$PROFILE" == "mask" ]]; then
    if [[ ! -f "$MODPROBE_FILE" ]]; then
        emit_status "drift" "missing $MODPROBE_FILE (mask profile)"
        drift=$((drift + 1))
    elif ! head -1 "$MODPROBE_FILE" | grep -qF "$HEADER_MARKER"; then
        emit_status "drift" "$MODPROBE_FILE lacks selfdef header marker"
        drift=$((drift + 1))
    fi
    # Is cfg80211 still loaded?
    if [[ -r /proc/modules ]] && awk '$1=="cfg80211"{f=1} END{exit !f}' /proc/modules; then
        log "cfg80211 still loaded — blacklist takes effect next reboot"
    fi
fi

if [[ "$drift" -gt 0 ]]; then
    emit_status "drift" "wireless-disable profile=$PROFILE drift=$drift"
    exit 1
fi
emit_status "ok" "wireless-disable profile=$PROFILE no drift"
