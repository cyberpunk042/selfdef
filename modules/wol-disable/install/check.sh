#!/usr/bin/env bash
# wol-disable — check. Read-only.

set -euo pipefail

MODULE="wol-disable"
DRY_RUN=0
CONFIG_FILE="${SELFDEF_WOL_CONFIG:-/etc/selfdef/modules/wol-disable.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
LIBEXEC_DIR="${SELFDEF_LIBEXEC_DIR:-/usr/local/libexec/selfdef}"
SYSTEMD_DIR="${SELFDEF_SYSTEMD_DIR:-/etc/systemd/system}"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"
PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "enforce")

drift=0
[[ -x "${LIBEXEC_DIR}/wol-disable.sh" ]] || { emit_status "drift" "wrapper script missing/not exec"; drift=$((drift + 1)); }
[[ -f "${SYSTEMD_DIR}/selfdef-wol-disable.service" ]] || { emit_status "drift" "service unit missing"; drift=$((drift + 1)); }

if command -v systemctl >/dev/null 2>&1; then
    if ! systemctl is-enabled --quiet selfdef-wol-disable.service 2>/dev/null; then
        emit_status "drift" "selfdef-wol-disable.service NOT enabled"
        drift=$((drift + 1))
    fi
fi

# Live state: query each ethernet NIC.
if command -v ethtool >/dev/null 2>&1; then
    nics_wol_enabled=0
    for iface in /sys/class/net/*; do
        i="$(basename "$iface")"
        [[ "$i" == "lo" ]] && continue
        [[ -d "$iface/wireless" ]] && continue
        case "$i" in br*|veth*|docker*|virbr*|vnet*|tun*|tap*|dummy*) continue ;; esac
        wol_state=$(ethtool "$i" 2>/dev/null | awk -F': ' '/Wake-on/ {print $2; exit}' || echo "?")
        if [[ "$PROFILE" == "enforce" ]] && [[ "$wol_state" != "d" ]] && [[ "$wol_state" != "?" ]]; then
            log "iface $i has wol=$wol_state (enforce profile expects d)"
            nics_wol_enabled=$((nics_wol_enabled + 1))
        fi
    done
    if [[ "$PROFILE" == "enforce" ]] && [[ "$nics_wol_enabled" -gt 0 ]]; then
        emit_status "drift" "enforce profile: $nics_wol_enabled NIC(s) have WoL not 'd' — service may not have run since boot"
        drift=$((drift + 1))
    fi
fi

if [[ "$drift" -gt 0 ]]; then
    emit_status "drift" "wol-disable profile=$PROFILE drift=$drift"
    exit 1
fi
emit_status "ok" "wol-disable profile=$PROFILE no drift"
