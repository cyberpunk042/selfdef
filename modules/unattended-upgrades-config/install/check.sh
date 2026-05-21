#!/usr/bin/env bash
# unattended-upgrades-config — check. Read-only.

set -euo pipefail

MODULE="unattended-upgrades-config"
DRY_RUN=0
CONFIG_FILE="${SELFDEF_UU_CONFIG:-/etc/selfdef/modules/unattended-upgrades-config.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
APT_CONFD="${SELFDEF_APT_CONFD:-/etc/apt/apt.conf.d}"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"
PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "security-only")

drift=0
[[ -f "${APT_CONFD}/50selfdef-unattended-upgrades" ]] || { emit_status "drift" "50selfdef-unattended-upgrades missing"; drift=$((drift + 1)); }
[[ -f "${APT_CONFD}/20selfdef-periodic" ]] || { emit_status "drift" "20selfdef-periodic missing"; drift=$((drift + 1)); }

if [[ "$PROFILE" == "security-and-reboot" ]]; then
    [[ -f "${APT_CONFD}/60selfdef-unattended-reboot" ]] || { emit_status "drift" "60selfdef-unattended-reboot missing (profile requires it)"; drift=$((drift + 1)); }
fi

# Check the apt-daily-upgrade.timer is active.
if command -v systemctl >/dev/null 2>&1; then
    if ! systemctl is-active --quiet apt-daily-upgrade.timer; then
        log "apt-daily-upgrade.timer NOT active — run 'systemctl enable --now apt-daily-upgrade.timer'"
    fi
fi

# Best-effort: last unattended-upgrade run log line.
if [[ -r /var/log/unattended-upgrades/unattended-upgrades.log ]]; then
    last=$(tail -1 /var/log/unattended-upgrades/unattended-upgrades.log 2>/dev/null || echo "")
    if [[ -n "$last" ]]; then
        log "last UU run: ${last:0:200}"
    fi
fi

if [[ "$drift" -gt 0 ]]; then
    emit_status "drift" "unattended-upgrades-config profile=$PROFILE drift=$drift"
    exit 1
fi
emit_status "ok" "unattended-upgrades-config profile=$PROFILE no drift"
