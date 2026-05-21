#!/usr/bin/env bash
# dnf-automatic-config — check. Read-only.

set -euo pipefail

MODULE="dnf-automatic-config"
DRY_RUN=0
CONFIG_FILE="${SELFDEF_DNF_AUTO_CONFIG:-/etc/selfdef/modules/dnf-automatic-config.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"
PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "security-only")

drift=0
if [[ ! -f "$DNF_AUTO_CONF" ]]; then
    emit_status "drift" "automatic.conf missing: $DNF_AUTO_CONF"
    drift=$((drift + 1))
elif ! head -1 "$DNF_AUTO_CONF" | grep -qF "$DNF_AUTO_MARKER"; then
    emit_status "drift" "automatic.conf present but not selfdef-managed (no header marker)"
    drift=$((drift + 1))
fi

if command -v systemctl >/dev/null 2>&1; then
    if systemctl list-unit-files dnf-automatic.timer >/dev/null 2>&1; then
        if ! systemctl is-active --quiet dnf-automatic.timer; then
            emit_status "drift" "dnf-automatic.timer NOT active"
            drift=$((drift + 1))
        fi
    else
        log "dnf-automatic.timer not present — install dnf-automatic package"
    fi

    # Last run inspection.
    if command -v journalctl >/dev/null 2>&1; then
        last=$(journalctl -u dnf-automatic.service -n 1 --no-pager -o cat 2>/dev/null || echo "")
        if [[ -n "$last" ]]; then
            log "last dnf-automatic run: ${last:0:120}"
        fi
    fi
fi

if [[ "$drift" -gt 0 ]]; then
    emit_status "drift" "dnf-automatic-config profile=$PROFILE drift=$drift"
    exit 1
fi
emit_status "ok" "dnf-automatic-config profile=$PROFILE no drift"
