#!/usr/bin/env bash
# aide-bridge — check. Read-only.
#
# Verifies all files present + AIDE DB exists + timer is active.
# Logs the last journal entry tagged selfdef-aide.

set -euo pipefail

MODULE="aide-bridge"
DRY_RUN=0
CONFIG_FILE="${SELFDEF_AIDE_BRIDGE_CONFIG:-/etc/selfdef/modules/aide-bridge.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"

AIDE_CONFD="${SELFDEF_AIDE_CONFD:-/etc/aide/aide.conf.d}"
AIDE_DROPIN="${AIDE_CONFD}/50-selfdef.conf"
AIDE_DB="${SELFDEF_AIDE_DB_DIR:-/var/lib/aide}/aide.db"
LIBEXEC_DIR="${SELFDEF_LIBEXEC_DIR:-/usr/local/libexec/selfdef}"
SYSTEMD_DIR="${SELFDEF_SYSTEMD_DIR:-/etc/systemd/system}"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"
PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "baseline")

drift=0
[[ -f "$AIDE_DROPIN" ]] || { emit_status "drift" "aide.conf drop-in missing"; drift=$((drift + 1)); }
[[ -x "${LIBEXEC_DIR}/aide-check.sh" ]] || { emit_status "drift" "check script missing/not exec"; drift=$((drift + 1)); }
[[ -f "${SYSTEMD_DIR}/selfdef-aide-check.service" ]] || { emit_status "drift" "service unit missing"; drift=$((drift + 1)); }
[[ -f "${SYSTEMD_DIR}/selfdef-aide-check.timer" ]] || { emit_status "drift" "timer unit missing"; drift=$((drift + 1)); }
[[ -f "$AIDE_DB" ]] || { emit_status "drift" "AIDE database missing: $AIDE_DB"; drift=$((drift + 1)); }

if command -v systemctl >/dev/null 2>&1; then
    if ! systemctl is-active --quiet selfdef-aide-check.timer; then
        log "selfdef-aide-check.timer NOT active"
    fi
    if command -v journalctl >/dev/null 2>&1; then
        last=$(journalctl -t selfdef-aide -n 1 --no-pager -o cat 2>/dev/null || echo "")
        if [[ -n "$last" ]]; then
            log "last check event: $last"
        else
            log "no check events yet (timer may not have fired since boot)"
        fi
    fi
fi

if [[ "$drift" -gt 0 ]]; then
    emit_status "drift" "aide-bridge profile=$PROFILE drift=$drift"
    exit 1
fi
emit_status "ok" "aide-bridge profile=$PROFILE no drift"
