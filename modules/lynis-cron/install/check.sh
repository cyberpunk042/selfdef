#!/usr/bin/env bash
# lynis-cron — check. Read-only.

set -euo pipefail

MODULE="lynis-cron"
DRY_RUN=0
CONFIG_FILE="${SELFDEF_LYNIS_CRON_CONFIG:-/etc/selfdef/modules/lynis-cron.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
LIBEXEC_DIR="${SELFDEF_LIBEXEC_DIR:-/usr/local/libexec/selfdef}"
SYSTEMD_DIR="${SELFDEF_SYSTEMD_DIR:-/etc/systemd/system}"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"
PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "quick")

drift=0
[[ -x "${LIBEXEC_DIR}/lynis-audit.sh" ]] || { emit_status "drift" "wrapper script missing/not exec"; drift=$((drift + 1)); }
[[ -f "${SYSTEMD_DIR}/selfdef-lynis-audit.service" ]] || { emit_status "drift" "service unit missing"; drift=$((drift + 1)); }
[[ -f "${SYSTEMD_DIR}/selfdef-lynis-audit.timer" ]] || { emit_status "drift" "timer unit missing"; drift=$((drift + 1)); }

if command -v systemctl >/dev/null 2>&1; then
    if ! systemctl is-active --quiet selfdef-lynis-audit.timer; then
        log "selfdef-lynis-audit.timer NOT active"
    fi
    if command -v journalctl >/dev/null 2>&1; then
        last=$(journalctl -t selfdef-lynis -n 1 --no-pager -o cat 2>/dev/null || echo "")
        if [[ -n "$last" ]]; then
            log "last audit event: $last"
        else
            log "no audit events yet (timer fires weekly; may not have triggered since boot)"
        fi
    fi
fi

if [[ "$drift" -gt 0 ]]; then
    emit_status "drift" "lynis-cron profile=$PROFILE drift=$drift"
    exit 1
fi
emit_status "ok" "lynis-cron profile=$PROFILE no drift"
