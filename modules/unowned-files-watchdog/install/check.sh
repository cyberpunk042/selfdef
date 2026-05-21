#!/usr/bin/env bash
# unowned-files-watchdog — check. Read-only.

set -euo pipefail

MODULE="unowned-files-watchdog"
DRY_RUN=0
CONFIG_FILE="${SELFDEF_UNOWNED_CONFIG:-/etc/selfdef/modules/unowned-files-watchdog.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
LIBEXEC_DIR="${SELFDEF_LIBEXEC_DIR:-/usr/local/libexec/selfdef}"
SYSTEMD_DIR="${SELFDEF_SYSTEMD_DIR:-/etc/systemd/system}"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"
PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "report")

drift=0
[[ -x "${LIBEXEC_DIR}/unowned-files-watchdog.sh" ]] || { emit_status "drift" "wrapper script missing/not exec"; drift=$((drift + 1)); }
[[ -f "${SYSTEMD_DIR}/selfdef-unowned-files.service" ]] || { emit_status "drift" "service unit missing"; drift=$((drift + 1)); }
[[ -f "${SYSTEMD_DIR}/selfdef-unowned-files.timer" ]] || { emit_status "drift" "timer unit missing"; drift=$((drift + 1)); }

if command -v systemctl >/dev/null 2>&1; then
    if ! systemctl is-active --quiet selfdef-unowned-files.timer; then
        log "selfdef-unowned-files.timer NOT active"
    fi
    if command -v journalctl >/dev/null 2>&1; then
        last=$(journalctl -t selfdef-unowned-files -n 1 --no-pager -o cat 2>/dev/null || echo "")
        if [[ -n "$last" ]]; then
            log "last scan event: $last"
        else
            log "no scan events yet (weekly timer; may not have fired since boot)"
        fi
    fi
fi

if [[ "$drift" -gt 0 ]]; then
    emit_status "drift" "unowned-files-watchdog profile=$PROFILE drift=$drift"
    exit 1
fi
emit_status "ok" "unowned-files-watchdog profile=$PROFILE no drift"
