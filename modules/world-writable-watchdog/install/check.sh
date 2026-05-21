#!/usr/bin/env bash
# world-writable-watchdog — check. Read-only.

set -euo pipefail

MODULE="world-writable-watchdog"
DRY_RUN=0
CONFIG_FILE="${SELFDEF_WORLDWRITE_CONFIG:-/etc/selfdef/modules/world-writable-watchdog.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
LIBEXEC_DIR="${SELFDEF_LIBEXEC_DIR:-/usr/local/libexec/selfdef}"
SYSTEMD_DIR="${SELFDEF_SYSTEMD_DIR:-/etc/systemd/system}"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"
PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "report")

drift=0
[[ -x "${LIBEXEC_DIR}/world-writable-watchdog.sh" ]] || { emit_status "drift" "wrapper script missing/not exec"; drift=$((drift + 1)); }
[[ -f "${SYSTEMD_DIR}/selfdef-world-writable.service" ]] || { emit_status "drift" "service unit missing"; drift=$((drift + 1)); }
[[ -f "${SYSTEMD_DIR}/selfdef-world-writable.timer" ]] || { emit_status "drift" "timer unit missing"; drift=$((drift + 1)); }

if command -v systemctl >/dev/null 2>&1; then
    if ! systemctl is-active --quiet selfdef-world-writable.timer; then
        log "selfdef-world-writable.timer NOT active"
    fi
    if command -v journalctl >/dev/null 2>&1; then
        last=$(journalctl -t selfdef-world-writable -n 1 --no-pager -o cat 2>/dev/null || echo "")
        if [[ -n "$last" ]]; then
            log "last scan event: $last"
        else
            log "no scan events yet (timer may not have fired since boot)"
        fi
    fi
fi

if [[ "$drift" -gt 0 ]]; then
    emit_status "drift" "world-writable-watchdog profile=$PROFILE drift=$drift"
    exit 1
fi
emit_status "ok" "world-writable-watchdog profile=$PROFILE no drift"
