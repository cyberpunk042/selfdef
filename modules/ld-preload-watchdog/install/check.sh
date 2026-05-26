#!/usr/bin/env bash
# ld-preload-watchdog — check. Read-only.

set -euo pipefail

MODULE="ld-preload-watchdog"
DRY_RUN=0
CONFIG_FILE="${SELFDEF_LDPRELOAD_CONFIG:-/etc/selfdef/modules/ld-preload-watchdog.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
LIBEXEC_DIR="${SELFDEF_LIBEXEC_DIR:-/usr/local/libexec/selfdef}"
SYSTEMD_DIR="${SELFDEF_SYSTEMD_DIR:-/etc/systemd/system}"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"
PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "report")

drift=0
[[ -x "${LIBEXEC_DIR}/ld-preload-watchdog.sh" ]]      || { emit_status "drift" "wrapper script missing/not exec"; drift=$((drift + 1)); }
[[ -f "${SYSTEMD_DIR}/selfdef-ld-preload.service" ]]  || { emit_status "drift" "service unit missing"; drift=$((drift + 1)); }
[[ -f "${SYSTEMD_DIR}/selfdef-ld-preload.timer" ]]    || { emit_status "drift" "timer unit missing"; drift=$((drift + 1)); }

if command -v systemctl >/dev/null 2>&1; then
    if ! systemctl is-active --quiet selfdef-ld-preload.timer; then
        log "selfdef-ld-preload.timer NOT active"
    fi
    if command -v journalctl >/dev/null 2>&1; then
        last=$(journalctl -t selfdef-ld-preload -n 1 --no-pager -o cat 2>/dev/null || echo "")
        [[ -n "$last" ]] && log "last scan event: $last"
    fi
fi

if [[ "$drift" -gt 0 ]]; then
    emit_status "drift" "ld-preload-watchdog profile=$PROFILE drift=$drift"
    exit 1
fi
emit_status "ok" "ld-preload-watchdog profile=$PROFILE no drift"
