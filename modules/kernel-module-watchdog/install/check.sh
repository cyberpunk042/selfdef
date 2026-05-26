#!/usr/bin/env bash
# kernel-module-watchdog — check. Read-only.

set -euo pipefail

MODULE="kernel-module-watchdog"
DRY_RUN=0
CONFIG_FILE="${SELFDEF_KMOD_CONFIG:-/etc/selfdef/modules/kernel-module-watchdog.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
LIBEXEC_DIR="${SELFDEF_LIBEXEC_DIR:-/usr/local/libexec/selfdef}"
SYSTEMD_DIR="${SELFDEF_SYSTEMD_DIR:-/etc/systemd/system}"
BASELINE="${SELFDEF_KMOD_BASELINE:-/var/lib/selfdef/kernel-modules-baseline.tsv}"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"
PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "report")

drift=0
[[ -x "${LIBEXEC_DIR}/kernel-module-watchdog.sh" ]]        || { emit_status "drift" "wrapper script missing/not exec"; drift=$((drift + 1)); }
[[ -f "${SYSTEMD_DIR}/selfdef-kernel-modules.service" ]]   || { emit_status "drift" "service unit missing"; drift=$((drift + 1)); }
[[ -f "${SYSTEMD_DIR}/selfdef-kernel-modules.timer" ]]     || { emit_status "drift" "timer unit missing"; drift=$((drift + 1)); }

if command -v systemctl >/dev/null 2>&1; then
    if ! systemctl is-active --quiet selfdef-kernel-modules.timer; then
        log "selfdef-kernel-modules.timer NOT active"
    fi
fi

if [[ -f "$BASELINE" ]]; then
    bc=$(wc -l < "$BASELINE" | tr -d ' ')
    log "baseline present: $BASELINE ($bc modules)"
    mode=$(stat -c '%a' "$BASELINE" 2>/dev/null || echo "?")
    if [[ "$mode" != "600" ]]; then
        emit_status "drift" "baseline file mode is $mode; expected 600"
        drift=$((drift + 1))
    fi
else
    log "no baseline yet (first scan after install will baseline)"
fi

if command -v journalctl >/dev/null 2>&1; then
    last=$(journalctl -t selfdef-kernel-modules -n 1 --no-pager -o cat 2>/dev/null || echo "")
    [[ -n "$last" ]] && log "last scan event: $last"
fi

if [[ "$drift" -gt 0 ]]; then
    emit_status "drift" "kernel-module-watchdog profile=$PROFILE drift=$drift"
    exit 1
fi
emit_status "ok" "kernel-module-watchdog profile=$PROFILE no drift"
