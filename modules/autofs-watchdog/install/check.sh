#!/usr/bin/env bash
# autofs-watchdog — check. Read-only.

set -euo pipefail

MODULE="autofs-watchdog"
DRY_RUN=0
CONFIG_FILE="${SELFDEF_AUTOFS_CONFIG:-/etc/selfdef/modules/autofs-watchdog.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
LIBEXEC_DIR="${SELFDEF_LIBEXEC_DIR:-/usr/local/libexec/selfdef}"
SYSTEMD_DIR="${SELFDEF_SYSTEMD_DIR:-/etc/systemd/system}"
BASELINE="${SELFDEF_AUTOFS_BASELINE:-/var/lib/selfdef/autofs-baseline.tsv}"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"
PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "report")

drift=0
[[ -x "${LIBEXEC_DIR}/autofs-watchdog.sh" ]]      || { emit_status "drift" "wrapper script missing/not exec"; drift=$((drift + 1)); }
[[ -f "${SYSTEMD_DIR}/selfdef-autofs.service" ]]  || { emit_status "drift" "service unit missing"; drift=$((drift + 1)); }
[[ -f "${SYSTEMD_DIR}/selfdef-autofs.timer" ]]    || { emit_status "drift" "timer unit missing"; drift=$((drift + 1)); }

if command -v systemctl >/dev/null 2>&1; then
    if ! systemctl is-active --quiet selfdef-autofs.timer; then
        log "selfdef-autofs.timer NOT active"
    fi
fi

if [[ -f "$BASELINE" ]]; then
    log "baseline present: $BASELINE ($(wc -l < "$BASELINE" | tr -d ' ') entries)"
    mode=$(stat -c '%a' "$BASELINE" 2>/dev/null || echo "?")
    [[ "$mode" != "600" ]] && { emit_status "drift" "baseline mode $mode; expected 600"; drift=$((drift + 1)); }
else
    log "no baseline yet (first scan baselines)"
fi

if command -v journalctl >/dev/null 2>&1; then
    last=$(journalctl -t selfdef-autofs -n 1 --no-pager -o cat 2>/dev/null || echo "")
    [[ -n "$last" ]] && log "last scan event: $last"
fi

if [[ "$drift" -gt 0 ]]; then
    emit_status "drift" "autofs-watchdog profile=$PROFILE drift=$drift"
    exit 1
fi
emit_status "ok" "autofs-watchdog profile=$PROFILE no drift"
