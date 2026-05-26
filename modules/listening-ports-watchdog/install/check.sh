#!/usr/bin/env bash
# listening-ports-watchdog — check. Read-only.

set -euo pipefail

MODULE="listening-ports-watchdog"
DRY_RUN=0
CONFIG_FILE="${SELFDEF_LISTENPORTS_CONFIG:-/etc/selfdef/modules/listening-ports-watchdog.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
LIBEXEC_DIR="${SELFDEF_LIBEXEC_DIR:-/usr/local/libexec/selfdef}"
SYSTEMD_DIR="${SELFDEF_SYSTEMD_DIR:-/etc/systemd/system}"
BASELINE="${SELFDEF_LISTENPORTS_BASELINE:-/var/lib/selfdef/listening-ports-baseline.tsv}"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"
PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "report")

drift=0
[[ -x "${LIBEXEC_DIR}/listening-ports-watchdog.sh" ]]      || { emit_status "drift" "wrapper script missing/not exec"; drift=$((drift + 1)); }
[[ -f "${SYSTEMD_DIR}/selfdef-listening-ports.service" ]]  || { emit_status "drift" "service unit missing"; drift=$((drift + 1)); }
[[ -f "${SYSTEMD_DIR}/selfdef-listening-ports.timer" ]]    || { emit_status "drift" "timer unit missing"; drift=$((drift + 1)); }

if command -v systemctl >/dev/null 2>&1; then
    if ! systemctl is-active --quiet selfdef-listening-ports.timer; then
        log "selfdef-listening-ports.timer NOT active"
    fi
fi

if [[ -f "$BASELINE" ]]; then
    bc=$(wc -l < "$BASELINE" | tr -d ' ')
    log "baseline present: $BASELINE ($bc listeners)"
    mode=$(stat -c '%a' "$BASELINE" 2>/dev/null || echo "?")
    if [[ "$mode" != "600" ]]; then
        emit_status "drift" "baseline file mode is $mode; expected 600"
        drift=$((drift + 1))
    fi
else
    log "no baseline yet (first scan after install will baseline)"
fi

if command -v journalctl >/dev/null 2>&1; then
    last=$(journalctl -t selfdef-listening-ports -n 1 --no-pager -o cat 2>/dev/null || echo "")
    [[ -n "$last" ]] && log "last scan event: $last"
fi

if [[ "$drift" -gt 0 ]]; then
    emit_status "drift" "listening-ports-watchdog profile=$PROFILE drift=$drift"
    exit 1
fi
emit_status "ok" "listening-ports-watchdog profile=$PROFILE no drift"
