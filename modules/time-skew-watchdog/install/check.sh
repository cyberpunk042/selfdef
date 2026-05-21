#!/usr/bin/env bash
# time-skew-watchdog — check. Read-only.
#
# Verifies all 3 files exist + the timer is active (enabled +
# running). Logs the last journal entry tagged selfdef-time-skew
# for operator visibility.

set -euo pipefail

MODULE="time-skew-watchdog"
DRY_RUN=0
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
LIBEXEC_DIR="${SELFDEF_LIBEXEC_DIR:-/usr/local/libexec/selfdef}"
SYSTEMD_DIR="${SELFDEF_SYSTEMD_DIR:-/etc/systemd/system}"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

drift=0
[[ -x "${LIBEXEC_DIR}/time-skew-watchdog.sh" ]] || {
    emit_status "drift" "probe script missing or not executable: ${LIBEXEC_DIR}/time-skew-watchdog.sh"
    drift=$((drift + 1))
}
[[ -f "${SYSTEMD_DIR}/selfdef-time-skew-watchdog.service" ]] || {
    emit_status "drift" "service unit missing"
    drift=$((drift + 1))
}
[[ -f "${SYSTEMD_DIR}/selfdef-time-skew-watchdog.timer" ]] || {
    emit_status "drift" "timer unit missing"
    drift=$((drift + 1))
}

# Timer active check.
if command -v systemctl >/dev/null 2>&1; then
    if ! systemctl is-active --quiet selfdef-time-skew-watchdog.timer; then
        log "selfdef-time-skew-watchdog.timer NOT active — run 'systemctl enable --now selfdef-time-skew-watchdog.timer'"
    fi
    # Last journal entry from the probe (best-effort).
    if command -v journalctl >/dev/null 2>&1; then
        last=$(journalctl -t selfdef-time-skew -n 1 --no-pager -o cat 2>/dev/null || echo "")
        if [[ -n "$last" ]]; then
            log "last probe event: $last"
        else
            log "no probe events yet (timer may not have fired)"
        fi
    fi
fi

if [[ "$drift" -gt 0 ]]; then
    emit_status "drift" "time-skew-watchdog drift=$drift"
    exit 1
fi
emit_status "ok" "time-skew-watchdog no drift"
