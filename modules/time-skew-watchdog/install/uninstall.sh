#!/usr/bin/env bash
# time-skew-watchdog — uninstall.
#
# Disables + removes the timer + service unit + probe script.
# systemctl reset-failed on the service unit name to clean
# operator-readable status.
# Idempotent. SELFDEF_DRY_RUN=1 aware.

set -euo pipefail

MODULE="time-skew-watchdog"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
LIBEXEC_DIR="${SELFDEF_LIBEXEC_DIR:-/usr/local/libexec/selfdef}"
SYSTEMD_DIR="${SELFDEF_SYSTEMD_DIR:-/etc/systemd/system}"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

if command -v systemctl >/dev/null 2>&1 && [[ "$DRY_RUN" != "1" ]]; then
    run "disable + stop timer" -- systemctl disable --now selfdef-time-skew-watchdog.timer || true
    systemctl reset-failed selfdef-time-skew-watchdog.service 2>/dev/null || true
fi

removed=0
for f in "${SYSTEMD_DIR}/selfdef-time-skew-watchdog.service" \
         "${SYSTEMD_DIR}/selfdef-time-skew-watchdog.timer" \
         "${LIBEXEC_DIR}/time-skew-watchdog.sh"; do
    if [[ -f "$f" ]]; then
        run "remove $(basename "$f")" -- rm -f "$f"
        removed=$((removed + 1))
    fi
done

if [[ "$removed" -gt 0 ]] && [[ "$DRY_RUN" != "1" ]] && command -v systemctl >/dev/null; then
    run "systemctl daemon-reload" -- systemctl daemon-reload || true
fi

emit_status "ok" "time-skew-watchdog removed=$removed"
