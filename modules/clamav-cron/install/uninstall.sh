#!/usr/bin/env bash
# clamav-cron — uninstall.

set -euo pipefail

MODULE="clamav-cron"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
LIBEXEC_DIR="${SELFDEF_LIBEXEC_DIR:-/usr/local/libexec/selfdef}"
SYSTEMD_DIR="${SELFDEF_SYSTEMD_DIR:-/etc/systemd/system}"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

if command -v systemctl >/dev/null 2>&1 && [[ "$DRY_RUN" != "1" ]]; then
    run "disable + stop timer" -- systemctl disable --now selfdef-clamav-scan.timer || true
    systemctl reset-failed selfdef-clamav-scan.service 2>/dev/null || true
fi

removed=0
for f in "${SYSTEMD_DIR}/selfdef-clamav-scan.service" \
         "${SYSTEMD_DIR}/selfdef-clamav-scan.timer" \
         "${LIBEXEC_DIR}/clamav-scan.sh"; do
    if [[ -f "$f" ]]; then
        run "remove $(basename "$f")" -- rm -f "$f"
        removed=$((removed + 1))
    fi
done

DROPIN_DIR_SVC="${SYSTEMD_DIR}/selfdef-clamav-scan.service.d"
if [[ -d "$DROPIN_DIR_SVC" ]]; then
    run "rm -r ${DROPIN_DIR_SVC}" -- rm -rf "$DROPIN_DIR_SVC"
    removed=$((removed + 1))
fi

if [[ "$removed" -gt 0 ]] && [[ "$DRY_RUN" != "1" ]] && command -v systemctl >/dev/null; then
    run "systemctl daemon-reload" -- systemctl daemon-reload || true
fi

emit_status "ok" "clamav-cron removed=$removed (NOTE: /var/lib/clamav/ DB preserved — operator-managed signature db)"
