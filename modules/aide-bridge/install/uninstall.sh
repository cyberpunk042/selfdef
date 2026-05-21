#!/usr/bin/env bash
# aide-bridge — uninstall.
#
# Removes the aide.conf.d drop-in + systemd unit + drop-in dir +
# wrapper script. PRESERVES /var/lib/aide/aide.db (operator-
# collected baseline; rebuilding takes minutes-to-hours).
# Idempotent. SELFDEF_DRY_RUN=1 aware.

set -euo pipefail

MODULE="aide-bridge"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"

AIDE_CONFD="${SELFDEF_AIDE_CONFD:-/etc/aide/aide.conf.d}"
LIBEXEC_DIR="${SELFDEF_LIBEXEC_DIR:-/usr/local/libexec/selfdef}"
SYSTEMD_DIR="${SELFDEF_SYSTEMD_DIR:-/etc/systemd/system}"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

if command -v systemctl >/dev/null 2>&1 && [[ "$DRY_RUN" != "1" ]]; then
    run "disable + stop timer" -- systemctl disable --now selfdef-aide-check.timer || true
    systemctl reset-failed selfdef-aide-check.service 2>/dev/null || true
fi

removed=0
for f in "${SYSTEMD_DIR}/selfdef-aide-check.service" \
         "${SYSTEMD_DIR}/selfdef-aide-check.timer" \
         "${AIDE_CONFD}/50-selfdef.conf" \
         "${LIBEXEC_DIR}/aide-check.sh"; do
    if [[ -f "$f" ]]; then
        run "remove $(basename "$f")" -- rm -f "$f"
        removed=$((removed + 1))
    fi
done

# Drop-in dir.
DROPIN_DIR_SVC="${SYSTEMD_DIR}/selfdef-aide-check.service.d"
if [[ -d "$DROPIN_DIR_SVC" ]]; then
    run "rm -r ${DROPIN_DIR_SVC}" -- rm -rf "$DROPIN_DIR_SVC"
    removed=$((removed + 1))
fi

if [[ "$removed" -gt 0 ]] && [[ "$DRY_RUN" != "1" ]] && command -v systemctl >/dev/null; then
    run "systemctl daemon-reload" -- systemctl daemon-reload || true
fi

emit_status "ok" "aide-bridge removed=$removed (NOTE: /var/lib/aide/aide.db preserved — rm manually to reclaim)"
