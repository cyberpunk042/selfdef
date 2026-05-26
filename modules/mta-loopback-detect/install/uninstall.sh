#!/usr/bin/env bash
# mta-loopback-detect — uninstall.

set -euo pipefail

MODULE="mta-loopback-detect"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
LIBEXEC_DIR="${SELFDEF_LIBEXEC_DIR:-/usr/local/libexec/selfdef}"
SYSTEMD_DIR="${SELFDEF_SYSTEMD_DIR:-/etc/systemd/system}"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

if command -v systemctl >/dev/null 2>&1 && [[ "$DRY_RUN" != "1" ]]; then
    run "disable + stop timer" -- systemctl disable --now selfdef-mta-loopback.timer || true
    systemctl reset-failed selfdef-mta-loopback.service 2>/dev/null || true
fi

removed=0
for f in "${SYSTEMD_DIR}/selfdef-mta-loopback.service" \
         "${SYSTEMD_DIR}/selfdef-mta-loopback.timer" \
         "${LIBEXEC_DIR}/mta-loopback-detect.sh"; do
    if [[ -f "$f" ]]; then
        run "remove $(basename "$f")" -- rm -f "$f"
        removed=$((removed + 1))
    fi
done

DROPIN_DIR_SVC="${SYSTEMD_DIR}/selfdef-mta-loopback.service.d"
if [[ -d "$DROPIN_DIR_SVC" ]]; then
    run "rm -r ${DROPIN_DIR_SVC}" -- rm -rf "$DROPIN_DIR_SVC"
    removed=$((removed + 1))
fi

if [[ "$removed" -gt 0 ]] && [[ "$DRY_RUN" != "1" ]] && command -v systemctl >/dev/null; then
    run "systemctl daemon-reload" -- systemctl daemon-reload || true
fi

emit_status "ok" "mta-loopback-detect removed=$removed"
