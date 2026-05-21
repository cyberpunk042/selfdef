#!/usr/bin/env bash
# unowned-files-watchdog — uninstall.

set -euo pipefail

MODULE="unowned-files-watchdog"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
LIBEXEC_DIR="${SELFDEF_LIBEXEC_DIR:-/usr/local/libexec/selfdef}"
SYSTEMD_DIR="${SELFDEF_SYSTEMD_DIR:-/etc/systemd/system}"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

if command -v systemctl >/dev/null 2>&1 && [[ "$DRY_RUN" != "1" ]]; then
    run "disable + stop timer" -- systemctl disable --now selfdef-unowned-files.timer || true
    systemctl reset-failed selfdef-unowned-files.service 2>/dev/null || true
fi

removed=0
for f in "${SYSTEMD_DIR}/selfdef-unowned-files.service" \
         "${SYSTEMD_DIR}/selfdef-unowned-files.timer" \
         "${LIBEXEC_DIR}/unowned-files-watchdog.sh"; do
    if [[ -f "$f" ]]; then
        run "remove $(basename "$f")" -- rm -f "$f"
        removed=$((removed + 1))
    fi
done

DROPIN_DIR_SVC="${SYSTEMD_DIR}/selfdef-unowned-files.service.d"
if [[ -d "$DROPIN_DIR_SVC" ]]; then
    run "rm -r ${DROPIN_DIR_SVC}" -- rm -rf "$DROPIN_DIR_SVC"
    removed=$((removed + 1))
fi

if [[ "$removed" -gt 0 ]] && [[ "$DRY_RUN" != "1" ]] && command -v systemctl >/dev/null; then
    run "systemctl daemon-reload" -- systemctl daemon-reload || true
fi

emit_status "ok" "unowned-files-watchdog removed=$removed"
