#!/usr/bin/env bash
# autofs-watchdog — uninstall.

set -euo pipefail

MODULE="autofs-watchdog"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
LIBEXEC_DIR="${SELFDEF_LIBEXEC_DIR:-/usr/local/libexec/selfdef}"
SYSTEMD_DIR="${SELFDEF_SYSTEMD_DIR:-/etc/systemd/system}"
BASELINE="${SELFDEF_AUTOFS_BASELINE:-/var/lib/selfdef/autofs-baseline.tsv}"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

if command -v systemctl >/dev/null 2>&1 && [[ "$DRY_RUN" != "1" ]]; then
    run "disable + stop timer" -- systemctl disable --now selfdef-autofs.timer || true
    systemctl reset-failed selfdef-autofs.service 2>/dev/null || true
fi

removed=0
for f in "${SYSTEMD_DIR}/selfdef-autofs.service" \
         "${SYSTEMD_DIR}/selfdef-autofs.timer" \
         "${LIBEXEC_DIR}/autofs-watchdog.sh"; do
    if [[ -f "$f" ]]; then
        run "remove $(basename "$f")" -- rm -f "$f"
        removed=$((removed + 1))
    fi
done

DROPIN_DIR_SVC="${SYSTEMD_DIR}/selfdef-autofs.service.d"
if [[ -d "$DROPIN_DIR_SVC" ]]; then
    run "rm -r ${DROPIN_DIR_SVC}" -- rm -rf "$DROPIN_DIR_SVC"
    removed=$((removed + 1))
fi

if [[ -f "$BASELINE" ]]; then
    log "preserving operator baseline: $BASELINE (remove manually if desired)"
fi

if [[ "$removed" -gt 0 ]] && [[ "$DRY_RUN" != "1" ]] && command -v systemctl >/dev/null; then
    run "systemctl daemon-reload" -- systemctl daemon-reload || true
fi

emit_status "ok" "autofs-watchdog removed=$removed (baseline preserved)"
