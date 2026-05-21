#!/usr/bin/env bash
# suid-sgid-watchdog — uninstall.

set -euo pipefail

MODULE="suid-sgid-watchdog"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
LIBEXEC_DIR="${SELFDEF_LIBEXEC_DIR:-/usr/local/libexec/selfdef}"
SYSTEMD_DIR="${SELFDEF_SYSTEMD_DIR:-/etc/systemd/system}"
BASELINE="${SELFDEF_SUIDSGID_BASELINE:-/var/lib/selfdef/suid-sgid-baseline.tsv}"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

if command -v systemctl >/dev/null 2>&1 && [[ "$DRY_RUN" != "1" ]]; then
    run "disable + stop timer" -- systemctl disable --now selfdef-suid-sgid.timer || true
    systemctl reset-failed selfdef-suid-sgid.service 2>/dev/null || true
fi

removed=0
for f in "${SYSTEMD_DIR}/selfdef-suid-sgid.service" \
         "${SYSTEMD_DIR}/selfdef-suid-sgid.timer" \
         "${LIBEXEC_DIR}/suid-sgid-watchdog.sh"; do
    if [[ -f "$f" ]]; then
        run "remove $(basename "$f")" -- rm -f "$f"
        removed=$((removed + 1))
    fi
done

DROPIN_DIR_SVC="${SYSTEMD_DIR}/selfdef-suid-sgid.service.d"
if [[ -d "$DROPIN_DIR_SVC" ]]; then
    run "rm -r ${DROPIN_DIR_SVC}" -- rm -rf "$DROPIN_DIR_SVC"
    removed=$((removed + 1))
fi

# Baseline is operator-state. Preserve by default; operator
# removes manually if desired (it's forensic evidence + may
# be useful for re-install).
if [[ -f "$BASELINE" ]]; then
    log "preserving operator baseline: $BASELINE (remove manually if desired)"
fi

if [[ "$removed" -gt 0 ]] && [[ "$DRY_RUN" != "1" ]] && command -v systemctl >/dev/null; then
    run "systemctl daemon-reload" -- systemctl daemon-reload || true
fi

emit_status "ok" "suid-sgid-watchdog removed=$removed (baseline preserved)"
