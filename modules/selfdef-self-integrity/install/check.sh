#!/usr/bin/env bash
# selfdef-self-integrity — check. Read-only.

set -euo pipefail

MODULE="selfdef-self-integrity"
DRY_RUN=0
CONFIG_FILE="${SELFDEF_SELFINT_CONFIG:-/etc/selfdef/modules/selfdef-self-integrity.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
LIBEXEC_DIR="${SELFDEF_LIBEXEC_DIR:-/usr/local/libexec/selfdef}"
SYSTEMD_DIR="${SELFDEF_SYSTEMD_DIR:-/etc/systemd/system}"
MANIFEST="${SELFDEF_SELFINT_MANIFEST:-/var/lib/selfdef/self-integrity-manifest.tsv}"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"
PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "report")

drift=0
[[ -x "${LIBEXEC_DIR}/selfdef-self-integrity.sh" ]]      || { emit_status "drift" "wrapper script missing/not exec"; drift=$((drift + 1)); }
[[ -f "${SYSTEMD_DIR}/selfdef-self-integrity.service" ]] || { emit_status "drift" "service unit missing"; drift=$((drift + 1)); }
[[ -f "${SYSTEMD_DIR}/selfdef-self-integrity.timer" ]]   || { emit_status "drift" "timer unit missing"; drift=$((drift + 1)); }

if command -v systemctl >/dev/null 2>&1; then
    if ! systemctl is-active --quiet selfdef-self-integrity.timer; then
        log "selfdef-self-integrity.timer NOT active"
    fi
fi

if [[ -f "$MANIFEST" ]]; then
    log "manifest present: $MANIFEST ($(wc -l < "$MANIFEST" | tr -d ' ') trust-root artifacts)"
    mode=$(stat -c '%a' "$MANIFEST" 2>/dev/null || echo "?")
    [[ "$mode" != "600" ]] && { emit_status "drift" "manifest mode $mode; expected 600"; drift=$((drift + 1)); }
else
    log "no manifest yet (first scan builds it)"
fi

if command -v journalctl >/dev/null 2>&1; then
    last=$(journalctl -t selfdef-self-integrity -n 1 --no-pager -o cat 2>/dev/null || echo "")
    [[ -n "$last" ]] && log "last scan event: $last"
fi

if [[ "$drift" -gt 0 ]]; then
    emit_status "drift" "selfdef-self-integrity profile=$PROFILE drift=$drift"
    exit 1
fi
emit_status "ok" "selfdef-self-integrity profile=$PROFILE no drift"
