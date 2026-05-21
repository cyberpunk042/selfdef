#!/usr/bin/env bash
# auditd-tune — check. Read-only.

set -euo pipefail

MODULE="auditd-tune"
DRY_RUN=0
CONFIG_FILE="${SELFDEF_AUDITD_TUNE_CONFIG:-/etc/selfdef/modules/auditd-tune.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"
PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "standard")
BACKLOG_LIMIT=$(toml_get backlog_limit "$CONFIG_FILE" || echo "8192")

drift=0
if [[ ! -f "$AUDITD_CONF" ]]; then
    emit_status "drift" "auditd.conf missing: $AUDITD_CONF"
    drift=$((drift + 1))
elif ! head -1 "$AUDITD_CONF" | grep -qF "$AUDITD_MARKER"; then
    emit_status "drift" "auditd.conf present but not selfdef-managed (no header marker)"
    drift=$((drift + 1))
fi

# Check kernel backlog limit live.
if command -v auditctl >/dev/null 2>&1; then
    live=$(auditctl -s 2>/dev/null | awk '/backlog_limit/ {print $2; exit}' || echo "")
    if [[ -n "$live" ]] && [[ "$live" -lt "$BACKLOG_LIMIT" ]]; then
        emit_status "drift" "kernel.audit_backlog_limit = $live (want >= $BACKLOG_LIMIT)"
        drift=$((drift + 1))
    fi
    # Lost-record warning is the biggest operational risk; surface
    # it as a log line (not a drift) so the operator's notifier
    # sees it via the journal.
    lost=$(auditctl -s 2>/dev/null | awk '/lost/ {print $2; exit}' || echo "0")
    if [[ -n "$lost" ]] && [[ "$lost" -gt 0 ]]; then
        log "auditctl reports $lost lost records — increase backlog_limit or downgrade audit-rules profile"
    fi
fi

if command -v systemctl >/dev/null 2>&1; then
    if ! systemctl is-active --quiet auditd; then
        log "auditd.service NOT active"
    fi
fi

if [[ "$drift" -gt 0 ]]; then
    emit_status "drift" "auditd-tune profile=$PROFILE drift=$drift"
    exit 1
fi
emit_status "ok" "auditd-tune profile=$PROFILE no drift"
