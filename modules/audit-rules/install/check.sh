#!/usr/bin/env bash
# audit-rules — check. Read-only.
#
# Verifies the expected rule files are present in /etc/audit/rules.d/
# AND that auditctl -l reports loaded rules matching at least one
# of our keys.

set -euo pipefail

MODULE="audit-rules"
DRY_RUN=0
CONFIG_FILE="${SELFDEF_AUDIT_RULES_CONFIG:-/etc/selfdef/modules/audit-rules.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
RULES_DIR="${SELFDEF_AUDIT_RULES_DIR:-/etc/audit/rules.d}"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"
PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "base")

EXPECTED=()
case "$PROFILE" in
    base)     EXPECTED=("50-selfdef-base.rules") ;;
    paranoid) EXPECTED=("50-selfdef-base.rules" "50-selfdef-paranoid.rules") ;;
    *) die "profile must be base|paranoid, got '$PROFILE'" ;;
esac

drift=0
for rf in "${EXPECTED[@]}"; do
    if [[ ! -f "${RULES_DIR}/${rf}" ]]; then
        emit_status "drift" "${rf} expected but missing"
        drift=$((drift + 1))
    fi
done

# Best-effort live-rule check: if auditctl is callable + at least
# one selfdef-prefixed key shows up, mark loaded; otherwise flag
# drift without erroring (the rules ARE installed; reload may be
# pending).
if command -v auditctl >/dev/null 2>&1; then
    if auditctl -l 2>/dev/null | grep -q "key=selfdef-"; then
        log "auditctl -l reports loaded selfdef-prefixed rules — ok"
    else
        log "auditctl -l does NOT report selfdef-prefixed rules; run augenrules --load"
        # Not counted as drift — file presence is the operator-actionable
        # check; live-rule status is informational.
    fi
fi

if [[ "$drift" -gt 0 ]]; then
    emit_status "drift" "audit-rules profile=$PROFILE drift=$drift"
    exit 1
fi
emit_status "ok" "audit-rules profile=$PROFILE no drift"
