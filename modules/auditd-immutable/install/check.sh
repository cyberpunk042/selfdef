#!/usr/bin/env bash
# auditd-immutable — check. Read-only.

set -euo pipefail

MODULE="auditd-immutable"
DRY_RUN=0
CONFIG_FILE="${SELFDEF_AUDITD_IMMUTABLE_CONFIG:-/etc/selfdef/modules/auditd-immutable.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
RULES_D="${SELFDEF_AUDIT_RULES_D:-/etc/audit/rules.d}"
DST="${RULES_D}/99-selfdef-immutable.rules"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"
PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "audit")

drift=0
[[ -f "$DST" ]] || { emit_status "drift" "rule file missing: $DST"; drift=$((drift + 1)); }

if command -v auditctl >/dev/null 2>&1; then
    live_e=$(auditctl -s 2>/dev/null | awk -F': *' '/^enabled/ {print $2; exit}' || echo "?")
    expected="1"
    [[ "$PROFILE" == "enforce" ]] && expected="2"

    if [[ "$live_e" == "?" ]]; then
        log "auditctl -s did not report enabled state (auditd may be inactive)"
    elif [[ "$live_e" != "$expected" ]]; then
        # enforce-pending: file is installed but kernel state hasn't been
        # locked yet. Reboot needed.
        if [[ "$PROFILE" == "enforce" ]] && [[ "$live_e" == "1" ]]; then
            log "PENDING: file installed with -e 2 but live state still -e 1; rules.d load not yet triggered OR augenrules --load skipped — reboot to apply"
        else
            emit_status "drift" "live audit enabled=$live_e (want $expected)"
            drift=$((drift + 1))
        fi
    fi
fi

if [[ "$drift" -gt 0 ]]; then
    emit_status "drift" "auditd-immutable profile=$PROFILE drift=$drift"
    exit 1
fi
emit_status "ok" "auditd-immutable profile=$PROFILE no drift"
