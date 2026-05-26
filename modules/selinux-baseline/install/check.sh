#!/usr/bin/env bash
# selinux-baseline — check. Read-only.

set -euo pipefail

MODULE="selinux-baseline"
DRY_RUN=0
CONFIG_FILE="${SELFDEF_SELINUX_CONFIG:-/etc/selfdef/modules/selinux-baseline.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"
PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "audit")

LIVE=$(selinux_live_mode)
CFG=$(selinux_config_mode)
DENIALS=$(selinux_recent_denials)

if [[ "$LIVE" == "unavailable" ]]; then
    emit_status "ok" "selinux-baseline (SELinux unavailable on this host)"
    exit 0
fi

log "SELinux live=$LIVE config=$CFG recent_denials=$DENIALS profile=$PROFILE"

drift=0
case "$PROFILE" in
    audit)
        : # report-only; never drifts
        ;;
    permissive)
        if [[ "$LIVE" == "Enforcing" ]]; then
            emit_status "drift" "live=Enforcing but profile=permissive"
            drift=$((drift + 1))
        fi
        if [[ "$CFG" != "permissive" ]]; then
            emit_status "drift" "config SELINUX=$CFG, profile=permissive expects permissive"
            drift=$((drift + 1))
        fi
        ;;
    enforcing)
        if [[ "$LIVE" != "Enforcing" ]]; then
            emit_status "drift" "live=$LIVE, profile=enforcing expects Enforcing (reboot pending if relabel scheduled)"
            drift=$((drift + 1))
        fi
        if [[ "$CFG" != "enforcing" ]]; then
            emit_status "drift" "config SELINUX=$CFG, profile=enforcing expects enforcing"
            drift=$((drift + 1))
        fi
        ;;
esac

if [[ "$drift" -gt 0 ]]; then
    emit_status "drift" "selinux-baseline profile=$PROFILE drift=$drift"
    exit 1
fi
emit_status "ok" "selinux-baseline profile=$PROFILE live=$LIVE no drift"
