#!/usr/bin/env bash
# apport-disable — apply.

set -euo pipefail

MODULE="apport-disable"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
CONFIG_FILE="${SELFDEF_APPORT_CONFIG:-/etc/selfdef/modules/apport-disable.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"

PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "mask")
case "$PROFILE" in
    mask|stop) ;;
    *) die "profile must be mask|stop, got '$PROFILE'" ;;
esac

if ! command -v systemctl >/dev/null 2>&1; then
    die "systemctl unavailable"
fi

acted=0
skipped=0
for unit in "${APPORT_UNITS[@]}"; do
    if ! systemctl list-unit-files "$unit" >/dev/null 2>&1; then
        skipped=$((skipped + 1))
        continue
    fi
    if [[ "$DRY_RUN" == "1" ]]; then
        log "DRY_RUN: would stop + disable $unit"
        [[ "$PROFILE" == "mask" ]] && log "DRY_RUN: would mask $unit"
        acted=$((acted + 1))
        continue
    fi
    run "stop $unit"    -- systemctl stop "$unit"    2>/dev/null || true
    run "disable $unit" -- systemctl disable "$unit" 2>/dev/null || true
    if [[ "$PROFILE" == "mask" ]]; then
        run "mask $unit" -- systemctl mask "$unit" 2>/dev/null || true
    fi
    acted=$((acted + 1))
done

# Reset core_pattern if it currently pipes to apport. Without
# this, the kernel still invokes the (now-masked-service)
# apport binary as the core-dump handler on every crash.
# Source override (SELFDEF_APPORT_COREPAT_SOURCE) enables L2 tests +
# operator dry-verify against a captured fixture file. Live default
# unchanged.
COREPAT_SOURCE="${SELFDEF_APPORT_COREPAT_SOURCE:-/proc/sys/kernel/core_pattern}"
if [[ -r "$COREPAT_SOURCE" ]]; then
    cp_now=$(cat "$COREPAT_SOURCE" 2>/dev/null || echo "")
    if [[ "$cp_now" == *apport* ]]; then
        if [[ "$DRY_RUN" == "1" ]]; then
            log "DRY_RUN: would reset core_pattern (currently pipes to apport: $cp_now)"
        else
            # 'core' is the kernel default (dump to cwd/core).
            if sysctl -w "kernel.core_pattern=core" >/dev/null 2>&1; then
                log "reset kernel.core_pattern from apport-pipe to 'core'"
            else
                log "WARN: failed to reset core_pattern (was: $cp_now)"
            fi
        fi
    fi
fi

if [[ "$acted" -eq 0 ]]; then
    log "apport not installed on this host (non-Ubuntu?) — no-op"
    emit_status "ok" "apport-disable no-op (apport not present)"
    exit 0
fi

emit_status "ok" "apport-disable profile=$PROFILE acted=$acted skipped=$skipped"
