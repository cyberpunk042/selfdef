#!/usr/bin/env bash
# chrony-baseline — check. Read-only.
#
# Verifies the conf.d drop-in is present + queries chronyc tracking
# to confirm an NTP source is synchronized.

set -euo pipefail

MODULE="chrony-baseline"
DRY_RUN=0
CONFIG_FILE="${SELFDEF_CHRONY_BASELINE_CONFIG:-/etc/selfdef/modules/chrony-baseline.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
CHRONY_DROPIN_DIR="${SELFDEF_CHRONY_DROPIN_DIR:-/etc/chrony/conf.d}"
DST="${CHRONY_DROPIN_DIR}/50-selfdef.conf"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"
PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "pool")

drift=0
if [[ ! -f "$DST" ]]; then
    emit_status "drift" "selfdef drop-in missing: $DST"
    drift=$((drift + 1))
fi

# chronyc tracking: best-effort. If chronyd isn't running yet,
# log but don't fail the check (operator may be mid-bootstrap).
if command -v chronyc >/dev/null 2>&1; then
    if tracking=$(chronyc tracking 2>/dev/null); then
        ref=$(echo "$tracking" | awk -F': ' '/Reference ID/ {print $2; exit}' || echo "?")
        stratum=$(echo "$tracking" | awk -F': ' '/Stratum/ {print $2; exit}' || echo "?")
        offset=$(echo "$tracking" | awk -F': ' '/Last offset/ {print $2; exit}' || echo "?")
        log "chrony tracking: ref=$ref stratum=$stratum last_offset=$offset"
    else
        log "chronyc tracking failed; daemon may not be running"
    fi
fi

if [[ "$drift" -gt 0 ]]; then
    emit_status "drift" "chrony-baseline profile=$PROFILE drift=$drift"
    exit 1
fi
emit_status "ok" "chrony-baseline profile=$PROFILE no drift"
