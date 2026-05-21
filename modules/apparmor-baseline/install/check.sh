#!/usr/bin/env bash
# apparmor-baseline — check. Read-only.
#
# Verifies the curated list is present + aa-status reports the
# expected mode counts (enforce vs complain) for our profiles.

set -euo pipefail

MODULE="apparmor-baseline"
DRY_RUN=0
CONFIG_FILE="${SELFDEF_AA_BASELINE_CONFIG:-/etc/selfdef/modules/apparmor-baseline.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"
PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "complain")

drift=0
[[ -f "$SELFDEF_AA_LIST" ]] || { emit_status "drift" "curated list missing: $SELFDEF_AA_LIST"; drift=$((drift + 1)); }

# AppArmor live state.
if [[ ! -d /sys/kernel/security/apparmor ]]; then
    emit_status "drift" "AppArmor LSM not enabled in running kernel"
    drift=$((drift + 1))
fi

if command -v aa-status >/dev/null 2>&1; then
    # aa-status reports loaded profile counts + per-profile modes.
    enforce_count=$(aa-status --enforced 2>/dev/null | wc -l || echo 0)
    complain_count=$(aa-status --complaining 2>/dev/null | wc -l || echo 0)
    log "apparmor live: enforced=$enforce_count complain=$complain_count"

    # Count how many of OUR profiles are in the expected mode.
    expected_mode_count=0
    if [[ -f "$SELFDEF_AA_LIST" ]]; then
        while IFS= read -r line; do
            profile_name="${line%%#*}"
            profile_name="$(echo "$profile_name" | tr -d ' \t')"
            [[ -z "$profile_name" ]] && continue

            if [[ "$PROFILE" == "enforce" ]]; then
                aa-status --enforced 2>/dev/null | grep -qFx "$profile_name" && \
                    expected_mode_count=$((expected_mode_count + 1))
            else
                aa-status --complaining 2>/dev/null | grep -qFx "$profile_name" && \
                    expected_mode_count=$((expected_mode_count + 1))
            fi
        done < "$SELFDEF_AA_LIST"
    fi
    log "selfdef-curated profiles in target mode ($PROFILE): $expected_mode_count"

    # Check service.
    if command -v systemctl >/dev/null 2>&1; then
        if ! systemctl is-active --quiet apparmor; then
            emit_status "drift" "apparmor.service NOT active"
            drift=$((drift + 1))
        fi
    fi
fi

if [[ "$drift" -gt 0 ]]; then
    emit_status "drift" "apparmor-baseline profile=$PROFILE drift=$drift"
    exit 1
fi
emit_status "ok" "apparmor-baseline profile=$PROFILE no drift"
