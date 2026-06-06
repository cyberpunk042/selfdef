#!/usr/bin/env bash
# apparmor-baseline — apply.
#
# 1. Verifies the AppArmor LSM is enabled in the running kernel
#    (`/sys/kernel/security/apparmor` exists).
# 2. Verifies apparmor.service is active (or starts it).
# 3. Installs /etc/selfdef/apparmor/selfdef-curated-profiles.list
#    if not present (operator-tunable).
# 4. For each entry in the curated list that maps to an INSTALLED
#    AppArmor profile, runs `aa-{enforce,complain} <profile>` per
#    profile selection.
#
# Profiles that aren't installed are SKIPPED with a log line —
# operator can install the apparmor-profiles + apparmor-profiles-
# extra packages to get more coverage.

set -euo pipefail

MODULE="apparmor-baseline"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
CONFIG_FILE="${SELFDEF_AA_BASELINE_CONFIG:-/etc/selfdef/modules/apparmor-baseline.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
MODULE_DIR="$(dirname "$LIB_DIR")"
# Source override: operator-test affordance + L2 testability.
CONFIGS_SRC="${SELFDEF_AA_CONFIGS_SRC:-${MODULE_DIR}/configs}"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"

PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "complain")
case "$PROFILE" in
    complain|enforce) ;;
    *) die "profile must be complain|enforce, got '$PROFILE'" ;;
esac

# Verify AppArmor is enabled in the running kernel. The sysfs check
# location can be overridden via SELFDEF_AA_SYSFS_DIR (operator-test
# affordance + L2 testability) so a captured snapshot or fixture can
# be fed in; live default is /sys/kernel/security/apparmor.
AA_SYSFS_DIR="${SELFDEF_AA_SYSFS_DIR:-/sys/kernel/security/apparmor}"
if [[ ! -d "$AA_SYSFS_DIR" ]]; then
    die "AppArmor LSM not enabled in running kernel — boot with apparmor=1 OR install + reboot with the apparmor package"
fi

# Service active.
if command -v systemctl >/dev/null 2>&1 && [[ "$DRY_RUN" != "1" ]]; then
    if ! systemctl is-active --quiet apparmor; then
        run "start apparmor.service" -- systemctl start apparmor || true
    fi
fi

# Install the curated list (operator-editable).
mkdir -p "$(dirname "$SELFDEF_AA_LIST")"
if [[ ! -f "$SELFDEF_AA_LIST" ]] || ! cmp -s "${CONFIGS_SRC}/selfdef-curated-profiles.list" "$SELFDEF_AA_LIST"; then
    if [[ "$DRY_RUN" == "1" ]]; then
        log "DRY_RUN: would install $SELFDEF_AA_LIST"
    else
        install -m 0644 "${CONFIGS_SRC}/selfdef-curated-profiles.list" "$SELFDEF_AA_LIST"
    fi
fi

# Walk the list + flip mode per profile.
AA_TOOL="aa-complain"
[[ "$PROFILE" == "enforce" ]] && AA_TOOL="aa-enforce"

installed_count=0
skipped_count=0
flipped=0
while IFS= read -r line; do
    # Strip comments + whitespace.
    profile_name="${line%%#*}"
    profile_name="$(echo "$profile_name" | tr -d ' \t')"
    [[ -z "$profile_name" ]] && continue

    # Check if profile is loaded.
    if ! aa-status --profiled 2>/dev/null | grep -qFx "$profile_name"; then
        # Also accept slash-prefixed path forms (some profiles are
        # registered by full path).
        if ! aa-status 2>/dev/null | grep -qF "$profile_name"; then
            log "skip $profile_name (not loaded; install the relevant apparmor-profiles-* package)"
            skipped_count=$((skipped_count + 1))
            continue
        fi
    fi
    installed_count=$((installed_count + 1))

    if [[ "$DRY_RUN" == "1" ]]; then
        log "DRY_RUN: would $AA_TOOL $profile_name"
        flipped=$((flipped + 1))
        continue
    fi

    if "$AA_TOOL" "$profile_name" >/dev/null 2>&1; then
        flipped=$((flipped + 1))
    else
        log "WARN: $AA_TOOL $profile_name failed"
    fi
done < "$SELFDEF_AA_LIST"

emit_status "ok" "apparmor-baseline profile=$PROFILE installed=$installed_count flipped=$flipped skipped=$skipped_count"
