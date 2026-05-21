#!/usr/bin/env bash
# kernel-lockdown — apply.
#
# Installs sysctl drop-ins at /etc/sysctl.d/ + runs
# `sysctl --system` (or per-file `sysctl -p`) to apply the new
# baseline live.
#
# `strict` profile gates kernel.modules_disabled=1 behind an
# explicit operator-acknowledgment flag — refuse-to-brick guard.
# Same pattern as usbguard's baseline check.
#
# Idempotent: re-running with the same profile writes byte-
# identical drop-ins. SELFDEF_DRY_RUN=1 aware.

set -euo pipefail

MODULE="kernel-lockdown"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
CONFIG_FILE="${SELFDEF_KERNEL_LOCKDOWN_CONFIG:-/etc/selfdef/modules/kernel-lockdown.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
MODULE_DIR="$(dirname "$LIB_DIR")"
SYSCTL_SRC="${SELFDEF_KERNEL_LOCKDOWN_SYSCTL:-${MODULE_DIR}/sysctl}"
SYSCTL_DIR="${SELFDEF_SYSCTL_DIR:-/etc/sysctl.d}"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"
[[ -d "$SYSCTL_SRC" ]] || die "sysctl source dir missing: $SYSCTL_SRC"

PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "balanced")
case "$PROFILE" in
    balanced|strict) ;;
    *) die "profile must be balanced|strict, got '$PROFILE'" ;;
esac

ACK_MODULES_DISABLED=$(toml_get acknowledge_modules_disabled "$CONFIG_FILE" || echo "false")
if [[ "$PROFILE" == "strict" && "$ACK_MODULES_DISABLED" != "true" ]]; then
    die "strict profile sets kernel.modules_disabled=1 (IRREVERSIBLE until reboot); \
set acknowledge_modules_disabled = true in $CONFIG_FILE to apply"
fi

# Always install the balanced drop-in.
DST_BAL="${SYSCTL_DIR}/50-selfdef-kernel-lockdown.conf"
DST_STR="${SYSCTL_DIR}/50-selfdef-kernel-lockdown-strict.conf"

mkdir -p "$SYSCTL_DIR"

changes=0
src_bal="${SYSCTL_SRC}/balanced.conf"
if [[ -f "$DST_BAL" ]] && cmp -s "$src_bal" "$DST_BAL"; then
    :
else
    if [[ "$DRY_RUN" == "1" ]]; then
        log "DRY_RUN: would install $DST_BAL"
    else
        install -m 0644 "$src_bal" "$DST_BAL"
    fi
    changes=$((changes + 1))
fi

if [[ "$PROFILE" == "strict" ]]; then
    src_str="${SYSCTL_SRC}/strict.conf"
    if [[ -f "$DST_STR" ]] && cmp -s "$src_str" "$DST_STR"; then
        :
    else
        if [[ "$DRY_RUN" == "1" ]]; then
            log "DRY_RUN: would install $DST_STR"
        else
            install -m 0644 "$src_str" "$DST_STR"
        fi
        changes=$((changes + 1))
    fi
else
    # Downgrade: profile flipped from strict → balanced. Remove the
    # strict drop-in. (kernel.modules_disabled survives in-kernel
    # until reboot, but new boots will be balanced.)
    if [[ -f "$DST_STR" ]]; then
        run "remove strict drop-in (profile downgrade)" -- rm -f "$DST_STR"
        changes=$((changes + 1))
    fi
fi

# Apply live if anything changed.
if [[ "$changes" -gt 0 ]] && [[ "$DRY_RUN" != "1" ]]; then
    if [[ "$PROFILE" == "strict" ]]; then
        run "sysctl --system (load all drop-ins)" -- sysctl --system || true
    else
        # Apply only the balanced drop-in for a profile downgrade,
        # otherwise --system to be safe.
        run "sysctl --system (load all drop-ins)" -- sysctl --system || true
    fi
fi

emit_status "ok" "kernel-lockdown profile=$PROFILE changes=$changes"
