#!/usr/bin/env bash
# kernel-yama-baseline — apply.

set -euo pipefail

MODULE="kernel-yama-baseline"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
CONFIG_FILE="${SELFDEF_YAMA_CONFIG:-/etc/selfdef/modules/kernel-yama-baseline.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"

PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "relaxed")
case "$PROFILE" in
    relaxed|strict|paranoid) ;;
    *) die "profile must be relaxed|strict|paranoid, got '$PROFILE'" ;;
esac

WANT=$(profile_to_value "$PROFILE")
[[ "$WANT" == "?" ]] && die "internal: profile_to_value bug for '$PROFILE'"

if ! command -v sysctl >/dev/null 2>&1; then
    die "sysctl unavailable"
fi

# Refuse-to-brick gate: paranoid (=3) is irreversible without
# reboot. Require explicit acknowledge_paranoid=true in the
# config file before applying.
if [[ "$PROFILE" == "paranoid" ]]; then
    ack=$(toml_get acknowledge_paranoid "$CONFIG_FILE" 2>/dev/null || echo "false")
    if [[ "$ack" != "true" ]]; then
        die "paranoid profile is IRREVERSIBLE until reboot. Add 'acknowledge_paranoid = true' to $CONFIG_FILE to confirm."
    fi
fi

# Check live state to avoid setting a lower value when current
# is already 3 (refused-by-kernel: returns EINVAL → would be a
# no-op but log as failure). Safe-degrade: if live=3, log +
# exit ok (drop-in still placed for post-reboot effect).
LIVE=$(sysctl -n kernel.yama.ptrace_scope 2>/dev/null || echo "-1")
if [[ "$LIVE" == "3" && "$WANT" != "3" ]]; then
    log "WARN: live ptrace_scope=3 (paranoid, locked until reboot). Drop-in for profile=$PROFILE will take effect after reboot only."
fi

SRC="${LIB_DIR}/../configs/${PROFILE}.conf"
[[ -r "$SRC" ]] || die "missing config source: $SRC"

if [[ "$DRY_RUN" == "1" ]]; then
    log "DRY_RUN: would render $SYSCTL_DROPIN with kernel.yama.ptrace_scope=$WANT"
    emit_status "ok" "kernel-yama-baseline DRY_RUN profile=$PROFILE"
    exit 0
fi

tmp="$(mktemp "${SYSCTL_DROPIN}.XXXXXX")"
{
    echo "$HEADER_MARKER"
    echo "# Generated $(date -u '+%Y-%m-%dT%H:%M:%SZ') — profile=$PROFILE (ptrace_scope=$WANT)"
    cat "$SRC"
} > "$tmp"
chmod 0644 "$tmp"
mv -f "$tmp" "$SYSCTL_DROPIN"
log "wrote $SYSCTL_DROPIN"

# Apply live (subject to the EINVAL-if-live=3 caveat above).
if sysctl -w "kernel.yama.ptrace_scope=$WANT" >/dev/null 2>&1; then
    log "live: kernel.yama.ptrace_scope set to $WANT"
else
    log "live sysctl set failed (likely yama LSM disabled OR live value already at $LIVE and not decreasable)"
fi

emit_status "ok" "kernel-yama-baseline profile=$PROFILE value=$WANT (live=$(sysctl -n kernel.yama.ptrace_scope 2>/dev/null || echo unknown))"
