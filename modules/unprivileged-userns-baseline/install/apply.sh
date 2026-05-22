#!/usr/bin/env bash
# unprivileged-userns-baseline — apply.

set -euo pipefail

MODULE="unprivileged-userns-baseline"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
CONFIG_FILE="${SELFDEF_USERNS_CONFIG:-/etc/selfdef/modules/unprivileged-userns-baseline.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"

PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "allow")
case "$PROFILE" in
    allow|deny) ;;
    *) die "profile must be allow|deny, got '$PROFILE'" ;;
esac

# Refuse-to-brick gate: deny BREAKS rootless containers +
# bubblewrap-based sandboxing. Require explicit acknowledge.
if [[ "$PROFILE" == "deny" ]]; then
    ack=$(toml_get acknowledge_no_rootless "$CONFIG_FILE" 2>/dev/null || echo "false")
    if [[ "$ack" != "true" ]]; then
        die "deny profile breaks rootless podman/docker + bubblewrap + Flatpak. Add 'acknowledge_no_rootless = true' to $CONFIG_FILE to confirm."
    fi
fi

SRC="${LIB_DIR}/../configs/${PROFILE}.conf"
[[ -r "$SRC" ]] || die "missing config source: $SRC"

if ! command -v sysctl >/dev/null 2>&1; then
    die "sysctl unavailable"
fi

if [[ "$DRY_RUN" == "1" ]]; then
    log "DRY_RUN: would render $SYSCTL_DROPIN from $SRC"
    emit_status "ok" "unprivileged-userns-baseline DRY_RUN profile=$PROFILE"
    exit 0
fi

tmp="$(mktemp "${SYSCTL_DROPIN}.XXXXXX")"
{
    echo "$HEADER_MARKER"
    echo "# Generated $(date -u '+%Y-%m-%dT%H:%M:%SZ') — profile=$PROFILE"
    cat "$SRC"
} > "$tmp"
chmod 0644 "$tmp"
mv -f "$tmp" "$SYSCTL_DROPIN"
log "wrote $SYSCTL_DROPIN"

WANT=$([ "$PROFILE" == "deny" ] && echo 0 || echo 1)
if sysctl -w "kernel.unprivileged_userns_clone=$WANT" >/dev/null 2>&1; then
    log "live: kernel.unprivileged_userns_clone=$WANT"
else
    log "live sysctl set failed (kernel may lack the sysctl on non-Debian-derived distros)"
fi

emit_status "ok" "unprivileged-userns-baseline profile=$PROFILE (live=$(sysctl -n kernel.unprivileged_userns_clone 2>/dev/null || echo unknown))"
