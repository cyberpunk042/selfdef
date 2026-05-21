#!/usr/bin/env bash
# sysctl-network-baseline — apply.

set -euo pipefail

MODULE="sysctl-network-baseline"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
CONFIG_FILE="${SELFDEF_SYSCTL_NETWORK_CONFIG:-/etc/selfdef/modules/sysctl-network-baseline.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"

PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "baseline")
case "$PROFILE" in
    baseline|router|paranoid) ;;
    *) die "profile must be baseline|router|paranoid, got '$PROFILE'" ;;
esac

SRC="${LIB_DIR}/../configs/${PROFILE}.conf"
[[ -r "$SRC" ]] || die "missing config source: $SRC"

if ! command -v sysctl >/dev/null 2>&1; then
    die "sysctl unavailable"
fi

# Render with header marker.
if [[ "$DRY_RUN" == "1" ]]; then
    log "DRY_RUN: would render $SYSCTL_DROPIN from $SRC"
    log "DRY_RUN: would sysctl --load=$SYSCTL_DROPIN"
    emit_status "ok" "sysctl-network-baseline DRY_RUN profile=$PROFILE"
    exit 0
fi

tmp="$(mktemp "${SYSCTL_DROPIN}.XXXXXX")"
{
    echo "$HEADER_MARKER"
    echo "# Generated $(date -u '+%Y-%m-%dT%H:%M:%SZ') — profile=$PROFILE"
    echo "# Do not hand-edit. Source: modules/sysctl-network-baseline/configs/${PROFILE}.conf"
    echo
    cat "$SRC"
} > "$tmp"
chmod 0644 "$tmp"
mv -f "$tmp" "$SYSCTL_DROPIN"
log "wrote $SYSCTL_DROPIN"

# Apply live (and capture any per-key failure — common when running
# inside a container that lacks the relevant net.* namespace).
applied=0
soft_fails=0
while IFS='=' read -r key val; do
    key="${key%% *}"; key="${key## *}"
    val="${val## *}"; val="${val%% *}"
    [[ -z "$key" || "${key:0:1}" == "#" ]] && continue
    if sysctl -w "${key}=${val}" >/dev/null 2>&1; then
        applied=$((applied + 1))
    else
        soft_fails=$((soft_fails + 1))
        log "WARN: sysctl set failed ${key}=${val} (likely container/namespace-restricted)"
    fi
done < <(grep -v '^[[:space:]]*\(#\|$\)' "$SYSCTL_DROPIN" | sed 's/[[:space:]]*=[[:space:]]*/=/')

# Final consolidated reload via sysctl --load for any drop-in
# interactions (--system would re-load all of /etc/sysctl.d).
if sysctl --load="$SYSCTL_DROPIN" >/dev/null 2>&1; then
    log "sysctl --load=$SYSCTL_DROPIN succeeded"
fi

emit_status "ok" "sysctl-network-baseline profile=$PROFILE applied=$applied soft_fails=$soft_fails"
