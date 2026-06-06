#!/usr/bin/env bash
# file-protections-baseline — apply.

set -euo pipefail

MODULE="file-protections-baseline"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
CONFIG_FILE="${SELFDEF_FILEPROT_CONFIG:-/etc/selfdef/modules/file-protections-baseline.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"

PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "baseline")
case "$PROFILE" in
    baseline|strict) ;;
    *) die "profile must be baseline|strict, got '$PROFILE'" ;;
esac

SRC="${LIB_DIR}/../configs/${PROFILE}.conf"
[[ -r "$SRC" ]] || die "missing config source: $SRC"

if ! command -v sysctl >/dev/null 2>&1; then
    die "sysctl unavailable"
fi

if [[ "$DRY_RUN" == "1" ]]; then
    log "DRY_RUN: would render $SYSCTL_DROPIN from $SRC"
    emit_status "ok" "file-protections-baseline DRY_RUN profile=$PROFILE"
    exit 0
fi

tmp="$(mktemp "${SYSCTL_DROPIN}.XXXXXX")"
{
    echo "$HEADER_MARKER"
    # No render-timestamp — defeats cmp -s idempotency (2026-06-06).
    echo "# profile=$PROFILE"
    cat "$SRC"
} > "$tmp"
chmod 0644 "$tmp"

# Idempotency: skip rewrite when content unchanged.
if [[ -f "$SYSCTL_DROPIN" ]] && cmp -s "$tmp" "$SYSCTL_DROPIN"; then
    rm -f "$tmp"
else
    mv -f "$tmp" "$SYSCTL_DROPIN"
    log "wrote $SYSCTL_DROPIN"
fi

applied=0; soft_fails=0
while IFS='=' read -r key val; do
    key="${key%% *}"; key="${key## *}"
    val="${val## *}"; val="${val%% *}"
    [[ -z "$key" || "${key:0:1}" == "#" ]] && continue
    if sysctl -w "${key}=${val}" >/dev/null 2>&1; then
        applied=$((applied + 1))
    else
        soft_fails=$((soft_fails + 1))
        log "WARN: sysctl set failed ${key}=${val} (kernel may lack the option)"
    fi
done < <(grep -v '^[[:space:]]*\(#\|$\)' "$SYSCTL_DROPIN" | sed 's/[[:space:]]*=[[:space:]]*/=/')

emit_status "ok" "file-protections-baseline profile=$PROFILE applied=$applied soft_fails=$soft_fails"
