#!/usr/bin/env bash
# kernel-sysrq-restrict — apply.

set -euo pipefail

MODULE="kernel-sysrq-restrict"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
CONFIG_FILE="${SELFDEF_SYSRQ_CONFIG:-/etc/selfdef/modules/kernel-sysrq-restrict.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"

PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "off")
case "$PROFILE" in
    off|safe-subset|full) ;;
    *) die "profile must be off|safe-subset|full, got '$PROFILE'" ;;
esac

WANT=$(profile_to_value "$PROFILE")
SRC="${LIB_DIR}/../configs/${PROFILE}.conf"
[[ -r "$SRC" ]] || die "missing config source: $SRC"

if ! command -v sysctl >/dev/null 2>&1; then
    die "sysctl unavailable"
fi

if [[ "$DRY_RUN" == "1" ]]; then
    log "DRY_RUN: would render $SYSCTL_DROPIN from $SRC (kernel.sysrq=$WANT)"
    emit_status "ok" "kernel-sysrq-restrict DRY_RUN profile=$PROFILE"
    exit 0
fi

tmp="$(mktemp "${SYSCTL_DROPIN}.XXXXXX")"
{
    echo "$HEADER_MARKER"
    # No render-timestamp — defeats cmp -s idempotency (2026-06-06).
    echo "# profile=$PROFILE (kernel.sysrq=$WANT)"
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

if sysctl -w "kernel.sysrq=$WANT" >/dev/null 2>&1; then
    log "live: kernel.sysrq=$WANT"
else
    log "live sysctl set failed (kernel may have CONFIG_MAGIC_SYSRQ=n)"
fi

emit_status "ok" "kernel-sysrq-restrict profile=$PROFILE value=$WANT (live=$(sysctl -n kernel.sysrq 2>/dev/null || echo unknown))"
