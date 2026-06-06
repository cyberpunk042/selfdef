#!/usr/bin/env bash
# aslr-baseline — apply.

set -euo pipefail

MODULE="aslr-baseline"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
CONFIG_FILE="${SELFDEF_ASLR_CONFIG:-/etc/selfdef/modules/aslr-baseline.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
MODULE_DIR="$(dirname "$LIB_DIR")"
CONFIGS_SRC="${MODULE_DIR}/configs"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"

PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "full")
[[ "$PROFILE" == "full" ]] || die "profile must be full, got '$PROFILE'"

if ! command -v sysctl >/dev/null 2>&1; then
    die "sysctl unavailable"
fi

if [[ "$DRY_RUN" == "1" ]]; then
    log "DRY_RUN: would render $SYSCTL_DROPIN (kernel.randomize_va_space=2)"
    emit_status "ok" "aslr-baseline DRY_RUN profile=full"
    exit 0
fi

tmp="$(mktemp "${SYSCTL_DROPIN}.XXXXXX")"
{
    echo "$HEADER_MARKER"
    # No render-timestamp — defeats cmp -s idempotency.
    echo "# profile=full"
    cat "${CONFIGS_SRC}/full.conf"
} > "$tmp"
chmod 0644 "$tmp"

# Idempotency: skip rewrite when content unchanged (preserves
# mtime so downstream watchdogs don't flag spurious findings).
if [[ -f "$SYSCTL_DROPIN" ]] && cmp -s "$tmp" "$SYSCTL_DROPIN"; then
    rm -f "$tmp"
else
    mv -f "$tmp" "$SYSCTL_DROPIN"
    log "wrote $SYSCTL_DROPIN"
fi

if sysctl -w "kernel.randomize_va_space=2" >/dev/null 2>&1; then
    log "live: kernel.randomize_va_space=2 (full ASLR)"
else
    log "WARN: failed to set kernel.randomize_va_space live"
fi

emit_status "ok" "aslr-baseline profile=full (live=$(sysctl -n kernel.randomize_va_space 2>/dev/null || echo unknown))"
