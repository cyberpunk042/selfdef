#!/usr/bin/env bash
# shell-timeout-baseline — apply.

set -euo pipefail

MODULE="shell-timeout-baseline"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
CONFIG_FILE="${SELFDEF_TMOUT_CONFIG:-/etc/selfdef/modules/shell-timeout-baseline.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
MODULE_DIR="$(dirname "$LIB_DIR")"
CONFIGS_SRC="${MODULE_DIR}/configs"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"

PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "standard")
case "$PROFILE" in
    standard|strict) ;;
    *) die "profile must be standard|strict, got '$PROFILE'" ;;
esac

src="${CONFIGS_SRC}/${PROFILE}.sh"
[[ -r "$src" ]] || die "profile source missing: $src"

if [[ "$DRY_RUN" == "1" ]]; then
    log "DRY_RUN: would render $DROPIN from $src"
    emit_status "ok" "shell-timeout-baseline DRY_RUN profile=$PROFILE"
    exit 0
fi

mkdir -p "$PROFILE_D"
tmp="$(mktemp "${DROPIN}.XXXXXX")"
{
    echo "#!/bin/sh"
    echo "$HEADER_MARKER"
    echo "# Generated $(date -u '+%Y-%m-%dT%H:%M:%SZ') — profile=$PROFILE"
    cat "$src"
} > "$tmp"
chmod 0644 "$tmp"
mv -f "$tmp" "$DROPIN"
log "wrote $DROPIN (takes effect on NEXT login shell)"

emit_status "ok" "shell-timeout-baseline profile=$PROFILE (effective next login)"
