#!/usr/bin/env bash
# login-defs-baseline — apply.
#
# Renders /etc/login.defs.d/50-selfdef-login-defs.conf. On
# distros that don't read login.defs.d (older Debian, RHEL 7),
# ALSO append the directives to /etc/login.defs between marker
# fences so the values still take effect.

set -euo pipefail

MODULE="login-defs-baseline"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
CONFIG_FILE="${SELFDEF_LOGINDEFS_CONFIG:-/etc/selfdef/modules/login-defs-baseline.toml}"
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

src="${CONFIGS_SRC}/${PROFILE}.conf"
[[ -r "$src" ]] || die "profile source missing: $src"

if [[ "$DRY_RUN" == "1" ]]; then
    log "DRY_RUN: would render $DROPIN from $src"
    emit_status "ok" "login-defs-baseline DRY_RUN profile=$PROFILE"
    exit 0
fi

# Primary: login.defs.d drop-in.
if [[ -d "$LOGIN_DEFS_D" ]] || mkdir -p "$LOGIN_DEFS_D" 2>/dev/null; then
    tmp="$(mktemp "${DROPIN}.XXXXXX")"
    {
        echo "$HEADER_MARKER"
        echo "# Generated $(date -u '+%Y-%m-%dT%H:%M:%SZ') — profile=$PROFILE"
        cat "$src"
    } > "$tmp"
    chmod 0644 "$tmp"
    mv -f "$tmp" "$DROPIN"
    log "wrote $DROPIN"
fi

# Fallback: some login(1) builds only consult /etc/login.defs.
# Append a marker-fenced block (idempotent — replace if present).
if [[ -f "$LEGACY_LOGIN_DEFS" ]]; then
    # Strip any prior selfdef block, then append the fresh one.
    if grep -qF "$HEADER_MARKER" "$LEGACY_LOGIN_DEFS"; then
        sed -i "/$HEADER_MARKER/,/# end-selfdef login-defs-baseline/d" "$LEGACY_LOGIN_DEFS" 2>/dev/null || true
    fi
    {
        echo "$HEADER_MARKER"
        cat "$src"
        echo "# end-selfdef login-defs-baseline"
    } >> "$LEGACY_LOGIN_DEFS"
    log "appended marker-fenced block to $LEGACY_LOGIN_DEFS (fallback for non-login.defs.d distros)"
fi

emit_status "ok" "login-defs-baseline profile=$PROFILE (affects NEW accounts + password changes; existing accounts via chage)"
