#!/usr/bin/env bash
# coredump-suid-restrict — apply.

set -euo pipefail

MODULE="coredump-suid-restrict"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
CONFIG_FILE="${SELFDEF_COREDUMP_SUID_CONFIG:-/etc/selfdef/modules/coredump-suid-restrict.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
MODULE_DIR="$(dirname "$LIB_DIR")"
CONFIGS_SRC="${MODULE_DIR}/configs"
LIMITS_D="${SELFDEF_LIMITS_D:-/etc/security/limits.d}"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"

PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "suid-only")
case "$PROFILE" in
    suid-only|all-off) ;;
    *) die "profile must be suid-only|all-off, got '$PROFILE'" ;;
esac

if ! command -v sysctl >/dev/null 2>&1; then
    die "sysctl unavailable"
fi

render() {
    local src="$1" dst="$2"
    local tmp
    tmp="$(mktemp "${dst}.XXXXXX")"
    {
        echo "$HEADER_MARKER"
        # No render-timestamp — defeats cmp -s idempotency (2026-06-06).
        echo "# profile=$PROFILE"
        cat "$src"
    } > "$tmp"
    chmod 0644 "$tmp"
    # Idempotency: skip rewrite when content unchanged.
    if [[ -f "$dst" ]] && cmp -s "$tmp" "$dst"; then
        rm -f "$tmp"
    else
        mv -f "$tmp" "$dst"
        log "wrote $dst"
    fi
}

# Always render the suid_dumpable sysctl drop-in.
if [[ "$DRY_RUN" == "1" ]]; then
    log "DRY_RUN: would render $SYSCTL_DROPIN (fs.suid_dumpable=0)"
else
    render "${CONFIGS_SRC}/sysctl-suid-only.conf" "$SYSCTL_DROPIN"
    sysctl -w "fs.suid_dumpable=0" >/dev/null 2>&1 \
        && log "live: fs.suid_dumpable=0" \
        || log "WARN: failed to set fs.suid_dumpable live"
fi

# all-off profile ALSO writes the limits.d hard-core-0 file.
if [[ "$PROFILE" == "all-off" ]]; then
    mkdir -p "$LIMITS_D"
    if [[ "$DRY_RUN" == "1" ]]; then
        log "DRY_RUN: would render $LIMITS_DROPIN (hard core 0 for all users)"
    else
        render "${CONFIGS_SRC}/limits-all-off.conf" "$LIMITS_DROPIN"
        log "NOTE: limits.d hard-core-0 takes effect on NEXT login session (PAM-evaluated)"
    fi
else
    # suid-only: ensure we don't leave a stale all-off limits file.
    if [[ -f "$LIMITS_DROPIN" ]] && head -1 "$LIMITS_DROPIN" 2>/dev/null | grep -qF "$HEADER_MARKER"; then
        [[ "$DRY_RUN" == "1" ]] && log "DRY_RUN: would remove stale $LIMITS_DROPIN" || { rm -f "$LIMITS_DROPIN"; log "removed stale $LIMITS_DROPIN (suid-only profile)"; }
    fi
fi

emit_status "ok" "coredump-suid-restrict profile=$PROFILE (live suid_dumpable=$(sysctl -n fs.suid_dumpable 2>/dev/null || echo unknown))"
