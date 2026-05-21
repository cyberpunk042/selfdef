#!/usr/bin/env bash
# sudo-tune — check. Read-only.

set -euo pipefail

MODULE="sudo-tune"
DRY_RUN=0
CONFIG_FILE="${SELFDEF_SUDO_TUNE_CONFIG:-/etc/selfdef/modules/sudo-tune.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
SUDOERS_D="${SELFDEF_SUDOERS_D:-/etc/sudoers.d}"
DST="${SUDOERS_D}/50-selfdef-tune"
IOLOG_DIR="${SELFDEF_SUDO_IOLOG_DIR:-/var/log/sudo-io}"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"
PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "audit-trail")

drift=0
if [[ ! -f "$DST" ]]; then
    emit_status "drift" "sudoers.d drop-in missing: $DST"
    drift=$((drift + 1))
fi

if [[ ! -d "$IOLOG_DIR" ]]; then
    emit_status "drift" "iolog dir missing: $IOLOG_DIR"
    drift=$((drift + 1))
else
    perms=$(stat -c '%a %u %g' "$IOLOG_DIR" 2>/dev/null || echo "")
    if [[ "$perms" != "700 0 0" ]]; then
        emit_status "drift" "iolog dir perms = '$perms' (want '700 0 0')"
        drift=$((drift + 1))
    fi
fi

# visudo -c verifies the COMPLETE sudoers tree (main file +
# sudoers.d/) parses cleanly. If it doesn't, sudo is broken right
# now.
if command -v visudo >/dev/null 2>&1; then
    if ! visudo -c >/dev/null 2>&1; then
        emit_status "drift" "visudo -c reports sudoers tree DOES NOT parse cleanly — sudo broken"
        drift=$((drift + 1))
    fi
fi

# Best-effort I/O log inventory (operator-readable: 'how many
# sessions have been recorded since last cleanup').
if [[ -d "$IOLOG_DIR" ]] && command -v find >/dev/null; then
    n_sessions=$(find "$IOLOG_DIR" -maxdepth 5 -name "log" -type f 2>/dev/null | wc -l || echo 0)
    log "sudo-tune iolog sessions recorded: $n_sessions"
fi

if [[ "$drift" -gt 0 ]]; then
    emit_status "drift" "sudo-tune profile=$PROFILE drift=$drift"
    exit 1
fi
emit_status "ok" "sudo-tune profile=$PROFILE no drift"
