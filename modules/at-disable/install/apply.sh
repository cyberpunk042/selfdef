#!/usr/bin/env bash
# at-disable — apply.
#
# systemctl stop + disable atd.service. mask profile additionally
# runs systemctl mask atd. Idempotent.

set -euo pipefail

MODULE="at-disable"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
CONFIG_FILE="${SELFDEF_AT_DISABLE_CONFIG:-/etc/selfdef/modules/at-disable.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"

PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "mask")
case "$PROFILE" in
    mask|stop) ;;
    *) die "profile must be mask|stop, got '$PROFILE'" ;;
esac

# Check if atd unit exists at all (some distros don't install
# at(1) by default — Arch base, Alpine).
if ! command -v systemctl >/dev/null 2>&1; then
    die "systemctl unavailable"
fi

if ! systemctl list-unit-files atd.service >/dev/null 2>&1; then
    log "atd.service not present on this host — at(1) likely not installed; no-op"
    emit_status "ok" "at-disable no-op (atd.service not installed)"
    exit 0
fi

if [[ "$DRY_RUN" == "1" ]]; then
    log "DRY_RUN: would stop + disable atd.service"
    [[ "$PROFILE" == "mask" ]] && log "DRY_RUN: would mask atd.service"
    emit_status "ok" "at-disable DRY_RUN profile=$PROFILE"
    exit 0
fi

# Stop + disable.
run "stop atd.service" -- systemctl stop atd.service || true
run "disable atd.service" -- systemctl disable atd.service || true

# Mask (mask profile only).
if [[ "$PROFILE" == "mask" ]]; then
    run "mask atd.service" -- systemctl mask atd.service || true
fi

# Also remove any operator-pending at jobs (best-effort; atrm
# requires atd running on some kernel paths but is safe to call
# while atd is stopped on most).
if command -v atq >/dev/null 2>&1; then
    pending=$(atq 2>/dev/null | wc -l)
    if [[ "$pending" -gt 0 ]]; then
        log "NOTICE: $pending at-job(s) were pending — operator should atrm <id> manually OR clear /var/spool/at/"
    fi
fi

emit_status "ok" "at-disable profile=$PROFILE"
