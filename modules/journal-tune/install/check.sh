#!/usr/bin/env bash
# journal-tune — check. Read-only.

set -euo pipefail

MODULE="journal-tune"
DRY_RUN=0
CONFIG_FILE="${SELFDEF_JOURNAL_TUNE_CONFIG:-/etc/selfdef/modules/journal-tune.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
DROPIN_DIR="${SELFDEF_JOURNAL_DROPIN_DIR:-/etc/systemd/journald.conf.d}"
DST="${DROPIN_DIR}/50-selfdef.conf"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"
PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "standard")

drift=0
if [[ ! -f "$DST" ]]; then
    emit_status "drift" "drop-in missing: $DST"
    drift=$((drift + 1))
fi

# Best-effort live check.
if command -v systemctl >/dev/null 2>&1; then
    if ! systemctl is-active --quiet systemd-journald; then
        log "systemd-journald NOT active"
    fi
fi

# journalctl --disk-usage tells the operator the live retention size
# vs the configured SystemMaxUse target.
if command -v journalctl >/dev/null 2>&1; then
    disk=$(journalctl --disk-usage 2>/dev/null | head -1 || echo "")
    if [[ -n "$disk" ]]; then
        log "journal $disk"
    fi
fi

if [[ "$drift" -gt 0 ]]; then
    emit_status "drift" "journal-tune profile=$PROFILE drift=$drift"
    exit 1
fi
emit_status "ok" "journal-tune profile=$PROFILE no drift"
