#!/usr/bin/env bash
# acct-baseline — check. Read-only.

set -euo pipefail

MODULE="acct-baseline"
DRY_RUN=0
CONFIG_FILE="${SELFDEF_ACCT_CONFIG:-/etc/selfdef/modules/acct-baseline.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
LOGROTATE_DIR="${SELFDEF_LOGROTATE_DIR:-/etc/logrotate.d}"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"
PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "enabled")

drift=0
[[ -f "${LOGROTATE_DIR}/selfdef-acct" ]] || { emit_status "drift" "logrotate drop-in missing"; drift=$((drift + 1)); }
[[ -f "$PACCT_FILE" ]] || { emit_status "drift" "pacct file missing: $PACCT_FILE"; drift=$((drift + 1)); }

# Best-effort live state: read /proc/<self>/comm + see if accton
# is "on". `lastcomm -f /var/account/pacct | head -1` exits 0
# only if the pacct file is being written.
if [[ "$PROFILE" == "enabled" ]]; then
    if command -v lastcomm >/dev/null 2>&1; then
        recent=$(lastcomm -f "$PACCT_FILE" 2>/dev/null | head -1 || echo "")
        if [[ -n "$recent" ]]; then
            log "process accounting LIVE — last record: ${recent:0:80}"
        else
            log "process accounting may be OFF — no records in $PACCT_FILE"
        fi
    fi

    # Service-active check (best-effort across distro variation).
    if command -v systemctl >/dev/null 2>&1; then
        if systemctl is-active --quiet acct 2>/dev/null || \
           systemctl is-active --quiet psacct 2>/dev/null; then
            log "acct/psacct service active"
        else
            emit_status "drift" "acct/psacct service NOT active"
            drift=$((drift + 1))
        fi
    fi
fi

# pacct size — operator-readable cost signal.
if [[ -f "$PACCT_FILE" ]]; then
    sz=$(stat -c %s "$PACCT_FILE" 2>/dev/null || echo 0)
    log "pacct file size: ${sz} bytes"
fi

if [[ "$drift" -gt 0 ]]; then
    emit_status "drift" "acct-baseline profile=$PROFILE drift=$drift"
    exit 1
fi
emit_status "ok" "acct-baseline profile=$PROFILE no drift"
