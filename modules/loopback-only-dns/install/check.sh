#!/usr/bin/env bash
# loopback-only-dns — check. Read-only.

set -euo pipefail

MODULE="loopback-only-dns"
DRY_RUN=0
CONFIG_FILE="${SELFDEF_LOOPBACK_DNS_CONFIG:-/etc/selfdef/modules/loopback-only-dns.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
DROPIN_DIR="${SELFDEF_RESOLVED_DROPIN_DIR:-/etc/systemd/resolved.conf.d}"
DST="${DROPIN_DIR}/50-selfdef-loopback.conf"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"
PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "loopback")

drift=0
[[ -f "$DST" ]] || { emit_status "drift" "drop-in missing: $DST"; drift=$((drift + 1)); }

# Live check: resolvectl status reports the listener state.
if command -v resolvectl >/dev/null 2>&1; then
    if status=$(resolvectl status 2>&1); then
        log "resolvectl status (head): $(echo "$status" | head -5 | tr '\n' '|')"
    fi
fi

# Verify the resolver is NOT listening on a non-loopback address.
# A 0.0.0.0:53 listener after our drop-in means the drop-in was
# OVERRIDDEN by a later-numbered drop-in OR the OS-shipped
# default leaks through.
if command -v ss >/dev/null 2>&1; then
    non_loopback=$(ss -lntu 2>/dev/null | awk '$5 ~ /:53$/ && $5 !~ /^(127\.|::1)/ {print $5}' | head -3)
    if [[ -n "$non_loopback" ]]; then
        emit_status "drift" "port 53 listener on non-loopback: $non_loopback"
        drift=$((drift + 1))
    fi
fi

if [[ "$drift" -gt 0 ]]; then
    emit_status "drift" "loopback-only-dns profile=$PROFILE drift=$drift"
    exit 1
fi
emit_status "ok" "loopback-only-dns profile=$PROFILE no drift"
