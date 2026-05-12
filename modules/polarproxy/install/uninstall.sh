#!/usr/bin/env bash
# polarproxy — uninstall.
#
# Removes nftables redirect (if present), stops + disables the
# systemd service, removes the unit file. Does NOT delete the
# PolarProxy binary, captured PCAPs, or the CA bundle.

set -euo pipefail

MODULE="polarproxy"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
UNIT_PATH="${SELFDEF_POLARPROXY_UNIT_PATH:-/etc/systemd/system/polarproxy.service}"
NFT_RULESET_PATH="${SELFDEF_POLARPROXY_NFT_PATH:-/etc/nftables.d/selfdef-polarproxy.conf}"

log() { echo "[polarproxy:uninstall] $*" >&2; }
emit_status() {
    local status="$1" message="$2"
    printf '{"module":"%s","status":"%s","message":"%s"}\n' \
        "$MODULE" "$status" "${message//\"/\\\"}"
}
run() {
    local desc="$1"; shift
    [[ "$1" == "--" ]] && shift
    if [[ "$DRY_RUN" == "1" ]]; then
        log "DRY-RUN: $desc"
        log "    \$ $*"
    else
        log "$desc"
        "$@" || log "(continuing past failure)"
    fi
}

# Stop + disable service first so we don't race the unit removal.
if command -v systemctl >/dev/null; then
    if systemctl is-active --quiet polarproxy.service; then
        run "stop polarproxy.service" -- systemctl stop polarproxy.service
    fi
    if systemctl is-enabled --quiet polarproxy.service 2>/dev/null; then
        run "disable polarproxy.service" -- systemctl disable polarproxy.service
    fi
fi

if [[ -f "$UNIT_PATH" ]]; then
    run "remove $UNIT_PATH" -- rm -f "$UNIT_PATH"
    run "systemctl daemon-reload" -- systemctl daemon-reload
fi

if command -v nft >/dev/null && nft list table inet selfdef_polarproxy >/dev/null 2>&1; then
    run "delete nftables table inet selfdef_polarproxy" -- nft delete table inet selfdef_polarproxy
fi
if [[ -f "$NFT_RULESET_PATH" ]]; then
    run "remove $NFT_RULESET_PATH" -- rm -f "$NFT_RULESET_PATH"
fi

emit_status "ok" "uninstalled"
