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

# shellcheck source=lib.sh
source "${BASH_SOURCE[0]%/*}/lib.sh"

# Uninstall overrides: annotated log prefix + lenient run() that
# tolerates per-step failures (partial uninstalls are acceptable).
log() { echo "[polarproxy:uninstall] $*" >&2; }
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

if command -v nft >/dev/null && nft list table inet selfdef_polarproxy >/dev/null 2>&1; then
    run "delete nftables table inet selfdef_polarproxy" -- nft delete table inet selfdef_polarproxy
fi

# F-2027-024: walk the rendered-file manifest. apply.sh records
# UNIT_PATH (always) and NFT_RULESET_PATH (under host-tls-mitm
# only); we just iterate.
removed=0
manifest_count=0
unit_was_recorded=0
while IFS= read -r dst; do
    [[ -z "$dst" ]] && continue
    manifest_count=$((manifest_count + 1))
    if [[ "$dst" == "$UNIT_PATH" ]]; then
        unit_was_recorded=1
    fi
    if [[ -f "$dst" ]]; then
        run "remove $dst" -- rm -f "$dst"
        removed=$((removed + 1))
    fi
done < <(module_render_files)

# Migration path: pre-v2 install. Fall back to the legacy hand-
# coded paths so existing deployments don't leave orphan files.
if [[ "$manifest_count" -eq 0 ]]; then
    if [[ -f "$UNIT_PATH" ]]; then
        run "remove $UNIT_PATH (legacy enum)" -- rm -f "$UNIT_PATH"
        removed=$((removed + 1))
    fi
    if [[ -f "$NFT_RULESET_PATH" ]]; then
        run "remove $NFT_RULESET_PATH (legacy enum)" -- rm -f "$NFT_RULESET_PATH"
        removed=$((removed + 1))
    fi
fi

# Reload systemd if we removed (or migration-removed) the unit.
if [[ "$unit_was_recorded" -eq 1 || ( "$manifest_count" -eq 0 && ! -f "$UNIT_PATH" ) ]]; then
    run "systemctl daemon-reload" -- systemctl daemon-reload
fi

module_clear_manifest

emit_status "ok" "uninstalled ($removed file(s) removed)"
