#!/usr/bin/env bash
# bridge-l2 — uninstall.
#
# Removes the nftables ruleset and tears down the bridge. Member NICs
# are released back to standalone state but **not** re-configured for
# you — you re-apply their previous IP/DHCP setup. Operator must run
# this from console or via the management interface.
#
# Idempotent. Dry-run aware via SELFDEF_DRY_RUN=1.

set -euo pipefail

MODULE="bridge-l2"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
CONFIG_FILE="${SELFDEF_BRIDGE_L2_CONFIG:-/etc/selfdef/modules/bridge-l2.toml}"
# F-2027-024: post-v2 migration the manifest is the source of
# truth for which files to remove. NFT_RULESET_PATH stays as a
# fallback for pre-v2 installs that never recorded a manifest;
# see "manifest_count == 0" branch below.
NFT_RULESET_PATH="/etc/nftables.d/selfdef-bridge.conf"

# shellcheck source=lib.sh
source "${BASH_SOURCE[0]%/*}/lib.sh"

# Uninstall overrides:
#  - log()  annotates the prefix with `:uninstall` so debug logs
#    distinguish teardown traces from apply traces (this module's
#    convention pre-SDD-006; preserved).
#  - run()  keeps going past per-step failures rather than
#    exiting — partial uninstalls are tolerable.
log() { echo "[bridge-l2:uninstall] $*" >&2; }
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

BRIDGE_NAME="br0"
if [[ -r "$CONFIG_FILE" ]]; then
    BRIDGE_NAME=$(toml_get bridge_name "$CONFIG_FILE" || echo "br0")
fi

# Flush our nftables table; don't touch anything outside it.
if command -v nft >/dev/null && nft list table inet selfdef_bridge >/dev/null 2>&1; then
    run "delete nftables table inet selfdef_bridge" -- nft delete table inet selfdef_bridge
fi

# F-2027-024: walk the rendered-file manifest. apply.sh records
# every rendered file with module_record_file; we just iterate.
manifest_count=0
while IFS= read -r dst; do
    [[ -z "$dst" ]] && continue
    manifest_count=$((manifest_count + 1))
    if [[ -f "$dst" ]]; then
        run "remove $dst" -- rm -f "$dst"
    fi
done < <(module_render_files)

# Migration path: the manifest is empty (pre-v2 install OR
# uninstall-without-apply). Fall back to the legacy hand-coded
# path one last time so existing deployments don't leave the
# nftables ruleset orphaned.
if [[ "$manifest_count" -eq 0 && -f "$NFT_RULESET_PATH" ]]; then
    run "remove $NFT_RULESET_PATH (legacy enum)" -- rm -f "$NFT_RULESET_PATH"
fi

module_clear_manifest

# Tear down the bridge if we own it.
if ip link show dev "$BRIDGE_NAME" type bridge >/dev/null 2>&1; then
    run "bring down $BRIDGE_NAME" -- ip link set "$BRIDGE_NAME" down
    run "delete bridge $BRIDGE_NAME" -- ip link delete "$BRIDGE_NAME" type bridge
fi

emit_status "ok" "uninstalled"
