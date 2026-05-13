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
if [[ -f "$NFT_RULESET_PATH" ]]; then
    run "remove $NFT_RULESET_PATH" -- rm -f "$NFT_RULESET_PATH"
fi

# Tear down the bridge if we own it.
if ip link show dev "$BRIDGE_NAME" type bridge >/dev/null 2>&1; then
    run "bring down $BRIDGE_NAME" -- ip link set "$BRIDGE_NAME" down
    run "delete bridge $BRIDGE_NAME" -- ip link delete "$BRIDGE_NAME" type bridge
fi

emit_status "ok" "uninstalled"
