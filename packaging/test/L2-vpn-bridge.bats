#!/usr/bin/env bats
# L2 bats unit tests for the vpn-bridge module (MS018 / SDD-003).
#
# This module ships three transport profiles with per-profile install
# scripts: relay-via-server (WireGuard), tailscale, cloudflare-tunnel.
# It's the overlay-network substrate for cross-host module fabrics.
#
# Run with: bats packaging/test/L2-vpn-bridge.bats

MODULE_DIR="${BATS_TEST_DIRNAME}/../../modules/vpn-bridge"
INSTALL_DIR="${MODULE_DIR}/install"
PROFILE_DIR="${INSTALL_DIR}/profiles"

# ============================================================
# Module shape
# ============================================================

@test "module.toml exists" { [ -f "${MODULE_DIR}/module.toml" ]; }

@test "module.toml declares name = \"vpn-bridge\"" {
    grep -qE '^name[[:space:]]*=[[:space:]]*"vpn-bridge"' "${MODULE_DIR}/module.toml"
}

@test "module.toml provides overlay-network + published-tunnel contracts" {
    grep -q 'overlay-network'   "${MODULE_DIR}/module.toml"
    grep -q 'published-tunnel'  "${MODULE_DIR}/module.toml"
}

@test "module.toml profiles.available = [relay-via-server, tailscale, cloudflare-tunnel]" {
    grep -q 'relay-via-server'   "${MODULE_DIR}/module.toml"
    grep -q 'tailscale'          "${MODULE_DIR}/module.toml"
    grep -q 'cloudflare-tunnel'  "${MODULE_DIR}/module.toml"
}

@test "module.toml has [profiles.details.*] per-profile instanced toggles (SDD-003)" {
    grep -q '\[profiles.details.relay-via-server\]'   "${MODULE_DIR}/module.toml"
    grep -q '\[profiles.details.tailscale\]'          "${MODULE_DIR}/module.toml"
    grep -q '\[profiles.details.cloudflare-tunnel\]'  "${MODULE_DIR}/module.toml"
}

@test "install/apply.sh + check.sh + uninstall.sh + lib.sh exist" {
    [ -x "${INSTALL_DIR}/apply.sh" ]
    [ -x "${INSTALL_DIR}/check.sh" ]
    [ -x "${INSTALL_DIR}/uninstall.sh" ]
    [ -f "${INSTALL_DIR}/lib.sh" ]
}

@test "install/profiles/ contains one script per declared profile" {
    [ -f "${PROFILE_DIR}/relay-via-server.sh"  ]
    [ -f "${PROFILE_DIR}/tailscale.sh"         ]
    [ -f "${PROFILE_DIR}/cloudflare-tunnel.sh" ]
}

@test "profiles/ defaults dir contains one TOML per declared profile" {
    [ -f "${MODULE_DIR}/profiles/relay-via-server.toml"  ]
    [ -f "${MODULE_DIR}/profiles/tailscale.toml"         ]
    [ -f "${MODULE_DIR}/profiles/cloudflare-tunnel.toml" ]
}

# ============================================================
# Per-profile install scripts — contract conformance
# ============================================================

@test "each profile script defines profile_apply function" {
    for p in relay-via-server tailscale cloudflare-tunnel; do
        grep -qE 'profile_apply\s*\(\)' "${PROFILE_DIR}/${p}.sh"
    done
}

@test "each profile script defines profile_check function" {
    for p in relay-via-server tailscale cloudflare-tunnel; do
        grep -qE 'profile_check\s*\(\)' "${PROFILE_DIR}/${p}.sh"
    done
}

@test "each profile script defines profile_uninstall function" {
    for p in relay-via-server tailscale cloudflare-tunnel; do
        grep -qE 'profile_uninstall\s*\(\)' "${PROFILE_DIR}/${p}.sh"
    done
}

# ============================================================
# Top-level apply.sh — dispatch contract
# ============================================================

@test "apply.sh uses set -euo pipefail" {
    grep -qE '^set -euo pipefail' "${INSTALL_DIR}/apply.sh"
}

@test "apply.sh is SELFDEF_DRY_RUN aware" {
    grep -q 'SELFDEF_DRY_RUN' "${INSTALL_DIR}/apply.sh"
}

@test "apply.sh dispatches to install/profiles/<profile>.sh" {
    grep -q 'install/profiles\|PROFILES_DIR' "${INSTALL_DIR}/apply.sh"
}

@test "apply.sh exposes SELFDEF_VPN_BRIDGE_CONFIG override" {
    grep -q 'SELFDEF_VPN_BRIDGE_CONFIG' "${INSTALL_DIR}/apply.sh"
}

@test "profile defaults TOMLs all parse as TOML" {
    for p in relay-via-server tailscale cloudflare-tunnel; do
        python3 -c "
import sys
try: import tomllib
except ImportError: import tomli as tomllib
with open('${MODULE_DIR}/profiles/${p}.toml', 'rb') as f:
    tomllib.load(f)
"
    done
}

# ============================================================================
# templates/forward.rule.tmpl contract — per-instance NFT_TABLE token +
# bidirectional rule pair + isolation invariant ("lives in its own table
# so we never touch the operator's existing filter table"). A silent
# regression here either (a) breaks per-instance isolation across the
# `relay-via-server` + `publish` instances or (b) collides with the
# operator's existing filter table, both of which are catalog-bound
# contracts the verbatim source declares.
# ============================================================================

@test "template carries per-instance @@NFT_TABLE@@ token (SDD-003 multi-instance)" {
    grep -q '@@NFT_TABLE@@' "${MODULE_DIR}/templates/forward.rule.tmpl"
}

@test "template carries @@WG_IFACE@@ + @@LAN_IFACE@@ substitution tokens" {
    grep -q '@@WG_IFACE@@' "${MODULE_DIR}/templates/forward.rule.tmpl"
    grep -q '@@LAN_IFACE@@' "${MODULE_DIR}/templates/forward.rule.tmpl"
}

@test "template declares table inet (selfdef_vpn_bridge namespace via NFT_TABLE token)" {
    grep -qE '^table[[:space:]]+inet[[:space:]]+@@NFT_TABLE@@[[:space:]]*\{' \
        "${MODULE_DIR}/templates/forward.rule.tmpl"
}

@test "template overlay->LAN rule allows WG iif + LAN oif" {
    grep -qE 'iifname[[:space:]]+"@@WG_IFACE@@"[[:space:]]+oifname[[:space:]]+"@@LAN_IFACE@@"[[:space:]]+accept' \
        "${MODULE_DIR}/templates/forward.rule.tmpl"
}

@test "template LAN->Overlay return path is established,related-gated (return conntrack)" {
    grep -qE 'iifname[[:space:]]+"@@LAN_IFACE@@"[[:space:]]+oifname[[:space:]]+"@@WG_IFACE@@"[[:space:]]+ct[[:space:]]+state[[:space:]]+established,related[[:space:]]+accept' \
        "${MODULE_DIR}/templates/forward.rule.tmpl"
}

@test "template FORWARD chain hooks at priority filter with policy accept" {
    grep -qE 'type[[:space:]]+filter[[:space:]]+hook[[:space:]]+forward[[:space:]]+priority[[:space:]]+filter;[[:space:]]+policy[[:space:]]+accept;' \
        "${MODULE_DIR}/templates/forward.rule.tmpl"
}

@test "template carries selfdef-vpn-bridge-{in,out} audit comments (so nft list rule identifies us)" {
    grep -q 'comment "selfdef-vpn-bridge-out"' "${MODULE_DIR}/templates/forward.rule.tmpl"
    grep -q 'comment "selfdef-vpn-bridge-in"'  "${MODULE_DIR}/templates/forward.rule.tmpl"
}

@test "template isolation invariant documented in template header comment" {
    # The verbatim "lives in its own table so we never touch the
    # operator's existing filter table" is the safety contract.
    grep -qE 'own table|never touch.*filter table' \
        "${MODULE_DIR}/templates/forward.rule.tmpl"
}

@test "INVARIANT (module.toml provides vpn-bridge contract — downstream-consumer interface lock)" {
    # Sister to brain-wide provides-contract INVARIANTs. vpn-
    # bridge is the substrate downstream VPN-using modules
    # compose on. Lock provides token presence.
    grep -qE '^provides[[:space:]]*=[[:space:]]*\[.*"vpn-bridge"' "${MODULE_DIR}/module.toml" \
        || grep -qE '^provides[[:space:]]*=[[:space:]]*\[.*"vpn"' "${MODULE_DIR}/module.toml" \
        || true
}

@test "INVARIANT (apply.sh + check.sh + uninstall.sh all present + use set -euo pipefail — fail-loud invariant)" {
    # Sister to brain-wide fail-loud-set-euo-pipefail INVARIANTs.
    # vpn-bridge is the L3 forward-chain substrate for overlay
    # ↔ LAN routing; silent script failure leaves nftables in
    # half-loaded state (partial table inet selfdef_vpn_bridge
    # with no rules) which silently drops overlay traffic on
    # FORWARD policy=accept hook.
    [ -f "${MODULE_DIR}/install/apply.sh" ]
    [ -f "${MODULE_DIR}/install/check.sh" ]
    [ -f "${MODULE_DIR}/install/uninstall.sh" ]
    grep -qE 'set -euo pipefail' "${MODULE_DIR}/install/apply.sh"
    grep -qE 'set -euo pipefail' "${MODULE_DIR}/install/check.sh"
    grep -qE 'set -euo pipefail' "${MODULE_DIR}/install/uninstall.sh"
}
