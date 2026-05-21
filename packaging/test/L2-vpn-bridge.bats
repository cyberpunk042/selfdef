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
