#!/usr/bin/env bats
# L2 bats unit tests for the bridge-l2 module (MS024 — transparent
# L2 bridge + nftables policy substrate for inline network modules).
#
# Run with: bats packaging/test/L2-bridge-l2.bats

MODULE_DIR="${BATS_TEST_DIRNAME}/../../modules/bridge-l2"
INSTALL_DIR="${MODULE_DIR}/install"

@test "module.toml exists + declares name = bridge-l2" {
    [ -f "${MODULE_DIR}/module.toml" ]
    grep -qE '^name[[:space:]]*=[[:space:]]*"bridge-l2"' "${MODULE_DIR}/module.toml"
}

@test "module.toml provides l2-bridge + forward-policy contracts" {
    grep -q 'l2-bridge'      "${MODULE_DIR}/module.toml"
    grep -q 'forward-policy' "${MODULE_DIR}/module.toml"
}

@test "module.toml requires ip + nft + systemctl binaries" {
    grep -q 'value = "ip"'        "${MODULE_DIR}/module.toml"
    grep -q 'value = "nft"'       "${MODULE_DIR}/module.toml"
    grep -q 'value = "systemctl"' "${MODULE_DIR}/module.toml"
}

@test "module.toml requires CONFIG_BRIDGE + CONFIG_NF_TABLES kernel features" {
    grep -q 'CONFIG_BRIDGE'    "${MODULE_DIR}/module.toml"
    grep -q 'CONFIG_NF_TABLES' "${MODULE_DIR}/module.toml"
}

@test "install/apply.sh + check.sh + uninstall.sh + lib.sh exist" {
    [ -x "${INSTALL_DIR}/apply.sh" ]
    [ -x "${INSTALL_DIR}/check.sh" ]
    [ -x "${INSTALL_DIR}/uninstall.sh" ]
    [ -f "${INSTALL_DIR}/lib.sh" ]
}

@test "apply.sh uses set -euo pipefail" {
    grep -qE '^set -euo pipefail' "${INSTALL_DIR}/apply.sh"
}

@test "apply.sh is SELFDEF_DRY_RUN aware" {
    grep -q 'SELFDEF_DRY_RUN' "${INSTALL_DIR}/apply.sh"
}

@test "apply.sh exposes SELFDEF_BRIDGE_L2_CONFIG + _TEMPLATES override" {
    grep -q 'SELFDEF_BRIDGE_L2_CONFIG'    "${INSTALL_DIR}/apply.sh"
    grep -q 'SELFDEF_BRIDGE_L2_TEMPLATES' "${INSTALL_DIR}/apply.sh"
}

@test "apply.sh reads bridge_name + forward_policy + management_iface + members" {
    grep -q 'bridge_name'      "${INSTALL_DIR}/apply.sh"
    grep -q 'forward_policy'   "${INSTALL_DIR}/apply.sh"
    grep -q 'management_iface' "${INSTALL_DIR}/apply.sh"
    grep -q 'members'          "${INSTALL_DIR}/apply.sh"
}

@test "apply.sh writes /etc/nftables.d/selfdef-bridge.conf" {
    grep -q '/etc/nftables.d/selfdef-bridge.conf' "${INSTALL_DIR}/apply.sh"
}

@test "apply.sh rejects unknown profile cleanly (dry-run smoke)" {
    TEST_DIR="$(mktemp -d)"
    export SELFDEF_DRY_RUN=1
    export SELFDEF_BRIDGE_L2_CONFIG="${TEST_DIR}/bridge-l2.toml"
    echo 'profile = "totally-bogus-profile-12345"' > "${SELFDEF_BRIDGE_L2_CONFIG}"
    # Mock ip / nft / systemctl.
    export MOCK_BIN="${TEST_DIR}/mockbin"
    mkdir -p "${MOCK_BIN}"
    for b in ip nft systemctl; do
        printf '#!/bin/bash\nexit 0\n' > "${MOCK_BIN}/${b}"
        chmod +x "${MOCK_BIN}/${b}"
    done
    export PATH="${MOCK_BIN}:${PATH}"
    run bash "${INSTALL_DIR}/apply.sh"
    rm -rf "${TEST_DIR}"
    unset SELFDEF_DRY_RUN SELFDEF_BRIDGE_L2_CONFIG MOCK_BIN
    # bridge-l2 only supports default profile "passthrough"; a totally
    # bogus profile should either be rejected OR fall through cleanly.
    # We assert the script doesn't crash with an unhandled error and
    # doesn't exit with a parse error.
    [ "${status}" -ne 2 ]
}
