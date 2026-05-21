#!/usr/bin/env bats
# L2 bats unit tests for the polarproxy module (MS023 — transparent
# TLS termination → PCAP-over-IP for content visibility).
#
# Run with: bats packaging/test/L2-polarproxy.bats

MODULE_DIR="${BATS_TEST_DIRNAME}/../../modules/polarproxy"
INSTALL_DIR="${MODULE_DIR}/install"

@test "module.toml exists + declares name = polarproxy" {
    [ -f "${MODULE_DIR}/module.toml" ]
    grep -qE '^name[[:space:]]*=[[:space:]]*"polarproxy"' "${MODULE_DIR}/module.toml"
}

@test "module.toml install.kind = script" {
    grep -qE '^kind[[:space:]]*=[[:space:]]*"script"' "${MODULE_DIR}/module.toml"
}

@test "install/apply.sh + check.sh + uninstall.sh exist + executable" {
    [ -x "${INSTALL_DIR}/apply.sh" ]
    [ -x "${INSTALL_DIR}/check.sh" ]
    [ -x "${INSTALL_DIR}/uninstall.sh" ]
}

@test "apply.sh uses set -euo pipefail" {
    grep -qE '^set -euo pipefail' "${INSTALL_DIR}/apply.sh"
}

@test "apply.sh is SELFDEF_DRY_RUN aware" {
    grep -q 'SELFDEF_DRY_RUN' "${INSTALL_DIR}/apply.sh"
}

@test "apply.sh exposes 4 override env vars (CONFIG, TEMPLATES, UNIT, NFT)" {
    grep -q 'SELFDEF_POLARPROXY_CONFIG'    "${INSTALL_DIR}/apply.sh"
    grep -q 'SELFDEF_POLARPROXY_TEMPLATES' "${INSTALL_DIR}/apply.sh"
    grep -q 'SELFDEF_POLARPROXY_UNIT_PATH' "${INSTALL_DIR}/apply.sh"
    grep -q 'SELFDEF_POLARPROXY_NFT_PATH'  "${INSTALL_DIR}/apply.sh"
}

@test "apply.sh reads profile + listen_port + pcap_over_ip_port config keys" {
    grep -q 'listen_port'        "${INSTALL_DIR}/apply.sh"
    grep -q 'pcap_over_ip_port'  "${INSTALL_DIR}/apply.sh"
}

@test "module.toml profile default = host-tls-mitm" {
    grep -qE 'default[[:space:]]*=[[:space:]]*"host-tls-mitm"' "${MODULE_DIR}/module.toml"
}

@test "apply.sh writes a systemd unit + nftables ruleset" {
    grep -q 'polarproxy.service'        "${INSTALL_DIR}/apply.sh"
    grep -q 'selfdef-polarproxy.conf'   "${INSTALL_DIR}/apply.sh"
}
