#!/usr/bin/env bats
# L2 bats unit tests for the suricata module (MS023 sister — Inline
# IDS via Suricata, NFQUEUE or AF_PACKET copy-mode). Depends on
# bridge-l2 (MS024).
#
# Run with: bats packaging/test/L2-suricata.bats

MODULE_DIR="${BATS_TEST_DIRNAME}/../../modules/suricata"
INSTALL_DIR="${MODULE_DIR}/install"

@test "module.toml exists + name = suricata" {
    [ -f "${MODULE_DIR}/module.toml" ]
    grep -qE '^name[[:space:]]*=[[:space:]]*"suricata"' "${MODULE_DIR}/module.toml"
}

@test "module.toml depends_on bridge-l2 (MS024 substrate)" {
    grep -qE '^depends_on[[:space:]]*=[[:space:]]*\[.*"bridge-l2"' "${MODULE_DIR}/module.toml"
}

@test "module.toml profile default = host-ids" {
    grep -qE 'default[[:space:]]*=[[:space:]]*"host-ids"' "${MODULE_DIR}/module.toml"
}

@test "install scripts exist + executable" {
    [ -x "${INSTALL_DIR}/apply.sh" ]
    [ -x "${INSTALL_DIR}/check.sh" ]
    [ -x "${INSTALL_DIR}/uninstall.sh" ]
}

@test "apply.sh uses set -euo pipefail + DRY_RUN aware" {
    grep -qE '^set -euo pipefail' "${INSTALL_DIR}/apply.sh"
    grep -q 'SELFDEF_DRY_RUN' "${INSTALL_DIR}/apply.sh"
}

@test "apply.sh exposes SELFDEF_SURICATA_CONFIG + _TEMPLATES override" {
    grep -q 'SELFDEF_SURICATA_CONFIG'    "${INSTALL_DIR}/apply.sh"
    grep -q 'SELFDEF_SURICATA_TEMPLATES' "${INSTALL_DIR}/apply.sh"
}

@test "apply.sh reads mode + queue_num config keys (NFQUEUE)" {
    grep -q 'mode'      "${INSTALL_DIR}/apply.sh"
    grep -q 'queue_num' "${INSTALL_DIR}/apply.sh"
}

@test "apply.sh handles both NFQUEUE + AF_PACKET copy-modes" {
    grep -q 'nfqueue'    "${INSTALL_DIR}/apply.sh"
    grep -qE 'af.packet|AF_PACKET' "${INSTALL_DIR}/apply.sh"
}
